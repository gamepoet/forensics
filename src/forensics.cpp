#include "forensics.h"
#include "backtrace.h"
#include <cstdarg>
#include <cstdlib>
#include <mutex>
#include <thread>

#define DEFAULT_MAX_CONTEXT_DEPTH 128
#define DEFAULT_MAX_FORMATTED_MESSAGE_SIZE_BYTES (1 * 1024)
#define DEFAULT_MAX_ATTRIBUTE_COUNT 128
#define DEFAULT_ATTRIBUTE_BUF_SIZE_BYTES (4 * 1024)
#define DEFAULT_MAX_BACKTRACE_COUNT 256
#define DEFAULT_MAX_ID_SIZE_BYTES 512
#define DEFAULT_MAX_BREADCRUMB_COUNT 128
#define DEFAULT_BREADCRUMB_BUF_SIZE_BYTES (4 * 1024)

struct context_buffer_t {
  ~context_buffer_t();

  int count;
  int capacity;
  int overflow_count;
  bool initialized;
  const char** stack;

  context_buffer_t* prev;
  context_buffer_t* next;
};
struct breadcrumb_t {
  forensics_breadcrumb_t crumb;
  int buf_size;
};

static forensics_config_t s_config;
thread_local static context_buffer_t s_tls_context_buf;
static context_buffer_t* s_context_buf_list;
static std::mutex s_context_buf_list_mutex;

static breadcrumb_t* s_breadcrumbs;
static int s_breadcrumbs_index_next;
static int s_breadcrumbs_count;
static char* s_breadcrumbs_buf;
static int s_breadcrumbs_buf_read_index;
static int s_breadcrumbs_buf_write_index;

static char** s_attribute_keys;
static char** s_attribute_values;
static int s_attribute_count;
static char* s_attribute_buf;
static int s_attribute_buf_used;

static void** s_backtrace_buf;

static std::mutex s_report_mutex;
static char* s_report_id;
static char* s_report_formatted_msg;
static forensics_breadcrumb_t* s_report_breadcrumbs;

static void panic() {
  exit(EXIT_FAILURE);
}

static void* default_alloc(uintptr_t size, void* user_data) {
  return malloc(size);
}

static void default_free(void* memory, void* user_data) {
  free(memory);
}

static void* forensics_alloc(uintptr_t size) {
  return s_config.alloc(size, s_config.alloc_user_data);
}

static void forensics_free(void* memory) {
  s_config.free(memory, s_config.alloc_user_data);
}

static int attribute_find(const char* key) {
  for (int index = 0; index < s_attribute_count; ++index) {
    if (0 == strcmp(key, s_attribute_keys[index])) {
      return index;
    }
  }
  return -1;
}

static void attribute_clear(int index) {
  char* key = s_attribute_keys[index];
  char* value = s_attribute_values[index];
  const int key_size_bytes = strlen(key) + 1;
  const int value_size_bytes = strlen(value) + 1;
  const int size_bytes = key_size_bytes + value_size_bytes;

  // fill in the hole in the buffer
  const intptr_t key_offset = (intptr_t)(key - s_attribute_buf);
  const intptr_t bytes_to_copy = s_attribute_buf_used - key_offset - size_bytes;
  memcpy(key, key + size_bytes, bytes_to_copy);

  // fill in the hole in the pointers update the pointer dests
  for (int fix_index = index + 1; fix_index < s_attribute_count; ++fix_index) {
    const int dest_index = fix_index - 1;
    s_attribute_keys[dest_index] = s_attribute_keys[fix_index] - size_bytes;
    s_attribute_values[dest_index] = s_attribute_values[fix_index] - size_bytes;
  }
  --s_attribute_count;
}

static void attribute_append(const char* key, const char* value) {
  FORENSICS_ASSERTF(s_attribute_count < (int)s_config.max_attribute_count,
                    "Cannot set attribute because the attribute key array is full. Try increasing the size of "
                    "max_attribute_count. key=%s value=%s",
                    key,
                    value);

  const int key_size_bytes = strlen(key) + 1;
  const int value_size_bytes = strlen(value) + 1;
  const int size_bytes = key_size_bytes + value_size_bytes;

  const int avail = s_config.attribute_buf_size_bytes - s_attribute_buf_used;
  FORENSICS_ASSERTF(avail >= size_bytes,
                    "Cannot set attribute because the attribute buffer is full. Try increasing the size of "
                    "attribute_buf_size_bytes. attribute=%s needed=%d avail=%d",
                    key,
                    size_bytes,
                    avail);

  // copy in the string data
  char* key_in_buf = s_attribute_buf + s_attribute_buf_used;
  char* value_in_buf = key_in_buf + key_size_bytes;
  memmove(key_in_buf, key, key_size_bytes);
  memmove(value_in_buf, value, value_size_bytes);
  s_attribute_buf_used += size_bytes;

  // flesh out the KV pointers
  s_attribute_keys[s_attribute_count] = key_in_buf;
  s_attribute_values[s_attribute_count] = value_in_buf;
  ++s_attribute_count;
}

static char* breadcrumb_buf_alloc(int size_bytes) {
  int write_index = s_breadcrumbs_buf_write_index;
  const int read_index = s_breadcrumbs_buf_read_index;

  // check if the write head will pass the read head
  if ((write_index < read_index) && (write_index + size_bytes > read_index)) {
    return nullptr;
  }

  // wrap around if needed
  if (write_index + size_bytes > s_config.breadcrumb_buf_size_bytes) {
    write_index = 0;

    // check again if the write head will pass the read head
    if (size_bytes > read_index) {
      return nullptr;
    }
  }

  s_breadcrumbs_buf_write_index = write_index + size_bytes;
  return s_breadcrumbs_buf + write_index;
}

static void breadcrumb_deque() {
  const int first_index =
      (s_breadcrumbs_index_next + s_config.max_breadcrumb_count - s_breadcrumbs_count) % s_config.max_breadcrumb_count;
  breadcrumb_t* breadcrumb = s_breadcrumbs + first_index;

  // free the ring buffer space
  s_breadcrumbs_buf_read_index += breadcrumb->buf_size;
  if (s_breadcrumbs_buf_read_index >= s_config.breadcrumb_buf_size_bytes) {
    s_breadcrumbs_buf_read_index = 0;
  }

  // clear out the breadcrumb struct
  breadcrumb->crumb.name = nullptr;
  breadcrumb->crumb.meta_keys = nullptr;
  breadcrumb->crumb.meta_values = nullptr;
  breadcrumb->crumb.meta_count = 0;
  breadcrumb->crumb.count = 0;
  breadcrumb->buf_size = 0;

  // forget about the breadcrumb
  --s_breadcrumbs_count;
}

static void context_buffer_init(context_buffer_t* ctx_buf) {
  std::lock_guard<std::mutex> lock(s_context_buf_list_mutex);

  ctx_buf->count = 0;
  ctx_buf->capacity = s_config.max_context_depth;
  ctx_buf->overflow_count = 0;
  ctx_buf->initialized = true;
  ctx_buf->stack = (const char**)forensics_alloc(sizeof(const char*) * s_config.max_context_depth);
  ctx_buf->next = nullptr;
  ctx_buf->prev = nullptr;

  // add the context buffer to the linked list
  if (s_context_buf_list == nullptr) {
    // empty list
    s_context_buf_list = ctx_buf;
  }
  else {
    // insert at the head of the list
    ctx_buf->next = s_context_buf_list;
    s_context_buf_list = ctx_buf;
    if (ctx_buf->next != nullptr) {
      ctx_buf->prev = ctx_buf;
    }
  }
}

static void context_buffer_destroy(context_buffer_t* ctx_buf) {
  std::lock_guard<std::mutex> lock(s_context_buf_list_mutex);

  // handle multiple destroys (could be both explicit and implied from the destructor)
  if (ctx_buf->initialized) {
    forensics_free(ctx_buf->stack);
    ctx_buf->stack = nullptr;
    ctx_buf->initialized = false;

    // remove the context buffer from the linked list
    if (s_context_buf_list == ctx_buf) {
      // remove from head of the list
      s_context_buf_list = ctx_buf->next;
      if (ctx_buf->next != nullptr) {
        ctx_buf->next->prev = nullptr;
      }
    }
    else {
      // remove from the middle or end of the list
      if (ctx_buf->next != nullptr) {
        ctx_buf->next->prev = ctx_buf->prev;
      }
      if (ctx_buf->prev != nullptr) {
        ctx_buf->prev->next = ctx_buf->next;
      }
    }
  }
}

context_buffer_t::~context_buffer_t() {
  context_buffer_destroy(this);
}

void forensics_config_init(forensics_config_t* config) {
  if (config != nullptr) {
    config->fatal_should_halt = true;
    config->max_id_size_bytes = DEFAULT_MAX_ID_SIZE_BYTES;
    config->max_context_depth = DEFAULT_MAX_CONTEXT_DEPTH;
    config->max_formatted_message_size_bytes = DEFAULT_MAX_FORMATTED_MESSAGE_SIZE_BYTES;
    config->max_attribute_count = DEFAULT_MAX_ATTRIBUTE_COUNT;
    config->attribute_buf_size_bytes = DEFAULT_ATTRIBUTE_BUF_SIZE_BYTES;
    config->max_backtrace_count = DEFAULT_MAX_BACKTRACE_COUNT;
    config->max_breadcrumb_count = DEFAULT_MAX_BREADCRUMB_COUNT;
    config->breadcrumb_buf_size_bytes = DEFAULT_BREADCRUMB_BUF_SIZE_BYTES;
    config->report_handler = &forensics_default_report_handler;
    config->alloc = &default_alloc;
    config->free = &default_free;
    config->alloc_user_data = nullptr;
  }
}

void forensics_init(const forensics_config_t* config) {
  if (config) {
    s_config = *config;
  }
  else {
    forensics_config_init(&s_config);
  }

  s_context_buf_list = nullptr;

  s_report_id = (char*)forensics_alloc(s_config.max_id_size_bytes);
  s_report_formatted_msg = (char*)forensics_alloc(s_config.max_formatted_message_size_bytes);
  s_report_breadcrumbs =
      (forensics_breadcrumb_t*)forensics_alloc(s_config.max_breadcrumb_count * sizeof(forensics_breadcrumb_t));

  s_attribute_keys = (char**)forensics_alloc(s_config.max_attribute_count * sizeof(char*));
  s_attribute_values = (char**)forensics_alloc(s_config.max_attribute_count * sizeof(char*));
  s_attribute_buf = (char*)forensics_alloc(s_config.attribute_buf_size_bytes);
  s_attribute_count = 0;
  s_attribute_buf_used = 0;

  s_breadcrumbs = (breadcrumb_t*)forensics_alloc(s_config.max_breadcrumb_count * sizeof(breadcrumb_t));
  s_breadcrumbs_buf = (char*)forensics_alloc(s_config.breadcrumb_buf_size_bytes);
  s_breadcrumbs_count = 0;
  s_breadcrumbs_index_next = 0;
  s_breadcrumbs_buf_read_index = 0;
  s_breadcrumbs_buf_write_index = 0;

  s_backtrace_buf = (void**)forensics_alloc(s_config.max_backtrace_count * sizeof(void*));
}

void forensics_shutdown() {
  // free the allocated thread context buffers
  while (s_context_buf_list != nullptr) {
    context_buffer_destroy(s_context_buf_list);
  }

  forensics_free(s_backtrace_buf);

  forensics_free(s_breadcrumbs_buf);
  forensics_free(s_breadcrumbs);
  s_breadcrumbs_buf = nullptr;
  s_breadcrumbs = nullptr;
  s_breadcrumbs_count = 0;
  s_breadcrumbs_index_next = 0;
  s_breadcrumbs_buf_read_index = 0;
  s_breadcrumbs_buf_write_index = 0;

  forensics_free(s_attribute_buf);
  forensics_free(s_attribute_values);
  forensics_free(s_attribute_keys);
  s_attribute_buf = nullptr;
  s_attribute_values = nullptr;
  s_attribute_keys = nullptr;
  s_attribute_count = 0;
  s_attribute_buf_used = 0;

  forensics_free(s_report_breadcrumbs);
  s_report_breadcrumbs = nullptr;
  forensics_free(s_report_formatted_msg);
  s_report_formatted_msg = nullptr;
  forensics_free(s_report_id);
  s_report_id = nullptr;
}

void forensics_context_begin(const char* name) {
  struct context_buffer_t* ctx_buf = &s_tls_context_buf;

  // handle first-time initialization (per thread)
  if (!ctx_buf->initialized) {
    context_buffer_init(ctx_buf);
  }

  // check for overflow
  const int new_count = ctx_buf->count + 1;
  if (new_count > ctx_buf->capacity) {
    ++ctx_buf->overflow_count;
    return;
  }

  // append the new context
  ctx_buf->stack[ctx_buf->count] = name;
  ctx_buf->count = new_count;
}

void forensics_context_end() {
  struct context_buffer_t* ctx_buf = &s_tls_context_buf;

  // check for overflow
  if (ctx_buf->overflow_count > 0) {
    --ctx_buf->overflow_count;
    return;
  }

  // check for underflow
  FORENSICS_ASSERTF(ctx_buf->count > 0,
                    "The forensics context stack underflowed. Do you have mismatched "
                    "forensics_context_begin/forensics_context_end calls?");

  --ctx_buf->count;
}

void forensics_add_breadcrumb(const char* name, const char** meta_keys, const char** meta_values, int meta_count) {
  // allow multi-threaded access to this function and protect against the crash handler
  std::lock_guard<std::mutex> lock(s_report_mutex);

  // bail if configured to be disabled
  if (s_config.max_breadcrumb_count == 0) {
    return;
  }

  // compare against the last breadcrumb to see if we can just denote repetetion
  if (s_breadcrumbs_count > 0) {
    const int last_index =
        (s_breadcrumbs_index_next + s_config.max_breadcrumb_count - 1) % s_config.max_breadcrumb_count;
    forensics_breadcrumb_t* prev = &s_breadcrumbs[last_index].crumb;
    if (prev->meta_count == meta_count) {
      if (!strcmp(prev->name, name)) {
        bool match = true;
        for (int index = 0; index < meta_count; ++index) {
          if (0 != strcmp(prev->meta_keys[index], meta_keys[index])) {
            match = false;
            break;
          }
          if (0 != strcmp(prev->meta_values[index], meta_values[index])) {
            match = false;
            break;
          }
        }
        if (match == true) {
          // previous breadcrumb was identical; record the repetetion and bail
          ++prev->count;
          return;
        }
      }
    }
  }

  const int name_size_bytes = strlen(name) + 1;

  // compute the required space in the ringbuffer
  int required_size = 0;
  required_size += sizeof(char**) * meta_count * 2;
  required_size += name_size_bytes;
  for (int index = 0; index < meta_count; ++index) {
    required_size += strlen(meta_keys[index]) + 1;
    required_size += strlen(meta_values[index]) + 1;
  }

  // remove a breadcrumb if there are too many
  if (s_breadcrumbs_count >= s_config.max_breadcrumb_count) {
    breadcrumb_deque();
  }

  // alloc space from the ring buffer
  char* alloc = breadcrumb_buf_alloc(required_size);
  if (alloc == nullptr) {
    // bail in the pathalogical case where it can't fit
    if (required_size > s_config.breadcrumb_buf_size_bytes) {
      return;
    }

    // remove a breadcrumb to make room
    while (alloc == nullptr) {
      breadcrumb_deque();
      alloc = breadcrumb_buf_alloc(required_size);
    }
  }

  // copy the data into the ring buffer
  char** out_meta_keys = (char**)alloc;
  char** out_meta_values = (char**)(out_meta_keys + sizeof(char**) * meta_count);
  char* out_name = (char*)(out_meta_values + sizeof(char**) * meta_count);
  char* ptr = out_name + name_size_bytes;
  memmove(out_name, name, name_size_bytes);
  for (int index = 0; index < meta_count; ++index) {
    const int key_size_bytes = strlen(meta_keys[index]) + 1;
    const int value_size_bytes = strlen(meta_values[index]) + 1;
    char* out_key = ptr;
    char* out_value = out_key + key_size_bytes;
    ptr = out_value + value_size_bytes;

    memmove(out_key, meta_keys[index], key_size_bytes);
    memmove(out_value, meta_values[index], value_size_bytes);
    out_meta_keys[index] = out_key;
    out_meta_values[index] = out_value;
  }

  breadcrumb_t* breadcrumb = s_breadcrumbs + s_breadcrumbs_index_next;
  breadcrumb->buf_size = required_size;
  forensics_breadcrumb_t* crumb = &breadcrumb->crumb;
  crumb->name = out_name;
  if (meta_count > 0) {
    crumb->meta_keys = (const char**)out_meta_keys;
    crumb->meta_values = (const char**)out_meta_values;
  }
  else {
    crumb->meta_keys = nullptr;
    crumb->meta_values = nullptr;
  }
  crumb->meta_count = meta_count;
  crumb->count = 1;

  s_breadcrumbs_index_next = (s_breadcrumbs_index_next + 1) % s_config.max_breadcrumb_count;
  ++s_breadcrumbs_count;
}

void forensics_set_attribute(const char* key, const char* value) {
  // allow multi-threaded access to this function and protect against the crash handler
  std::lock_guard<std::mutex> lock(s_report_mutex);

  // bail if configured to be disabled
  if (s_config.max_attribute_count == 0) {
    return;
  }

  if (value == nullptr) {
    const int index = attribute_find(key);
    if (index != -1) {
      attribute_clear(index);
    }
  }
  else {
    const int index = attribute_find(key);
    if (index != -1) {
      attribute_clear(index);
    }
    attribute_append(key, value);
  }
}

void forensics_default_report_handler(const struct forensics_report_t* report) {
  const char* context = "<none>";
  if (report->context_count > 0) {
    context = report->context_stack[report->context_count - 1];
  }

  fprintf(stderr, "ASSERTION FAILED\n");
  fprintf(stderr, "expression: %s\n", report->expression);
  fprintf(stderr, "context: %s\n", context);
  fprintf(stderr, "file: %s\n", report->file);
  fprintf(stderr, "line: %d\n", report->line);
  fprintf(stderr, "function: %s\n", report->func);
  fprintf(stderr, "id: %s\n", report->id);
  fprintf(stderr, "backtrace:\n");
  for (int index = 0; index < report->backtrace_count; ++index) {
    fprintf(stderr, "  %p\n", report->backtrace[index]);
  }
}

void forensics_report_assert_failure(
    const char* file, int line, const char* func, bool fatal, const char* expression, const char* format, ...) {

  // grab the mutex so only one thread can crash at a time
  std::lock_guard<std::mutex> lock(s_report_mutex);

  // format the message
  va_list args;
  va_start(args, format);
  vsnprintf(s_report_formatted_msg, s_config.max_formatted_message_size_bytes, format, args);
  s_report_formatted_msg[s_config.max_formatted_message_size_bytes - 1] = 0;
  va_end(args);

  // build the report
  forensics_report_t report;
  report.file = file;
  report.line = line;
  report.func = func;
  report.expression = expression;
  report.format = format;
  report.formatted = s_report_formatted_msg;
  report.fatal = fatal;

  // grab the context stack
  struct context_buffer_t* ctx_buf = &s_tls_context_buf;
  if (ctx_buf->count > 0) {
    report.context_stack = ctx_buf->stack;
  }
  else {
    report.context_stack = nullptr;
  }
  report.context_count = ctx_buf->count;

  // gather the attributes
  report.attribute_count = s_attribute_count;
  if (s_attribute_count > 0) {
    report.attribute_keys = s_attribute_keys;
    report.attribute_values = s_attribute_values;
  }
  else {
    report.attribute_keys = nullptr;
    report.attribute_values = nullptr;
  }

  // gather the breadcrumbs
  report.breadcrumb_count = s_breadcrumbs_count;
  if (s_breadcrumbs_count > 0) {
    report.breadcrumbs = s_report_breadcrumbs;
    for (int index = 0; index < s_breadcrumbs_count; ++index) {
      const int src_index = (s_breadcrumbs_index_next + s_config.max_breadcrumb_count - s_breadcrumbs_count + index) %
                            s_config.max_breadcrumb_count;
      s_report_breadcrumbs[index] = s_breadcrumbs[src_index].crumb;
    }
  }
  else {
    report.breadcrumbs = nullptr;
  }

  // capture the backtrace
  report.backtrace_count = forensics_private_backtrace(s_backtrace_buf, s_config.max_backtrace_count);
  if (report.backtrace_count > 0) {
    report.backtrace = s_backtrace_buf;
  }
  else {
    report.backtrace = nullptr;
  }

  // generate the report id
  const char* context = report.context_count > 0 ? report.context_stack[report.context_count - 1] : "<none>";
  const char* file_basename = strrchr(file, '/');
  if (file_basename == nullptr) {
    file_basename = strrchr(file, '\\');
  }
  if (file_basename == nullptr) {
    file_basename = file;
  }
  if (file_basename != file) {
    file_basename += 1;
  }
  snprintf(s_report_id, s_config.max_id_size_bytes, "%s-%s-%s-%s", context, file_basename, func, format);
  s_report_id[s_config.max_id_size_bytes - 1] = 0;
  report.id = s_report_id;

  // call the report handler
  s_config.report_handler(&report);

  // halting?
  if (fatal && s_config.fatal_should_halt) {
    panic();
  }
}
