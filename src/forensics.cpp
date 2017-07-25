#include "forensics.h"
#include "backtrace.h"
#include <cstdarg>
#include <cstdlib>
#include <thread>

#define DEFAULT_MAX_CONTEXT_DEPTH 128
#define DEFAULT_MAX_FORMATTED_MESSAGE_SIZE_BYTES (1 * 1024)
#define DEFAULT_MAX_ATTRIBUTE_COUNT 128
#define DEFAULT_ATTRIBUTE_BUF_SIZE_BYTES (4 * 1024)
#define DEFAULT_MAX_BACKTRACE_COUNT 256

struct context_buffer_t {
  int count;
  int capacity;
  int overflow_count;
  bool initialized;
  const char** stack;
};

static forensics_config_t s_config;
thread_local static context_buffer_t s_tls_context_buf;

static char** s_attribute_keys;
static char** s_attribute_values;
static int s_attribute_count;
static char* s_attribute_buf;
static int s_attribute_buf_used;

static void** s_backtrace_buf;

static std::mutex s_report_mutex;
static char* s_report_formatted_msg;

static void panic() {
  exit(EXIT_FAILURE);
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
  const char* buf_end = s_attribute_buf + s_config.attribute_buf_size_bytes;
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
  FORENSICS_ASSERTF(s_attribute_count < s_config.max_attribute_count,
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

void forensics_config_init(forensics_config_t* config) {
  if (config != nullptr) {
    config->fatal_should_halt = true;
    config->max_context_depth = DEFAULT_MAX_CONTEXT_DEPTH;
    config->max_formatted_message_size_bytes = DEFAULT_MAX_FORMATTED_MESSAGE_SIZE_BYTES;
    config->max_attribute_count = DEFAULT_MAX_ATTRIBUTE_COUNT;
    config->attribute_buf_size_bytes = DEFAULT_ATTRIBUTE_BUF_SIZE_BYTES;
    config->max_backtrace_count = DEFAULT_MAX_BACKTRACE_COUNT;
    config->report_handler = &forensics_default_report_handler;
  }
}

void forensics_init(const forensics_config_t* config) {
  if (config) {
    s_config = *config;
  }
  else {
    forensics_config_init(&s_config);
  }

  s_report_formatted_msg = (char*)malloc(s_config.max_formatted_message_size_bytes);

  s_attribute_keys = (char**)malloc(s_config.max_attribute_count * sizeof(char*));
  s_attribute_values = (char**)malloc(s_config.max_attribute_count * sizeof(char*));
  s_attribute_buf = (char*)malloc(s_config.attribute_buf_size_bytes);
  s_attribute_count = 0;
  s_attribute_buf_used = 0;

  s_backtrace_buf = (void**)malloc(s_config.max_backtrace_count * sizeof(void*));
}

void forensics_shutdown() {
  free(s_backtrace_buf);

  free(s_attribute_buf);
  free(s_attribute_values);
  free(s_attribute_keys);
  s_attribute_buf = nullptr;
  s_attribute_values = nullptr;
  s_attribute_keys = nullptr;
  s_attribute_count = 0;
  s_attribute_buf_used = 0;

  free(s_report_formatted_msg);
  s_report_formatted_msg = nullptr;
}

void forensics_context_begin(const char* name) {
  struct context_buffer_t* ctx_buf = &s_tls_context_buf;

  // handle first-time initialization (per thread)
  if (!ctx_buf->initialized) {
    ctx_buf->count = 0;
    ctx_buf->capacity = s_config.max_context_depth;
    ctx_buf->overflow_count = 0;
    ctx_buf->initialized = true;
    ctx_buf->stack = (const char**)malloc(sizeof(const char*) * s_config.max_context_depth);
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

void forensics_set_attribute(const char* key, const char* value) {
  // TODO: grab a mutex here

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
  // TODO: implement me
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

  struct context_buffer_t* ctx_buf = &s_tls_context_buf;
  report.context_stack = ctx_buf->stack;
  report.context_count = ctx_buf->count;

  // TODO: gather the attributes
  report.attribute_count = s_attribute_count;
  if (s_attribute_count > 0) {
    report.attribute_keys = s_attribute_keys;
    report.attribute_values = s_attribute_values;
  }
  else {
    report.attribute_keys = nullptr;
    report.attribute_values = nullptr;
  }

  // TODO: gather the breadcrumbs

  // TODO: capture the backtrace
  report.backtrace_count = forensics_private_backtrace(s_backtrace_buf, s_config.max_backtrace_count);
  if (report.backtrace_count > 0) {
    report.backtrace = s_backtrace_buf;
  }
  else {
    report.backtrace = nullptr;
  }

  // call the report handler
  s_config.report_handler(&report);

  // halting?
  if (fatal && s_config.fatal_should_halt) {
    panic();
  }
}
