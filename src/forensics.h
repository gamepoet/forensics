#pragma once
#include <stdbool.h>

#ifdef __cplusplus
extern "C" {
#endif

struct forensics_report_t {
  const char* id;
  const char* file;
  int line;
  const char* func;
  const char* expression;
  const char* format;
  const char* formatted;
  bool fatal;

  // TODO: breadcrumbs

  const char* const* context_stack;
  int context_count;

  const char* const* attribute_keys;
  const char* const* attribute_values;
  int attribute_count;

  const void* const* backtrace;
  int backtrace_count;
};

typedef void (*forensics_report_handler_t)(const struct forensics_report_t* report);

struct forensics_config_t {
  bool fatal_should_halt;
  unsigned int max_id_size_bytes;
  unsigned int max_context_depth;
  unsigned int max_formatted_message_size_bytes;
  unsigned int max_attribute_count;
  unsigned int attribute_buf_size_bytes;
  unsigned int max_backtrace_count;
  forensics_report_handler_t report_handler;
};

void forensics_config_init(struct forensics_config_t* config);

void forensics_init(const struct forensics_config_t* config);
void forensics_shutdown();

void forensics_context_begin(const char* name);
void forensics_context_end();

void forensics_add_breadcrumb(const char* name, const char** meta_keys, const char** meta_values, int meta_count);
void forensics_set_attribute(const char* key, const char* value);

void forensics_default_report_handler(const struct forensics_report_t* report);

void forensics_report_assert_failure(
    const char* file, int line, const char* func, bool fatal, const char* expression, const char* format, ...);

#define FORENSICS_ASSERT(expr)                                                                                         \
  ((expr) ? true : (forensics_report_assert_failure(__FILE__, __LINE__, __func__, true, #expr, ""), false))
#define FORENSICS_ASSERTF(expr, ...)                                                                                   \
  ((expr) ? true : (forensics_report_assert_failure(__FILE__, __LINE__, __func__, true, #expr, __VA_ARGS__), false))
#define FORENSICS_VERIFY(expr)                                                                                         \
  ((expr) ? true : (forensics_report_assert_failure(__FILE__, __LINE__, __func__, false, #expr, ""), false))
#define FORENSICS_VERIFYF(expr, ...)                                                                                   \
  ((expr) ? true : (forensics_report_assert_failure(__FILE__, __LINE__, __func__, false, #expr, __VA_ARGS__), false))

#ifdef NDEBUG
#define FORENSICS_ASSERT_DBG(expr) true
#define FORENSICS_ASSERT_DBGF(expr, ...) true
#else
#define FORENSICS_ASSERT_DBG(expr)                                                                                     \
  ((expr) ? true : (forensics_report_assert_failure(__FILE__, __LINE__, __func__, true, #expr, ""), false))
#define FORENSICS_ASSERT_DBGF(expr, ...)                                                                               \
  ((expr) ? true : (forensics_report_assert_failure(__FILE__, __LINE__, __func__, true, #expr, __VA_ARGS__), false))
#endif // NDEBUG

#ifdef __cplusplus

#define FORENSICS_CONTEXT_CONCAT2(a, b) a##b
#define FORENSICS_CONTEXT_CONCAT(a, b) FORENSICS_CONTEXT_CONCAT2(a, b)
#define FORENSICS_CONTEXT(name) forensics_context_t FORENSICS_CONTEXT_CONCAT(forensics_context__, __LINE__)(name)

struct forensics_context_t {
  inline forensics_context_t(const char* name) {
    forensics_context_begin(name);
  }
  inline ~forensics_context_t() {
    forensics_context_end();
  }
};
#endif // __cplusplus

#ifdef __cplusplus
}
#endif
