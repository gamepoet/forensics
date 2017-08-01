#pragma once
#include <stdbool.h>

#ifdef __cplusplus
extern "C" {
#endif

// Contains information about a single breadcrumb in a report.
struct forensics_breadcrumb_t {
  const char* name;         // the name of this breadcrumb
  const char** meta_keys;   // array of metadata key strings
  const char** meta_values; // array of metadata value strings
  int meta_count;           // the number of metadata key/value pairs
  int count;                // the number of times this breadcrumb occurred in a row
};

// All the information available in an error report.
struct forensics_report_t {
  const char* id;   // A agrregation id (or fingerprint) for this report: "CONTEXT-FILE_BASENAME-FUNC-MSG_FORMAT_STRING"
  const char* file; // The source file where the assertion occurred.
  int line;         // The source line where the assertion occurred.
  const char* func; // The name of the func in which the assertion occurred.
  const char* expression; // The assertion conditional expression.
  const char* format;     // The format string (i.e. the unformatted message).
  const char* formatted;  // The formatted message.
  bool fatal;             // Is this a fatal assertion?

  const forensics_breadcrumb_t* breadcrumbs; // Array of breadcrumbs that have been left, in order.
  int breadcrumb_count;                      // The number of breadcrumbs.

  const char* const*
      context_stack; // The stack of error contexts. The most recent (i.e. responsible one) is at the end.
  int context_count; // The number of contexts on the stack

  const char* const* attribute_keys;   // Array of attribute key strings
  const char* const* attribute_values; // Array of attribute value strings
  int attribute_count;                 // The number of attributes

  const void* const*
      backtrace; // The code pointers that make up the backtrace at the point where the thread trigger the error report.
  int backtrace_count; // The number of frames in the backtrace.
};

typedef void (*forensics_report_handler_t)(const struct forensics_report_t* report);

struct forensics_config_t {
  // Fatal assertions should halt. Set to false if you don't actually want fatal assertions to halt. This can be useful
  // if you are running tests.
  bool fatal_should_halt;

  // The maximum byte size for a report id string (including null terminator).
  unsigned int max_id_size_bytes;

  // The maximum number of contexts at one time.
  unsigned int max_context_depth;

  // The maximum byte size for a formatted error message (including null terminator).
  unsigned int max_formatted_message_size_bytes;

  // The maximum number of attributes that can be set at once.
  unsigned int max_attribute_count;

  // The maximum byte size for all attribute data.
  unsigned int attribute_buf_size_bytes;

  // The maximum number of stack frames for a backtrace.
  unsigned int max_backtrace_count;

  // The maximum number of breadcrumbs to keep.
  unsigned int max_breadcrumb_count;

  // The maximum byte size for all breadcrumb data.
  unsigned int breadcrumb_buf_size_bytes;

  // The report handler to use for errors.
  forensics_report_handler_t report_handler;
};

// Initializes the given config struct to fill in the default values.
void forensics_config_init(struct forensics_config_t* config);

// Initializes this library with the given configuration. If NULL is given, then the default configuration will be used.
// This will allocate the buffers required to do all error handling and reporting except for a context stack buffer that
// is allocated for each thread that chooses to push on a context with `forensics_context_begin()`.
void forensics_init(const struct forensics_config_t* config);

// Tears down this library and frees all allocations.
void forensics_shutdown();

// Pushes on a new context with the given name for the current thread. If the current thread generates an error report,
// this context will on the contexxt stack made available in the report data. It is expected that when the code leaves
// the relevant context, `forensics_context_end()` will be called to pop this contexxt off the stack.
//
// You can use this as a blame mechanism for helping identify what area of code is responsible when an error occurs. A
// common pattern is to assert on the arguments to a library's public API functions and then assume ownership of any
// further errors by establishing itself as the current context.
//
// The name is copied into a thread-local buffer and does not need to live for the duration of the context.
void forensics_context_begin(const char* name);

// Pops a context off the stack for the current thread.
void forensics_context_end();

// Adds a breadcrumb to the queue of breadcrumbs that have been left behind. This is basically a way to track
// application evetns or state changes that have lead up to an error. Breadcrumbs are stored in a ring buffer, so you do
// not need to worry about removing them.
//
// A breadcrumb comprises of a name along with some arbitrary metadata provided as set of key/value pairs.
//
// The name and metadata key/value pairs are copied into a buffer and do not need to persist once the call returns. If
// the same breadcrumb is left sequentially, the subsequent breadcrumbs are coallesced into the first and do not take
// any additional space.
void forensics_add_breadcrumb(const char* name, const char** meta_keys, const char** meta_values, int meta_count);

// Sets an arbitrary attribute as a key/value pair that will be made available to error reports. Setting the value to
// NULL will remove the attribute. You can use this to set arbitrary data that you feel would be useful like a build id,
// platform name, runtime environment, etc.
//
// The key and value are copied into a buffer and do not need to persist once the call returns.
void forensics_set_attribute(const char* key, const char* value);

// The default report handler. It simply prints report information to stderr.
void forensics_default_report_handler(const struct forensics_report_t* report);

// Reports an assertion failure error. This will capture the backtrace and generate a report which will be given to the
// configured report handler to process.
void forensics_report_assert_failure(
    const char* file, int line, const char* func, bool fatal, const char* expression, const char* format, ...);

// A fatal assertion with no message.
#define FORENSICS_ASSERT(expr)                                                                                         \
  ((expr) ? true : (forensics_report_assert_failure(__FILE__, __LINE__, __func__, true, #expr, ""), false))

// A fatal assertion with a formatted message
#define FORENSICS_ASSERTF(expr, ...)                                                                                   \
  ((expr) ? true : (forensics_report_assert_failure(__FILE__, __LINE__, __func__, true, #expr, __VA_ARGS__), false))

// A non-fatal assertion with no message. Returns the boolean result of the expression.
#define FORENSICS_VERIFY(expr)                                                                                         \
  ((expr) ? true : (forensics_report_assert_failure(__FILE__, __LINE__, __func__, false, #expr, ""), false))

// A non-fatal assertion with a formatted message. Returns the boolean result of the expression.
#define FORENSICS_VERIFYF(expr, ...)                                                                                   \
  ((expr) ? true : (forensics_report_assert_failure(__FILE__, __LINE__, __func__, false, #expr, __VA_ARGS__), false))

#ifdef NDEBUG
#define FORENSICS_ASSERT_DBG(expr) true
#define FORENSICS_ASSERT_DBGF(expr, ...) true
#else

// A fatal assertion with no message that is compiled out in release builds (when NDEBUG is defined).
#define FORENSICS_ASSERT_DBG(expr)                                                                                     \
  ((expr) ? true : (forensics_report_assert_failure(__FILE__, __LINE__, __func__, true, #expr, ""), false))

// A fatal assertion with a formatted message that is compiled out in release builds (when NDEBUG is defined).
#define FORENSICS_ASSERT_DBGF(expr, ...)                                                                               \
  ((expr) ? true : (forensics_report_assert_failure(__FILE__, __LINE__, __func__, true, #expr, __VA_ARGS__), false))
#endif // NDEBUG

#ifdef __cplusplus

#define FORENSICS_CONTEXT_CONCAT2(a, b) a##b
#define FORENSICS_CONTEXT_CONCAT(a, b) FORENSICS_CONTEXT_CONCAT2(a, b)

// A utility macro for C++ that creates a scoped context with the given name.
#define FORENSICS_CONTEXT(name) forensics_context_t FORENSICS_CONTEXT_CONCAT(forensics_context__, __LINE__)(name)

// C++ RAII implementation of an error context that will automatically end the context at the end of the current scope.
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
