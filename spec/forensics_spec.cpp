#include <signal.h>
#include "catch.hpp"
#include "forensics.h"

static std::function<void(const forensics_report_t*)> s_report_handler;

static void test_report_handler(const forensics_report_t* report) {
  if (s_report_handler) {
    s_report_handler(report);
  }
}

// init/shutdown helper if an exception gets thrown
struct init_t {
  init_t(const forensics_config_t* config) {
    s_report_handler = nullptr;

    forensics_config_t config_default;
    if (!config) {
      forensics_config_init(&config_default);
      config_default.report_handler = &test_report_handler;
      config_default.fatal_should_halt = false;
      config = &config_default;
    }
    forensics_lib_init(config);
  }
  ~init_t() {
    forensics_lib_shutdown();
  }
};

static bool ends_with(const char* value, const char* suffix) {
  int len_value = (int)strlen(value);
  int len_suffix = (int)strlen(suffix);
  if (len_suffix > len_value) {
    return false;
  }
  if (0 != strcmp(value + (len_value - len_suffix), suffix)) {
    return false;
  }
  return true;
}

static void with_handler(std::function<void(const forensics_report_t*)> handler, std::function<void()> block) {
  s_report_handler = handler;
  block();
  s_report_handler = nullptr;
}

static bool has_attribute(const forensics_report_t* report, const char* key) {
  for (int index = 0; index < report->attribute_count; ++index) {
    if (0 == strcmp(report->attribute_keys[index], key)) {
      return true;
    }
  }
  return false;
}

static bool has_attribute_value(const forensics_report_t* report, const char* key, const char* value) {
  for (int index = 0; index < report->attribute_count; ++index) {
    if (0 == strcmp(report->attribute_keys[index], key)) {
      if (0 == strcmp(report->attribute_values[index], value)) {
        return true;
      }
      return false;
    }
  }
  return false;
}

#ifdef WIN32
#define REPORT_ID(context, file, msg) context##"-"##file##"-operator ()-"##msg
#else
#define REPORT_ID(context, file, msg) context "-" file "-operator()-" msg
#endif

TEST_CASE("basic report handling") {
  init_t init(nullptr);

  SECTION("when there is no formatted message") {
    auto handler = [=](const forensics_report_t* report) {
      CHECK(!strcmp(report->id, REPORT_ID("<none>", "forensics_spec.cpp", "")));
      CHECK(ends_with(report->file, "forensics_spec.cpp"));
      CHECK(0 == strcmp(report->expression, "false"));
      CHECK(report->format[0] == 0);
      CHECK(report->formatted[0] == 0);
      CHECK(report->fatal == true);
      CHECK(report->backtrace_count > 0);
      CHECK(report->backtrace != nullptr);
      CHECK(report->line == __LINE__ + 2);
    };
    with_handler(handler, []() { FORENSICS_ASSERT(false); });
  }

  SECTION("when there is a formatted message") {
    auto handler = [=](const forensics_report_t* report) {
      CHECK(!strcmp(report->id, REPORT_ID("<none>", "forensics_spec.cpp", "failed num=%d")));
      CHECK(ends_with(report->file, "forensics_spec.cpp"));
      CHECK(0 == strcmp(report->expression, "false"));
      CHECK(!strcmp(report->format, "failed num=%d"));
      CHECK(!strcmp(report->formatted, "failed num=2"));
      CHECK(report->fatal == true);
      CHECK(report->backtrace_count > 0);
      CHECK(report->backtrace != nullptr);
      CHECK(report->line == __LINE__ + 2);
    };
    with_handler(handler, []() { FORENSICS_ASSERTF(false, "failed num=%d", 2); });
  }
}

TEST_CASE("attributes") {
  init_t init(nullptr);

  SECTION("there are no attributes") {
    auto handler = [=](const forensics_report_t* report) {
      CHECK(report->attribute_count == 0);
      CHECK(report->attribute_keys == nullptr);
      CHECK(report->attribute_values == nullptr);
    };
    with_handler(handler, []() { FORENSICS_ASSERT(false); });
  }

  SECTION("there are some attributes") {
    forensics_set_attribute("user", "shawn spencer");
    forensics_set_attribute("version", "1.0.0");

    auto handler = [=](const forensics_report_t* report) {
      CHECK(report->attribute_count == 2);
      CHECK(has_attribute_value(report, "version", "1.0.0"));
      CHECK(has_attribute_value(report, "user", "shawn spencer"));
    };
    with_handler(handler, []() { FORENSICS_ASSERT(false); });
  }

  SECTION("some attributes are cleared with nullptr value") {
    forensics_set_attribute("user", "shawn spencer");
    forensics_set_attribute("version", "1.0.0");
    forensics_set_attribute("user", nullptr);

    auto handler = [=](const forensics_report_t* report) {
      CHECK(report->attribute_count == 1);
      CHECK(has_attribute_value(report, "version", "1.0.0"));
      CHECK(!has_attribute(report, "user"));
    };
    with_handler(handler, []() { FORENSICS_ASSERT(false); });
  }
}

TEST_CASE("context") {
  init_t init(nullptr);

  SECTION("there is no context") {
    auto handler = [=](const forensics_report_t* report) {
      CHECK(report->context_count == 0);
      CHECK(report->context_stack == nullptr);
      CHECK(!strcmp(report->id, REPORT_ID("<none>", "forensics_spec.cpp", "")));
    };
    with_handler(handler, []() { FORENSICS_ASSERT(false); });
  }

  SECTION("there is a single context") {
    auto handler = [=](const forensics_report_t* report) {
      CHECK(report->context_count == 1);
      CHECK(!strcmp(report->context_stack[0], "global"));
      CHECK(!strcmp(report->id, REPORT_ID("global", "forensics_spec.cpp", "")));
    };
    with_handler(handler, []() {
      FORENSICS_CONTEXT("global");
      FORENSICS_ASSERT(false);
    });
  }

  SECTION("there are many contexts") {
    auto handler = [=](const forensics_report_t* report) {
      CHECK(report->context_count == 3);
      CHECK(!strcmp(report->context_stack[0], "global"));
      CHECK(!strcmp(report->context_stack[1], "local"));
      CHECK(!strcmp(report->context_stack[2], "personal"));
      CHECK(!strcmp(report->id, REPORT_ID("personal", "forensics_spec.cpp", "")));
    };
    with_handler(handler, []() {
      FORENSICS_CONTEXT("global");
      FORENSICS_CONTEXT("local");
      FORENSICS_CONTEXT("personal");
      FORENSICS_ASSERT(false);
    });
  }
}

TEST_CASE("breadcrumbs") {
  init_t init(nullptr);

  SECTION("there are no breadcrumbs") {
    auto handler = [=](const forensics_report_t* report) {
      CHECK(report->breadcrumb_count == 0);
      CHECK(report->breadcrumbs == nullptr);
    };
    with_handler(handler, []() { FORENSICS_ASSERT(false); });
  }

  SECTION("there is a single breadcrumb with no meta") {
    auto handler = [=](const forensics_report_t* report) {
      CHECK(report->breadcrumb_count == 1);
      CHECK(report->breadcrumbs != nullptr);
      CHECK(!strcmp(report->breadcrumbs[0].name, "test"));
      CHECK(report->breadcrumbs[0].meta_keys == nullptr);
      CHECK(report->breadcrumbs[0].meta_values == nullptr);
      CHECK(report->breadcrumbs[0].meta_count == 0);
      CHECK(report->breadcrumbs[0].count == 1);
    };
    with_handler(handler, []() {
      forensics_add_breadcrumb("test", nullptr, nullptr, 0);
      FORENSICS_ASSERT(false);
    });
  }

  SECTION("there is a single breadcrumb with 1 meta") {
    auto handler = [=](const forensics_report_t* report) {
      CHECK(report->breadcrumb_count == 1);
      CHECK(report->breadcrumbs != nullptr);
      CHECK(!strcmp(report->breadcrumbs[0].name, "test"));
      CHECK(report->breadcrumbs[0].meta_keys != nullptr);
      CHECK(report->breadcrumbs[0].meta_values != nullptr);
      CHECK(report->breadcrumbs[0].meta_count == 1);
      CHECK(report->breadcrumbs[0].count == 1);
      CHECK(!strcmp(report->breadcrumbs[0].meta_keys[0], "env"));
      CHECK(!strcmp(report->breadcrumbs[0].meta_values[0], "production"));
    };
    with_handler(handler, []() {
      const char* meta_keys[] = {
          "env",
      };
      const char* meta_values[] = {
          "production",
      };
      forensics_add_breadcrumb("test", meta_keys, meta_values, 1);
      FORENSICS_ASSERT(false);
    });
  }

  SECTION("there is a single breadcrumb with several meta") {
    auto handler = [=](const forensics_report_t* report) {
      CHECK(report->breadcrumb_count == 1);
      CHECK(report->breadcrumbs != nullptr);
      CHECK(!strcmp(report->breadcrumbs[0].name, "test"));
      CHECK(report->breadcrumbs[0].meta_keys != nullptr);
      CHECK(report->breadcrumbs[0].meta_values != nullptr);
      CHECK(report->breadcrumbs[0].meta_count == 3);
      CHECK(report->breadcrumbs[0].count == 1);
      CHECK(!strcmp(report->breadcrumbs[0].meta_keys[0], "env"));
      CHECK(!strcmp(report->breadcrumbs[0].meta_values[0], "production"));
      CHECK(!strcmp(report->breadcrumbs[0].meta_keys[1], "build_id"));
      CHECK(!strcmp(report->breadcrumbs[0].meta_values[1], "1.0.7"));
      CHECK(!strcmp(report->breadcrumbs[0].meta_keys[2], "debug"));
      CHECK(!strcmp(report->breadcrumbs[0].meta_values[2], "false"));
    };
    with_handler(handler, []() {
      const char* meta_keys[] = {
          "env",
          "build_id",
          "debug",
      };
      const char* meta_values[] = {
          "production",
          "1.0.7",
          "false",
      };
      forensics_add_breadcrumb("test", meta_keys, meta_values, 3);
      FORENSICS_ASSERT(false);
    });
  }

  SECTION("there are multiple breadcrumbs") {
    auto handler = [=](const forensics_report_t* report) {
      CHECK(report->breadcrumb_count == 3);
      CHECK(report->breadcrumbs != nullptr);
      CHECK(!strcmp(report->breadcrumbs[0].name, "click"));
      CHECK(report->breadcrumbs[0].meta_count == 1);
      CHECK(report->breadcrumbs[0].count == 1);
      CHECK(!strcmp(report->breadcrumbs[0].meta_keys[0], "pos"));
      CHECK(!strcmp(report->breadcrumbs[0].meta_values[0], "37, 100"));

      CHECK(!strcmp(report->breadcrumbs[1].name, "connect"));
      CHECK(report->breadcrumbs[1].meta_count == 1);
      CHECK(report->breadcrumbs[1].count == 1);
      CHECK(!strcmp(report->breadcrumbs[1].meta_keys[0], "endpoint"));
      CHECK(!strcmp(report->breadcrumbs[1].meta_values[0], "127.0.0.1:8080"));

      CHECK(!strcmp(report->breadcrumbs[2].name, "connect"));
      CHECK(report->breadcrumbs[2].meta_count == 1);
      CHECK(report->breadcrumbs[2].count == 1);
      CHECK(!strcmp(report->breadcrumbs[2].meta_keys[0], "endpoint"));
      CHECK(!strcmp(report->breadcrumbs[2].meta_values[0], "10.0.0.1:9000"));
    };
    with_handler(handler, []() {
      const char* b1_keys[] = {
          "pos",
      };
      const char* b1_values[] = {
          "37, 100",
      };
      const char* b2_keys[] = {
          "endpoint",
      };
      const char* b2_values[] = {
          "127.0.0.1:8080",
      };
      const char* b3_keys[] = {
          "endpoint",
      };
      const char* b3_values[] = {
          "10.0.0.1:9000",
      };
      forensics_add_breadcrumb("click", b1_keys, b1_values, 1);
      forensics_add_breadcrumb("connect", b2_keys, b2_values, 1);
      forensics_add_breadcrumb("connect", b3_keys, b3_values, 1);
      FORENSICS_ASSERT(false);
    });
  }

  SECTION("repeated breadcrumbs are collapsed") {
    auto handler = [=](const forensics_report_t* report) {
      CHECK(report->breadcrumb_count == 1);
      CHECK(report->breadcrumbs != nullptr);
      CHECK(!strcmp(report->breadcrumbs[0].name, "boot"));
      CHECK(report->breadcrumbs[0].meta_count == 1);
      CHECK(report->breadcrumbs[0].count == 2);
      CHECK(!strcmp(report->breadcrumbs[0].meta_keys[0], "env"));
      CHECK(!strcmp(report->breadcrumbs[0].meta_values[0], "production"));
    };
    with_handler(handler, []() {
      const char* b1_keys[] = {
          "env",
      };
      const char* b1_values[] = {
          "production",
      };
      const char* b2_keys[] = {
          "env",
      };
      const char* b2_values[] = {
          "production",
      };
      forensics_add_breadcrumb("boot", b1_keys, b1_values, 1);
      forensics_add_breadcrumb("boot", b2_keys, b2_values, 1);
      FORENSICS_ASSERT(false);
    });
  }

  SECTION("repeated breadcrumbs are not collapsed if meta differs") {
    auto handler = [=](const forensics_report_t* report) {
      CHECK(report->breadcrumb_count == 2);
      CHECK(report->breadcrumbs != nullptr);
      CHECK(!strcmp(report->breadcrumbs[0].name, "boot"));
      CHECK(report->breadcrumbs[0].meta_count == 1);
      CHECK(report->breadcrumbs[0].count == 1);
      CHECK(!strcmp(report->breadcrumbs[0].meta_keys[0], "env"));
      CHECK(!strcmp(report->breadcrumbs[0].meta_values[0], "production"));

      CHECK(!strcmp(report->breadcrumbs[1].name, "boot"));
      CHECK(report->breadcrumbs[1].meta_count == 1);
      CHECK(report->breadcrumbs[1].count == 1);
      CHECK(!strcmp(report->breadcrumbs[1].meta_keys[0], "env"));
      CHECK(!strcmp(report->breadcrumbs[1].meta_values[0], "dev"));
    };
    with_handler(handler, []() {
      const char* b1_keys[] = {
          "env",
      };
      const char* b1_values[] = {
          "production",
      };
      const char* b2_keys[] = {
          "env",
      };
      const char* b2_values[] = {
          "dev",
      };
      forensics_add_breadcrumb("boot", b1_keys, b1_values, 1);
      forensics_add_breadcrumb("boot", b2_keys, b2_values, 1);
      FORENSICS_ASSERT(false);
    });
  }
}

TEST_CASE("breadcrumb count overflow") {
  forensics_config_t config;
  forensics_config_init(&config);
  config.max_breadcrumb_count = 2;
  config.report_handler = &test_report_handler;
  config.fatal_should_halt = false;
  init_t init(&config);

  SECTION("max breadcrumbs is reached, forget oldest crumb") {
    auto handler = [=](const forensics_report_t* report) {
      CHECK(report->breadcrumb_count == 2);
      CHECK(!strcmp(report->breadcrumbs[0].name, "three"));
      CHECK(!strcmp(report->breadcrumbs[1].name, "four"));
    };
    with_handler(handler, []() {
      forensics_add_breadcrumb("one", nullptr, nullptr, 0);
      forensics_add_breadcrumb("two", nullptr, nullptr, 0);
      forensics_add_breadcrumb("three", nullptr, nullptr, 0);
      forensics_add_breadcrumb("four", nullptr, nullptr, 0);
      FORENSICS_ASSERT(false);
    });
  }
}

TEST_CASE("zero capacity") {
  forensics_config_t config;
  forensics_config_init(&config);
  config.max_attribute_count = 0;
  config.max_breadcrumb_count = 0;
  config.max_context_depth = 0;
  config.report_handler = &test_report_handler;
  config.fatal_should_halt = false;
  init_t init(&config);

  SECTION("attribute overflow, don't crash") {
    auto handler = [=](const forensics_report_t* report) {
      CHECK(report->attribute_count == 0);
      CHECK(report->attribute_keys == nullptr);
      CHECK(report->attribute_values == nullptr);
    };
    with_handler(handler, []() {
      forensics_set_attribute("build_id", "1.0");
      FORENSICS_ASSERT(false);
    });
  }

  SECTION("breadcrumb overflow, don't crash") {
    auto handler = [=](const forensics_report_t* report) {
      CHECK(report->breadcrumb_count == 0);
      CHECK(report->breadcrumbs == nullptr);
    };
    with_handler(handler, []() {
      forensics_add_breadcrumb("one", nullptr, nullptr, 0);
      forensics_add_breadcrumb("two", nullptr, nullptr, 0);
      forensics_add_breadcrumb("three", nullptr, nullptr, 0);
      forensics_add_breadcrumb("four", nullptr, nullptr, 0);
      FORENSICS_ASSERT(false);
    });
  }

  SECTION("context overflow, don't crash") {
    auto handler = [=](const forensics_report_t* report) {
      CHECK(report->context_count == 0);
      CHECK(report->context_stack == nullptr);
    };
    with_handler(handler, []() {
      FORENSICS_CONTEXT("one");
      FORENSICS_CONTEXT("two");
      FORENSICS_ASSERT(false);
    });
  }
}

TEST_CASE("breadcrumb buf overflow") {
  forensics_config_t config;
  forensics_config_init(&config);
  config.breadcrumb_buf_size_bytes = 16;
  config.report_handler = &test_report_handler;
  config.fatal_should_halt = false;
  init_t init(&config);

  SECTION("buffer fills; throw out old breadcrumbs") {
    auto handler = [=](const forensics_report_t* report) {
      CHECK(report->breadcrumb_count == 2);
      CHECK(!strcmp(report->breadcrumbs[0].name, "three"));
      CHECK(!strcmp(report->breadcrumbs[1].name, "four"));
    };
    with_handler(handler, []() {
      forensics_add_breadcrumb("one", nullptr, nullptr, 0);
      forensics_add_breadcrumb("two", nullptr, nullptr, 0);
      forensics_add_breadcrumb("three", nullptr, nullptr, 0);
      forensics_add_breadcrumb("four", nullptr, nullptr, 0);
      FORENSICS_ASSERT(false);
    });
  }
}

// In response to issue https://github.com/gamepoet/forensics/issues/3
TEST_CASE("breadcrumb buf overflow for exact size of ring buffer") {
  forensics_config_t config;
  forensics_config_init(&config);
  config.breadcrumb_buf_size_bytes = 8;
  config.report_handler = &test_report_handler;
  config.fatal_should_halt = false;
  init_t init(&config);

  SECTION("buffer fills; throw out old breadcrumbs") {
    auto handler = [=](const forensics_report_t* report) {
      CHECK(report->breadcrumb_count == 1);
      CHECK(!strcmp(report->breadcrumbs[0].name, "four"));
    };
    with_handler(handler, []() {
      forensics_add_breadcrumb("one", nullptr, nullptr, 0);
      forensics_add_breadcrumb("two", nullptr, nullptr, 0);
      forensics_add_breadcrumb("three", nullptr, nullptr, 0);
      forensics_add_breadcrumb("four", nullptr, nullptr, 0);
      FORENSICS_ASSERT(false);
    });
  }
}

void test_signal_handler(int sig, const char* signal_name, std::function<void()> func) {
  char expected_message[64];
  snprintf(expected_message, sizeof(expected_message), "got signal: %s", signal_name);
  expected_message[sizeof(expected_message) - 1] = 0;

  auto handler = [&expected_message](const forensics_report_t* report) {
    CHECK(!strcmp(report->file, ""));
    CHECK(report->line == 0);
    CHECK(!strcmp(report->formatted, expected_message));
    throw std::runtime_error("got signal");
  };
  with_handler(handler, [&func]() {
    CHECK_THROWS_WITH(func(), "got signal");
  });
}

#ifdef __APPLE__
TEST_CASE("signals") {
  forensics_config_t config;
  forensics_config_init(&config);
  config.report_handler = &test_report_handler;
  config.fatal_should_halt = false;
  init_t init(&config);

  // NOTE: This one I can't figure out a way to recover from
  // SECTION("SIGABRT") {
  //   test_signal_handler(SIGABRT, "SIGABRT", []() {
  //     abort();
  //   });
  // }

  // NOTE: This one I can't figure out a way to recover from
  // SECTION("SIGBUS") {
  //   test_signal_handler(SIGBUS, "SIGBUS", []() {
  //     raise(SIGBUS);
  //   });
  // }

  SECTION("SIGFPE") {
    test_signal_handler(SIGFPE, "SIGFPE", []() {
      int a = 1;
      int b = 0;
      int c = a / b;
      printf("c = %d\n", c);
    });
  }

  // NOTE: This one I can't figure out a way to recover from
  // SECTION("SIGILL") {
  //   test_signal_handler(SIGILL, "SIGILL", []() {
  //     raise(SIGILL);
  //   });
  // }

  SECTION("SIGSEGV") {
    test_signal_handler(SIGSEGV, "SIGSEGV", []() {
      int* ptr = (int*)0x00000000;
      *ptr = 0;
    });
  }
}
#endif // __APPLE__
