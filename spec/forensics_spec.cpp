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
    forensics_init(config);
  }
  ~init_t() {
    forensics_shutdown();
  }
};

static bool ends_with(const char* value, const char* suffix) {
  int len_value = strlen(value);
  int len_suffix = strlen(suffix);
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

static bool has_attribute(const forensics_report_t* report, const wchar_t* key) {
  for (int index = 0; index < report->attribute_count; ++index) {
    if (0 == wcscmp(report->attribute_keys[index], key)) {
      return true;
    }
  }
  return false;
}

static bool has_attribute_value(const forensics_report_t* report, const wchar_t* key, const wchar_t* value) {
  for (int index = 0; index < report->attribute_count; ++index) {
    if (0 == wcscmp(report->attribute_keys[index], key)) {
      if (0 == wcscmp(report->attribute_values[index], value)) {
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
      CHECK(!wcscmp(report->id, REPORT_ID(L"<none>", L"forensics_spec.cpp", L"")));
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
      CHECK(!wcscmp(report->id, REPORT_ID(L"<none>", L"forensics_spec.cpp", L"failed num=%d")));
      CHECK(ends_with(report->file, "forensics_spec.cpp"));
      CHECK(0 == strcmp(report->expression, "false"));
      CHECK(!wcscmp(report->format, L"failed num=%d"));
      CHECK(!wcscmp(report->formatted, L"failed num=2"));
      CHECK(report->fatal == true);
      CHECK(report->backtrace_count > 0);
      CHECK(report->backtrace != nullptr);
      CHECK(report->line == __LINE__ + 2);
    };
    with_handler(handler, []() { FORENSICS_ASSERTF(false, L"failed num=%d", 2); });
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
    forensics_set_attribute(L"user", L"shawn spencer");
    forensics_set_attribute(L"version", L"1.0.0");

    auto handler = [=](const forensics_report_t* report) {
      CHECK(report->attribute_count == 2);
      CHECK(has_attribute_value(report, L"version", L"1.0.0"));
      CHECK(has_attribute_value(report, L"user", L"shawn spencer"));
    };
    with_handler(handler, []() { FORENSICS_ASSERT(false); });
  }

  SECTION("some attributes are cleared with nullptr value") {
    forensics_set_attribute(L"user", L"shawn spencer");
    forensics_set_attribute(L"version", L"1.0.0");
    forensics_set_attribute(L"user", nullptr);

    auto handler = [=](const forensics_report_t* report) {
      CHECK(report->attribute_count == 1);
      CHECK(has_attribute_value(report, L"version", L"1.0.0"));
      CHECK(!has_attribute(report, L"user"));
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
      CHECK(!wcscmp(report->id, REPORT_ID(L"<none>", L"forensics_spec.cpp", L"")));
    };
    with_handler(handler, []() { FORENSICS_ASSERT(false); });
  }

  SECTION("there is a single context") {
    auto handler = [=](const forensics_report_t* report) {
      CHECK(report->context_count == 1);
      CHECK(!wcscmp(report->context_stack[0], L"global"));
      CHECK(!wcscmp(report->id, REPORT_ID(L"global", L"forensics_spec.cpp", L"")));
    };
    with_handler(handler, []() {
      FORENSICS_CONTEXT(L"global");
      FORENSICS_ASSERT(false);
    });
  }

  SECTION("there are many contexts") {
    auto handler = [=](const forensics_report_t* report) {
      CHECK(report->context_count == 3);
      CHECK(!wcscmp(report->context_stack[0], L"global"));
      CHECK(!wcscmp(report->context_stack[1], L"local"));
      CHECK(!wcscmp(report->context_stack[2], L"personal"));
      CHECK(!wcscmp(report->id, REPORT_ID(L"personal", L"forensics_spec.cpp", L"")));
    };
    with_handler(handler, []() {
      FORENSICS_CONTEXT(L"global");
      FORENSICS_CONTEXT(L"local");
      FORENSICS_CONTEXT(L"personal");
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
      CHECK(!wcscmp(report->breadcrumbs[0].name, L"test"));
      CHECK(report->breadcrumbs[0].meta_keys == nullptr);
      CHECK(report->breadcrumbs[0].meta_values == nullptr);
      CHECK(report->breadcrumbs[0].meta_count == 0);
      CHECK(report->breadcrumbs[0].count == 1);
    };
    with_handler(handler, []() {
      forensics_add_breadcrumb(L"test", nullptr, nullptr, 0);
      FORENSICS_ASSERT(false);
    });
  }

  SECTION("there is a single breadcrumb with 1 meta") {
    auto handler = [=](const forensics_report_t* report) {
      CHECK(report->breadcrumb_count == 1);
      CHECK(report->breadcrumbs != nullptr);
      CHECK(!wcscmp(report->breadcrumbs[0].name, L"test"));
      CHECK(report->breadcrumbs[0].meta_keys != nullptr);
      CHECK(report->breadcrumbs[0].meta_values != nullptr);
      CHECK(report->breadcrumbs[0].meta_count == 1);
      CHECK(report->breadcrumbs[0].count == 1);
      CHECK(!wcscmp(report->breadcrumbs[0].meta_keys[0], L"env"));
      CHECK(!wcscmp(report->breadcrumbs[0].meta_values[0], L"production"));
    };
    with_handler(handler, []() {
      const wchar_t* meta_keys[] = {
          L"env",
      };
      const wchar_t* meta_values[] = {
          L"production",
      };
      forensics_add_breadcrumb(L"test", meta_keys, meta_values, 1);
      FORENSICS_ASSERT(false);
    });
  }

  SECTION("there is a single breadcrumb with several meta") {
    auto handler = [=](const forensics_report_t* report) {
      CHECK(report->breadcrumb_count == 1);
      CHECK(report->breadcrumbs != nullptr);
      CHECK(!wcscmp(report->breadcrumbs[0].name, L"test"));
      CHECK(report->breadcrumbs[0].meta_keys != nullptr);
      CHECK(report->breadcrumbs[0].meta_values != nullptr);
      CHECK(report->breadcrumbs[0].meta_count == 3);
      CHECK(report->breadcrumbs[0].count == 1);
      CHECK(!wcscmp(report->breadcrumbs[0].meta_keys[0], L"env"));
      CHECK(!wcscmp(report->breadcrumbs[0].meta_values[0], L"production"));
      CHECK(!wcscmp(report->breadcrumbs[0].meta_keys[1], L"build_id"));
      CHECK(!wcscmp(report->breadcrumbs[0].meta_values[1], L"1.0.7"));
      CHECK(!wcscmp(report->breadcrumbs[0].meta_keys[2], L"debug"));
      CHECK(!wcscmp(report->breadcrumbs[0].meta_values[2], L"false"));
    };
    with_handler(handler, []() {
      const wchar_t* meta_keys[] = {
          L"env",
          L"build_id",
          L"debug",
      };
      const wchar_t* meta_values[] = {
          L"production",
          L"1.0.7",
          L"false",
      };
      forensics_add_breadcrumb(L"test", meta_keys, meta_values, 3);
      FORENSICS_ASSERT(false);
    });
  }

  SECTION("there are multiple breadcrumbs") {
    auto handler = [=](const forensics_report_t* report) {
      CHECK(report->breadcrumb_count == 3);
      CHECK(report->breadcrumbs != nullptr);
      CHECK(!wcscmp(report->breadcrumbs[0].name, L"click"));
      CHECK(report->breadcrumbs[0].meta_count == 1);
      CHECK(report->breadcrumbs[0].count == 1);
      CHECK(!wcscmp(report->breadcrumbs[0].meta_keys[0], L"pos"));
      CHECK(!wcscmp(report->breadcrumbs[0].meta_values[0], L"37, 100"));

      CHECK(!wcscmp(report->breadcrumbs[1].name, L"connect"));
      CHECK(report->breadcrumbs[1].meta_count == 1);
      CHECK(report->breadcrumbs[1].count == 1);
      CHECK(!wcscmp(report->breadcrumbs[1].meta_keys[0], L"endpoint"));
      CHECK(!wcscmp(report->breadcrumbs[1].meta_values[0], L"127.0.0.1:8080"));

      CHECK(!wcscmp(report->breadcrumbs[2].name, L"connect"));
      CHECK(report->breadcrumbs[2].meta_count == 1);
      CHECK(report->breadcrumbs[2].count == 1);
      CHECK(!wcscmp(report->breadcrumbs[2].meta_keys[0], L"endpoint"));
      CHECK(!wcscmp(report->breadcrumbs[2].meta_values[0], L"10.0.0.1:9000"));
    };
    with_handler(handler, []() {
      const wchar_t* b1_keys[] = {
          L"pos",
      };
      const wchar_t* b1_values[] = {
          L"37, 100",
      };
      const wchar_t* b2_keys[] = {
          L"endpoint",
      };
      const wchar_t* b2_values[] = {
          L"127.0.0.1:8080",
      };
      const wchar_t* b3_keys[] = {
          L"endpoint",
      };
      const wchar_t* b3_values[] = {
          L"10.0.0.1:9000",
      };
      forensics_add_breadcrumb(L"click", b1_keys, b1_values, 1);
      forensics_add_breadcrumb(L"connect", b2_keys, b2_values, 1);
      forensics_add_breadcrumb(L"connect", b3_keys, b3_values, 1);
      FORENSICS_ASSERT(false);
    });
  }

  SECTION("repeated breadcrumbs are collapsed") {
    auto handler = [=](const forensics_report_t* report) {
      CHECK(report->breadcrumb_count == 1);
      CHECK(report->breadcrumbs != nullptr);
      CHECK(!wcscmp(report->breadcrumbs[0].name, L"boot"));
      CHECK(report->breadcrumbs[0].meta_count == 1);
      CHECK(report->breadcrumbs[0].count == 2);
      CHECK(!wcscmp(report->breadcrumbs[0].meta_keys[0], L"env"));
      CHECK(!wcscmp(report->breadcrumbs[0].meta_values[0], L"production"));
    };
    with_handler(handler, []() {
      const wchar_t* b1_keys[] = {
          L"env",
      };
      const wchar_t* b1_values[] = {
          L"production",
      };
      const wchar_t* b2_keys[] = {
          L"env",
      };
      const wchar_t* b2_values[] = {
          L"production",
      };
      forensics_add_breadcrumb(L"boot", b1_keys, b1_values, 1);
      forensics_add_breadcrumb(L"boot", b2_keys, b2_values, 1);
      FORENSICS_ASSERT(false);
    });
  }

  SECTION("repeated breadcrumbs are not collapsed if meta differs") {
    auto handler = [=](const forensics_report_t* report) {
      CHECK(report->breadcrumb_count == 2);
      CHECK(report->breadcrumbs != nullptr);
      CHECK(!wcscmp(report->breadcrumbs[0].name, L"boot"));
      CHECK(report->breadcrumbs[0].meta_count == 1);
      CHECK(report->breadcrumbs[0].count == 1);
      CHECK(!wcscmp(report->breadcrumbs[0].meta_keys[0], L"env"));
      CHECK(!wcscmp(report->breadcrumbs[0].meta_values[0], L"production"));

      CHECK(!wcscmp(report->breadcrumbs[1].name, L"boot"));
      CHECK(report->breadcrumbs[1].meta_count == 1);
      CHECK(report->breadcrumbs[1].count == 1);
      CHECK(!wcscmp(report->breadcrumbs[1].meta_keys[0], L"env"));
      CHECK(!wcscmp(report->breadcrumbs[1].meta_values[0], L"dev"));
    };
    with_handler(handler, []() {
      const wchar_t* b1_keys[] = {
          L"env",
      };
      const wchar_t* b1_values[] = {
          L"production",
      };
      const wchar_t* b2_keys[] = {
          L"env",
      };
      const wchar_t* b2_values[] = {
          L"dev",
      };
      forensics_add_breadcrumb(L"boot", b1_keys, b1_values, 1);
      forensics_add_breadcrumb(L"boot", b2_keys, b2_values, 1);
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
      CHECK(!wcscmp(report->breadcrumbs[0].name, L"three"));
      CHECK(!wcscmp(report->breadcrumbs[1].name, L"four"));
    };
    with_handler(handler, []() {
      forensics_add_breadcrumb(L"one", nullptr, nullptr, 0);
      forensics_add_breadcrumb(L"two", nullptr, nullptr, 0);
      forensics_add_breadcrumb(L"three", nullptr, nullptr, 0);
      forensics_add_breadcrumb(L"four", nullptr, nullptr, 0);
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
      forensics_set_attribute(L"build_id", L"1.0");
      FORENSICS_ASSERT(false);
    });
  }

  SECTION("breadcrumb overflow, don't crash") {
    auto handler = [=](const forensics_report_t* report) {
      CHECK(report->breadcrumb_count == 0);
      CHECK(report->breadcrumbs == nullptr);
    };
    with_handler(handler, []() {
      forensics_add_breadcrumb(L"one", nullptr, nullptr, 0);
      forensics_add_breadcrumb(L"two", nullptr, nullptr, 0);
      forensics_add_breadcrumb(L"three", nullptr, nullptr, 0);
      forensics_add_breadcrumb(L"four", nullptr, nullptr, 0);
      FORENSICS_ASSERT(false);
    });
  }

  SECTION("context overflow, don't crash") {
    auto handler = [=](const forensics_report_t* report) {
      CHECK(report->context_count == 0);
      CHECK(report->context_stack == nullptr);
    };
    with_handler(handler, []() {
      FORENSICS_CONTEXT(L"one");
      FORENSICS_CONTEXT(L"two");
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
      CHECK(!wcscmp(report->breadcrumbs[0].name, L"three"));
      CHECK(!wcscmp(report->breadcrumbs[1].name, L"four"));
    };
    with_handler(handler, []() {
      forensics_add_breadcrumb(L"one", nullptr, nullptr, 0);
      forensics_add_breadcrumb(L"two", nullptr, nullptr, 0);
      forensics_add_breadcrumb(L"three", nullptr, nullptr, 0);
      forensics_add_breadcrumb(L"four", nullptr, nullptr, 0);
      FORENSICS_ASSERT(false);
    });
  }
}
