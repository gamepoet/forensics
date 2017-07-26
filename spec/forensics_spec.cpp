#include "forensics.h"
#define lest_FEATURE_AUTO_REGISTER 1
#include "lest.hpp"

#define CASE(name) lest_CASE(specs, name)

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

static lest::tests specs;

CASE("basic report handling") {
  GIVEN("setup") {
    init_t init(nullptr);

    WHEN("there is no formatted message") {
      auto handler = [=](const forensics_report_t* report) {
        EXPECT(!strcmp(report->id, "<none>-forensics_spec.cpp-operator()-"));
        EXPECT(ends_with(report->file, "forensics_spec.cpp"));
        EXPECT(0 == strcmp(report->expression, "false"));
        EXPECT(report->format[0] == 0);
        EXPECT(report->formatted[0] == 0);
        EXPECT(report->fatal == true);
        EXPECT(report->backtrace_count > 0);
        EXPECT(report->backtrace != nullptr);
        EXPECT(report->line == __LINE__ + 2);
      };
      with_handler(handler, []() { FORENSICS_ASSERT(false); });
    }

    WHEN("there is a formatted message") {
      auto handler = [=](const forensics_report_t* report) {
        EXPECT(!strcmp(report->id, "<none>-forensics_spec.cpp-operator()-failed num=%d"));
        EXPECT(ends_with(report->file, "forensics_spec.cpp"));
        EXPECT(0 == strcmp(report->expression, "false"));
        EXPECT(!strcmp(report->format, "failed num=%d"));
        EXPECT(!strcmp(report->formatted, "failed num=2"));
        EXPECT(report->fatal == true);
        EXPECT(report->backtrace_count > 0);
        EXPECT(report->backtrace != nullptr);
        EXPECT(report->line == __LINE__ + 2);
      };
      with_handler(handler, []() { FORENSICS_ASSERTF(false, "failed num=%d", 2); });
    }
  }
}

CASE("attributes") {
  GIVEN("setup") {
    init_t init(nullptr);

    WHEN("there are no attributes") {
      auto handler = [=](const forensics_report_t* report) {
        EXPECT(report->attribute_count == 0);
        EXPECT(report->attribute_keys == nullptr);
        EXPECT(report->attribute_values == nullptr);
      };
      with_handler(handler, []() { FORENSICS_ASSERT(false); });
    }

    WHEN("there are some attributes") {
      forensics_set_attribute("user", "shawn spencer");
      forensics_set_attribute("version", "1.0.0");

      auto handler = [=](const forensics_report_t* report) {
        EXPECT(report->attribute_count == 2);
        EXPECT(has_attribute_value(report, "version", "1.0.0"));
        EXPECT(has_attribute_value(report, "user", "shawn spencer"));
      };
      with_handler(handler, []() { FORENSICS_ASSERT(false); });
    }

    WHEN("some attributes are cleared with nullptr value") {
      forensics_set_attribute("user", "shawn spencer");
      forensics_set_attribute("version", "1.0.0");
      forensics_set_attribute("user", nullptr);

      auto handler = [=](const forensics_report_t* report) {
        EXPECT(report->attribute_count == 1);
        EXPECT(has_attribute_value(report, "version", "1.0.0"));
        EXPECT(!has_attribute(report, "user"));
      };
      with_handler(handler, []() { FORENSICS_ASSERT(false); });
    }
  }
}

CASE("context") {
  GIVEN("setup") {
    init_t init(nullptr);

    WHEN("there is no context") {
      auto handler = [=](const forensics_report_t* report) {
        EXPECT(report->context_count == 0);
        EXPECT(report->context_stack == nullptr);
        EXPECT(!strcmp(report->id, "<none>-forensics_spec.cpp-operator()-"));
      };
      with_handler(handler, []() { FORENSICS_ASSERT(false); });
    }

    WHEN("there is a single context") {
      auto handler = [=](const forensics_report_t* report) {
        EXPECT(report->context_count == 1);
        EXPECT(!strcmp(report->context_stack[0], "global"));
        EXPECT(!strcmp(report->id, "global-forensics_spec.cpp-operator()-"));
      };
      with_handler(handler, []() {
        FORENSICS_CONTEXT("global");
        FORENSICS_ASSERT(false);
      });
    }

    WHEN("there are many contexts") {
      auto handler = [=](const forensics_report_t* report) {
        EXPECT(report->context_count == 3);
        EXPECT(!strcmp(report->context_stack[0], "global"));
        EXPECT(!strcmp(report->context_stack[1], "local"));
        EXPECT(!strcmp(report->context_stack[2], "personal"));
        EXPECT(!strcmp(report->id, "personal-forensics_spec.cpp-operator()-"));
      };
      with_handler(handler, []() {
        FORENSICS_CONTEXT("global");
        FORENSICS_CONTEXT("local");
        FORENSICS_CONTEXT("personal");
        FORENSICS_ASSERT(false);
      });
    }
  }
}

int main(int argc, char** argv) {
  int failed_count = lest::run(specs, argc, argv);
  if (failed_count == 0) {
    printf("All tests pass!\n");
  }
  else {
    printf("%d failures\n", failed_count);
  }

  return failed_count;
}
