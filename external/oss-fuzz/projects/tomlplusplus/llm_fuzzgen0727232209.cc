#include <cstddef>
#include <cstdint>
#include <string>
#include <vector>
#include <sstream>
#include <fuzzer/FuzzedDataProvider.h>
#include "tomlplusplus/toml.hpp"

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  FuzzedDataProvider fdp(data, size);

  try {
    std::string input_str = fdp.ConsumeRandomLengthString(1024);
    toml::table tbl = toml::parse(input_str);

    // ANALYSIS: The function-level coverage report showed toml::v3::toml_formatter::print_inline had low coverage (20.69%).
    // The line-level report confirmed this.
    // IMPLEMENTATION: The following code block creates a toml::toml_formatter and calls print_inline to exercise this uncovered code path.
    if (fdp.ConsumeBool()) {
      tbl.is_inline(true);
      std::stringstream ss;
      toml::toml_formatter formatter{tbl};
      ss << formatter;
    }

    // ANALYSIS: The function-level coverage report showed toml::v3::yaml_formatter::print_yaml_string had 0% coverage.
    // The line-level report confirmed this.
    // IMPLEMENTATION: The following code block creates a toml::value<std::string> and calls print_yaml_string to exercise this uncovered code path.
    if (fdp.ConsumeBool()) {
      std::string val_str = fdp.ConsumeRandomLengthString(128);
      toml::value<std::string> val(val_str);
      std::stringstream ss;
      toml::yaml_formatter formatter{val};
      ss << formatter;
    }

    // ANALYSIS: The function-level coverage report showed toml::v3::path::print_to had 0% coverage.
    // The line-level report confirmed this.
    // IMPLEMENTATION: The following code block creates a toml::path and calls print_to to exercise this uncovered code path.
    if (fdp.ConsumeBool()) {
      std::string path_str = fdp.ConsumeRandomLengthString(128);
      toml::path path(path_str);
      std::stringstream ss;
      ss << path;
    }

    // ANALYSIS: The function-level coverage report showed toml::v3::table::at had low coverage (50%).
    // The line-level report confirmed this.
    // IMPLEMENTATION: The following code block creates a toml::table, inserts a key-value pair, and calls at with a fuzzed key to exercise this uncovered code path.
    if (fdp.ConsumeBool()) {
      std::string key = fdp.ConsumeRandomLengthString(32);
      std::string val = fdp.ConsumeRandomLengthString(32);
      tbl.insert(key, val);
      try {
        (void)tbl.at(key);
      } catch (const std::out_of_range &) {
      }
    }

    // ANALYSIS: The function-level coverage report showed toml::v3::impl::impl_ex::parser::consume_rest_of_line had 0% coverage.
    // The line-level report confirmed this.
    // IMPLEMENTATION: The following code block calls toml::parse with a string containing a newline to exercise this uncovered code path.
    if (fdp.ConsumeBool()) {
      std::string toml_str = "a = 1\n";
      toml::parse(toml_str);
    }

  } catch (const toml::parse_error &) {
  } catch (const std::out_of_range &) {
  }

  return 0;
}