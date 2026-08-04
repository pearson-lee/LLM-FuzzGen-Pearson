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
    
    // ANALYSIS: The function-level coverage report showed that `toml::v3::array::is_homogeneous` is not covered for a non-homogeneous array.
    // The line-level report for `toml::v3::array::is_homogeneous(toml::v3::node_type, toml::v3::node*&)` confirmed the branch for non-homogeneous arrays was not taken.
    // IMPLEMENTATION: The following code block creates a non-homogeneous toml::array and calls is_homogeneous on it.
    if (fdp.ConsumeBool()) {
        toml::array arr;
        arr.push_back(fdp.ConsumeIntegral<int>());
        arr.push_back(fdp.ConsumeRandomLengthString(10));
        (void)arr.is_homogeneous<long>();
    }

    // ANALYSIS: The function-level coverage report showed that `toml::v3::table::prune(bool) &&` had 0% coverage.
    // IMPLEMENTATION: The following code block calls the r-value overload of `prune` by using `std::move`.
    if (fdp.ConsumeBool()) {
        toml::table t;
        t.insert("a", 1);
        (void)std::move(t).prune(fdp.ConsumeBool());
    }
    
    // ANALYSIS: The function-level coverage report for `toml::v3::json_formatter::print()` showed a branch for `dump_failed_parse_result()` was not taken.
    // IMPLEMENTATION: The following code block creates a json_formatter from a failed parse result to cover this branch.
    if (fdp.ConsumeBool()) {
        auto result = toml::parse("!invalid_toml!");
        std::stringstream ss;
        toml::json_formatter formatter{result};
        ss << formatter;
    }

    // ANALYSIS: The line-level coverage for `toml::v3::impl::print_to_stream` with a `time_offset` showed that positive offsets were not being tested.
    // IMPLEMENTATION: The following code block creates a `time_offset` with a positive value and prints it.
    if (fdp.ConsumeBool()) {
        int16_t h = fdp.ConsumeIntegralInRange<int16_t>(0, 23);
        int16_t m = fdp.ConsumeIntegralInRange<int16_t>(0, 59);
        if (h == 0 && m == 0)
        {
          m = 1;
        }
        toml::time_offset offset{h, m};
        std::stringstream ss;
        ss << offset;
    }

  } catch (const toml::parse_error &) {
  } catch (const std::out_of_range &) {
  }

  return 0;
}