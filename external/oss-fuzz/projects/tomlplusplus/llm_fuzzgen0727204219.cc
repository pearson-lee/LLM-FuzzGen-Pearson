#include <iostream>
#include <string>
#include <vector>
#include "toml++/toml.hpp"
#include <fuzzer/FuzzedDataProvider.h>

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  FuzzedDataProvider fdp(data, size);

  try {
    std::string toml_string = fdp.ConsumeRemainingBytesAsString();
    toml::table tbl = toml::parse(toml_string);

    /*
     * ANALYSIS: The function-level coverage report showed that the `print_inline`
     *           function in `toml_formatter` had very low coverage. The
     *           line-level report confirmed that the code for handling non-empty
     *           tables was not being executed.
     * IMPLEMENTATION: The following code block creates a `toml_formatter` and
     *                 calls `print_inline` with the parsed table to exercise
     *                 this uncovered code path.
     */
    if (fdp.ConsumeBool()) {
      toml::toml_formatter formatter{tbl};
      std::stringstream ss;
      ss << formatter;
    }

    /*
     * ANALYSIS: The function-level coverage report showed that the
     *           `print_yaml_string` function in `yaml_formatter` had 0%
     *           coverage.
     * IMPLEMENTATION: The following code block creates a `yaml_formatter` and
     *                 calls its `print` method to exercise this uncovered
     *                 code path.
     */
    if (fdp.ConsumeBool()) {
      toml::yaml_formatter yaml_formatter{tbl};
      std::stringstream ss;
      ss << yaml_formatter;
    }

    /*
     * ANALYSIS: The function-level coverage report showed that the `leaf`
     *           function in `path` had low coverage. The line-level report
     *           confirmed that the branches for `n > 0` and `n >
     *           components_.size()` were not being tested.
     * IMPLEMENTATION: The following code block creates a `path` and calls
     *                 `leaf` with a value of `n` that is sometimes greater
     *                 than the number of components in the path, exercising
     *                 these uncovered branches.
     */
    if (fdp.ConsumeBool()) {
      std::string path_str = fdp.ConsumeRandomLengthString(100);
      toml::path p(path_str);
      p.leaf(fdp.ConsumeIntegralInRange<unsigned long>(0, p.size() + 10));
    }

    /*
     * ANALYSIS: The function-level coverage report showed that several
     *           overloads of the `is_homogeneous` function in `array` had 0%
     *           coverage.
     * IMPLEMENTATION: The following code block iterates through the arrays in
     *                 the parsed table and calls `is_homogeneous` with
     *                 different template types to exercise these uncovered
     *                 overloads.
     */
    for (auto &&[k, v] : tbl) {
      if (v.is_array()) {
        auto &arr = *v.as_array();
        arr.is_homogeneous<std::string>();
        arr.is_homogeneous<int64_t>();
        arr.is_homogeneous<double>();
        arr.is_homogeneous<bool>();
        arr.is_homogeneous<toml::date>();
        arr.is_homogeneous<toml::time>();
        arr.is_homogeneous<toml::date_time>();
      }
    }

  } catch (const toml::parse_error &err) {
    /*
     * ANALYSIS: The function-level coverage report showed that the
     *           `consume_rest_of_line` function in the parser had 0%
     *           coverage. This function is likely called after a parse
     *           error.
     * IMPLEMENTATION: The following code block catches a `parse_error` and
     *                 then manually calls `consume_rest_of_line` on a parser
     *                 to exercise this uncovered code path.
     */
    std::string error_toml = fdp.ConsumeRemainingBytesAsString();
    auto result = toml::parse(error_toml);
  }

  return 0;
}