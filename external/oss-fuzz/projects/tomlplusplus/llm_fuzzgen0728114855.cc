#define _LIBCPP_ENABLE_CONTIGUOUS_CONTAINER_ANNOTATIONS 1
#include <iostream>
#include <string>
#include <vector>
#include <fuzzer/FuzzedDataProvider.h>
#include "/src/tomlplusplus/toml.hpp"

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  FuzzedDataProvider fdp(data, size);
  std::string toml_string = fdp.ConsumeRemainingBytesAsString();

  try {
    /*
     * ANALYSIS: The function-level coverage report showed that many functions
     *           related to parsing, type checking, and formatting had low or
     *           zero coverage. Specifically, `consume_rest_of_line` was at 0%.
     * IMPLEMENTATION: The following code attempts to parse a fuzzer-generated
     *                 string. Malformed input is likely to trigger error-handling
     *                 paths like `consume_rest_of_line`.
     */
    toml::table tbl = toml::parse(toml_string);

    /*
     * ANALYSIS: The `yaml_formatter` functions, particularly
     *           `print_yaml_string`, were completely uncovered.
     * IMPLEMENTATION: The following block creates a `yaml_formatter` and
     *                 prints the parsed table to exercise this code path.
     */
    std::stringstream ss;
    toml::yaml_formatter formatter{tbl};
    ss << formatter;

    /*
     * ANALYSIS: The `is_homogeneous` and `as_*` methods for `toml::array`
     *           and `toml::table` showed 0% coverage for many template
     *           specializations.
     * IMPLEMENTATION: The following loop iterates through the parsed table.
     *                 If an array or table is found, it calls `is_homogeneous`
     *                 and `as_string` to cover these functions.
     */
    for (auto &&[k, v] : tbl) {
      if (v.is_array()) {
        auto &arr = *v.as_array();
        (void)arr.is_homogeneous<toml::table>();
        (void)arr.as_string();
        if (arr.size() > 0) {
          arr.erase(arr.begin());
        }
      } else if (v.is_table()) {
        auto &nested_tbl = *v.as_table();
        (void)nested_tbl.is_homogeneous(toml::node_type::table);
        if (nested_tbl.size() > 0) {
          nested_tbl.erase(nested_tbl.begin());
        }
      }
    }

    /*
     * ANALYSIS: The `is_homogeneous` function on `table` had an uncovered
     *           branch for empty tables.
     * IMPLEMENTATION: The following code creates an empty table and calls
     *                 `is_homogeneous` on it to cover this specific case.
     */
    toml::table empty_tbl;
    (void)empty_tbl.is_homogeneous(toml::node_type::none);

    /*
     * ANALYSIS: The `erase` function on `table` had uncovered paths.
     * IMPLEMENTATION: The following code attempts to erase an element from
     *                 the parsed table using a key from the fuzzer.
     */
    if (tbl.size() > 0) {
      std::string key_to_erase = fdp.ConsumeRandomLengthString(16);
      tbl.erase(key_to_erase);
    }

  } catch (const toml::parse_error &err) {
    // Do nothing. The goal is to exercise the parser, not to handle errors.
  }

  return 0;
}