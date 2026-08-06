/* BLOCKER_STRATEGY_CONTRACT
required_state: The `terse_key_value_pairs` format flag must be set on the `yaml_formatter` instance. This causes `terse_kvps()` to return true.
state_constructor: The `toml::yaml_formatter` is constructed with an additional argument, `toml::format_flags::terse_key_value_pairs`, to enable the required formatting flag.
trigger_api: `ss << formatter;` which invokes `toml::v3::yaml_formatter::print(toml::v3::table const&, bool)`, reaching the blocker.
preserved_invariants: The top-level input contract is preserved. The fuzzer input is still parsed as a TOML string via `toml::parse`, and the resulting table is used. The `FuzzedDataProvider` consumption sequence is unchanged.
END_BLOCKER_STRATEGY_CONTRACT */

#include "/src/tomlplusplus/toml.hpp"
#include <fuzzer/FuzzedDataProvider.h>
#include <iostream>
#include <sstream>

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  FuzzedDataProvider fdp(data, size);

  const std::string toml_string = fdp.ConsumeRemainingBytesAsString();

  try {
    /*
     * ANALYSIS: The function-level coverage report showed that many functions
     *           related to parsing, formatting, and data structure manipulation had
     *           low or zero coverage. Specifically, `consume_rest_of_line`,
     *           `print_yaml_string`, `is_homogeneous` for arrays and tables, and
     *           `at_path` were identified as high-priority targets.
     * IMPLEMENTATION: The following code block attempts to parse the fuzzer
     *                 input as a TOML string. A successful parse allows for further
     *                 testing of data manipulation and formatting APIs. This also
     *                 has the potential to trigger the `consume_rest_of_line`
     *                 function within the parser when encountering malformed lines.
     */
    toml::table tbl = toml::parse(toml_string);

    /*
     * ANALYSIS: The `is_homogeneous` method for both `toml::array` and
     *           `toml::table` had many template specializations with 0% coverage.
     * IMPLEMENTATION: The following code iterates through the parsed table and
     *                 calls `is_homogeneous` with various template arguments on any
     *                 arrays and tables it finds. This directly targets the
     *                 uncovered specializations.
     */
    for (auto &&[k, v] : tbl) {
      if (v.is_array()) {
        auto &arr = *v.as_array();
        arr.is_homogeneous<toml::table>();
        arr.is_homogeneous<toml::array>();
        arr.is_homogeneous<std::string>();
        arr.is_homogeneous<int64_t>();
        arr.is_homogeneous<double>();
        arr.is_homogeneous<bool>();
        arr.is_homogeneous<toml::date>();
        arr.is_homogeneous<toml::time>();
        arr.is_homogeneous<toml::date_time>();
      } else if (v.is_table()) {
        auto &t = *v.as_table();
        t.is_homogeneous<toml::table>();
        t.is_homogeneous<toml::array>();
        t.is_homogeneous<std::string>();
        t.is_homogeneous<int64_t>();
        t.is_homogeneous<double>();
        t.is_homogeneous<bool>();
        t.is_homogeneous<toml::date>();
        t.is_homogeneous<toml::time>();
        t.is_homogeneous<toml::date_time>();
      }
    }

    /*
     * ANALYSIS: The `at_path` function had several uncovered branches related to
     *           handling different node types and empty containers.
     * IMPLEMENTATION: A path string is generated from the fuzzer input, and
     *                 `at_path` is called on the parsed table. This exercises the
     *                 path parsing and node traversal logic, aiming to cover the
     *                 previously missed branches.
     */
    std::string path_str = fdp.ConsumeRandomLengthString(32);
    tbl.at_path(path_str);

    /*
     * ANALYSIS: The `print_yaml_string` function in the `yaml_formatter` had
     *           0% coverage.
     * IMPLEMENTATION: A `yaml_formatter` is created with the parsed table, and
     *                 the output is written to a string stream. This directly
     *                 triggers the `print` methods of the formatter, including
     *                 `print_yaml_string`.
     */
    std::stringstream ss;
    // BLOCKER_SPECIFIC_CODE
    // To satisfy the `if (terse_kvps())` predicate, the `yaml_formatter` must
    // be constructed with the `terse_key_value_pairs` format flag.
    toml::yaml_formatter formatter{tbl, toml::format_flags::terse_key_value_pairs};
    ss << formatter;

  } catch (const toml::parse_error &) {
    // The input was not valid TOML, which is a valid fuzzing outcome.
  }

  return 0;
}