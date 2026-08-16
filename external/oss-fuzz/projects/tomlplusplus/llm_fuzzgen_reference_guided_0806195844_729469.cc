/* BLOCKER_STRATEGY_CONTRACT
required_state: Two `toml::table` instances, `lhs` and `rhs`, where `lhs.size() == rhs.size()`, all corresponding keys are identical, but at least one pair of corresponding values have different types (e.g., `lhs["key"]` is an integer, `rhs["key"]` is a string).
state_constructor: A copy of the parsed `toml::table` is created. If the table is not empty, the value of the first element in the copy is replaced with a value of a different type using `insert_or_assign`. This ensures the keys and ordering remain the same, but a type mismatch is introduced.
trigger_api: The `toml::table::operator==` is called on the original and modified tables. This operator calls the blocker function `toml::v3::table::equal`.
preserved_invariants: The top-level input contract is preserved by operating on a copy of the table parsed from the fuzzer input. The original `tbl` object and the sequence of other API calls remain unchanged.
END_BLOCKER_STRATEGY_CONTRACT */

#include "/src/tomlplusplus/toml.hpp"
#include <fuzzer/FuzzedDataProvider.h>
#include <iostream>
#include <sstream>
#include <fstream>
#include <unistd.h>

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
    toml::yaml_formatter formatter{tbl};
    ss << formatter;
    
    /*
     * ANALYSIS: The `json_formatter` related functions had 0% or low coverage.
     *           Specifically, the `terse_kvps()` branch was not being hit.
     * IMPLEMENTATION: A `json_formatter` is created with the parsed table and
     *                 randomly selected format flags. The output is written to a
     *                 string stream. This directly triggers the `print` methods
     *                 of the `json_formatter`, including the uncovered branches.
     */
    std::stringstream ss_json;
    toml::json_formatter formatter_json{
        tbl, fdp.ConsumeBool() ? toml::format_flags::terse_key_value_pairs
                               : toml::format_flags::none};
    ss_json << formatter_json;
    
    // Create a modified copy of the table to trigger the type-inequality branch in table::equal.
    toml::table tbl_modified = tbl;
    if (!tbl_modified.empty()) {
      auto key_view = tbl_modified.begin()->first;
      
      // Replace the value for the first key with a value of a different type
      // to force the 'lhs_type != rhs_type' branch to be taken.
      if (tbl_modified[key_view].is_string()) {
        tbl_modified.insert_or_assign(key_view, 12345);
      } else {
        tbl_modified.insert_or_assign(key_view, "a string value");
      }
    }
    // This comparison now has a high chance of triggering the desired blocker path.
    if (tbl == tbl_modified) {
      // Unlikely path.
    }
    
    for (auto &&[k, v] : tbl) {
      if (v.is_array()) {
        toml::array arr_copy = *v.as_array();
        if (*v.as_array() == arr_copy) {
          // Do nothing.
        }
      }
    }


  } catch (const toml::parse_error &) {
    // The input was not valid TOML, which is a valid fuzzing outcome.
  }

  /*
   * ANALYSIS: The function `do_parse_file` was completely uncovered.
   * IMPLEMENTATION: The fuzzer input is written to a temporary file, which is
   *                 then parsed using `toml::parse_file`. This directly targets
   *                 the `do_parse_file` function and its file I/O logic.
   *                 The temporary file is deleted before the function returns.
   */
  std::string path = std::string("/tmp/") + _FUZZ_TARGET_NAME + ".tmp";
  std::ofstream out(path);
  out << toml_string;
  out.close();
  try {
    toml::table tbl = toml::parse_file(path);
  } catch (const toml::parse_error &) {
    // The input was not valid TOML, which is a valid fuzzing outcome.
  }
  unlink(path.c_str());

  return 0;
}
