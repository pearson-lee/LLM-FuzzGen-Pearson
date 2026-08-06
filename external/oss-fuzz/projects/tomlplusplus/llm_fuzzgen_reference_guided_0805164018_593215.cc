/* BLOCKER_STRATEGY_CONTRACT
required_state: Two `toml::table` objects, `lhs` and `rhs`, where `lhs.size() == rhs.size()` and the set of keys in `lhs` is different from the set of keys in `rhs`.
state_constructor: A `toml::table` is parsed from the input. A copy is made. One key-value pair is removed from the copy, and a new key-value pair (with a unique key to avoid changing table size unexpectedly) is inserted. This creates two tables of the same size with different keys.
trigger_api: The `operator==` on the two `toml::table` objects, which calls `toml::v3::table::equal`.
preserved_invariants: The top-level input consumption sequence from `FuzzedDataProvider` and the initial `toml::parse` call are preserved to maintain seed compatibility.
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
    
    /*
     * ANALYSIS: The `table::equal` and `array::equal` functions had low coverage.
     * IMPLEMENTATION: A copy of the parsed table is created and compared with
     *                 the original table to exercise the `table::equal` function.
     *                 Similarly, arrays within the table are copied and compared.
     */
    toml::table tbl_copy = tbl;
    if (tbl == tbl_copy) {
      // Do nothing, just exercise the operator.
    }
    // START BLOCKER-SPECIFIC CODE
    // Goal: trigger l->first != r->first in toml::v3::table::equal
    if (!tbl.empty())
    {
        toml::table tbl2 = tbl;

        // Remove an element from the copy
        auto key_to_remove = tbl2.begin()->first;
        tbl2.erase(key_to_remove);

        // Add a new element with a key that is very unlikely to be in the original table.
        // This is done to ensure the table sizes of tbl and tbl2 are equal, but their
        // key sets are different.
        static int key_suffix_counter = 0;
        std::string new_key = "fuzzer_key_" + std::to_string(key_suffix_counter++);
        tbl2.insert(new_key, 1); // Insert a new key-value pair.

        // Now, `tbl` and `tbl2` should have the same size, but different keys.
        // This comparison is intended to trigger the desired branch in `table::equal`.
        if (tbl == tbl2) {
            // This branch will likely not be taken.
        }
    }
    // END BLOCKER-SPECIFIC CODE
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
  std::string path = std::string("/tmp/") + "llm_fuzzgen0728050935" + ".tmp";
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
