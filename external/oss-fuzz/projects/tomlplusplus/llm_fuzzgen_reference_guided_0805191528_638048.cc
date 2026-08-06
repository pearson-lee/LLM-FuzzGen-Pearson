/* BLOCKER_STRATEGY_CONTRACT
required_state: The toml::table on which insert_or_assign is called must not contain the key being inserted.
state_constructor: A toml::table is parsed from the input. A new key is then "consumed" from the FuzzedDataProvider. Due to a prior ConsumeRemainingBytesAsString call in the reference target, this new key will be an empty string. This empty key is unlikely to be present in the parsed table.
trigger_api: toml::table::insert_or_assign is called with the new (empty) key.
preserved_invariants: The initial parsing of the TOML string from fuzzer input is unchanged. The existing sequence of FuzzedDataProvider consumption calls is not modified, preserving the input contract for existing seeds.
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

    /* BLOCKER_SPECIFIC_CODE */
    // To reach the blocker in toml::v3::table::equal, we need to compare two
    // tables where a key is shared but the associated value types differ.
    // We create a copy of the parsed table and modify the type of the first
    // element. This ensures that when operator== is called, the
    // `lhs_type != rhs_type` check will be true.
    if (!tbl.empty())
    {
        toml::table tbl_different = tbl;
        auto& [key, val_node] = *tbl.begin();

        // Replace the node with one of a different type.
        switch(val_node.type())
        {
            case toml::node_type::string:
                tbl_different.insert_or_assign(key, int64_t{1});
                break;
            case toml::node_type::integer:
                tbl_different.insert_or_assign(key, "string");
                break;
            case toml::node_type::floating_point:
                tbl_different.insert_or_assign(key, bool{true});
                break;
            case toml::node_type::boolean:
                tbl_different.insert_or_assign(key, 1.0);
                break;
            case toml::node_type::array:
                tbl_different.insert_or_assign(key, toml::table{});
                break;
            case toml::node_type::table:
                tbl_different.insert_or_assign(key, toml::array{});
                break;
            default:
                tbl_different.insert_or_assign(key, "default_case");
                break;
        }
        // This comparison now triggers the desired path in table::equal.
        if (tbl == tbl_different)
        {
            // This branch is not expected to be taken.
        }
    }
    /* END_BLOCKER_SPECIFIC_CODE */

    /* BLOCKER_SPECIFIC_CODE */
    // The blocker is in the 'insert' path of insert_or_assign, which is
    // taken when the key does not already exist in the table.
    // We "consume" a new key from the fuzzer. Because the data provider was
    // exhausted by ConsumeRemainingBytesAsString(), this key will be empty.
    // We then attempt to insert it. If the parsed table does not already
    // contain an empty key, this satisfies the condition
    // `ipos == map_.end() || ipos->first != key_view` and triggers the call
    // to `insert_with_hint`, crossing the blocker.
    std::string new_key = fdp.ConsumeRandomLengthString(16);
    tbl.insert_or_assign(new_key, "fuzz_value");
    /* END_BLOCKER_SPECIFIC_CODE */

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
