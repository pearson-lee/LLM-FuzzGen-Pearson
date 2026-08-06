/* BLOCKER_STRATEGY_CONTRACT
required_state: Two `toml::table` instances under comparison must have the same set of keys, but the values associated with at least one of those keys must be different. The types of the values for any given key must be the same across both tables to get past an earlier check.
state_constructor: A `toml::table` (`tbl`) is parsed from the input. A deep copy (`tbl_copy`) is created. If `tbl` is not empty, the value of the first key-value pair in `tbl_copy` is replaced with a different value of the same type. For primitive types, this is a simple modification (e.g., `+1`, `!val`). For container types (table, array), an element is added to the container in `tbl_copy` to make it different. This ensures the tables have the same size and keys, forcing a deep value comparison.
trigger_api: The `toml::table::operator==` is invoked to compare `tbl` and `tbl_copy`. This operator calls the blocker function `toml::v3::table::equal`.
preserved_invariants: The fuzzer maintains its original input consumption sequence (`ConsumeRemainingBytesAsString`, `ConsumeRandomLengthString`, `ConsumeBool`). The initial TOML parsing and calls to other APIs like `at_path`, `yaml_formatter`, and `json_formatter` are preserved. The new logic does not consume any new data from the fuzzer provider.
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
    // BLOCKER_STRATEGY: To hit the `!equal` branch in `table::equal`, we need two tables
    // with the same keys but different values for at least one key.
    // We find an existing key in the original table, and in a copy of the table, we replace
    // its value with a different value of the same type. This ensures the comparison
    // proceeds to the value-level check where the blocker is located.
    if (!tbl.empty()) {
      auto& [key_to_modify, node_to_modify] = *tbl.begin();

      node_to_modify.visit([&](auto&& original_value) {
        using value_type = std::decay_t<decltype(original_value)>;

        if constexpr (std::is_same_v<value_type, toml::table>) {
          toml::table new_table = original_value;
          new_table.insert("fuzz_key", "fuzz_value");
          tbl_copy.insert_or_assign(key_to_modify, new_table);
        } else if constexpr (std::is_same_v<value_type, toml::array>) {
          toml::array new_array = original_value;
          new_array.push_back(12345);
          tbl_copy.insert_or_assign(key_to_modify, new_array);
        } else if constexpr (std::is_same_v<value_type, std::string>) {
          tbl_copy.insert_or_assign(key_to_modify, original_value + "fuzz");
        } else if constexpr (std::is_same_v<value_type, int64_t>) {
          tbl_copy.insert_or_assign(key_to_modify, original_value + 1);
        } else if constexpr (std::is_same_v<value_type, double>) {
          tbl_copy.insert_or_assign(key_to_modify, original_value + 1.0);
        } else if constexpr (std::is_same_v<value_type, bool>) {
          tbl_copy.insert_or_assign(key_to_modify, !original_value);
        }
      });
    }
    if (tbl == tbl_copy) {
      // This branch is now less likely to be taken, but is kept for completeness.
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
