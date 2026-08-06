/* BLOCKER_STRATEGY_CONTRACT
required_state: A `toml::value<double>` containing a NaN must be compared with a `toml::value<double>` containing a non-NaN value.
state_constructor: Two `toml::array` objects are created. A NaN double is pushed into one, and a non-NaN double is pushed into the other.
trigger_api: The equality operator (`operator==`) is called on the two `toml::array` objects, which in turn compares their elements, triggering the desired `value<double>` comparison.
preserved_invariants: The top-level input contract is maintained by parsing the fuzzer input into a TOML string. The new logic is added after the initial parse and does not alter the `FuzzedDataProvider` consumption sequence.
END_BLOCKER_STRATEGY_CONTRACT */

#include "/src/tomlplusplus/toml.hpp"
#include <fuzzer/FuzzedDataProvider.h>
#include <iostream>
#include <sstream>
#include <fstream>
#include <unistd.h>
#include <cmath>
#include <limits>

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
     *           Additionally, the `as_*` methods for `value` and `array` were
     *           completely uncovered. The `key` class was also largely uncovered.
     * IMPLEMENTATION: The following code iterates through the parsed table.
     *                 It exercises the `key` API by creating copies and performing
     *                 comparisons. It then uses a switch on the value's type to
     *                 call the corresponding `as_*` methods, directly targeting
     *                 the uncovered functions in `value.hpp` and `array.hpp`.
     *                 It also calls `is_homogeneous` with various template
     *                 arguments on any arrays and tables it finds.
     */
    for (auto &&[k, v] : tbl) {
      // Key coverage
      toml::key k_copy = k;
      if (k == k_copy) {}
      if (k != k_copy) {}
      (void)k.str();
      (void)k.data();
      (void)k.length();

      switch (v.type()) {
        case toml::node_type::string:
          v.as_string()->get();
          break;
        case toml::node_type::integer:
          v.as_integer()->get();
          break;
        case toml::node_type::floating_point:
          v.as_floating_point()->get();
          break;
        case toml::node_type::boolean:
          v.as_boolean()->get();
          break;
        case toml::node_type::date:
          v.as_date()->get();
          break;
        case toml::node_type::time:
          v.as_time()->get();
          break;
        case toml::node_type::date_time:
          v.as_date_time()->get();
          break;
        case toml::node_type::array: {
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
          for (const auto& elem : arr) {
              // Exercise array element access
          }
          if (!arr.empty()) {
              (void)arr.front();
              (void)arr.back();
          }
          break;
        }
        case toml::node_type::table: {
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
          break;
        }
        case toml::node_type::none:
        default:
          break;
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
     *                 triggers the `print` methods of the formatter. A specific
     *                 call with a string value is added to cover `print_yaml_string`.
     */
    std::stringstream ss;
    toml::yaml_formatter formatter{tbl};
    ss << formatter;
    if (fdp.ConsumeBool()) {
        toml::value<std::string> str_val(fdp.ConsumeRandomLengthString(16));
        toml::yaml_formatter formatter_str(str_val);
        ss << formatter_str;
    }
    
    /*
     * ANALYSIS: The `json_formatter` related functions had low coverage.
     *           Specifically, the `terse_key_value_pairs` branch was never hit.
     * IMPLEMENTATION: A `json_formatter` is created with the parsed table.
     *                 The format flags are explicitly toggled to ensure both
     *                 the `terse_key_value_pairs` and `none` paths are exercised,
     *                 addressing the previously missed branch.
     */
    std::stringstream ss_json;
    if (fdp.ConsumeBool()) {
        toml::json_formatter formatter_json{tbl, toml::format_flags::terse_key_value_pairs};
        ss_json << formatter_json;
    } else {
        toml::json_formatter formatter_json{tbl, toml::format_flags::none};
        ss_json << formatter_json;
    }
    
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
    for (auto &&[k, v] : tbl) {
      if (v.is_array()) {
        toml::array arr_copy = *v.as_array();
        if (*v.as_array() == arr_copy) {
          // Do nothing.
        }
      }
    }

    // START BLOCKER-SPECIFIC CODE
    // The blocker requires comparing a NaN double with a non-NaN double.
    // We create two arrays, one with a NaN and one with a non-NaN value, and compare them.
    // This will trigger the operator== for array, which in turn
    // will call operator== for value<double>, satisfying the blocker condition.
    toml::array arr1;
    toml::array arr2;
    if (fdp.ConsumeBool()) {
        arr1.push_back(std::numeric_limits<double>::quiet_NaN());
        arr2.push_back(1.0);
    } else {
        arr1.push_back(1.0);
        arr2.push_back(std::numeric_limits<double>::quiet_NaN());
    }
    if (arr1 == arr2) {
        // This will be false, but the comparison will exercise the desired path.
    }
    // END BLOCKER-SPECIFIC CODE


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
  std::string path = std::string("/tmp/") + "llm_fuzzgen0728054325" + ".tmp";
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
