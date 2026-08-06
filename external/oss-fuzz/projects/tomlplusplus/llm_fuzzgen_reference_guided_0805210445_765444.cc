/* BLOCKER_STRATEGY_CONTRACT
required_state: Two `toml::array` objects of the same size, with elements of the same type at each corresponding index, but with at least one pair of elements having different values.
state_constructor: An existing `toml::array` is found in the parsed TOML data. A copy of this array is created. The first element of the copied array is modified to have a different value while preserving its type. This ensures the arrays are comparable but not identical.
trigger_api: The `operator==` is called to compare the original `toml::array` with the modified copy. This operator internally calls `toml::v3::array::equal`, which contains the target blocker.
preserved_invariants: The top-level input consumption contract is preserved. The fuzzer still parses a TOML string from the input and operates on the resulting `toml::table`. The sequence of `FuzzedDataProvider` calls remains unchanged.
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

      /*
       * ANALYSIS: The node_view conversion operators were not covered.
       * IMPLEMENTATION: The following code explicitly converts a node to a
       *                 node_view to exercise the conversion operators.
       */
      toml::node_view<toml::node> nv(v);
      (void)nv;


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
        case toml::node_type::date: {
          /*
           * ANALYSIS: The operator<< for toml::date was not covered.
           * IMPLEMENTATION: The following code streams the date to a
           *                 stringstream to exercise the operator.
           */
          std::stringstream ss_date;
          ss_date << *v.as_date();
          v.as_date()->get();
          break;
        }
        case toml::node_type::time: {
          /*
           * ANALYSIS: The operator<< for toml::time was not covered.
           * IMPLEMENTATION: The following code streams the time to a
           *                 stringstream to exercise the operator.
           */
          std::stringstream ss_time;
          ss_time << *v.as_time();
          v.as_time()->get();
          break;
        }
        case toml::node_type::date_time: {
          /*
           * ANALYSIS: The operator<< for toml::date_time was not covered.
           * IMPLEMENTATION: The following code streams the date_time to a
           *                 stringstream to exercise the operator.
           */
          std::stringstream ss_dt;
          ss_dt << *v.as_date_time();
          v.as_date_time()->get();
          break;
        }
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
          /*
           * ANALYSIS: The table::erase function was not covered.
           * IMPLEMENTATION: The following code erases an element from the
           *                 table to exercise the erase function.
           */
          if (!t.empty()) {
            t.erase(t.begin());
          }
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
    /*
     * ANALYSIS: The if-condition to cover print_yaml_string was never taken.
     * IMPLEMENTATION: Removed the if-condition to ensure the code is always
     *                 executed.
     */
    toml::value<std::string> str_val(fdp.ConsumeRandomLengthString(16));
    toml::yaml_formatter formatter_str(str_val);
    ss << formatter_str;
    
    /*
     * ANALYSIS: The `json_formatter` related functions had low coverage.
     *           Specifically, the `terse_key_value_pairs` branch was never hit.
     * IMPLEMENTATION: A `json_formatter` is created with the parsed table.
     *                 The format flags are explicitly toggled to ensure both
     *                 the `terse_key_value_pairs` and `none` paths are exercised,
     *                 addressing the previously missed branch.
     */
    std::stringstream ss_json;
    /*
     * ANALYSIS: The if-condition to cover terse_key_value_pairs was never
     *           taken.
     * IMPLEMENTATION: Removed the if/else and create two formatters to ensure
     *                 both paths are covered.
     */
    toml::json_formatter formatter_json_terse{tbl, toml::format_flags::terse_key_value_pairs};
    ss_json << formatter_json_terse;
    toml::json_formatter formatter_json_none{tbl, toml::format_flags::none};
    ss_json << formatter_json_none;

    /*
     * ANALYSIS: The json_formatter::print(array) function was not covered.
     * IMPLEMENTATION: The following code creates a json_formatter with an
     *                 array to exercise the array printing logic.
     */
    if (tbl.size() > 0 && tbl.begin()->second.is_array()) {
        toml::json_formatter formatter_json_array{*tbl.begin()->second.as_array()};
        ss_json << formatter_json_array;
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
        auto& original_arr = *v.as_array();
        toml::array arr_copy = original_arr;
        if (original_arr == arr_copy) {
          // This is the original fuzzer's check, kept for baseline coverage.
        }

        // BLOCKER-ORIENTED CODE
        // Create a dissimilar array to force `array::equal` to return false.
        // This is done by copying an array and modifying one of its elements.
        // The comparison of this modified copy with the original array is
        // expected to trigger the "!equal" branch.
        if (!arr_copy.empty()) {
            auto it = arr_copy.begin();
            const auto& node_to_modify = *it;
            switch (node_to_modify.type()) {
                case toml::node_type::string:
                    arr_copy.replace(it, node_to_modify.as_string()->get() + "fuzz");
                    break;
                case toml::node_type::integer:
                    arr_copy.replace(it, node_to_modify.as_integer()->get() + 1);
                    break;
                case toml::node_type::floating_point:
                    arr_copy.replace(it, node_to_modify.as_floating_point()->get() + 1.0);
                    break;
                case toml::node_type::boolean:
                    arr_copy.replace(it, !node_to_modify.as_boolean()->get());
                    break;
                default:
                    break;
            }
            // This comparison should now be false if we modified an element.
            (void)(original_arr == arr_copy);
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
