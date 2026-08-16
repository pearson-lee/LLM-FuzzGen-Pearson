/* BLOCKER_STRATEGY_CONTRACT
required_state: The internal `config_.flags` of the `yaml_formatter` must have the `format_flags::terse_key_value_pairs` bit set, causing `terse_kvps()` to return true.
state_constructor: The `toml::yaml_formatter` is constructed with an additional argument, `toml::format_flags::terse_key_value_pairs`, passed to its constructor, i.e., `toml::yaml_formatter(tbl, flags)`.
trigger_api: Streaming the constructed `toml::yaml_formatter` to `std::stringstream` (`ss << ...`), which invokes `toml::v3::yaml_formatter::print` and reaches the blocker.
preserved_invariants: The top-level input contract is preserved. The target continues to parse a TOML string from the input data and reuse the parsed `toml::table` for all subsequent operations, including the original API calls. The `FuzzedDataProvider` consume sequence is not modified.
END_BLOCKER_STRATEGY_CONTRACT */

#include "/src/tomlplusplus/toml.hpp"
#include <fuzzer/FuzzedDataProvider.h>
#include <iostream>
#include <sstream>

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  FuzzedDataProvider fdp(data, size);
  std::string toml_string = fdp.ConsumeRemainingBytesAsString();

  try {
    /*
     * ANALYSIS: The function-level coverage report showed that many functions
     * related to parsing, path traversal, type checking, and formatting had
     * low or zero coverage.
     * IMPLEMENTATION: This fuzz target first parses a TOML string, then
     * exercises the at_path, is_homogeneous, and yaml_formatter functions to
     * improve coverage in these areas.
     */
    toml::table tbl = toml::parse(toml_string);

    /*
     * ANALYSIS: The line-coverage report for toml::v3::at_path showed that
     * the branch `if (root.is_value())` was never taken.
     * IMPLEMENTATION: The following code attempts to get a value from the
     * parsed table and then calls at_path on it to cover this branch.
     */
    if (!tbl.empty()) {
      auto key = tbl.begin()->first;
      auto val = tbl.get(key);
      if (val && val->is_value()) {
        val->at_path("a.b.c");
      }
    }

    std::string path_str = fdp.ConsumeRandomLengthString(32);
    try {
      tbl.at_path(path_str);
    } catch (...) {
      // Ignore exceptions from invalid paths
    }

    /*
     * ANALYSIS: The function-level coverage report showed that many template
     * instantiations of is_homogeneous for both toml::array and toml::table
     * were completely uncovered.
     * IMPLEMENTATION: The following code explicitly calls is_homogeneous for
     * all supported types on the root table and on any arrays found within
     * the table.
     */
    tbl.is_homogeneous<toml::table>();
    tbl.is_homogeneous<toml::array>();
    tbl.is_homogeneous<std::string>();
    tbl.is_homogeneous<int64_t>();
    tbl.is_homogeneous<double>();
    tbl.is_homogeneous<bool>();
    tbl.is_homogeneous<toml::date>();
    tbl.is_homogeneous<toml::time>();
    tbl.is_homogeneous<toml::date_time>();

    tbl.for_each([&](const toml::key &, auto &v) {
      if (v.is_array()) {
        auto &arr = *v.as_array();
        arr.template is_homogeneous<toml::table>();
        arr.template is_homogeneous<toml::array>();
        arr.template is_homogeneous<std::string>();
        arr.template is_homogeneous<int64_t>();
        arr.template is_homogeneous<double>();
        arr.template is_homogeneous<bool>();
        arr.template is_homogeneous<toml::date>();
        arr.template is_homogeneous<toml::time>();
        arr.template is_homogeneous<toml::date_time>();
      }
    });

    /*
     * ANALYSIS: The function toml::v3::yaml_formatter::print_yaml_string was
     * found to have zero coverage.
     * IMPLEMENTATION: The following code constructs a yaml_formatter with the
     * parsed TOML table and writes it to a string stream to exercise this
     * functionality.
     */
    std::stringstream ss;
    // BLOCKER-ORIENTED CHANGE: To hit the desired branch in the blocker
    // `if (terse_kvps())`, we must construct the yaml_formatter with the
    // `terse_key_value_pairs` flag.
    ss << toml::yaml_formatter{tbl, toml::format_flags::terse_key_value_pairs};

  } catch (const toml::parse_error &) {
    // Consume parse errors.
  } catch (...) {
    // Consume other exceptions.
  }

  return 0;
}
