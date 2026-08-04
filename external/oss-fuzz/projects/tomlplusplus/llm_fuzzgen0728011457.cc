#include <string>
#include <vector>
#include <iostream>
#include "tomlplusplus/toml.hpp"
#include <fuzzer/FuzzedDataProvider.h>

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  FuzzedDataProvider fdp(data, size);

  // ANALYSIS: The function `toml::v3::impl::impl_ex::parser::consume_rest_of_line`
  // had 0% coverage. It is called after parsing a comment.
  // IMPLEMENTATION: Generate a TOML string that may contain comments to
  // exercise this function.
  std::string toml_string = fdp.ConsumeRandomLengthString(1000);
  if (fdp.ConsumeBool()) {
    toml_string += "\n# a comment\n";
  }

  try {
    toml::table tbl = toml::parse(toml_string);

    // ANALYSIS: The function `toml::v3::at_path` had a branch for array indexing
    // that was never taken.
    // IMPLEMENTATION: Construct a path that includes an array index to cover
    // this branch.
    if (fdp.ConsumeBool()) {
      std::string path_str = fdp.ConsumeRandomLengthString(20);
      if (fdp.ConsumeBool()) {
        path_str += "[" + std::to_string(fdp.ConsumeIntegral<uint8_t>()) + "]";
      }
      try {
        (void)tbl.at_path(path_str);
      } catch (const toml::parse_error &) {
      } catch (const std::out_of_range &) {
      }
    }

    // ANALYSIS: The function `toml::v3::table::at` never had its error-handling
    // branch for a missing key exercised.
    // IMPLEMENTATION: Call `at()` with a randomly generated key that is
    // unlikely to exist, which will trigger the desired `out_of_range` exception.
    std::string key = fdp.ConsumeRandomLengthString(10);
    try {
      (void)tbl.at(key);
    } catch (const std::out_of_range &) {
    }

    for (auto &&[k, v] : tbl) {
      if (v.is_array()) {
        toml::array &arr = *v.as_array();

        // ANALYSIS: The `is_homogeneous` function templates for `toml::array`
        // were completely uncovered.
        // IMPLEMENTATION: Call `is_homogeneous` for each possible TOML type to
        // ensure these templates are instantiated and covered.
        arr.is_homogeneous<toml::table>();
        arr.is_homogeneous<toml::array>();
        arr.is_homogeneous<std::string>();
        arr.is_homogeneous<int64_t>();
        arr.is_homogeneous<double>();
        arr.is_homogeneous<bool>();
        arr.is_homogeneous<toml::date>();
        arr.is_homogeneous<toml::time>();
        arr.is_homogeneous<toml::date_time>();

        if (arr.size() > 0) {
          size_t index = fdp.ConsumeIntegralInRange<size_t>(0, arr.size() - 1);
          try {
            (void)arr.at(index);
          } catch (const std::out_of_range &) {
          }
        }
        break;
      }
    }

    // ANALYSIS: The YAML formatter function `print_yaml_string` was not covered.
    // IMPLEMENTATION: Create a `yaml_formatter` and stream it. This will
    // implicitly call the string printing functions if the parsed TOML contains
    // string values.
    if (fdp.ConsumeBool()) {
      std::stringstream ss;
      ss << toml::yaml_formatter{tbl};
    }
    
    // Exercise the JSON formatter as well for good measure.
    if (fdp.ConsumeBool()) {
      std::stringstream ss;
      ss << toml::json_formatter{tbl};
    }

  } catch (const toml::parse_error &) {
    // The input was not valid TOML, which is fine.
  }

  return 0;
}