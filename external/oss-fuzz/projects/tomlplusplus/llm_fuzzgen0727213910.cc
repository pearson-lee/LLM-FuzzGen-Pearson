#include <iostream>
#include <string>
#include <vector>
#include "toml++/toml.hpp"
#include <fuzzer/FuzzedDataProvider.h>
#include <unistd.h>
#include <stdio.h>

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  FuzzedDataProvider fdp(data, size);
  
  // Consume a portion of the data for parsing, leaving the rest for other operations.
  std::string toml_string = fdp.ConsumeRandomLengthString(fdp.remaining_bytes());

  /*
   * ANALYSIS: The function-level coverage report showed that `do_parse_file`
   *           was not being fully exercised. Specifically, the code paths for
   *           handling file I/O were not covered.
   * IMPLEMENTATION: The following block writes the fuzzer-generated TOML
   *                 string to a temporary file and calls `toml::parse_file` to
   *                 exercise the file-based parsing logic. The temporary file
   *                 is created and deleted safely.
   */
  if (fdp.ConsumeBool()) {
    std::string path = std::string("/tmp/") + _FUZZ_TARGET_NAME + ".tmp";
    FILE* fp = fopen(path.c_str(), "wb");
    if (fp) {
      fwrite(toml_string.c_str(), 1, toml_string.size(), fp);
      fclose(fp);
      try {
        toml::table tbl_file = toml::parse_file(path);
      } catch (const toml::parse_error&) {
        // ignore
      }
      unlink(path.c_str());
    }
  }

  try {
    toml::table tbl = toml::parse(toml_string);

    if (fdp.ConsumeBool()) {
      /*
       * ANALYSIS: The function-level coverage report showed that the bitwise
       *           operators for `format_flags` were not covered.
       * IMPLEMENTATION: The following lines exercise the `|` and `~` operators
       *                 on `format_flags` and use the result to construct the
       *                 formatter, improving coverage.
       */
      auto flags = toml::format_flags::allow_literal_strings | toml::format_flags::allow_multi_line_strings;
      flags = ~flags;
      toml::toml_formatter formatter{tbl, {flags}};
      std::stringstream ss;
      ss << formatter;
    }

    if (fdp.ConsumeBool()) {
      /*
       * ANALYSIS: The function `yaml_formatter::print_yaml_string` had 0% coverage.
       * IMPLEMENTATION: By inserting a multi-line string, we encourage the
       *                 `yaml_formatter` to take the code path for printing
       *                 complex strings.
       */
      tbl.insert("a_multiline_string", "first line\nsecond line");
      toml::yaml_formatter yaml_formatter{tbl};
      std::stringstream ss;
      ss << yaml_formatter;
    }
    
    /*
     * ANALYSIS: The function-level coverage report showed that `table::at`
     *           and many `is_*` and `as_*` functions on tables and arrays had
     *           0% coverage.
     * IMPLEMENTATION: The following loop iterates through the parsed table,
     *                 calling `at()` on the table and various uncovered
     *                 accessor/type-checking functions on the nodes to improve
     *                 coverage. Exceptions are caught to handle type mismatches.
     */
    for (auto &&[k, v] : tbl) {
      try {
        (void)tbl.at(k); // Cover table::at
        if (v.is_array()) {
          auto &arr = *v.as_array();
          if (!arr.empty()) {
            (void)arr.at(0);
            (void)arr.front();
            (void)arr.back();
            /*
             * ANALYSIS: The function `array::flatten` had low coverage.
             * IMPLEMENTATION: This call exercises the array flattening logic.
             */
            arr.flatten();
            toml::node* first_non_match = nullptr;
            arr.is_homogeneous(toml::node_type::none, first_non_match);
            arr.is_homogeneous<toml::table>();
          }
        } else if (v.is_table()) {
            auto& inner_tbl = *v.as_table();
            inner_tbl.is_array_of_tables();
        }
        /*
         * ANALYSIS: The `operator<<` for various node types was uncovered.
         * IMPLEMENTATION: The following lines stream the node to a stringstream
         *                 to exercise the corresponding `operator<<` overload.
         */
        std::stringstream ss;
        v.visit([&](auto& el) { ss << el; });
      } catch (...) {
        // ignore
      }
    }

    /*
     * ANALYSIS: The const-qualified overloads for accessor functions like
     *           `as_array` and `is_homogeneous` were not covered.
     * IMPLEMENTATION: This loop iterates over the table using a const reference
     *                 to ensure the const overloads of various node methods are called.
     */
    for (const auto &[k, v] : tbl) {
      try {
        if (v.is_array()) {
          const auto &arr = *v.as_array();
          arr.is_homogeneous<double>();
        }
      } catch (...) {
        // ignore
      }
    }

    /*
     * ANALYSIS: The function-level coverage showed `node_deep_equality` was
     *           completely uncovered. This function is used by `operator==`.
     * IMPLEMENTATION: The following block creates a copy of the table and
     *                 compares it with the original, exercising the equality operator
     *                 and its underlying `node_deep_equality` implementation.
     */
    if (fdp.ConsumeBool()) {
      toml::table tbl2 = tbl;
      (void)(tbl == tbl2);
    }

    /*
     * ANALYSIS: The function-level coverage report showed that many path
     *           manipulation functions like `append`, `prepend`, `truncate`,
     *           and `leaf` had 0% coverage.
     * IMPLEMENTATION: The following block creates a `toml::path`, exercises
     *                 these uncovered manipulation functions, and then uses the
     *                 path to access the table.
     */
    if (fdp.ConsumeBool()) {
      std::string path_str1 = fdp.ConsumeRandomLengthString(10);
      std::string path_str2 = fdp.ConsumeRandomLengthString(10);
      try {
        toml::path p1(path_str1);
        toml::path p2(path_str2);
        p1.append(std::move(p2));
        p1.prepend(toml::path(fdp.ConsumeRandomLengthString(5)));
        p1.truncate(fdp.ConsumeIntegralInRange<size_t>(0, p1.size()));
        if (!p1.empty()) {
            (void)p1.leaf(fdp.ConsumeIntegralInRange<size_t>(0, p1.size() - 1));
        }
        (void)tbl[p1];
      } catch (...) {
        // ignore
      }
    }

  } catch (const toml::parse_error &err) {
    // The main toml::parse call is sufficient to trigger and explore
    // different parsing error code paths.
  }

  return 0;
}