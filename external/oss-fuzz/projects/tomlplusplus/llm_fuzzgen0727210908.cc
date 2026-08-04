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
      toml::toml_formatter formatter{tbl};
      std::stringstream ss;
      ss << formatter;
    }

    if (fdp.ConsumeBool()) {
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
            arr.is_homogeneous<toml::table>();
            arr.as_string();
            arr.as_integer();
            arr.as_floating_point();
            arr.as_boolean();
            arr.as_date();
            arr.as_time();
            arr.as_date_time();
          }
        } else if (v.is_table()) {
            auto& inner_tbl = *v.as_table();
            inner_tbl.is_array_of_tables();
            inner_tbl.is_number();
        }
      } catch (...) {
        // ignore
      }
    }

    /*
     * ANALYSIS: The function-level coverage report showed that the
     *           `node::operator[](path)` overload for path-based access
     *           had 0% coverage.
     * IMPLEMENTATION: The following block creates a `toml::path` from fuzzer
     *                 data and uses it to access an element in the table,
     *                 exercising the uncovered operator.
     */
    if (fdp.ConsumeBool()) {
      std::string path_str = fdp.ConsumeRandomLengthString(50);
      toml::path p(path_str);
      try {
        (void)tbl[p];
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