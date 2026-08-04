#include <cstddef>
#include <cstdint>
#include <fstream>
#include <iostream>
#include <string>
#include <vector>
#include <fuzzer/FuzzedDataProvider.h>
#include "/src/tomlplusplus/toml.hpp"
#include <unistd.h>

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  FuzzedDataProvider fdp(data, size);
  std::string toml_str = fdp.ConsumeRandomLengthString(1000);

  /*
   * ANALYSIS: The function-level coverage report showed that
   * toml::v3::impl::do_parse_file had a branch with zero hits. The line-level
   * report confirmed this was for files larger than 2MB.
   * IMPLEMENTATION: The following code block sometimes writes a large amount of
   * data to a temporary file to specifically exercise this uncovered path.
   */
  std::string path = std::string("/tmp/") + _FUZZ_TARGET_NAME + ".tmp";
  std::ofstream ofs(path, std::ios::binary);
  if (fdp.ConsumeBool()) {
    std::string large_data = fdp.ConsumeRandomLengthString(1024 * 1024 * 3);
    ofs.write(large_data.c_str(), large_data.length());
  } else {
    ofs.write(toml_str.c_str(), toml_str.length());
  }
  ofs.close();

  try {
    (void)toml::parse_file(path);
  } catch (...) {
  }
  unlink(path.c_str());

  try {
    toml::table tbl = toml::parse(toml_str);
    std::string path_str = fdp.ConsumeRandomLengthString(100);

    /*
     * ANALYSIS: The function-level coverage report showed that toml::v3::at_path
     * had a branch with zero hits. The line-level report confirmed this was for
     * when at_path was called on a value node.
     * IMPLEMENTATION: The following code block sometimes calls at_path on a
     * value node to exercise this uncovered path.
     */
    if (fdp.ConsumeBool()) {
      if (auto val_node = tbl.get(fdp.ConsumeRandomLengthString(10))) {
        if (val_node->is_value()) {
          try {
            (void)val_node->at_path(path_str);
          } catch (...) {
          }
        }
      }
    }

    /*
     * ANALYSIS: The function-level coverage report showed that toml::v3::at_path
     * had a branch with zero hits. The line-level report confirmed this was for
     * when at_path was called on an empty array.
     * IMPLEMENTATION: The following code block sometimes calls at_path on an
     * empty array to exercise this uncovered path.
     */
    if (fdp.ConsumeBool()) {
      toml::array arr;
      try {
        (void)toml::at_path(arr, path_str);
      } catch (...) {
      }
    }

    /*
     * ANALYSIS: The function-level coverage report showed that
     * toml::v3::array::as_string had 0% coverage.
     * IMPLEMENTATION: The following code block creates an array of integers and
     * calls as_string() on it to exercise this function.
     */
    if (fdp.ConsumeBool()) {
      toml::array arr;
      arr.push_back(1);
      arr.push_back(2);
      (void)arr.as_string();
    }

    /*
     * ANALYSIS: The function-level coverage report showed that
     * toml::v3::yaml_formatter::print_yaml_string had 0% coverage on one of its
     * overloads and low coverage on another.
     * IMPLEMENTATION: The following code block creates a toml::value<std::string>
     * and uses a yaml_formatter to print it. The string sometimes contains
     * newlines to exercise different branches in the function.
     */
    if (fdp.ConsumeBool()) {
      std::string s = fdp.ConsumeRandomLengthString(100);
      if (fdp.ConsumeBool()) {
        s += "\n";
      }
      toml::value<std::string> val(s);
      std::stringstream ss;
      ss << toml::yaml_formatter{val};
    }

  } catch (...) {
    // Catch all exceptions from parsing and exercising the APIs.
    // This helps trigger error-handling code paths like
    // consume_rest_of_line.
  }

  return 0;
}