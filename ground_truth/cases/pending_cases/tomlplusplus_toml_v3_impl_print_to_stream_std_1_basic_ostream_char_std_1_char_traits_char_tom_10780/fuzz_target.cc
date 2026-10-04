#include "/src/tomlplusplus/toml.hpp"
#include <fuzzer/FuzzedDataProvider.h>
#include <iostream>
#include <fstream>
#include <unistd.h>

// Helper function to recursively explore the TOML document and call is_homogeneous
void explore_node(FuzzedDataProvider& fdp, toml::node& node) {
  if (node.is_table()) {
    auto& table = *node.as_table();
    table.is_homogeneous<toml::table>();
    table.is_homogeneous<toml::array>();
    table.is_homogeneous<std::string>();
    table.is_homogeneous<int64_t>();
    table.is_homogeneous<double>();
    table.is_homogeneous<bool>();
    table.is_homogeneous<toml::date>();
    table.is_homogeneous<toml::time>();
    table.is_homogeneous<toml::date_time>();
    for (auto&& [key, val] : table) {
      explore_node(fdp, val);
    }
  } else if (node.is_array()) {
    auto& arr = *node.as_array();
    arr.is_homogeneous<toml::table>();
    arr.is_homogeneous<toml::array>();
    arr.is_homogeneous<std::string>();
    arr.is_homogeneous<int64_t>();
    arr.is_homogeneous<double>();
    arr.is_homogeneous<bool>();
    arr.is_homogeneous<toml::date>();
    arr.is_homogeneous<toml::time>();
    arr.is_homogeneous<toml::date_time>();
    for (auto&& val : arr) {
      explore_node(fdp, val);
    }
  }
}

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
  FuzzedDataProvider fdp(data, size);

  // Create a unique temporary file path
  const std::string path = std::string("/tmp/") + _FUZZ_TARGET_NAME + ".toml";

  /*
   * ANALYSIS: The function-level coverage report showed `do_parse_file` had
   *           low coverage. The line-level report confirmed this was because the
   *           streaming parser path and error handling paths were not being exercised.
   * IMPLEMENTATION: The following code block writes fuzzed data to a temporary
   *                 file and then calls `toml::parse_file` to exercise the file
   *                 parsing logic. The amount of data written is fuzzed to
   *                 trigger both the regular and streaming parser paths.
   */
  std::ofstream ofs(path, std::ios::binary);
  std::string file_content = fdp.ConsumeRemainingBytesAsString();
  ofs.write(file_content.c_str(), file_content.length());
  ofs.close();

  try {
    // Parse the temporary file
    toml::table tbl = toml::parse_file(path);

    /*
     * ANALYSIS: The function-level coverage report showed that multiple
     *           template specializations of `is_homogeneous` for both `toml::array`
     *           and `toml::table` had zero coverage.
     * IMPLEMENTATION: The `explore_node` function recursively traverses the
     *                 parsed TOML document and calls `is_homogeneous` with various
     *                 types on every array and table it encounters. This will
     *                 exercise the uncovered template specializations.
     */
    explore_node(fdp, tbl);

    /*
     * ANALYSIS: The function-level coverage report showed that the
     *           `yaml_formatter` functions had zero coverage.
     * IMPLEMENTATION: The following code block creates a `yaml_formatter` and
     *                 uses it to print the parsed TOML document. This will
     *                 exercise the `print` and `print_yaml_string` functions.
     */
    std::stringstream ss;
    ss << toml::yaml_formatter{ tbl };

  } catch (const toml::parse_error& err) {
    // Handle parsing errors
    std::cerr << err << std::endl;
  }

  // Clean up the temporary file
  unlink(path.c_str());

  return 0;
}