#include "/src/tomlplusplus/toml.hpp"
#include <fuzzer/FuzzedDataProvider.h>
#include <iostream>
#include <fstream>
#include <unistd.h>
#include <sstream>

// Helper function to recursively explore the TOML document
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
    if (!arr.empty()) {
        (void)arr.front();
        (void)arr.back();
        if (arr.size() > 0) {
            size_t index = fdp.ConsumeIntegralInRange<size_t>(0, arr.size() - 1);
            explore_node(fdp, arr[index]);
        }
    }
    /*
     * ANALYSIS: The function-level coverage report showed that the
     *           `json_formatter` and `toml_formatter` functions for arrays had zero coverage.
     * IMPLEMENTATION: The following code block creates formatters for any arrays
     *                 found in the TOML document to exercise these uncovered paths.
     */
    std::stringstream ss_json, ss_toml;
    ss_json << toml::json_formatter{ arr };
    ss_toml << toml::toml_formatter{ arr };

  }

  // Generic node accessors
  if (node.is_string()) (void)node.as_string();
  if (node.is_integer()) (void)node.as_integer();
  if (node.is_floating_point()) (void)node.as_floating_point();
  if (node.is_boolean()) (void)node.as_boolean();
  if (node.is_date()) (void)node.as_date();
  if (node.is_time()) (void)node.as_time();
  if (node.is_date_time()) (void)node.as_date_time();
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
     *           and `toml::table` had zero coverage. The `as_*` accessors on various
     *           node types were also uncovered.
     * IMPLEMENTATION: The `explore_node` function recursively traverses the
     *                 parsed TOML document and calls `is_homogeneous` with various
     *                 types, as well as `as_*`, `front`, `back`, and index/key accessors.
     *                 This will exercise the uncovered template specializations and accessors.
     */
    explore_node(fdp, tbl);

    /*
     * ANALYSIS: The function-level coverage report showed that the
     *           `yaml_formatter`, `json_formatter` and `toml_formatter` functions had zero or low coverage.
     * IMPLEMENTATION: The following code block creates the various formatters and
     *                 uses them to print the parsed TOML document. This will
     *                 exercise the various printing functions.
     */
    std::stringstream ss_yaml, ss_json, ss_toml;
    ss_yaml << toml::yaml_formatter{ tbl };
    ss_json << toml::json_formatter{ tbl };
    ss_toml << toml::toml_formatter{ tbl };

    /*
     * ANALYSIS: The function-level coverage report showed that the `at_path`
     *           functions had zero coverage.
     * IMPLEMENTATION: The following code block calls `at_path` with a fuzzed
     *                 string to exercise this uncovered functionality. It is
     *                 wrapped in a try-catch block to handle invalid paths.
     */
    try {
        std::string path_str = fdp.ConsumeRandomLengthString(32);
        (void)tbl.at_path(path_str);
    } catch (...) {
    }


  } catch (const toml::parse_error& err) {
    // Handle parsing errors
    std::cerr << err << std::endl;
  }

  // Clean up the temporary file
  unlink(path.c_str());

  return 0;
}