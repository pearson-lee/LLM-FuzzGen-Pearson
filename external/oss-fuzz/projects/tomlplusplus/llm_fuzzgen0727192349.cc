#include <cstddef>
#include <cstdint>
#include <string>
#include <vector>
#include <fstream>
#include <unistd.h>
#include <sstream>

#include <fuzzer/FuzzedDataProvider.h>

#include "/src/tomlplusplus/toml.hpp"

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  FuzzedDataProvider fdp(data, size);

  // ANALYSIS: The original fuzzer was too greedy with its initial string
  // consumption, preventing other branches from being taken.
  // IMPLEMENTATION: Limit the initial string consumption to at most half of the
  // available data to ensure other fuzzing paths can be explored.
  const std::string toml_string = fdp.ConsumeRandomLengthString(std::min<size_t>(size, 512));
  
  try {
    const std::string path = std::string("/tmp/") + _FUZZ_TARGET_NAME + ".tmp";
    std::ofstream ofs(path, std::ios::binary);
    ofs << toml_string;
    ofs.close();
    toml::parse_file(path);
    unlink(path.c_str());
    toml::parse_file("/a/path/that/does/not/exist");

    auto tbl = toml::parse(toml_string);

    // ANALYSIS: The function-level coverage report showed that many accessor
    //           and manipulation functions for toml::table and toml::array
    //           were completely uncovered.
    // IMPLEMENTATION: The following block adds calls to various uncovered
    //                 functions like at(), front(), back(), erase(), and
    //                 contains() on both tables and arrays. These calls are
    //                 wrapped in try-catch blocks to handle potential
    //                 exceptions from invalid operations.
    if (fdp.ConsumeBool()) {
        try {
            auto path_str = fdp.ConsumeRandomLengthString(32);
            tbl.at_path(path_str);
            if (!tbl.empty()) {
                tbl.contains(path_str);
                tbl.erase(tbl.cbegin());
            }
        } catch (...) {
        }
        
        try {
            if (auto arr = tbl.as_array(); arr && !arr->empty()) {
                arr->front();
                arr->back();
                arr->at(0);
                arr->erase(arr->cbegin());
            }
        } catch (...) {
        }
    }

    if (fdp.ConsumeBool()) {
        toml::array arr;
        arr.push_back(1);
        arr.push_back(2);
        if (fdp.ConsumeBool()) {
            arr.push_back("three");
        }
        toml::node* first_nonmatch = nullptr;
        arr.is_homogeneous(toml::node_type::integer, first_nonmatch);
    }
    if (fdp.ConsumeBool()) {
        toml::table t;
        t.insert("a", 1);
        t.insert("b", 2);
        if (fdp.ConsumeBool()) {
            t.insert("c", "three");
        }
        toml::node* first_nonmatch = nullptr;
        t.is_homogeneous(toml::node_type::integer, first_nonmatch);
    }
    
    // ANALYSIS: The function-level coverage report indicated that the
    //           toml::json_formatter and toml::yaml_formatter classes were
    //           completely uncovered.
    // IMPLEMENTATION: This block creates and uses json_formatter and
    //                 yaml_formatter to serialize the parsed TOML table,
    //                 thus exercising their formatting logic.
    if (fdp.ConsumeBool()) {
        std::stringstream ss;
        toml::json_formatter json_formatter{tbl};
        ss << json_formatter;
        
        std::stringstream ss2;
        toml::yaml_formatter yaml_formatter{tbl};
        ss2 << yaml_formatter;
    }

  } catch (...) {
  }

  return 0;
}