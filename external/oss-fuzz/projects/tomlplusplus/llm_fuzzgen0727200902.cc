#include <cstddef>
#include <cstdint>
#include <string>
#include <vector>
#include <fstream>
#include <unistd.h>
#include <sstream>
#include <iostream>

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

    // ANALYSIS: The detailed fuzz target coverage report showed that all conditional
    //           blocks were unreachable because `fdp.ConsumeIntegralInRange<uint8_t>(0, 1)`
    //           was consistently returning 0.
    // IMPLEMENTATION: Replaced `fdp.ConsumeIntegralInRange<uint8_t>(0, 1) == 1` with
    //                 `fdp.ConsumeBool()` to ensure these branches are explored.
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
                // ANALYSIS: The function-level coverage report showed that
                //           `toml::v3::array::flatten()` was not fully covered.
                // IMPLEMENTATION: Call flatten() to improve coverage.
                arr->flatten();
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
        // ANALYSIS: The function-level coverage report showed that
        //           `toml::v3::table::prune()` was uncovered.
        // IMPLEMENTATION: Call prune() to improve coverage.
        std::move(t).prune(fdp.ConsumeBool());
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

    // ANALYSIS: The function-level coverage report showed that many
    //           `operator<<` overloads were uncovered.
    // IMPLEMENTATION: Add calls to `operator<<` for various toml types.
    if (fdp.ConsumeBool()) {
        std::cout << tbl;
        if (auto arr = tbl.as_array()) {
            std::cout << *arr;
        }
        if (!tbl.empty()) {
            std::cout << tbl.cbegin()->first;
        }
    }
    
    // ANALYSIS: The function-level coverage report showed that many
    //           `toml::path` related functions were uncovered.
    // IMPLEMENTATION: Create and manipulate a toml::path object.
    if (fdp.ConsumeBool()) {
        try {
            toml::path p(fdp.ConsumeRandomLengthString(32));
            if (!p.empty()) {
                p.leaf(0);
                p.truncate(1);
                std::cout << p;
            }
        } catch (...) {
        }
    }

    /*
     * ANALYSIS: The function-level coverage report showed that the equality operators
     *           for toml::table and toml::array (e.g., `operator==`) were uncovered.
     * IMPLEMENTATION: This block creates a second table from fuzzer data and compares
     *                 it against the first one. It also attempts to get arrays from
     *                 both tables and compares them to exercise array equality operators.
     */
    if (fdp.ConsumeBool()) {
        try {
            auto tbl2 = toml::parse(fdp.ConsumeRandomLengthString(100));
            (void)(tbl == tbl2);
            (void)(tbl != tbl2);

            if (auto arr1 = tbl.as_array()) {
                if (auto arr2 = tbl2.as_array()) {
                    (void)(*arr1 == *arr2);
                    (void)(*arr1 != *arr2);
                }
            }
        } catch (...) {
        }
    }

    /*
     * ANALYSIS: The function-level coverage report showed that many value<T>
     *           methods like is_homogeneous and as_* were uncovered.
     * IMPLEMENTATION: Iterate through the parsed table, and for each node,
     *                 call various uncovered methods on the underlying value.
     */
    if (fdp.ConsumeBool() && !tbl.empty()) {
        for (auto&& [k, v] : tbl) {
            if (v.is_value()) {
                try {
                    v.is_homogeneous(toml::node_type::none);
                    v.is_array_of_tables();
                    v.is_number();
                } catch (...) {}
            }
        }
    }


  } catch (...) {
  }

  return 0;
}