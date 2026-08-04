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

  const std::string toml_string = fdp.ConsumeRandomLengthString(1024);
  
  try {
    const std::string path = std::string("/tmp/") + _FUZZ_TARGET_NAME + ".tmp";
    std::ofstream ofs(path, std::ios::binary);
    ofs << toml_string;
    ofs.close();
    toml::parse_file(path);
    unlink(path.c_str());
    toml::parse_file("/a/path/that/does/not/exist");

    auto tbl = toml::parse(toml_string);

    if (fdp.ConsumeBool()) {
        toml::value<int64_t> v(42);
        toml::at_path(v, "foo");
    }

    if (fdp.ConsumeBool()) {
        auto path_str = fdp.ConsumeRandomLengthString(32);
        tbl.at_path(path_str);
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
    
    if (fdp.ConsumeBool()) {
        std::stringstream ss;
        toml::toml_formatter formatter{tbl};
        ss << formatter;
    }

  } catch (...) {
  }

  return 0;
}