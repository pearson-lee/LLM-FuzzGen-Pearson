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
   * toml::v3::impl::parser::consume_rest_of_line had 0% coverage. This
   * function is likely called on parsing errors.
   * IMPLEMENTATION: The following code block sometimes adds invalid TOML syntax
   * to the end of the string to trigger parsing errors.
   */
  if (fdp.ConsumeBool()) {
    toml_str += "\n[some_table] # this is valid\n invalid stuff at the end";
  }

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
     * when at_path was called on a value node. The fuzz target coverage shows
     * the call to get() never succeeds.
     * IMPLEMENTATION: The following code block emplaces a value and then gets
     * it to ensure the call to at_path is made.
     */
    if (fdp.ConsumeBool()) {
      std::string key = fdp.ConsumeRandomLengthString(10);
      tbl.emplace(key, fdp.ConsumeRandomLengthString(10));
      if (auto val_node = tbl.get(key)) {
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

    /*
     * ANALYSIS: The function-level coverage report showed that toml::v3::array::as_integer,
     * as_floating_point, as_boolean, as_date, as_time, as_date_time and is_homogeneous
     * had 0% or low coverage.
     * IMPLEMENTATION: The following code block creates arrays of different types and
     * calls the corresponding as_* and is_homogeneous functions on them.
     */
    if (fdp.ConsumeBool()) {
        toml::array arr;
        arr.push_back(fdp.ConsumeIntegral<int64_t>());
        arr.push_back(fdp.ConsumeIntegral<int64_t>());
        (void)arr.as_integer();
        (void)arr.is_homogeneous<int64_t>();
        const toml::array const_arr = arr;
        (void)const_arr.as_integer();
    }
    if (fdp.ConsumeBool()) {
        toml::array arr;
        arr.push_back(fdp.ConsumeFloatingPoint<double>());
        arr.push_back(fdp.ConsumeFloatingPoint<double>());
        (void)arr.as_floating_point();
        (void)arr.is_homogeneous<double>();
        const toml::array const_arr = arr;
        (void)const_arr.as_floating_point();
    }
    if (fdp.ConsumeBool()) {
        toml::array arr;
        arr.push_back(fdp.ConsumeBool());
        arr.push_back(fdp.ConsumeBool());
        (void)arr.as_boolean();
        (void)arr.is_homogeneous<bool>();
        const toml::array const_arr = arr;
        (void)const_arr.as_boolean();
    }
    if (fdp.ConsumeBool()) {
        toml::array arr;
        arr.push_back(toml::date{fdp.ConsumeIntegralInRange<uint16_t>(1900, 2100), fdp.ConsumeIntegralInRange<uint8_t>(1, 12), fdp.ConsumeIntegralInRange<uint8_t>(1, 28)});
        (void)arr.as_date();
        (void)arr.is_homogeneous<toml::date>();
        const toml::array const_arr = arr;
        (void)const_arr.as_date();
    }
    if (fdp.ConsumeBool()) {
        toml::array arr;
        arr.push_back(toml::time{fdp.ConsumeIntegralInRange<uint8_t>(0, 23), fdp.ConsumeIntegralInRange<uint8_t>(0, 59), fdp.ConsumeIntegralInRange<uint8_t>(0, 59)});
        (void)arr.as_time();
        (void)arr.is_homogeneous<toml::time>();
        const toml::array const_arr = arr;
        (void)const_arr.as_time();
    }
    if (fdp.ConsumeBool()) {
        toml::array arr;
        arr.push_back(toml::date_time{toml::date{fdp.ConsumeIntegralInRange<uint16_t>(1900, 2100), fdp.ConsumeIntegralInRange<uint8_t>(1, 12), fdp.ConsumeIntegralInRange<uint8_t>(1, 28)}, toml::time{fdp.ConsumeIntegralInRange<uint8_t>(0, 23), fdp.ConsumeIntegralInRange<uint8_t>(0, 59), fdp.ConsumeIntegralInRange<uint8_t>(0, 59)}});
        (void)arr.as_date_time();
        (void)arr.is_homogeneous<toml::date_time>();
        const toml::array const_arr = arr;
        (void)const_arr.as_date_time();
    }
    if (fdp.ConsumeBool()) {
        toml::array arr;
        arr.push_back(INT64_C(1));
        arr.push_back("hello");
        (void)arr.is_homogeneous<int64_t>();
    }

    /*
     * ANALYSIS: The function-level coverage report showed that
     * toml::v3::yaml_formatter::print had 0% coverage on its overloads for
     * array and table.
     * IMPLEMENTATION: The following code block creates a toml::array and a
     * toml::table and uses a yaml_formatter to print them.
     */
    if (fdp.ConsumeBool()) {
      toml::array arr;
      arr.push_back(1);
      arr.push_back(2);
      std::stringstream ss;
      ss << toml::yaml_formatter{arr};
    }
    if (fdp.ConsumeBool()) {
      toml::table tbl;
      tbl.emplace("a", 1);
      tbl.emplace("b", 2);
      std::stringstream ss;
      ss << toml::yaml_formatter{tbl};
    }

    /*
     * ANALYSIS: The function-level coverage report showed that
     * toml::v3::node::operator toml::v3::node_view had 0% coverage.
     * IMPLEMENTATION: The following code block explicitly casts a node to a
     * node_view to exercise this uncovered operator.
     */
    if (fdp.ConsumeBool()) {
        tbl.emplace(fdp.ConsumeRandomLengthString(10), fdp.ConsumeRandomLengthString(10));
        if (auto val_node = tbl.get(fdp.ConsumeRandomLengthString(10))) {
            toml::node_view<toml::node> nv(*val_node);
            (void)nv;
        }
    }

    /*
     * ANALYSIS: The function-level coverage report showed that
     * toml::v3::table::is_homogeneous has 0% coverage.
     * IMPLEMENTATION: The following code block creates a toml::table,
     * adds some values to it, and calls is_homogeneous.
     */
    if (fdp.ConsumeBool()) {
      toml::table tbl_homo;
      tbl_homo.emplace("a", 1);
      tbl_homo.emplace("b", 2);
      (void)tbl_homo.is_homogeneous<int64_t>();
      (void)tbl_homo.is_homogeneous<double>();
    }

    /*
     * ANALYSIS: The function-level coverage report showed that
     * toml::v3::table::find has 0% coverage.
     * IMPLEMENTATION: The following code block creates a toml::table,
     * adds a value to it, and then calls find.
     */
    if (fdp.ConsumeBool()) {
      toml::table tbl_find;
      std::string key = fdp.ConsumeRandomLengthString(10);
      tbl_find.emplace(key, 1);
      (void)tbl_find.find(key);
      (void)tbl_find.find("key_not_present");
    }

    /*
     * ANALYSIS: The function-level coverage report showed that
     * toml::v3::table::operator[] with a path has 0% coverage.
     * IMPLEMENTATION: The following code block creates a toml::table,
     * and calls operator[] with a path.
     */
    if (fdp.ConsumeBool()) {
      toml::table tbl_path;
      tbl_path.emplace("a", toml::table{});
      try {
        (void)tbl_path[toml::path("a.b")];
      } catch (...) {
      }
    }
    
    /*
     * ANALYSIS: The function-level coverage report showed that
     * toml::v3::table::erase, lower_bound and contains have 0% coverage.
     * IMPLEMENTATION: The following code block creates a toml::table,
     * adds a value to it, and then calls these methods.
     */
    if (fdp.ConsumeBool()) {
      toml::table tbl_erase;
      std::string key = fdp.ConsumeRandomLengthString(10);
      tbl_erase.emplace(key, 1);
      if (auto it = tbl_erase.find(key); it != tbl_erase.end()) {
          tbl_erase.erase(it);
      }
      (void)tbl_erase.lower_bound(key);
      (void)tbl_erase.contains(key);
    }

    /*
     * ANALYSIS: The function-level coverage report showed that
     * toml::v3::array::as_table had 0% coverage.
     * IMPLEMENTATION: The following code block creates an array of tables
     * and calls as_table() on it.
     */
    if (fdp.ConsumeBool()) {
      toml::array arr;
      arr.push_back(toml::table{});
      arr.push_back(toml::table{});
      (void)arr.as_table();
      const toml::array const_arr = arr;
      (void)const_arr.as_table();
    }

    /*
     * ANALYSIS: The function-level coverage report showed that
     * toml::v3::impl::node_deep_equality has 0% coverage. This is called
     * by operator== on nodes.
     * IMPLEMENTATION: The following code block creates two nodes and compares them.
     */
    if (fdp.ConsumeBool()) {
        toml::table t1, t2;
        t1.emplace("a", 1);
        t2.emplace("a", 1);
        (void)(t1 == t2);
        (void)(t1 != t2);
    }

    /*
     * ANALYSIS: The function-level coverage report showed that many methods
     * on toml::v3::path have 0% coverage.
     * IMPLEMENTATION: The following code block creates a toml::path and calls
     * various methods on it.
     */
    if (fdp.ConsumeBool()) {
        toml::path p1("a.b.c");
        (void)p1.leaf();
        p1.truncate(1);
        toml::path p2 = p1.subpath(0, 1);
        p2.append("d");
        p2.prepend("z");
        std::stringstream ss;
        ss << p2;
    }

    /*
     * ANALYSIS: The function-level coverage report showed that
     * toml::v3::impl::print_to_stream has 0% coverage for several integer
     * and float overloads.
     * IMPLEMENTATION: The following code block creates values of these types
     * and prints them to a stream.
     */
    if (fdp.ConsumeBool()) {
        std::stringstream ss;
        ss << toml::value{fdp.ConsumeIntegral<signed char>()};
        ss << toml::value{fdp.ConsumeIntegral<short>()};
        ss << toml::value{fdp.ConsumeIntegral<int>()};
        ss << toml::value{fdp.ConsumeIntegral<long long>()};
        ss << toml::value{fdp.ConsumeIntegral<unsigned long long>()};
        ss << toml::value{fdp.ConsumeFloatingPoint<float>()};
    }


  } catch (...) {
    // Catch all exceptions from parsing and exercising the APIs.
    // This helps trigger error-handling code paths like
    // consume_rest_of_line.
  }

  return 0;
}