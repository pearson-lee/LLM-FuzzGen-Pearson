/* BLOCKER_STRATEGY_CONTRACT
required_state: The `start` iterator must be greater than or equal to the `end` iterator in the call to `toml::v3::path::subpath(std::vector<path_component>::const_iterator, std::vector<path_component>::const_iterator)`. This is achieved by calling the `toml::v3::path::subpath(size_t, size_t)` overload with a `length` argument of 0.
state_constructor: A `toml::path` object `p1` is created from fuzzer data. If this path is not empty, a valid `start_index` is generated using `FuzzedDataProvider`.
trigger_api: `p1.subpath(start_index, 0)` is called, which in turn calls the target `subpath` overload with iterators where `start >= end`.
preserved_invariants: The existing `FuzzedDataProvider` consumption order is maintained. The new logic is added to an existing `try-catch` block and operates on an object (`p1`) that was already being created and used, preserving the original fuzzing logic's structure.
END_BLOCKER_STRATEGY_CONTRACT */

#include <iostream>
#include <fstream>
#include <string>
#include <vector>
#include <unistd.h>
#include <sstream>
#include <optional>
#include <fuzzer/FuzzedDataProvider.h>
#include "/src/tomlplusplus/include/toml++/toml.h"
#include "/src/tomlplusplus/include/toml++/impl/yaml_formatter.hpp"
#include "/src/tomlplusplus/include/toml++/impl/json_formatter.hpp"

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  FuzzedDataProvider fdp(data, size);
  // volatile sink to prevent the compiler from optimizing away unused return values.
  volatile int sink = 0;

  std::string toml_string = fdp.ConsumeRandomLengthString(fdp.ConsumeIntegralInRange<size_t>(0, 1024));
  
  if (fdp.ConsumeBool()) {
    toml_string += "\nkey1 = ''''\n" + fdp.ConsumeRandomLengthString(50) + "''''\n";
  }
  if (fdp.ConsumeBool()) {
    toml_string += "\nkey2 = \"\"\"\n" + fdp.ConsumeRandomLengthString(50) + "\\\n" + fdp.ConsumeRandomLengthString(50) + "\"\"\"\n";
  }
  if (fdp.ConsumeBool()) {
    toml_string += std::string("\nkey3 = ") + fdp.PickValueInArray({"+inf", "-inf", "inf", "+nan", "-nan", "nan"}) + "\n";
  }
  if (fdp.ConsumeBool()) {
    toml_string += "\nkey4 = 0x" + fdp.ConsumeRandomLengthString(4) + "." + fdp.ConsumeRandomLengthString(4) + "p-" + std::to_string(fdp.ConsumeIntegralInRange<int>(0, 5)) + "\n";
  }

  if (fdp.ConsumeBool()) {
    toml_string += "\nbool1 = true\n";
  }
  if (fdp.ConsumeBool()) {
    toml_string += "\nld1 = 1979-05-27\n";
  }
  if (fdp.ConsumeBool()) {
    toml_string += "\nlt1 = 07:32:00\n";
    toml_string += "\nlt2 = 08:00:00\n";
  }
  if (fdp.ConsumeBool()) {
    toml_string += "\nldt1 = 1979-05-27T07:32:00\n";
  }
  if (fdp.ConsumeBool()) {
    toml_string += "\nodt1 = 1979-05-27T07:32:00-07:00\n";
  }

  if (fdp.ConsumeBool()) {
    toml_string += "\narr1 = [1, 2, 3]\n";
  }
  if (fdp.ConsumeBool()) {
    toml_string += "\n[[products]]\nname = \"Hammer\"\n\n[[products]]\nname = \"Nail\"\n";
  }
  if (fdp.ConsumeBool()) {
    toml_string += "\narr_of_arr = [[1, 2], [3, 4]]\n";
  }
  
  if (fdp.ConsumeBool()) {
    toml_string += "\narr_het = [1, \"two\", 3.0, true]\n";
  }

  /*
   * ANALYSIS: The function `parser::consume_rest_of_line` was uncovered. The previous
   *           attempt to trigger it by adding `garbage` after an integer failed.
   * IMPLEMENTATION: Appending garbage characters at the end of the entire TOML
   *                 string is more likely to be parsed as trailing junk after a
   *                 valid document, which should trigger `consume_rest_of_line`.
   */
  if (fdp.ConsumeBool()) {
    toml_string += "\n garbage";
  }


  std::optional<toml::table> tbl;

  try {
    int parse_mode = fdp.ConsumeIntegralInRange(0, 2);
    if (parse_mode == 0) {
      tbl = toml::parse(toml_string);
    } else if (parse_mode == 1) {
      std::string path = std::string("/tmp/") + _FUZZ_TARGET_NAME + ".tmp";
      std::ofstream out(path);
      out << toml_string;
      out.close();
      tbl = toml::parse_file(path);
      unlink(path.c_str());
    } else {
        /*
         * ANALYSIS: The function-level coverage report showed 0% coverage for the
         *           `istream` parsing overload that takes a source path.
         * IMPLEMENTATION: Call the `toml::parse` overload that accepts an istream
         *                 and a source path string to cover this function.
         */
        std::stringstream ss(toml_string);
        tbl = toml::parse(ss, std::string("fuzz_source"));
    }

    if (tbl) {
      if (fdp.ConsumeBool()) {
        toml::table t1{{"a", 1}, {"b", "2"}, {"c", toml::array{1, 2}}};
        toml::table t2{{"a", 1}, {"b", "2"}, {"c", toml::array{1, 2}}};
        if (fdp.ConsumeBool()) sink += (t1 == t2);

        toml::array a1{1, "2", toml::table{{"a", 1}}};
        toml::array a2{1, "2", toml::table{{"a", 1}}};
        if (fdp.ConsumeBool()) sink += (a1 == a2);
      }

      if (fdp.ConsumeBool()) {
        std::stringstream ss;
        ss << *tbl;
      }
      if (fdp.ConsumeBool()) {
        std::stringstream ss;
        ss << toml::json_formatter{*tbl};
      }
      if (fdp.ConsumeBool()) {
        std::stringstream ss;
        /*
         * ANALYSIS: The function `yaml_formatter::print_yaml_string` was uncovered.
         * IMPLEMENTATION: Iterate through the table and explicitly format any string
         *                 values found using the `yaml_formatter` to exercise the
         *                 specialized string printing logic.
         */
        for (auto&& [k, v] : *tbl) {
            if (v.is_string()) {
                ss << toml::yaml_formatter{v};
            }
        }
        toml::table yaml_tbl;
        yaml_tbl.insert("multi", "first line\nsecond line");
        ss << toml::yaml_formatter{yaml_tbl};

        toml::array yaml_arr{1, 2, 3};
        ss << toml::yaml_formatter{yaml_arr};
      }
      
      if (fdp.ConsumeBool()) {
        toml::table inline_table;
        inline_table.insert("a", 1);
        inline_table.insert("b", "two");
        std::stringstream ss;
        ss << toml::toml_formatter{inline_table};
      }

      if (fdp.ConsumeBool()) {
        tbl->erase(fdp.ConsumeRandomLengthString(10));
      }
      
      if (fdp.ConsumeBool()) {
        tbl->clear();
      }

      std::vector<toml::node*> nodes;
      nodes.push_back(&*tbl);
      std::optional<toml::date> first_date;
      std::optional<toml::time> first_time;
      std::optional<toml::date_time> first_date_time;
      while (!nodes.empty() && fdp.remaining_bytes() > 2) {
          toml::node* n = nodes.back();
          nodes.pop_back();
          if (!n) continue;

          toml::node_view view{n};

          /*
           * ANALYSIS: Many `is_*` and `as_*` methods on node_view, array, and value
           *           were uncovered because their return values were unused and optimized out.
           * IMPLEMENTATION: The return values of these functions are now conditionally
           *                 added to a volatile sink to force the compiler to evaluate them.
           */
          if (fdp.ConsumeBool()) sink += view.is_table();
          if (fdp.ConsumeBool()) sink += view.is_array();
          if (fdp.ConsumeBool()) sink += view.is_value();
          
          if (fdp.ConsumeBool()) sink += view.is_homogeneous();
          if (fdp.ConsumeBool()) sink += view.is_homogeneous(toml::node_type::array);


          if (auto t = view.as_table()) {
              if (fdp.ConsumeBool()) {
                  t->prune(fdp.ConsumeBool());
              }
              for (auto&& [k, v] : *t) {
                  nodes.push_back(&v);
              }
          } else if (auto a = view.as_array()) {
              if (fdp.ConsumeBool()) {
                  a->prune(fdp.ConsumeBool());
              }
              if (fdp.ConsumeBool()) {
                  a->flatten();
              }
              for (auto&& v : *a) {
                  nodes.push_back(&v);
              }
              if (!a->empty() && fdp.ConsumeBool()) {
                  size_t index = fdp.ConsumeIntegralInRange<size_t>(0, a->size() - 1);
                  (void)a->get(index);
                  try {
                      (void)a->at(index);
                  } catch (...) {}
              }
              if (fdp.ConsumeBool()) {
                toml::array new_arr;
                new_arr.push_back(1);
                new_arr.pop_back();
                /*
                 * ANALYSIS: The detailed fuzzer coverage showed the `if` at line 301
                 *           was always true.
                 * IMPLEMENTATION: Make the `emplace_back` call conditional to allow
                 *                 the array to sometimes be empty, exercising both branches.
                 */
                if (fdp.ConsumeBool()) {
                    new_arr.emplace_back(false);
                }
                if (!new_arr.empty()) {
                  new_arr.truncate(1);
                  new_arr.shrink_to_fit();
                  new_arr.erase(new_arr.cbegin());
                }
                new_arr.insert(new_arr.cbegin(), 42);
                new_arr.clear();
              }
          } else if (view.is_value()) {
              if (fdp.ConsumeBool()) sink += view.is_string();
              if (view.as_string() && fdp.ConsumeBool()) sink++;
              if (fdp.ConsumeBool()) sink += view.is_integer();
              if (view.as_integer() && fdp.ConsumeBool()) sink++;
              if (fdp.ConsumeBool()) sink += view.is_floating_point();
              if (view.as_floating_point() && fdp.ConsumeBool()) sink++;
              if (fdp.ConsumeBool()) sink += view.is_boolean();
              if (view.as_boolean() && fdp.ConsumeBool()) sink++;
              if (fdp.ConsumeBool()) sink += view.is_date();
              if (view.as_date() && fdp.ConsumeBool()) sink++;
              if (fdp.ConsumeBool()) sink += view.is_time();
              if (view.as_time() && fdp.ConsumeBool()) sink++;
              if (fdp.ConsumeBool()) sink += view.is_date_time();
              if (view.as_date_time() && fdp.ConsumeBool()) sink++;
              
              if (auto val = view.as_string()) { if (fdp.ConsumeBool()) sink += val->is_string(); if (val->as_string() && fdp.ConsumeBool()) sink++; }
              if (auto val = view.as_integer()) { if (fdp.ConsumeBool()) sink += val->is_integer(); if (val->as_integer() && fdp.ConsumeBool()) sink++; }
              if (auto val = view.as_floating_point()) { if (fdp.ConsumeBool()) sink += val->is_floating_point(); if (val->as_floating_point() && fdp.ConsumeBool()) sink++; }
              if (auto val = view.as_boolean()) { if (fdp.ConsumeBool()) sink += val->is_boolean(); if (val->as_boolean() && fdp.ConsumeBool()) sink++; }
              if (auto val = view.as_date()) { if (fdp.ConsumeBool()) sink += val->is_date(); if (val->as_date() && fdp.ConsumeBool()) sink++; }
              if (auto val = view.as_time()) { if (fdp.ConsumeBool()) sink += val->is_time(); if (val->as_time() && fdp.ConsumeBool()) sink++; }
              if (auto val = view.as_date_time()) { if (fdp.ConsumeBool()) sink += val->is_date_time(); if (val->as_date_time() && fdp.ConsumeBool()) sink++; }

              if (auto d = view.as_date()) {
                if (!first_date) first_date.emplace(*d);
                else {
                    if (fdp.ConsumeBool()) sink += (*d == *first_date); if (fdp.ConsumeBool()) sink += (*d != *first_date);
                    if (fdp.ConsumeBool()) sink += (*d < *first_date); if (fdp.ConsumeBool()) sink += (*d <= *first_date);
                    if (fdp.ConsumeBool()) sink += (*d > *first_date); if (fdp.ConsumeBool()) sink += (*d >= *first_date);
                }
              }
              if (auto t = view.as_time()) {
                if (!first_time) first_time.emplace(*t);
                else {
                    if (fdp.ConsumeBool()) sink += (*t == *first_time); if (fdp.ConsumeBool()) sink += (*t != *first_time);
                    if (fdp.ConsumeBool()) sink += (*t < *first_time); if (fdp.ConsumeBool()) sink += (*t <= *first_time);
                    if (fdp.ConsumeBool()) sink += (*t > *first_time); if (fdp.ConsumeBool()) sink += (*t >= *first_time);
                }
              }
              if (auto dt = view.as_date_time()) {
                if (!first_date_time) first_date_time.emplace(*dt);
                else {
                    if (fdp.ConsumeBool()) sink += (*dt == *first_date_time); if (fdp.ConsumeBool()) sink += (*dt != *first_date_time);
                    if (fdp.ConsumeBool()) sink += (*dt < *first_date_time); if (fdp.ConsumeBool()) sink += (*dt <= *first_date_time);
                    if (fdp.ConsumeBool()) sink += (*dt > *first_date_time); if (fdp.ConsumeBool()) sink += (*dt >= *first_date_time);
                }
              }
          }
      }

      if (fdp.remaining_bytes() > 20) {
          try {
              toml::path p1(fdp.ConsumeRandomLengthString(8));
              toml::path p2(fdp.ConsumeRandomLengthString(8));
              if (fdp.ConsumeBool()) sink += (p1 == p2);
              if (fdp.ConsumeBool()) sink += (p1 != p2);
              p1.append(p2);
              if (fdp.ConsumeBool()) { auto p3 = p1 + p2; }
              p1 += p2;
              if (!p1.empty()) {
                (void)p1.subpath(0, 1);
                (void)p1.leaf(0);
                // The blocker is in `path::subpath` where `start >= end`.
                // This is triggered by calling the other `subpath` overload
                // with a length of 0.
                if (fdp.ConsumeBool()) {
                    size_t start_index = fdp.ConsumeIntegralInRange<size_t>(0, p1.size() - 1);
                    (void)p1.subpath(start_index, 0);
                }
              }
              p1.prepend(p2);
          } catch (...) {
          }
      }
      if (fdp.ConsumeBool()) {
          std::stringstream ss;
          ss << toml::value{fdp.ConsumeIntegral<int>()};
          ss << toml::value{fdp.ConsumeIntegral<unsigned short>()};
          ss << toml::value{fdp.ConsumeIntegral<long long>()};
          ss << toml::value{fdp.ConsumeFloatingPoint<float>()};
          ss << toml::value{fdp.ConsumeIntegral<signed char>()};
          ss << toml::value{fdp.ConsumeIntegral<short>()};
          ss << toml::value{fdp.ConsumeIntegral<unsigned long>()};
          ss << toml::value{fdp.ConsumeIntegral<unsigned long long>()};
      }
      if (fdp.ConsumeBool()) {
        toml::table t1;
        t1.insert("a", 1);
        toml::table t2;
        t2 = t1;
        t2 = std::move(t1);

        toml::array a1;
        a1.push_back(1);
        toml::array a2;
        a2 = a1;
        a2 = std::move(a1);

        toml::value<int64_t> v1(42);
        toml::value<int64_t> v2;
        v2 = v1;
        v2 = std::move(v1);
      }
    }
  } catch (const toml::parse_error &err) {
       std::stringstream ss;
       ss << err;
  }

  return 0;
}
