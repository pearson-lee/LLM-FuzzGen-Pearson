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

  std::string toml_string = fdp.ConsumeRandomLengthString(fdp.ConsumeIntegralInRange<size_t>(0, 1024));
  
  /*
   * ANALYSIS: The function-level coverage report showed that
   *           toml::v3::impl::impl_ex::parser::parse_literal_string and
   *           toml::v3::impl::impl_ex::parser::parse_basic_string had low
   *           branch coverage, especially for multi-line strings.
   *           The functions toml::v3::impl::impl_ex::parser::parse_inf_or_nan and
   *           toml::v3::impl::impl_ex::parser::parse_hex_float had low coverage.
   * IMPLEMENTATION: The following code block generates various TOML constructs
   *                 to exercise these uncovered code paths. This was present in the
   *                 original fuzzer but was not being executed according to the
   *                 coverage report. The conditional logic has been fixed.
   */
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

  /*
   * ANALYSIS: The function-level coverage report showed 0% coverage for functions
   *           in `date_time.hpp` and for `value<bool>`. This is because the fuzzer
   *           never generated TOML with boolean, date, or time types. The detailed
   *           fuzzer coverage report also showed the time comparison logic was never hit.
   * IMPLEMENTATION: The following code blocks add various boolean, date, and time
   *                 formats to the generated TOML string to exercise the parsing and
   *                 formatting logic for these uncovered types. A second time value
   *                 is added to ensure comparison operators are exercised.
   */
  if (fdp.ConsumeBool()) {
    toml_string += "\nbool1 = true\n";
  }
  if (fdp.ConsumeBool()) {
    toml_string += "\nld1 = 1979-05-27\n";
  }
  if (fdp.ConsumeBool()) {
    toml_string += "\nlt1 = 07:32:00\n";
    toml_string += "\nlt2 = 08:00:00\n"; // Add a second time to hit comparison logic.
  }
  if (fdp.ConsumeBool()) {
    toml_string += "\nldt1 = 1979-05-27T07:32:00\n";
  }
  if (fdp.ConsumeBool()) {
    toml_string += "\nodt1 = 1979-05-27T07:32:00-07:00\n";
  }


  /*
   * ANALYSIS: The detailed fuzz target coverage report showed that the code path for
   *           handling arrays (view.as_array()) was never taken. This resulted in 0%
   *           coverage for almost all functions in toml::v3::array. The function
   *           `array::flatten` also had low coverage because it was not being called
   *           on an array of arrays.
   * IMPLEMENTATION: The following code explicitly adds array, array-of-table, and
   *                 array-of-array constructs to the generated TOML string, ensuring
   *                 that the array-handling logic in the fuzzer is exercised and that
   *                 `flatten()` is called on a valid target.
   */
  if (fdp.ConsumeBool()) {
    toml_string += "\narr1 = [1, 2, 3]\n";
  }
  if (fdp.ConsumeBool()) {
    toml_string += "\n[[products]]\nname = \"Hammer\"\n\n[[products]]\nname = \"Nail\"\n";
  }
  if (fdp.ConsumeBool()) {
    toml_string += "\narr_of_arr = [[1, 2], [3, 4]]\n";
  }
  
  /*
   * ANALYSIS: The function `array::is_homogeneous` was completely uncovered. This function
   *           is used to check if all elements in an array are of the same type.
   * IMPLEMENTATION: The following code adds a heterogeneous array to the TOML string
   *                 to ensure the `is_homogeneous` function is called and returns false.
   */
  if (fdp.ConsumeBool()) {
    toml_string += "\narr_het = [1, \"two\", 3.0, true]\n";
  }

  /*
   * ANALYSIS: The function `parser::consume_rest_of_line` was uncovered. This function
   *           is likely called when the parser encounters invalid syntax and needs to skip
   *           to the next line.
   * IMPLEMENTATION: The following code adds a line with invalid syntax after a valid
   *                 key-value pair to trigger the `consume_rest_of_line` function.
   */
  if (fdp.ConsumeBool()) {
    toml_string += "\ninvalid_line = 100 garbage\n";
  }


  std::optional<toml::table> tbl;

  try {
    /*
     * ANALYSIS: The function-level coverage report showed 0% coverage for parsing
     *           from an istream (e.g., toml::v3::ex::parse(std::basic_istream&, ...)).
     * IMPLEMENTATION: Added a third parsing path that uses a std::stringstream to
     *                 create an istream from the fuzzed data, which is then passed
     *                 to toml::parse to cover the istream-based parsing functions.
     */
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
        std::stringstream ss(toml_string);
        tbl = toml::parse(ss);
    }

    if (tbl) {
       /*
       * ANALYSIS: The function-level coverage report showed 0% coverage for the
       *           equality operators (==, !=) for tables and arrays, specifically the
       *           inequality paths.
       * IMPLEMENTATION: The following block creates a copy of the parsed table,
       *                 modifies it slightly, and then compares it with the original.
       *                 This exercises the uncovered inequality-checking logic in
       *                 `table::equal` and `array::equal`.
       */
      if (fdp.ConsumeBool()) {
        toml::table tbl2 = *tbl;
        (void)(tbl2 == *tbl); // Test equality
        tbl2.insert("new_fuzzed_key", 42); // Modify the copy
        (void)(tbl2 != *tbl); // Test inequality
      }

      /*
       * ANALYSIS: The function-level coverage report showed that the toml::v3::toml_formatter,
       *           toml::v3::json_formatter, and toml::v3::yaml_formatter classes and their
       *           associated functions had 0% coverage.
       * IMPLEMENTATION: The following code blocks create instances of these formatters
       *                 and stream the parsed table to a stringstream to exercise the
       *                 formatting logic.
       */
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
        ss << toml::yaml_formatter{*tbl};
      }
      /*
       * ANALYSIS: The function `yaml_formatter::print_yaml_string` was uncovered. This
       *           function handles special string formatting for YAML. The original fuzzer
       *           passed a string with a newline, which caused the code to take a fallback
       *           path.
       * IMPLEMENTATION: This call specifically targets the multi-line block printing
       *                 logic by formatting a simple string value without any special
       *                 characters that would require escaping.
       */
      if (fdp.ConsumeBool()) {
        std::stringstream ss;
        ss << toml::yaml_formatter{toml::value{"a simple string"}};
      }
      
      /*
       * ANALYSIS: The `toml_formatter::print_inline` function had low coverage. This
       *           is responsible for printing tables in an inline format (e.g., `{ a = 1, b = 2 }`).
       * IMPLEMENTATION: The following code creates a simple table and formats it using
       *                 the `toml_formatter` to specifically exercise the inline printing logic.
       */
      if (fdp.ConsumeBool()) {
        toml::table inline_table;
        inline_table.insert("a", 1);
        inline_table.insert("b", "two");
        std::stringstream ss;
        ss << toml::toml_formatter{inline_table};
      }

      /*
       * ANALYSIS: The function-level coverage report showed that toml::v3::table::erase
       *           was uncovered.
       * IMPLEMENTATION: The following code block calls erase() on the parsed table
       *                 with a fuzzer-generated key to exercise this function.
       */
      if (fdp.ConsumeBool()) {
        tbl->erase(fdp.ConsumeRandomLengthString(10));
      }

      /*
       * ANALYSIS: The function-level coverage report showed that many methods of toml::v3::table,
       *           toml::v3::array, and toml::v3::node_view had 0% coverage, particularly
       *           functions for type checking (e.g., is_table()), access (e.g., as_string()),
       *           and manipulation (e.g., prune(), flatten()).
       * IMPLEMENTATION: The following code iterates through the parsed table, recursively
       *                 descends into sub-tables and arrays, and calls various methods
       *                 on the nodes to improve coverage.
       */
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

          (void)view.is_table();
          (void)view.is_array();
          (void)view.is_value();
          
          /*
           * ANALYSIS: The `is_homogeneous` method on arrays and tables was uncovered.
           * IMPLEMENTATION: Explicitly call `is_homogeneous` on tables and arrays
           *                 to improve coverage.
           */
          (void)view.is_homogeneous();
          (void)view.is_homogeneous(toml::node_type::array);


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
              /*
               * ANALYSIS: The function-level coverage report showed that array accessors
               *           like get() and at() were uncovered.
               * IMPLEMENTATION: Added calls to get() and at() with a fuzzer-controlled
               *                 index to exercise these functions. A try-catch block handles
               *                 out-of-bounds access for at().
               */
              if (!a->empty() && fdp.ConsumeBool()) {
                  size_t index = fdp.ConsumeIntegralInRange<size_t>(0, a->size() - 1);
                  (void)a->get(index);
                  try {
                      (void)a->at(index);
                  } catch (...) {}
              }
             /*
              * ANALYSIS: The function-level coverage report showed that many array
              *           manipulation functions like clear() and pop_back() were uncovered.
              * IMPLEMENTATION: The following code block explicitly calls these functions
              *                 on a newly created array to improve coverage.
              */
              if (fdp.ConsumeBool()) {
                toml::array new_arr;
                new_arr.push_back(1);
                new_arr.pop_back();
                new_arr.emplace_back(false);
                if (!new_arr.empty()) {
                  new_arr.truncate(1);
                  new_arr.shrink_to_fit();
                  new_arr.erase(new_arr.cbegin());
                }
                new_arr.insert(new_arr.cbegin(), 42);
                new_arr.clear();
              }
          } else if (view.is_value()) {
              /*
               * ANALYSIS: The function-level coverage report showed that numerous
               *           type-checking and value-retrieval functions on node_view
               *           were uncovered.
               * IMPLEMENTATION: The following block calls all is_* and as_* variants
               *                 to exercise these simple but uncovered functions.
               */
              (void)view.is_string();
              (void)view.as_string();
              (void)view.is_integer();
              (void)view.as_integer();
              (void)view.is_floating_point();
              (void)view.as_floating_point();
              (void)view.is_boolean();
              (void)view.as_boolean();
              (void)view.is_date();
              (void)view.as_date();
              (void)view.is_time();
              (void)view.as_time();
              (void)view.is_date_time();
              (void)view.as_date_time();
              
              /*
               * ANALYSIS: The function-level coverage report showed that the `is_...` and `as_...`
               *           methods on the concrete `toml::value<T>` types were completely uncovered.
               * IMPLEMENTATION: The following code checks the type of the value and then calls
               *                 the corresponding methods on the concrete `toml::value` object.
               */
              if (auto val = view.as_string()) { (void)val->is_string(); (void)val->as_string(); }
              if (auto val = view.as_integer()) { (void)val->is_integer(); (void)val->as_integer(); }
              if (auto val = view.as_floating_point()) { (void)val->is_floating_point(); (void)val->as_floating_point(); }
              if (auto val = view.as_boolean()) { (void)val->is_boolean(); (void)val->as_boolean(); }
              if (auto val = view.as_date()) { (void)val->is_date(); (void)val->as_date(); }
              if (auto val = view.as_time()) { (void)val->is_time(); (void)val->as_time(); }
              if (auto val = view.as_date_time()) { (void)val->is_date_time(); (void)val->as_date_time(); }

              /*
               * ANALYSIS: The function-level coverage report showed 0% coverage for
               *           the comparison operators in `date_time.hpp`.
               * IMPLEMENTATION: The following code captures the first date/time values
               *                 found and compares them with subsequent ones to exercise
               *                 the uncovered comparison logic.
               */
              if (auto d = view.as_date()) {
                if (!first_date) first_date.emplace(*d);
                else {
                    (void)(*d == *first_date); (void)(*d != *first_date);
                    (void)(*d < *first_date); (void)(*d <= *first_date);
                    (void)(*d > *first_date); (void)(*d >= *first_date);
                }
              }
              if (auto t = view.as_time()) {
                if (!first_time) first_time.emplace(*t);
                else {
                    (void)(*t == *first_time); (void)(*t != *first_time);
                    (void)(*t < *first_time); (void)(*t <= *first_time);
                    (void)(*t > *first_time); (void)(*t >= *first_time);
                }
              }
              if (auto dt = view.as_date_time()) {
                if (!first_date_time) first_date_time.emplace(*dt);
                else {
                    (void)(*dt == *first_date_time); (void)(*dt != *first_date_time);
                    (void)(*dt < *first_date_time); (void)(*dt <= *first_date_time);
                    (void)(*dt > *first_date_time); (void)(*dt >= *first_date_time);
                }
              }
          }
      }

      /*
       * ANALYSIS: The function-level coverage report indicated that functions related
       *           to `toml::v3::path` were completely uncovered.
       * IMPLEMENTATION: The following block exercises various path manipulation functions
       *                 like `pop_back`, `clear`, `truncate`, `assign`, and `append`
       *                 to improve coverage of the path API.
       */
      if (fdp.remaining_bytes() > 0) {
          std::string path_str = fdp.ConsumeRandomLengthString(16);
          try {
              (void)tbl->at_path(path_str);
              toml::path p1(path_str);
              if (!p1.empty()) p1 = p1.parent();
              (void)p1.parent();
              if (fdp.ConsumeBool()) {
                toml::path p2(fdp.ConsumeRandomLengthString(8));
                (void)(p1 == p2);
                (void)(p1 != p2);
                p1.append(p2);
              }
              (void)tbl->at_path(p1);
              p1.clear();
              p1.assign(path_str);
              if (!p1.empty()) p1.truncate(1);
          } catch (...) {
              // Errors are expected with random paths.
          }
      }
      /*
       * ANALYSIS: The coverage report for `print_to_stream.inl` shows that template
       *           specializations for various integer and float types are uncovered.
       * IMPLEMENTATION: The following block explicitly creates and streams values
       *                 of these specific types to exercise the corresponding
       *                 `print_integer_to_stream` and `print_floating_point_to_stream`
       *                 functions.
       */
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
      /*
       * ANALYSIS: The function-level coverage report showed that the assignment
       *           operators for `toml::node` were completely uncovered.
       * IMPLEMENTATION: The following code block exercises the copy and move
       *                 assignment operators for the concrete node types (`table`,
       *                 `array`, `value`) to trigger the uncovered `node::operator=`
       *                 functions. A direct instantiation of `toml::node` is not
       *                 possible since it is an abstract class.
       */
      if (fdp.ConsumeBool()) {
        // Test table assignment
        toml::table t1;
        t1.insert("a", 1);
        toml::table t2;
        t2 = t1; // copy-assignment
        t2 = std::move(t1); // move-assignment

        // Test array assignment
        toml::array a1;
        a1.push_back(1);
        toml::array a2;
        a2 = a1; // copy-assignment
        a2 = std::move(a1); // move-assignment

        // Test value assignment
        toml::value<int64_t> v1(42);
        toml::value<int64_t> v2;
        v2 = v1; // copy-assignment
        v2 = std::move(v1); // move-assignment
      }
    }
  } catch (const toml::parse_error &err) {
      /*
       * ANALYSIS: The `parse_error` exception class and its methods were uncovered.
       * IMPLEMENTATION: Catching the `parse_error` and streaming it exercises
       *                 the `description()` and `source()` methods, as well as the
       *                 stream insertion operator.
       */
       std::stringstream ss;
       ss << err;
  }

  return 0;
}