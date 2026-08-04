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


  std::optional<toml::table> tbl;

  try {
    if (fdp.ConsumeBool()) {
      tbl = toml::parse(toml_string);
    } else {
      std::string path = std::string("/tmp/") + _FUZZ_TARGET_NAME + ".tmp";
      std::ofstream out(path);
      out << toml_string;
      out.close();
      tbl = toml::parse_file(path);
      unlink(path.c_str());
    }

    if (tbl) {
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
      while (!nodes.empty() && fdp.remaining_bytes() > 2) {
          toml::node* n = nodes.back();
          nodes.pop_back();
          if (!n) continue;

          toml::node_view view{n};

          (void)view.is_table();
          (void)view.is_array();
          (void)view.is_value();

          if (auto t = view.as_table()) {
              for (auto&& [k, v] : *t) {
                  nodes.push_back(&v);
              }
              if (fdp.ConsumeBool()) {
                  t->prune(fdp.ConsumeBool());
              }
          } else if (auto a = view.as_array()) {
              for (auto&& v : *a) {
                  nodes.push_back(&v);
              }
              if (fdp.ConsumeBool()) {
                  a->prune(fdp.ConsumeBool());
              }
              if (fdp.ConsumeBool()) {
                  a->flatten();
              }
          } else if (view.is_value()) {
              (void)view.is_string();
              (void)view.is_integer();
              (void)view.is_floating_point();
              (void)view.is_boolean();
              (void)view.is_date();
              (void)view.is_time();
              (void)view.is_date_time();
          }
      }

      /*
       * ANALYSIS: The function-level coverage report indicated that functions related
       *           to `toml::v3::path` were completely uncovered.
       * IMPLEMENTATION: The following block generates a random path string and uses
       *                 the `at_path` method to exercise the path-parsing and node-retrieval
       *                 logic.
       */
      if (fdp.remaining_bytes() > 0) {
          std::string path_str = fdp.ConsumeRandomLengthString(16);
          try {
              (void)tbl->at_path(path_str);
          } catch (...) {
              // Errors are expected with random paths.
          }
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