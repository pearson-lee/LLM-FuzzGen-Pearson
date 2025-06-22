#include "/src/tomlplusplus/include/toml++/toml.h"
#include <fuzzer/FuzzedDataProvider.h>
#include <string>
#include <sstream>
#include <vector>
#include <iterator> // For std::advance, std::next
#include <algorithm> // For std::min, std::max if needed
#include <stdexcept> // For std::out_of_range, std::runtime_error


extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  FuzzedDataProvider data_provider(data, size);

  toml::table tbl;
  std::string toml_data_str = data_provider.ConsumeRandomLengthString(1024);
  bool parsed_successfully = false;

  try {
    tbl = toml::parse(toml_data_str);
    parsed_successfully = true;
  } catch (const toml::ex::parse_error & /*e*/) { 
    // Parsing failed, tbl remains default-constructed (empty).
  } catch (const std::exception & /*e*/) {
    // Catch any other std::exception during parsing
  }

  // 1. Exercise toml::table::erase(string_view)
  if (!tbl.empty() && data_provider.ConsumeBool()) {
    std::string key_to_erase = data_provider.ConsumeRandomLengthString(32);
    try {
      tbl.erase(key_to_erase); 
    } catch (const std::exception &) {
      // Catch any unexpected errors.
    }
  }

  // 2. Exercise toml::path::subpath(const_iterator, const_iterator)
  toml::path p_for_subpath(data_provider.ConsumeRandomLengthString(64));
  if (!p_for_subpath.empty() && data_provider.ConsumeBool()) {
    size_t path_size = p_for_subpath.size();
    size_t start_offset = data_provider.ConsumeIntegralInRange<size_t>(0, path_size);
    size_t end_offset = data_provider.ConsumeIntegralInRange<size_t>(start_offset, path_size);

    auto sub_start_it = p_for_subpath.begin();
    std::advance(sub_start_it, start_offset);

    auto sub_end_it = p_for_subpath.begin();
    std::advance(sub_end_it, end_offset);
    
    try {
      toml::path sub_p = p_for_subpath.subpath(sub_start_it, sub_end_it);
    } catch (const std::exception &) {
      // Catch potential exceptions.
    }
  }

  // 3. Exercise toml::at_path(node&, const path&) and toml::at_path(node&, string_view)
  if (data_provider.ConsumeBool()) {
    toml::path path_obj_for_at(data_provider.ConsumeRandomLengthString(64));
    try {
      toml::node_view<toml::node> nv = toml::at_path(tbl, path_obj_for_at);
      if (nv && nv.is_string() && data_provider.ConsumeBool()) {
        auto val = nv.value<std::string>();
      }
    } catch (const std::out_of_range &) {
    } catch (const std::exception &) { // Broadened catch
    }
  }

  if (data_provider.ConsumeBool()) {
    std::string path_str_for_at = data_provider.ConsumeRandomLengthString(64);
    try {
      toml::node_view<toml::node> nv_sv = toml::at_path(tbl, path_str_for_at);
      if (nv_sv && nv_sv.is_integer() && data_provider.ConsumeBool()) {
        auto val = nv_sv.value<int64_t>();
      }
    } catch (const std::out_of_range &) {
    } catch (const std::exception &) { // Broadened catch
    }
  }

  // 4. Exercise toml::array::flatten()
  toml::array array_for_flattening;
  int num_outer_elements = data_provider.ConsumeIntegralInRange<int>(0, 3);
  for (int i = 0; i < num_outer_elements; ++i) {
    if (data_provider.ConsumeBool()) { 
      toml::array sub_array;
      int num_inner_elements = data_provider.ConsumeIntegralInRange<int>(0, 2);
      for (int j = 0; j < num_inner_elements; ++j) {
        uint8_t type_choice = data_provider.ConsumeIntegralInRange<uint8_t>(0, 3);
        if (type_choice == 0) sub_array.push_back(data_provider.ConsumeIntegral<int64_t>());
        else if (type_choice == 1) sub_array.push_back(data_provider.ConsumeRandomLengthString(5));
        else if (type_choice == 2) sub_array.push_back(data_provider.ConsumeBool());
        else sub_array.push_back(data_provider.ConsumeFloatingPoint<double>());
      }
      array_for_flattening.push_back(sub_array);
    } else { 
      array_for_flattening.push_back(data_provider.ConsumeIntegral<int64_t>());
    }
  }

  if (!array_for_flattening.empty()) {
    try {
      array_for_flattening.flatten();
    } catch (const std::exception &) { // Broadened catch
    }
  }

  // 5. Exercise toml::json_formatter (via operator<<)
  if (parsed_successfully || data_provider.ConsumeBool()) { 
    try {
      std::ostringstream oss_json;
      toml::json_formatter formatter{tbl};
      oss_json << formatter;
      std::string json_output = oss_json.str();
    } catch (const std::exception &) {
    }
  }
  return 0;
}