#include "/src/tomlplusplus/include/toml++/toml.h"
#include <fuzzer/FuzzedDataProvider.h>
#include <string>
#include <sstream>
#include <vector>
#include <iterator> // For std::advance, std::next
#include <algorithm> // For std::min, std::max if needed
#include <stdexcept> // For std::out_of_range, std::runtime_error
#include <iostream>  // For std::ostringstream (though sstream usually brings it)


extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  FuzzedDataProvider data_provider(data, size);

  toml::table tbl;
  std::string toml_data_str = data_provider.ConsumeRandomLengthString(1024);
  bool parsed_successfully = false;

  try {
    tbl = toml::parse(toml_data_str);
    parsed_successfully = true;
  } catch (const toml::ex::parse_error &e) { 
    // Parsing failed, tbl remains default-constructed (empty).
    // Coverage for toml::ex::parse_error::description(), source(), and operator<<
    std::string error_desc = e.description().data(); 
    const toml::source_region& error_src = e.source(); 
    (void)error_desc; 
    (void)error_src;  
    std::ostringstream err_oss;
    err_oss << e;
    std::string err_str = err_oss.str();
    (void)err_str; 
  } catch (const std::exception & /*e*/) {
    // Catch any other std::exception during parsing
  }

  // 1. Exercise toml::table::erase(string_view) - Existing
  if (!tbl.empty() && data_provider.ConsumeBool()) {
    std::string key_to_erase = data_provider.ConsumeRandomLengthString(32);
    try {
      tbl.erase(key_to_erase); 
    } catch (const std::exception &) {
      // Catch any unexpected errors.
    }
  }

  // 2. Exercise toml::path::subpath(const_iterator, const_iterator) - Existing
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

  // 3. Exercise toml::at_path(node&, const path&) and toml::at_path(node&, string_view) - Existing
  // Also adding node::at_path coverage
  if (data_provider.ConsumeBool()) {
    toml::path path_obj_for_at(data_provider.ConsumeRandomLengthString(64));
    try {
      toml::node_view<toml::node> nv = toml::at_path(tbl, path_obj_for_at);
      if (nv && nv.is_string() && data_provider.ConsumeBool()) {
        auto val = nv.value<std::string>();
      }
      // Coverage for node::at_path(path)
      if (parsed_successfully && !tbl.empty() && nv) { // nv must be valid to call its methods
         if(nv.is_table() || nv.is_array()){ // Only call at_path on container nodes
            (void)nv.node()->at_path(data_provider.ConsumeRandomLengthString(10));
         }
      }
    } catch (const std::out_of_range &) {
    } catch (const std::exception &) { 
    }
  }

  if (data_provider.ConsumeBool()) {
    std::string path_str_for_at = data_provider.ConsumeRandomLengthString(64);
    try {
      toml::node_view<toml::node> nv_sv = toml::at_path(tbl, path_str_for_at);
      if (nv_sv && nv_sv.is_integer() && data_provider.ConsumeBool()) {
        auto val = nv_sv.value<int64_t>();
      }
      // Coverage for node::at_path(string_view)
      if (parsed_successfully && !tbl.empty() && nv_sv) { // nv_sv must be valid
         if(nv_sv.is_table() || nv_sv.is_array()){ // Only call at_path on container nodes
            (void)nv_sv.node()->at_path(data_provider.ConsumeRandomLengthString(10));
         }
      }
    } catch (const std::out_of_range &) {
    } catch (const std::exception &) { 
    }
  }
  
  // Coverage for const free function overloads of toml::at_path
  if (parsed_successfully && data_provider.ConsumeBool()) {
    const toml::table& const_tbl = tbl;
    toml::path path_obj_for_const_at(data_provider.ConsumeRandomLengthString(64));
    std::string path_str_for_const_at = data_provider.ConsumeRandomLengthString(64);
    try {
        (void)toml::at_path(const_tbl, path_obj_for_const_at);
        (void)toml::at_path(const_tbl, path_str_for_const_at);
    } catch (const std::out_of_range &) {
    } catch (const std::exception &) {}
  }


  // 4. Exercise toml::array::flatten() - Existing
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
    } catch (const std::exception &) { 
    }
  }

  // 5. Exercise toml::json_formatter (via operator<<) - Existing
  if (parsed_successfully || data_provider.ConsumeBool()) { 
    try {
      std::ostringstream oss_json;
      toml::json_formatter formatter{tbl};
      oss_json << formatter;
      std::string json_output = oss_json.str();
    } catch (const std::exception &) {
    }
  }

  // 6. Enhanced toml::array exercising
  if (data_provider.ConsumeBool()) {
    toml::array arr;
    // Case 1: Empty array for is_homogeneous branch
    if (data_provider.ConsumeBool()) {
        arr.is_homogeneous(toml::node_type::none); // Branch: elems_.empty() == true
        arr.is_homogeneous(toml::node_type::integer);
    }

    int num_elements = data_provider.ConsumeIntegralInRange<int>(0, 3);
    bool make_homogeneous = data_provider.ConsumeBool();
    int64_t homo_int_val = data_provider.ConsumeIntegral<int64_t>();
    std::string homo_str_val = data_provider.ConsumeRandomLengthString(5);

    for (int i = 0; i < num_elements; ++i) {
        if (make_homogeneous) {
            if (data_provider.ConsumeBool()) arr.push_back(homo_int_val);
            else arr.push_back(homo_str_val); // Will be homogeneous if only one type is chosen by outer bool
        } else { // Non-homogeneous
             uint8_t type_choice = data_provider.ConsumeIntegralInRange<uint8_t>(0, 1);
             if (type_choice == 0) arr.push_back(data_provider.ConsumeIntegral<int64_t>());
             else arr.push_back(data_provider.ConsumeRandomLengthString(5));
        }
    }
    
    // Coverage for: is_homogeneous branches
    arr.is_homogeneous(toml::node_type::none);    // Branch: ntype == node_type::none
    arr.is_homogeneous(toml::node_type::integer); // Branch: loop and type matching/mismatching
    arr.is_homogeneous(toml::node_type::string);

    // Coverage for: get(idx) branches
    if (!arr.empty()) {
        (void)arr.get(0); // Branch: index < elems_.size() == true
    }
    (void)arr.get(arr.size()); // Branch: index < elems_.size() == false (for non-empty); also for empty

    // Coverage for: at(idx)
    if (!arr.empty()) {
        try { (void)arr.at(0); } catch (const std::out_of_range&) {}
    }
    try { (void)arr.at(arr.size()); } catch (const std::out_of_range&) {} // Exception for out of bounds

    // Coverage for: operator<<(ostream, array)
    std::ostringstream arr_oss;
    arr_oss << arr;
    (void)arr_oss.str();
  }

  // 7. Enhanced toml::table exercising
  if (parsed_successfully || data_provider.ConsumeBool()) {
    std::string key1 = data_provider.ConsumeRandomLengthString(10);
    std::string key_non_existent = data_provider.ConsumeRandomLengthString(10) + "_ne";

    if (data_provider.ConsumeBool() && !key1.empty()) {
        tbl.insert_or_assign(key1, data_provider.ConsumeIntegral<int64_t>());
    }

    // Coverage for: tbl.contains(key)
    if (!key1.empty()) { (void)tbl.contains(key1); }
    (void)tbl.contains(key_non_existent);

    // Coverage for: tbl.at(key)
    if (!key1.empty() && tbl.contains(key1)) {
        try { (void)tbl.at(key1); } catch (const std::out_of_range&) {}
    }
    try { (void)tbl.at(key_non_existent); } catch (const std::out_of_range&) {}
    
    // Coverage for: operator<<(ostream, table)
    std::ostringstream tbl_oss;
    tbl_oss << tbl;
    (void)tbl_oss.str();
  }

  return 0;
}