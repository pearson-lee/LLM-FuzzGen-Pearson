#include "/src/tomlplusplus/include/toml++/toml.h"
#include <fuzzer/FuzzedDataProvider.h>
#include <string>
#include <sstream>
#include <vector>
#include <iterator> // For std::advance, std::next
#include <algorithm> // For std::min, std::max if needed
#include <stdexcept> // For std::out_of_range, std::runtime_error
#include <iostream>  // For std::ostringstream (though sstream usually brings it)
#include <optional>  // For std::optional
#include <memory>    // For std::make_shared

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  FuzzedDataProvider data_provider(data, size);

  toml::table tbl;
  std::string toml_data_str = data_provider.ConsumeRandomLengthString(1024);
  bool parsed_successfully = false;

  try {
    tbl = toml::parse(toml_data_str);
    parsed_successfully = true;
  } catch (const toml::ex::parse_error &e) { 
    std::string error_desc = e.description().data(); 
    const toml::source_region& error_src = e.source(); 
    (void)error_desc; 
    // Coverage for source_position and source_region operators
    if (error_src.begin) { // Test operator bool for source_position
        toml::source_position pos_cmp = {error_src.begin.line + data_provider.ConsumeIntegralInRange<uint32_t>(0,1), error_src.begin.column + data_provider.ConsumeIntegralInRange<uint32_t>(0,1)};
        (void)(error_src.begin == pos_cmp);
        (void)(error_src.begin != pos_cmp);
        (void)(error_src.begin < pos_cmp);
        (void)(error_src.begin <= pos_cmp);
        (void)(error_src.begin > pos_cmp);
        (void)(error_src.begin >= pos_cmp);
        std::ostringstream pos_oss; pos_oss << error_src.begin; (void)pos_oss.str(); // operator<< for source_position
    }
    toml::source_region src_assign_dest;
    src_assign_dest = error_src; // Test source_region::operator=
    std::ostringstream sr_oss; sr_oss << src_assign_dest; (void)sr_oss.str(); // operator<< for source_region
    
    std::ostringstream err_oss;
    err_oss << e; // This also uses source_region printing
    std::string err_str = err_oss.str();
    (void)err_str; 
  } catch (const std::exception & /*e*/) {
  }

  // Coverage for toml::get_line
  if (!toml_data_str.empty() && data_provider.ConsumeBool()) {
    (void)toml::get_line(toml_data_str, data_provider.ConsumeIntegralInRange<unsigned int>(0, 5)); // line 0 is invalid
    (void)toml::get_line(toml_data_str, data_provider.ConsumeIntegralInRange<unsigned int>(1, 5)); // valid lines
  }

  // 1. Exercise toml::table::erase(string_view) - Existing
  if (!tbl.empty() && data_provider.ConsumeBool()) {
    std::string key_to_erase = data_provider.ConsumeRandomLengthString(32);
    try {
      tbl.erase(key_to_erase); 
    } catch (const std::exception &) {
    }
  }

  // 2. Exercise toml::path::subpath(const_iterator, const_iterator) - Existing
  // Enhanced toml::path and toml::path_component exercising
  std::string p_str1_for_subpath = data_provider.ConsumeRandomLengthString(32);
  toml::path p_for_subpath(p_str1_for_subpath);
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
    }
  }
  // Further path and path_component coverage
  if (data_provider.ConsumeBool()) {
      std::string p_str_ops1 = data_provider.ConsumeRandomLengthString(32);
      std::string p_str_ops2 = data_provider.ConsumeRandomLengthString(32);
      toml::path path_ops1(p_str_ops1);
      toml::path path_ops2(p_str_ops2);

      (void)path_ops1.empty(); // operator bool
      if (!path_ops1.empty()) {
          (void)path_ops1[0]; // Coverage for path::operator[]
          (void)static_cast<const toml::path&>(path_ops1)[0]; // Coverage for path::operator[] const
          toml::path_component pc_ops = path_ops1[0];
          if (pc_ops.type() == toml::path_component_type::key) (void)pc_ops.key(); else (void)pc_ops.index();
          // Test path_component assignment and conversions
          if (data_provider.ConsumeBool()) {
              toml::path_component pc_assign_ops;
              if (data_provider.ConsumeBool()) pc_assign_ops = data_provider.ConsumeRandomLengthString(5); // assign string_view
              else pc_assign_ops = data_provider.ConsumeIntegralInRange<size_t>(0,5); // assign index
              
              if (data_provider.ConsumeBool()) pc_assign_ops = pc_ops; // copy assign
              else {
                  toml::path_component pc_move_src_ops;
                  if (pc_ops.type() == toml::path_component_type::key) pc_move_src_ops = pc_ops.key(); else pc_move_src_ops = pc_ops.index();
                  pc_assign_ops = std::move(pc_move_src_ops); // move assign
              }
              (void)(pc_assign_ops.type() == toml::path_component_type::key); (void)(pc_assign_ops.type() == toml::path_component_type::array_index);
              if (pc_assign_ops.type() == toml::path_component_type::key) { (void)static_cast<const std::string&>(pc_assign_ops); } 
              else { (void)static_cast<size_t>(pc_assign_ops); }
          }
      }
      
      toml::path path_copy_assign_ops; path_copy_assign_ops.assign(path_ops1); // Coverage for path::assign
      toml::path path_move_assign_ops; path_move_assign_ops.assign(std::move(path_ops2)); 
      toml::path path_sv_assign_ops; path_sv_assign_ops.assign(data_provider.ConsumeRandomLengthString(10));

      path_ops1.append(data_provider.ConsumeRandomLengthString(10)); // Coverage for path::append
      toml::path path_to_append_ops(data_provider.ConsumeRandomLengthString(5));
      path_ops1.append(path_to_append_ops);
      path_ops1.append(std::move(path_to_append_ops)); 

      path_ops1.prepend(data_provider.ConsumeRandomLengthString(10)); // Coverage for path::prepend
      toml::path path_to_prepend_ops(data_provider.ConsumeRandomLengthString(5));
      path_ops1.prepend(path_to_prepend_ops);
      path_ops1.prepend(std::move(path_to_prepend_ops));

      (void)(path_ops1 + path_copy_assign_ops); // Coverage for path operators
      (void)(path_ops1 + std::string_view("sv_path"));
      (void)(std::string_view("sv_path_prefix") + path_ops1);

      std::ostringstream path_oss_ops; path_oss_ops << path_ops1; (void)path_oss_ops.str(); // Coverage for path operator<<
      std::string path_as_std_string_ops = static_cast<std::string>(path_ops1); // Coverage for path conversion to string

      (void)(path_ops1 == path_copy_assign_ops); (void)(path_ops1 != path_copy_assign_ops);
      (void)(path_ops1 == std::string_view("test.path")); (void)(std::string_view("test.path") == path_ops1);
      (void)(path_ops1 != std::string_view("test.path")); (void)(std::string_view("test.path") != path_ops1);

      if (!path_ops1.empty()) {
          (void)path_ops1.cbegin(); (void)path_ops1.cend(); // Coverage for path iterators
          (void)path_ops1.subpath(0, data_provider.ConsumeIntegralInRange<size_t>(0, path_ops1.size())); // Coverage for subpath by index
          (void)path_ops1.parent(); // Coverage for path::parent
          (void)path_ops1.leaf(data_provider.ConsumeIntegralInRange<size_t>(0, path_ops1.size() + 1)); // Coverage for path::leaf
          (void)path_ops1.truncated(data_provider.ConsumeIntegralInRange<size_t>(0, path_ops1.size() + 1)); // Coverage for path::truncated
      }
      path_ops1.clear(); // Coverage for path::clear
      
      // Coverage for toml::path constructor with very long string to potentially trigger length_error
      if (data_provider.ConsumeBool()) {
        try {
            std::string long_path_str_ops; 
            size_t num_segments = data_provider.ConsumeIntegralInRange<size_t>(100, 200); // Moderately many segments
            for (size_t i = 0; i < num_segments; ++i) {
                long_path_str_ops += data_provider.ConsumeRandomLengthString(data_provider.ConsumeIntegralInRange<size_t>(5,10));
                if (i < num_segments - 1) long_path_str_ops += ".";
            }
            toml::path long_p_ops(long_path_str_ops);
        } catch (const std::length_error&) { /* caught */ } 
          catch (const std::exception&) { /* other */ }
      }
  }


  // 3. Exercise toml::at_path(node&, const path&) and toml::at_path(node&, string_view) - Existing
  if (data_provider.ConsumeBool()) {
    toml::path path_obj_for_at(data_provider.ConsumeRandomLengthString(64));
    try {
      toml::node_view<toml::node> nv = toml::at_path(tbl, path_obj_for_at);
      if (nv && nv.is_string() && data_provider.ConsumeBool()) {
        auto val = nv.value<std::string>();
      }
      if (parsed_successfully && !tbl.empty() && nv) { 
         if(nv.is_table() || nv.is_array()){ 
            if (nv.node()) 
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
      if (parsed_successfully && !tbl.empty() && nv_sv) { 
         if(nv_sv.is_table() || nv_sv.is_array()){
            if (nv_sv.node()) 
                (void)nv_sv.node()->at_path(data_provider.ConsumeRandomLengthString(10));
         }
      }
    } catch (const std::out_of_range &) {
    } catch (const std::exception &) { 
    }
  }
  
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
      array_for_flattening.flatten(); // Coverage for lvalue flatten
      if (data_provider.ConsumeBool()) { // Coverage for rvalue flatten
          toml::array temp_flatten_arr = array_for_flattening; 
          std::move(temp_flatten_arr).flatten(); 
      }
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
    toml::node* first_nonmatch_node = nullptr; 
    const toml::node* const_first_nonmatch_node = nullptr; 

    if (data_provider.ConsumeBool()) { 
        (void)arr.is_homogeneous(toml::node_type::none); 
        (void)arr.is_homogeneous(toml::node_type::integer);
        (void)arr.is_homogeneous(toml::node_type::string, first_nonmatch_node); 
        const toml::array& const_empty_arr = arr;
        (void)const_empty_arr.is_homogeneous(toml::node_type::string, const_first_nonmatch_node); 
    }

    int num_elements = data_provider.ConsumeIntegralInRange<int>(0, 3);
    bool make_homogeneous = data_provider.ConsumeBool();
    int64_t homo_int_val = data_provider.ConsumeIntegral<int64_t>();
    std::string homo_str_val = data_provider.ConsumeRandomLengthString(5);

    for (int i = 0; i < num_elements; ++i) {
        if (make_homogeneous) {
            if (data_provider.ConsumeBool()) arr.push_back(homo_int_val);
            else arr.push_back(homo_str_val); 
        } else { 
             uint8_t type_choice = data_provider.ConsumeIntegralInRange<uint8_t>(0, 1);
             if (type_choice == 0) arr.push_back(data_provider.ConsumeIntegral<int64_t>());
             else arr.push_back(data_provider.ConsumeRandomLengthString(5));
        }
    }
    
    (void)arr.is_homogeneous(toml::node_type::none);   
    (void)arr.is_homogeneous(toml::node_type::integer); 
    (void)arr.is_homogeneous(toml::node_type::string);

    (void)arr.is_homogeneous(toml::node_type::integer, first_nonmatch_node); 
    (void)arr.is_homogeneous(toml::node_type::none, first_nonmatch_node);    
    if (data_provider.ConsumeBool()) { 
        toml::array non_homo_arr_for_test;
        non_homo_arr_for_test.push_back(10);
        non_homo_arr_for_test.push_back("test_str");
        (void)non_homo_arr_for_test.is_homogeneous(toml::node_type::integer, first_nonmatch_node); 
    }
    const toml::array& const_arr_ref = arr; // Used throughout this section
    (void)const_arr_ref.is_homogeneous(toml::node_type::string, const_first_nonmatch_node); 

    // Coverage for get and at (const and non-const, true and false branches)
    if (!arr.empty()) {
        (void)arr.get(0); 
        (void)const_arr_ref.get(0); 
        try { (void)arr.at(0); } catch (const std::out_of_range&) {}
        try { (void)const_arr_ref.at(0); } catch (const std::out_of_range&) {}
    }
    (void)arr.get(arr.size()); 
    (void)const_arr_ref.get(arr.size());
    try { (void)arr.at(arr.size()); } catch (const std::out_of_range&) {} 
    try { (void)const_arr_ref.at(arr.size()); } catch (const std::out_of_range&) {}

    std::ostringstream arr_oss;
    arr_oss << arr;
    (void)arr_oss.str();

    if (!arr.empty()) {
        (void)arr.front(); 
        (void)arr.back();  
        (void)const_arr_ref.front(); 
        (void)const_arr_ref.back();  
        (void)arr[0];      
        (void)const_arr_ref[0]; // Coverage for const operator[]
    }
    
    // Coverage for iterators
    (void)arr.begin(); (void)arr.end();
    (void)const_arr_ref.begin(); (void)const_arr_ref.end();
    (void)arr.cbegin(); (void)arr.cend(); // Coverage for cbegin/cend
    (void)const_arr_ref.cbegin(); (void)const_arr_ref.cend();


    if (!arr.empty() && data_provider.ConsumeBool()) {
        arr.pop_back(); 
    }
    if (data_provider.ConsumeBool()) {
        arr.clear();    
    }
    
    if (data_provider.ConsumeBool()) {
        toml::array arr_assign_source;
        arr_assign_source.push_back(data_provider.ConsumeIntegral<int>());
        toml::array arr_assigned_copy;
        arr_assigned_copy = arr_assign_source; 
        toml::array arr_assigned_move;
        arr_assigned_move = std::move(arr_assign_source); 
    }

    if (data_provider.ConsumeBool()) {
        toml::array arr_cmp1, arr_cmp2;
        if (data_provider.ConsumeBool()) arr_cmp1.push_back(1); else arr_cmp1.push_back("a");
        if (data_provider.ConsumeBool()) arr_cmp2.push_back(1); else arr_cmp2.push_back("a");
        if (data_provider.ConsumeBool()) arr_cmp1.push_back(2.0);
        // Coverage for array::equal lambda specializations
        if (data_provider.ConsumeBool()) { toml::table t_cmp; t_cmp.insert("x",1); arr_cmp1.push_back(t_cmp); if (data_provider.ConsumeBool()) arr_cmp2.push_back(t_cmp); }
        if (data_provider.ConsumeBool()) { toml::array a_cmp; a_cmp.push_back(true); arr_cmp1.push_back(a_cmp); if (data_provider.ConsumeBool()) arr_cmp2.push_back(a_cmp); }

        (void)(arr_cmp1 == arr_cmp2); 
        (void)(arr_cmp1 != arr_cmp2); 
    }
    // Explicitly call all is_X/as_X for array and const array
    (void)arr.is_table(); (void)arr.is_array(); (void)arr.is_value();
    (void)arr.is_string(); (void)arr.is_integer(); (void)arr.is_floating_point(); (void)arr.is_number();
    (void)arr.is_boolean(); (void)arr.is_date(); (void)arr.is_time(); (void)arr.is_date_time();
    (void)arr.as_table(); (void)arr.as_string(); (void)arr.as_integer(); (void)arr.as_floating_point();
    (void)arr.as_boolean(); (void)arr.as_date(); (void)arr.as_time(); (void)arr.as_date_time();

    (void)const_arr_ref.is_table(); (void)const_arr_ref.is_array(); (void)const_arr_ref.is_value();
    (void)const_arr_ref.is_string(); (void)const_arr_ref.is_integer(); (void)const_arr_ref.is_floating_point(); (void)const_arr_ref.is_number();
    (void)const_arr_ref.is_boolean(); (void)const_arr_ref.is_date(); (void)const_arr_ref.is_time(); (void)const_arr_ref.is_date_time();
    (void)const_arr_ref.as_table(); (void)const_arr_ref.as_string(); (void)const_arr_ref.as_integer(); (void)const_arr_ref.as_floating_point();
    (void)const_arr_ref.as_boolean(); (void)const_arr_ref.as_date(); (void)const_arr_ref.as_time(); (void)const_arr_ref.as_date_time();

    // Coverage for other array methods
    (void)arr.max_size();
    arr.shrink_to_fit();
    arr.truncate(data_provider.ConsumeIntegralInRange<size_t>(0, arr.size() + 1)); // Test with new_size >= current size too
    if (!arr.empty() && data_provider.ConsumeBool()) {
        arr.erase(arr.cbegin()); // Use const_iterator version
    }
    if (arr.size() > 1 && data_provider.ConsumeBool()) {
        arr.erase(arr.cbegin(), arr.cbegin() + 1); // Use const_iterator range version
    }
    // Coverage for prune
    if (data_provider.ConsumeBool()) {
        toml::array arr_for_prune;
        arr_for_prune.push_back(toml::array{}); // Empty sub-array
        arr_for_prune.push_back(1);
        arr_for_prune.push_back(toml::table{}); // Empty sub-table
        if (data_provider.ConsumeBool()) { arr_for_prune.prune(data_provider.ConsumeBool()); }
        else { std::move(arr_for_prune).prune(data_provider.ConsumeBool()); }
    }
  }

  // 7. Enhanced toml::table exercising
  if (parsed_successfully || data_provider.ConsumeBool()) {
    toml::table current_tbl; 
    if (parsed_successfully && data_provider.ConsumeBool()) {
        current_tbl = tbl; 
    }
    toml::node* first_nonmatch_tbl_node = nullptr;
    const toml::node* const_first_nonmatch_tbl_node = nullptr;

    std::string key1 = data_provider.ConsumeRandomLengthString(10);
    std::string key_non_existent = data_provider.ConsumeRandomLengthString(10) + "_ne";

    if (data_provider.ConsumeBool() && !key1.empty()) {
        current_tbl.insert_or_assign(key1, data_provider.ConsumeIntegral<int64_t>());
    }
     if (data_provider.ConsumeBool()) { 
        current_tbl.insert_or_assign(data_provider.ConsumeRandomLengthString(10), data_provider.ConsumeRandomLengthString(5));
    }

    if (!key1.empty()) { (void)current_tbl.contains(key1); }
    (void)current_tbl.contains(key_non_existent);

    const toml::table& const_current_tbl = current_tbl; // Used throughout this section
    if (!key1.empty() && current_tbl.contains(key1)) {
        try { (void)current_tbl.at(key1); } catch (const std::out_of_range&) {}
        try { (void)const_current_tbl.at(key1); } catch (const std::out_of_range&) {} 
    }
    try { (void)current_tbl.at(key_non_existent); } catch (const std::out_of_range&) {}
    try { (void)const_current_tbl.at(key_non_existent); } catch (const std::out_of_range&) {}
    
    std::ostringstream tbl_oss;
    tbl_oss << current_tbl;
    (void)tbl_oss.str();

    if (!key1.empty()) {
        (void)current_tbl.find(key1);         
        (void)const_current_tbl.find(key1);   
    }
    // Coverage for iterators and size
    (void)current_tbl.begin(); (void)current_tbl.end();
    (void)const_current_tbl.begin(); (void)const_current_tbl.end();
    (void)current_tbl.cbegin(); (void)current_tbl.cend(); // Coverage for cbegin/cend
    (void)const_current_tbl.cbegin(); (void)const_current_tbl.cend();
    (void)current_tbl.size(); (void)const_current_tbl.size(); // Coverage for size()

    // Coverage for table-specific is_X/as_X methods
    (void)current_tbl.is_table(); (void)current_tbl.is_array(); (void)current_tbl.is_array_of_tables();
    (void)current_tbl.is_string(); (void)current_tbl.is_integer(); (void)current_tbl.is_floating_point(); (void)current_tbl.is_number();
    (void)current_tbl.is_boolean(); (void)current_tbl.is_date(); (void)current_tbl.is_time(); (void)current_tbl.is_date_time();
    (void)current_tbl.as_table(); (void)current_tbl.as_string(); (void)current_tbl.as_integer(); (void)current_tbl.as_floating_point();
    (void)current_tbl.as_boolean(); (void)current_tbl.as_date(); (void)current_tbl.as_time(); (void)current_tbl.as_date_time();

    (void)const_current_tbl.is_table(); (void)const_current_tbl.is_array(); (void)const_current_tbl.is_array_of_tables();
    (void)const_current_tbl.is_string(); (void)const_current_tbl.is_integer(); (void)const_current_tbl.is_floating_point(); (void)const_current_tbl.is_number();
    (void)const_current_tbl.is_boolean(); (void)const_current_tbl.is_date(); (void)const_current_tbl.is_time(); (void)const_current_tbl.is_date_time();
    (void)const_current_tbl.as_table(); (void)const_current_tbl.as_string(); (void)const_current_tbl.as_integer(); (void)const_current_tbl.as_floating_point();
    (void)const_current_tbl.as_boolean(); (void)const_current_tbl.as_date(); (void)const_current_tbl.as_time(); (void)const_current_tbl.as_date_time();


    toml::table empty_tbl_for_homo_test;
    (void)empty_tbl_for_homo_test.is_homogeneous(toml::node_type::string); 
    (void)empty_tbl_for_homo_test.is_homogeneous(toml::node_type::string, first_nonmatch_tbl_node); 

    if(!current_tbl.empty()){
        (void)current_tbl.is_homogeneous(toml::node_type::none); 
        (void)current_tbl.is_homogeneous(toml::node_type::none, first_nonmatch_tbl_node); 
        
        toml::table non_homo_tbl_const; non_homo_tbl_const.insert("a",1); non_homo_tbl_const.insert("b", "s");
        (void)non_homo_tbl_const.is_homogeneous(toml::node_type::integer);

        toml::table non_homo_tbl_ptr; non_homo_tbl_ptr.insert("x",true); non_homo_tbl_ptr.insert("y", 0.5);
        (void)non_homo_tbl_ptr.is_homogeneous(toml::node_type::boolean, first_nonmatch_tbl_node);
    }
    (void)current_tbl.is_homogeneous(toml::node_type::integer, first_nonmatch_tbl_node); 
    (void)const_current_tbl.is_homogeneous(toml::node_type::string, const_first_nonmatch_tbl_node); 


    if (data_provider.ConsumeBool()) {
        toml::table tbl_assign_source; tbl_assign_source.insert("k", "v");
        toml::table tbl_assigned_copy;
        tbl_assigned_copy = tbl_assign_source; 
        toml::table tbl_assigned_move;
        tbl_assigned_move = std::move(tbl_assign_source); 
    }

    if (data_provider.ConsumeBool()) {
        toml::table tbl_cmp1, tbl_cmp2;
        if (data_provider.ConsumeBool()) { tbl_cmp1.insert("key", 1); tbl_cmp2.insert("key",1); }
        else { tbl_cmp1.insert("keyA", 1); tbl_cmp2.insert("keyB", 2); }
        // Coverage for table::equal lambda specializations
        if (data_provider.ConsumeBool()) { toml::table t_cmp_inner; t_cmp_inner.insert("y",true); tbl_cmp1.insert("sub_table", t_cmp_inner); if (data_provider.ConsumeBool()) tbl_cmp2.insert("sub_table", t_cmp_inner); }
        if (data_provider.ConsumeBool()) { toml::array a_cmp_inner; a_cmp_inner.push_back(3.0); tbl_cmp1.insert("sub_array", a_cmp_inner); if (data_provider.ConsumeBool()) tbl_cmp2.insert("sub_array", a_cmp_inner); }

        (void)(tbl_cmp1 == tbl_cmp2); 
        (void)(tbl_cmp1 != tbl_cmp2); 
    }
    
    // Coverage for erase and lower_bound
    if (!current_tbl.empty() && data_provider.ConsumeBool()) {
        current_tbl.erase(current_tbl.cbegin()); // Use const_iterator version
    }
    (void)current_tbl.lower_bound(data_provider.ConsumeRandomLengthString(10));
    (void)const_current_tbl.lower_bound(data_provider.ConsumeRandomLengthString(10)); // const version

    // Coverage for prune
    if (data_provider.ConsumeBool()) {
        toml::table tbl_for_prune;
        tbl_for_prune.insert("a", toml::array{}); 
        tbl_for_prune.insert("b", 1);
        tbl_for_prune.insert("c", toml::table{});
        if (data_provider.ConsumeBool()) { tbl_for_prune.prune(data_provider.ConsumeBool()); }
        else { std::move(tbl_for_prune).prune(data_provider.ConsumeBool()); }
    }

    if (data_provider.ConsumeBool()) {
        current_tbl.clear(); 
    }
  }

  // 8. Exercise toml::date, toml::time, toml::time_offset, toml::date_time
  if (data_provider.ConsumeBool()) {
    toml::date d1{ 
        data_provider.ConsumeIntegralInRange<uint16_t>(1, 9999),
        data_provider.ConsumeIntegralInRange<uint8_t>(1, 12),
        data_provider.ConsumeIntegralInRange<uint8_t>(1, 28) };
    
    // Coverage: Make d2 more varied for date comparison branches
    uint16_t d2_year = d1.year;
    uint8_t  d2_month = d1.month;
    uint8_t  d2_day = d1.day;
    if (data_provider.ConsumeBool()) d2_year = data_provider.ConsumeIntegralInRange<uint16_t>(1,9999);
    if (data_provider.ConsumeBool()) d2_month = data_provider.ConsumeIntegralInRange<uint8_t>(1,12);
    if (data_provider.ConsumeBool()) d2_day = data_provider.ConsumeIntegralInRange<uint8_t>(1,28);
    toml::date d2{ d2_year, d2_month, d2_day };

    (void)(d1 == d2); (void)(d1 != d2); (void)(d1 < d2); (void)(d1 <= d2); (void)(d1 > d2); (void)(d1 >= d2);
    std::ostringstream date_oss; date_oss << d1; (void)date_oss.str(); 

    toml::time t1{ 
        data_provider.ConsumeIntegralInRange<uint8_t>(0, 23), data_provider.ConsumeIntegralInRange<uint8_t>(0, 59),
        data_provider.ConsumeIntegralInRange<uint8_t>(0, 59), data_provider.ConsumeIntegralInRange<uint32_t>(0, 999999999)};
    
    // Coverage: Make t2 more varied for time comparison branches
    toml::time t2{
        data_provider.ConsumeIntegralInRange<uint8_t>(0,23), 
        data_provider.ConsumeIntegralInRange<uint8_t>(0,59), 
        data_provider.ConsumeIntegralInRange<uint8_t>(0,59), 
        data_provider.ConsumeIntegralInRange<uint32_t>(0,999999999)};

    (void)(t1 == t2); (void)(t1 != t2); (void)(t1 < t2); (void)(t1 <= t2); (void)(t1 > t2); (void)(t1 >= t2);
    std::ostringstream time_oss; time_oss << t1; (void)time_oss.str(); 

    toml::time_offset actual_to1;
    actual_to1.minutes = data_provider.ConsumeIntegralInRange<int16_t>(-1439, 1439); // Max TOML offset range
    toml::time_offset actual_to2;
    actual_to2.minutes = data_provider.ConsumeIntegralInRange<int16_t>(-1439, 1439);
    
    (void)(actual_to1 == actual_to2); (void)(actual_to1 != actual_to2); (void)(actual_to1 < actual_to2); (void)(actual_to1 <= actual_to2); (void)(actual_to1 > actual_to2); (void)(actual_to1 >= actual_to2);
    std::ostringstream offset_oss; offset_oss << actual_to1; (void)offset_oss.str(); 
    
    std::optional<toml::time_offset> opt_actual_to1;
    if (data_provider.ConsumeBool()) opt_actual_to1 = actual_to1;
    
    std::optional<toml::time_offset> opt_actual_to2;
    if (data_provider.ConsumeBool()) opt_actual_to2 = actual_to2;
    
    toml::date_time actual_dt1;
    if (opt_actual_to1) actual_dt1 = toml::date_time{d1, t1, *opt_actual_to1};
    else actual_dt1 = toml::date_time{d1, t1};
    
    toml::date_time actual_dt2;
    if (opt_actual_to2) actual_dt2 = toml::date_time{d2, t2, *opt_actual_to2};
    else actual_dt2 = toml::date_time{d2, t2};
    
    (void)actual_dt1.is_local(); 
    (void)(actual_dt1 == actual_dt2); (void)(actual_dt1 != actual_dt2); (void)(actual_dt1 < actual_dt2); (void)(actual_dt1 <= actual_dt2); (void)(actual_dt1 > actual_dt2); (void)(actual_dt1 >= actual_dt2);
    std::ostringstream datetime_oss; datetime_oss << actual_dt1; (void)datetime_oss.str(); 

    // Coverage for date_time(date) and date_time(time) constructors
    if (data_provider.ConsumeBool()) { toml::date_time dt_from_date(d1); (void)dt_from_date.is_local(); }
    if (data_provider.ConsumeBool()) { toml::date_time dt_from_time(t1); (void)dt_from_time.is_local(); }
  }

  // 9. Exercise istream parsing for utf8_reader<istream> paths
  if (data_provider.ConsumeBool()) {
    std::string stream_data_str = data_provider.ConsumeRandomLengthString(256);
    std::istringstream iss(stream_data_str);
    std::string stream_source_path = "fuzz_istream.toml";
    try {
      (void)toml::parse(iss, stream_source_path);
    } catch (const toml::ex::parse_error&) {
    } catch (const std::exception&) {}
  }
  
  // 10. Exercise toml::node specific methods
  if (parsed_successfully && !tbl.empty() && data_provider.ConsumeBool()) {
    toml::node* random_node_ptr = nullptr;
    if (tbl.begin() != tbl.end()) { 
        random_node_ptr = &tbl.begin()->second; 
    }

    if (random_node_ptr) {
        if (data_provider.ConsumeBool()) {
            toml::value<std::string> n_assign_src("source_val");
            toml::value<std::string> n_assign_dest("dest_val");
            n_assign_dest = n_assign_src; 
        }

        toml::node_view<toml::node> nv_from_node_op(*random_node_ptr); 
        toml::node_view<const toml::node> const_nv_from_node_op(*random_node_ptr); 
        (void)nv_from_node_op;
        (void)const_nv_from_node_op;

        // Coverage for node::at_path and node::operator[]
        toml::path p_for_node_at(data_provider.ConsumeRandomLengthString(10));
        try {
            (void)random_node_ptr->at_path(p_for_node_at);
            (void)static_cast<const toml::node*>(random_node_ptr)->at_path(p_for_node_at);
            (void)static_cast<const toml::node*>(random_node_ptr)->at_path(data_provider.ConsumeRandomLengthString(10));

            (void)(*random_node_ptr)[p_for_node_at];
            (void)(*static_cast<const toml::node*>(random_node_ptr))[p_for_node_at];
        } catch (const std::out_of_range &) {}
          catch (const std::exception &) {}

        // Coverage for node::as<T>()
        (void)random_node_ptr->as<toml::table>(); (void)random_node_ptr->as<toml::array>();
        (void)random_node_ptr->as<std::string>(); (void)random_node_ptr->as<int64_t>();
        (void)random_node_ptr->as<double>(); (void)random_node_ptr->as<bool>();
        (void)random_node_ptr->as<toml::date>(); (void)random_node_ptr->as<toml::time>();
        (void)random_node_ptr->as<toml::date_time>();
    }
  }

  // 11. Exercise toml::key methods
  if (data_provider.ConsumeBool()) {
      std::string key_str_ops = data_provider.ConsumeRandomLengthString(32);
      toml::key k1_ops(key_str_ops);
      toml::key k2_ops(data_provider.ConsumeRandomLengthString(32));
      
      (void)k1_ops.str(); (void)k1_ops.length(); (void)k1_ops.empty(); (void)k1_ops.data(); (void)k1_ops.source();
      (void)(k1_ops == k2_ops); (void)(k1_ops != k2_ops); (void)(k1_ops < k2_ops);
      (void)(k1_ops <= k2_ops); (void)(k1_ops > k2_ops); (void)(k1_ops >= k2_ops);

      std::string sv_ops_str = data_provider.ConsumeRandomLengthString(16);
      std::string_view sv_ops(sv_ops_str);
      (void)(k1_ops == sv_ops); (void)(sv_ops == k1_ops); (void)(k1_ops < sv_ops); (void)(sv_ops < k1_ops);
      // ... other comparisons with string_view ...

      if (!k1_ops.empty()) { (void)k1_ops.begin(); (void)k1_ops.end(); }
      std::ostringstream key_oss_ops; key_oss_ops << k1_ops; (void)key_oss_ops.str();

      toml::source_region src_reg_ops{};
      if (data_provider.ConsumeBool()) {
           src_reg_ops.begin = {data_provider.ConsumeIntegralInRange<uint32_t>(1,5), data_provider.ConsumeIntegralInRange<uint32_t>(1,5)};
           src_reg_ops.end = {src_reg_ops.begin.line, (uint32_t)(src_reg_ops.begin.column + data_provider.ConsumeIntegralInRange<uint32_t>(0,5))};
           if (data_provider.ConsumeBool()) { src_reg_ops.path = std::make_shared<const std::string>(data_provider.ConsumeRandomLengthString(10));}
      }
      toml::key k_src1_ops(data_provider.ConsumeRandomLengthString(10), src_reg_ops);
      std::string str_for_k_src2_ops = data_provider.ConsumeRandomLengthString(10);
      toml::key k_src2_ops(std::move(str_for_k_src2_ops), src_reg_ops);
  }

  // 12. Exercise toml::yaml_formatter
  if (parsed_successfully || data_provider.ConsumeBool()) {
      try {
          toml::format_flags yaml_fmt_flags = toml::format_flags::none;
          if (data_provider.ConsumeBool()) yaml_fmt_flags |= toml::format_flags::indentation;
          // if (data_provider.ConsumeBool()) yaml_fmt_flags |= toml::format_flags::terse_output; // Flag removed
          // Coverage for format_flags bitwise operators
          // if (data_provider.ConsumeBool()) yaml_fmt_flags &= ~toml::format_flags::terse_output; // Flag removed
          if (data_provider.ConsumeBool()) yaml_fmt_flags ^= toml::format_flags::indentation;
          (void)(yaml_fmt_flags | toml::format_flags::allow_unicode_strings);
          (void)(yaml_fmt_flags & toml::format_flags::indentation);
          // (void)(yaml_fmt_flags ^ toml::format_flags::terse_output); // Flag removed


          std::ostringstream oss_yaml;
          toml::yaml_formatter yf{tbl, yaml_fmt_flags};
          oss_yaml << yf; 
          (void)oss_yaml.str();

          std::ostringstream oss_yaml_rv; // rvalue version
          oss_yaml_rv << toml::yaml_formatter{tbl, yaml_fmt_flags};
          (void)oss_yaml_rv.str();

      } catch (const std::exception &) {}
  }
  
  // 13. Exercise toml_formatter more thoroughly (including print_inline)
  if (parsed_successfully || data_provider.ConsumeBool()) {
      try {
          toml::format_flags tf_flags = toml::format_flags::none;
          if (data_provider.ConsumeBool()) tf_flags |= toml::format_flags::indentation;
          // if (data_provider.ConsumeBool()) tf_flags |= toml::format_flags::terse_output; // Flag removed

          std::ostringstream oss_toml_extra;
          toml::toml_formatter tf_custom{tbl, tf_flags};
          oss_toml_extra << tf_custom;
          (void)oss_toml_extra.str();

          if (data_provider.ConsumeBool()) { // Specifically for print_inline branches
              toml::table outer_tbl_pi;
              toml::table inline_candidate_tbl_pi;
              if (data_provider.ConsumeBool()) { /* empty table */ } 
              else { inline_candidate_tbl_pi.insert("a", 1); }
              outer_tbl_pi.insert("inline_table", inline_candidate_tbl_pi);
              
              std::ostringstream oss_inline_test;
              toml::toml_formatter tf_inline_test{outer_tbl_pi, tf_flags};
              oss_inline_test << tf_inline_test;
              (void)oss_inline_test.str();
          }
      } catch (const std::exception &) {}
  }

  // 14. Exercise toml::value specific operations and flags
  if (data_provider.ConsumeBool()) {
    toml::value<int64_t> v_int(data_provider.ConsumeIntegral<int64_t>());
    toml::value_flags val_flags = toml::value_flags::none;
    if (data_provider.ConsumeBool()) val_flags |= toml::value_flags::format_as_octal; // Was format_as_hex
    if (data_provider.ConsumeBool()) val_flags |= toml::value_flags::format_as_binary;
    // Coverage for value_flags bitwise operators
    if (data_provider.ConsumeBool()) val_flags &= ~toml::value_flags::format_as_octal; // Was format_as_hex
    if (data_provider.ConsumeBool()) val_flags ^= toml::value_flags::format_as_binary;
    (void)(val_flags | toml::value_flags::format_as_octal);
    (void)(val_flags & toml::value_flags::format_as_octal); // Was format_as_hex
    (void)(val_flags ^ toml::value_flags::format_as_octal);

    v_int.flags(val_flags); // Set flags
    (void)v_int.flags();    // Get flags

    // is_X/as_X for value<int64_t>
    (void)v_int.is_table(); (void)v_int.as_table(); (void)v_int.is_array(); (void)v_int.as_array();
    (void)v_int.is_value(); (void)v_int.is_string(); (void)v_int.as_string();
    (void)v_int.is_integer(); (void)v_int.as_integer(); (void)v_int.is_floating_point(); (void)v_int.as_floating_point();
    (void)v_int.is_number(); (void)v_int.is_boolean(); (void)v_int.as_boolean();
    (void)v_int.is_date(); (void)v_int.as_date(); (void)v_int.is_time(); (void)v_int.as_time();
    (void)v_int.is_date_time(); (void)v_int.as_date_time();
    const auto& const_v_int = v_int; // Const versions
    (void)const_v_int.as_table(); (void)const_v_int.as_array(); (void)const_v_int.as_string(); // etc.
     // Minimal check for const versions to avoid excessive verbosity, assuming similar pattern to non-const
    (void)const_v_int.as_integer(); (void)const_v_int.as_boolean(); (void)const_v_int.as_date_time();
  }


  return 0;
}