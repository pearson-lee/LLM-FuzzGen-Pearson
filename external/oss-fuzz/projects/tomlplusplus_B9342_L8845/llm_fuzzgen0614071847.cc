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
    (void)error_src;  
    std::ostringstream err_oss;
    err_oss << e;
    std::string err_str = err_oss.str();
    (void)err_str; 
  } catch (const std::exception & /*e*/) {
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
            if (nv.node()) // Ensure node is not nullptr before calling at_path
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
            if (nv_sv.node()) // Ensure node is not nullptr
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
    toml::node* first_nonmatch_node = nullptr; 
    const toml::node* const_first_nonmatch_node = nullptr; 

    // Case 1: Empty array for is_homogeneous branch
    if (data_provider.ConsumeBool()) { // arr is empty here
        arr.is_homogeneous(toml::node_type::none); 
        arr.is_homogeneous(toml::node_type::integer);
        // Coverage for: is_homogeneous(toml::node_type, node*&) with empty array
        arr.is_homogeneous(toml::node_type::string, first_nonmatch_node); // Branch: elems_.empty() == true
        const toml::array& const_empty_arr = arr;
        const_empty_arr.is_homogeneous(toml::node_type::string, const_first_nonmatch_node); // Const overload with empty array
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
    
    // Coverage for: is_homogeneous branches (for is_homogeneous(toml::node_type) const)
    arr.is_homogeneous(toml::node_type::none);    // Branch: ntype == node_type::none
    arr.is_homogeneous(toml::node_type::integer); // Branch: loop and type matching/mismatching
    arr.is_homogeneous(toml::node_type::string);

    // Coverage for: is_homogeneous(toml::node_type, node*&) and const overload branches
    arr.is_homogeneous(toml::node_type::integer, first_nonmatch_node); // Potentially homogeneous
    arr.is_homogeneous(toml::node_type::none, first_nonmatch_node);    // Branch: ntype == node_type::none (if not empty)
    if (data_provider.ConsumeBool()) { // Create a non-homogeneous array for the mismatch branch
        toml::array non_homo_arr_for_test;
        non_homo_arr_for_test.push_back(10);
        non_homo_arr_for_test.push_back("test_str");
        non_homo_arr_for_test.is_homogeneous(toml::node_type::integer, first_nonmatch_node); // Branch: val->type() != ntype
    }
    const toml::array& const_arr_ref = arr;
    const_arr_ref.is_homogeneous(toml::node_type::string, const_first_nonmatch_node); // Const overload

    if (!arr.empty()) {
        (void)arr.get(0); 
    }
    (void)arr.get(arr.size()); 

    if (!arr.empty()) {
        try { (void)arr.at(0); } catch (const std::out_of_range&) {}
    }
    try { (void)arr.at(arr.size()); } catch (const std::out_of_range&) {} 

    std::ostringstream arr_oss;
    arr_oss << arr;
    (void)arr_oss.str();

    // Coverage for: front(), back(), operator[]
    if (!arr.empty()) {
        (void)arr.front(); 
        (void)arr.back();  
        (void)const_arr_ref.front(); 
        (void)const_arr_ref.back();  
        (void)arr[0];      
    }

    // Coverage for: pop_back(), clear()
    if (!arr.empty() && data_provider.ConsumeBool()) {
        arr.pop_back(); 
    }
    if (data_provider.ConsumeBool()) {
        arr.clear();    
    }
    
    // Coverage for assignment operators
    if (data_provider.ConsumeBool()) {
        toml::array arr_assign_source;
        arr_assign_source.push_back(data_provider.ConsumeIntegral<int>());
        toml::array arr_assigned_copy;
        arr_assigned_copy = arr_assign_source; 
        toml::array arr_assigned_move;
        arr_assigned_move = std::move(arr_assign_source); 
    }

    // Coverage for comparison operators
    if (data_provider.ConsumeBool()) {
        toml::array arr_cmp1, arr_cmp2;
        // Populate arrays to test equality branches in toml::v3::array::equal
        if (data_provider.ConsumeBool()) arr_cmp1.push_back(1); else arr_cmp1.push_back("a");
        if (data_provider.ConsumeBool()) arr_cmp2.push_back(1); else arr_cmp2.push_back("a");
        if (data_provider.ConsumeBool()) arr_cmp1.push_back(2.0);
        
        (void)(arr_cmp1 == arr_cmp2); 
        (void)(arr_cmp1 != arr_cmp2); 
    }
     // Coverage for array-specific is_X/as_X methods (always false/nullptr)
    (void)arr.is_floating_point(); (void)arr.as_floating_point();
    (void)arr.is_number();
    (void)arr.is_boolean(); (void)arr.as_boolean();
    (void)arr.is_date(); (void)arr.as_date();
    (void)arr.is_time(); (void)arr.as_time();
    (void)arr.is_date_time(); (void)arr.as_date_time();
    (void)arr.as_string();
    (void)arr.as_integer();
    (void)const_arr_ref.as_table();
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
     if (data_provider.ConsumeBool()) { // Add another key for heterogeneity
        current_tbl.insert_or_assign(data_provider.ConsumeRandomLengthString(10), data_provider.ConsumeRandomLengthString(5));
    }

    if (!key1.empty()) { (void)current_tbl.contains(key1); }
    (void)current_tbl.contains(key_non_existent);

    const toml::table& const_current_tbl = current_tbl;
    if (!key1.empty() && current_tbl.contains(key1)) {
        try { (void)current_tbl.at(key1); } catch (const std::out_of_range&) {}
        try { (void)const_current_tbl.at(key1); } catch (const std::out_of_range&) {} 
    }
    try { (void)current_tbl.at(key_non_existent); } catch (const std::out_of_range&) {}
    try { (void)const_current_tbl.at(key_non_existent); } catch (const std::out_of_range&) {}
    
    std::ostringstream tbl_oss;
    tbl_oss << current_tbl;
    (void)tbl_oss.str();

    // Coverage for: find(string_view) (const and non-const)
    if (!key1.empty()) {
        (void)current_tbl.find(key1);         
        (void)const_current_tbl.find(key1);   
    }

    // Coverage for table-specific is_X/as_X methods
    (void)current_tbl.is_array(); (void)current_tbl.is_array_of_tables();
    (void)current_tbl.is_floating_point(); (void)current_tbl.as_floating_point();
    (void)current_tbl.is_number();
    (void)current_tbl.is_boolean(); (void)current_tbl.as_boolean();
    (void)current_tbl.is_date(); (void)current_tbl.as_date();
    (void)current_tbl.is_time(); (void)current_tbl.as_time();
    (void)current_tbl.is_date_time(); (void)current_tbl.as_date_time();
    (void)current_tbl.as_string(); (void)current_tbl.as_integer();
    (void)const_current_tbl.as_table(); // Returns this

    // Coverage for: is_homogeneous branches
    toml::table empty_tbl_for_homo_test;
    empty_tbl_for_homo_test.is_homogeneous(toml::node_type::string); 
    empty_tbl_for_homo_test.is_homogeneous(toml::node_type::string, first_nonmatch_tbl_node); 

    if(!current_tbl.empty()){
        current_tbl.is_homogeneous(toml::node_type::none); 
        current_tbl.is_homogeneous(toml::node_type::none, first_nonmatch_tbl_node); 
        
        toml::table non_homo_tbl_const; non_homo_tbl_const.insert("a",1); non_homo_tbl_const.insert("b", "s");
        non_homo_tbl_const.is_homogeneous(toml::node_type::integer);

        toml::table non_homo_tbl_ptr; non_homo_tbl_ptr.insert("x",true); non_homo_tbl_ptr.insert("y", 0.5);
        non_homo_tbl_ptr.is_homogeneous(toml::node_type::boolean, first_nonmatch_tbl_node);
    }
    current_tbl.is_homogeneous(toml::node_type::integer, first_nonmatch_tbl_node); 
    const_current_tbl.is_homogeneous(toml::node_type::string, const_first_nonmatch_tbl_node); 


    // Coverage for assignment operators
    if (data_provider.ConsumeBool()) {
        toml::table tbl_assign_source; tbl_assign_source.insert("k", "v");
        toml::table tbl_assigned_copy;
        tbl_assigned_copy = tbl_assign_source; 
        toml::table tbl_assigned_move;
        tbl_assigned_move = std::move(tbl_assign_source); 
    }

    // Coverage for comparison operators
    if (data_provider.ConsumeBool()) {
        toml::table tbl_cmp1, tbl_cmp2;
        if (data_provider.ConsumeBool()) { tbl_cmp1.insert("key", 1); tbl_cmp2.insert("key",1); }
        else { tbl_cmp1.insert("keyA", 1); tbl_cmp2.insert("keyB", 2); }
        (void)(tbl_cmp1 == tbl_cmp2); 
        (void)(tbl_cmp1 != tbl_cmp2); 
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
    toml::date d2{ (uint16_t)(d1.year + data_provider.ConsumeIntegralInRange<int8_t>(-1,1)), d1.month, d1.day};
    (void)(d1 == d2); (void)(d1 != d2); (void)(d1 < d2); (void)(d1 <= d2); (void)(d1 > d2); (void)(d1 >= d2);
    std::ostringstream date_oss; date_oss << d1; (void)date_oss.str(); 

    toml::time t1{ 
        data_provider.ConsumeIntegralInRange<uint8_t>(0, 23), data_provider.ConsumeIntegralInRange<uint8_t>(0, 59),
        data_provider.ConsumeIntegralInRange<uint8_t>(0, 59), data_provider.ConsumeIntegralInRange<uint32_t>(0, 500000000)};
    toml::time t2{t1.hour, t1.minute, (uint8_t)(t1.second + data_provider.ConsumeIntegralInRange<int8_t>(-1,1)), t1.nanosecond};
    (void)(t1 == t2); (void)(t1 != t2); (void)(t1 < t2); (void)(t1 <= t2); (void)(t1 > t2); (void)(t1 >= t2);
    std::ostringstream time_oss; time_oss << t1; (void)time_oss.str(); 

    toml::time_offset actual_to1;
    actual_to1.minutes = data_provider.ConsumeIntegralInRange<int16_t>(-720, 840);
    toml::time_offset actual_to2;
    actual_to2.minutes = static_cast<int16_t>(actual_to1.minutes + data_provider.ConsumeIntegralInRange<int8_t>(-10,10));
    
    (void)(actual_to1 == actual_to2); (void)(actual_to1 != actual_to2); (void)(actual_to1 < actual_to2); (void)(actual_to1 <= actual_to2); (void)(actual_to1 > actual_to2); (void)(actual_to1 >= actual_to2);
    std::ostringstream offset_oss; offset_oss << actual_to1; (void)offset_oss.str(); 
    
    std::optional<toml::time_offset> opt_actual_to1;
    if (data_provider.ConsumeBool()) {
        opt_actual_to1 = actual_to1;
    }
    std::optional<toml::time_offset> opt_actual_to2;
     if (data_provider.ConsumeBool()) {
        opt_actual_to2 = actual_to2;
    }
    
    toml::date_time actual_dt1;
    if (opt_actual_to1) {
        actual_dt1 = toml::date_time{d1, t1, *opt_actual_to1};
    } else {
        actual_dt1 = toml::date_time{d1, t1};
    }
    
    toml::date_time actual_dt2;
    if (opt_actual_to2) {
        actual_dt2 = toml::date_time{d2, t2, *opt_actual_to2};
    } else {
        actual_dt2 = toml::date_time{d2, t2};
    }
    (void)actual_dt1.is_local(); 
    (void)(actual_dt1 == actual_dt2); (void)(actual_dt1 != actual_dt2); (void)(actual_dt1 < actual_dt2); (void)(actual_dt1 <= actual_dt2); (void)(actual_dt1 > actual_dt2); (void)(actual_dt1 >= actual_dt2);
    std::ostringstream datetime_oss; datetime_oss << actual_dt1; (void)datetime_oss.str(); 
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
    if (tbl.begin() != tbl.end()) { // Ensure iterator is valid before dereferencing
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
    }
  }

  return 0;
}