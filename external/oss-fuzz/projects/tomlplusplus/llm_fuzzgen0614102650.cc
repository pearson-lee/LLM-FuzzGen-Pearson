#include "/src/tomlplusplus/include/toml++/toml.hpp" // Main TOML++ library header
#include <fuzzer/FuzzedDataProvider.h>
#include <string>
#include <vector>
#include <sstream>    // For std::ostringstream with formatters
#include <optional>   // For toml::time_offset
#include <variant>    // For std::visit (though not directly used for path_component now)
#include <iostream>   // For err_ss (though not strictly necessary for fuzzing)

// Target APIs:
// 1. toml::parse(std::string_view): Core TOML parsing.
// 2. toml::table::insert_or_assign(toml::key&&, ValueType&&): Table manipulation with various types.
// 3. toml::node::at_path(const toml::path&): Path-based node access.
// 4. toml::toml_formatter and its usage (operator<<): Serializing TOML data. This also covers its destructor.
// 5. toml::source_region::operator=(const toml::source_region&): Assignment of source_region objects.
// Additional coverage targets: toml::array, toml::table methods, toml::key, date/time types, other formatters.

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size) {
    FuzzedDataProvider fdp(Data, Size);

    // All memory is managed by RAII (tomlplusplus objects, std::string, std::vector, etc.)
    // No manual new/delete or malloc/free is needed.

    // 1. Parsing TOML input
    std::string toml_string = fdp.ConsumeRandomLengthString(2048);
    toml::table tbl;
    try {
        tbl = toml::parse(toml_string);
    } catch (const toml::parse_error& err) {
        // Parsing failed, expected.
        // --- Start of new code for parse_error coverage ---
        (void)err.description(); // Coverage for parse_error::description()
        (void)err.source();      // Coverage for parse_error::source()
        if (fdp.ConsumeBool()) {
            std::ostringstream err_ss;
            err_ss << err; // Coverage for operator<<(ostream&, parse_error const&)
        }
        // --- End of new code for parse_error coverage ---
    } catch (...) {
        // Other unexpected exceptions.
        return 0;
    }

    // --- Start of new code for istream parsing coverage ---
    if (fdp.ConsumeBool()) {
        std::string toml_string_for_istream = fdp.ConsumeRandomLengthString(512);
        std::istringstream toml_s_stream(toml_string_for_istream);
        try {
            // Provide a source path for coverage of parse overloads taking it
            std::string source_path_str = fdp.ConsumeBool() ? "fuzzed_stream.toml" : "";
            if (fdp.ConsumeBool()) {
                 (void)toml::parse(toml_s_stream, std::string(source_path_str)); // Coverage for parse(istream&, string&&)
            } else {
                 (void)toml::parse(toml_s_stream, std::string_view{source_path_str}); // Coverage for parse(istream&, string_view)
            }
        } catch (const toml::parse_error& ) {
            // Parsing failed, expected.
        } catch (...) {
            // Other unexpected exceptions.
        }
    }
    // --- End of new code for istream parsing coverage ---


    // 2. Table Manipulation (insert_or_assign)
    if (fdp.ConsumeBool()) {
        std::string key_str = fdp.ConsumeRandomLengthString(64);
        if (!key_str.empty()) {
            try {
                toml::key k(key_str);
                // --- Start of new code for key coverage ---
                (void)k.str();
                (void)k.length();
                (void)k.empty();
                (void)k.data();
                if (!k.empty()) {
                    (void)k.begin(); 
                    (void)k.end();   
                }
                if (fdp.ConsumeBool()) { // Coverage for key stream operator
                    std::ostringstream key_ss;
                    key_ss << k;
                }
                // Test comparison operators for key
                if (fdp.ConsumeBool()) {
                    std::string another_key_str = fdp.ConsumeRandomLengthString(64);
                    if (!another_key_str.empty()) {
                        try {
                            toml::key k2(another_key_str);
                            (void)(k == k2); 
                            (void)(k != k2);
                            (void)(k < k2);
                            (void)(k <= k2); 
                            (void)(k > k2);  
                            (void)(k >= k2); 

                            std::string_view sv_key = k2.str();
                            (void)(k == sv_key);
                            (void)(sv_key == k); 
                            (void)(k != sv_key); // Coverage for key::operator!=(string_view)
                            (void)(sv_key != k); // Coverage for key::operator!=(string_view) (reversed)
                            (void)(k < sv_key);  // Coverage for key::operator<(string_view)
                            (void)(sv_key < k);  // Coverage for key::operator<(string_view) (reversed)
                            (void)(k <= sv_key); // Coverage for key::operator<=(string_view)
                            (void)(sv_key <= k); // Coverage for key::operator<=(string_view) (reversed)
                            (void)(k > sv_key);  // Coverage for key::operator>(string_view)
                            (void)(sv_key > k);  // Coverage for key::operator>(string_view) (reversed)
                            (void)(k >= sv_key); // Coverage for key::operator>=(string_view)
                            (void)(sv_key >= k); // Coverage for key::operator>=(string_view) (reversed)
                        } catch (const std::exception&){ /*ignore*/ }
                    }
                }
                // --- End of new code for key coverage ---

                uint8_t type_selector = fdp.ConsumeIntegralInRange<uint8_t>(0, 8);
                switch (type_selector) {
                    case 0:
                        tbl.insert_or_assign(k, fdp.ConsumeRandomLengthString(128));
                        break;
                    case 1: // Integer
                        if (fdp.ConsumeBool()) { 
                            toml::value<int64_t> int_val_with_flags(fdp.ConsumeIntegral<int64_t>());
                            uint8_t flag_type = fdp.ConsumeIntegralInRange<uint8_t>(0,3);
                            if (flag_type == 0) int_val_with_flags.flags(toml::value_flags::format_as_hexadecimal);
                            else if (flag_type == 1) int_val_with_flags.flags(toml::value_flags::format_as_binary);
                            else if (flag_type == 2) int_val_with_flags.flags(toml::value_flags::format_as_octal);
                            tbl.insert_or_assign(k, int_val_with_flags);
                        } else {
                            tbl.insert_or_assign(k, fdp.ConsumeIntegral<int64_t>());
                        }
                        break;
                    case 2:
                        tbl.insert_or_assign(k, fdp.ConsumeFloatingPoint<double>());
                        break;
                    case 3:
                        tbl.insert_or_assign(k, fdp.ConsumeBool());
                        break;
                    case 4: // Date
                        {
                            toml::date d{
                                fdp.ConsumeIntegralInRange<uint16_t>(0, 10000),
                                fdp.ConsumeIntegralInRange<uint8_t>(0, 15),
                                fdp.ConsumeIntegralInRange<uint8_t>(0, 35)
                            };
                            tbl.insert_or_assign(k, d);

                            if (fdp.ConsumeBool()) { 
                                toml::date d2{
                                    fdp.ConsumeIntegralInRange<uint16_t>(0, 10000),
                                    fdp.ConsumeIntegralInRange<uint8_t>(0, 15),
                                    fdp.ConsumeIntegralInRange<uint8_t>(0, 35)
                                };
                                (void)(d == d2); (void)(d != d2);
                                (void)(d < d2); (void)(d <= d2);
                                (void)(d > d2); (void)(d >= d2);
                            }
                            if (fdp.ConsumeBool()) { 
                                std::ostringstream date_ss;
                                date_ss << d;
                            }
                        }
                        break;
                    case 5: // Time
                        {
                            toml::time t{
                                fdp.ConsumeIntegralInRange<uint8_t>(0, 25),
                                fdp.ConsumeIntegralInRange<uint8_t>(0, 65),
                                fdp.ConsumeIntegralInRange<uint8_t>(0, 65),
                                fdp.ConsumeIntegralInRange<uint32_t>(0, 1000000000)
                            };
                            tbl.insert_or_assign(k, t);
                            if (fdp.ConsumeBool()) { 
                                toml::time t2{
                                    fdp.ConsumeIntegralInRange<uint8_t>(0, 25),
                                    fdp.ConsumeIntegralInRange<uint8_t>(0, 65),
                                    fdp.ConsumeIntegralInRange<uint8_t>(0, 65),
                                    fdp.ConsumeIntegralInRange<uint32_t>(0, 1000000000)
                                };
                                (void)(t == t2); (void)(t != t2);
                                (void)(t < t2); (void)(t <= t2);
                                (void)(t > t2); (void)(t >= t2);
                            }
                            if (fdp.ConsumeBool()) { 
                                std::ostringstream time_ss;
                                time_ss << t;
                            }
                        }
                        break;
                    case 6: // Datetime
                        {
                            toml::date dt_d{
                                fdp.ConsumeIntegralInRange<uint16_t>(1, 9999),
                                fdp.ConsumeIntegralInRange<uint8_t>(1, 12),
                                fdp.ConsumeIntegralInRange<uint8_t>(1, 31)
                            };
                            toml::time dt_t{
                                fdp.ConsumeIntegralInRange<uint8_t>(0, 23),
                                fdp.ConsumeIntegralInRange<uint8_t>(0, 59),
                                fdp.ConsumeIntegralInRange<uint8_t>(0, 59),
                                fdp.ConsumeIntegralInRange<uint32_t>(0, 999999999)
                            };
                            std::optional<toml::time_offset> offset;
                            toml::time_offset raw_offset{
                                fdp.ConsumeIntegralInRange<int8_t>(-23, 23),
                                fdp.ConsumeIntegralInRange<int8_t>(0, 59)
                            };
                            if (fdp.ConsumeBool()) {
                                offset.emplace(raw_offset);
                            }

                            toml::date_time dt_val = offset ? toml::date_time{dt_d, dt_t, *offset} : toml::date_time{dt_d, dt_t};
                            tbl.insert_or_assign(k, dt_val);

                            if (fdp.ConsumeBool()) { 
                                toml::date_time dt_val2 = offset ? toml::date_time{dt_d, dt_t, *offset} : toml::date_time{dt_d, dt_t}; 
                                (void)(dt_val == dt_val2); (void)(dt_val != dt_val2);
                                (void)(dt_val < dt_val2); (void)(dt_val <= dt_val2);
                                (void)(dt_val > dt_val2); (void)(dt_val >= dt_val2);
                            }
                            if (fdp.ConsumeBool()) { 
                                std::ostringstream dt_ss;
                                dt_ss << dt_val;
                            }
                            if (offset && fdp.ConsumeBool()) { 
                                toml::time_offset offset2{fdp.ConsumeIntegralInRange<int8_t>(-23,23), fdp.ConsumeIntegralInRange<int8_t>(0,59)};
                                (void)(*offset == offset2); (void)(*offset != offset2);
                                (void)(*offset < offset2);
                                (void)(*offset <= offset2); // Coverage for time_offset::operator<=
                                (void)(*offset > offset2);  // Coverage for time_offset::operator>
                                (void)(*offset >= offset2); // Coverage for time_offset::operator>=
                                std::ostringstream offset_ss;
                                offset_ss << *offset;
                            }
                            if (fdp.ConsumeBool()) { 
                                toml::date_time dt_from_date(dt_d); (void)dt_from_date.date;
                            }
                             if (fdp.ConsumeBool()) { 
                                toml::date_time dt_from_time(dt_t); (void)dt_from_time.time;
                            }
                            (void)dt_val.is_local(); 
                        }
                        break;
                    case 7: // Array
                        {
                            toml::array arr;
                            if (fdp.ConsumeBool()) arr.push_back(fdp.ConsumeIntegral<int64_t>());
                            if (fdp.ConsumeBool()) arr.push_back(fdp.ConsumeRandomLengthString(16));
                            if (fdp.ConsumeBool()) arr.push_back(fdp.ConsumeBool());
                            if (fdp.ConsumeBool()) { 
                                toml::array nested_arr;
                                if (fdp.ConsumeBool()) nested_arr.push_back(fdp.ConsumeFloatingPoint<double>());
                                arr.push_back(nested_arr);
                            }


                            // --- Start of new/enhanced code for array coverage ---
                            if (fdp.ConsumeBool()) { // Coverage for array insert methods
                                if (fdp.ConsumeBool()) arr.insert(arr.begin(), fdp.ConsumeRandomLengthString(5));
                                if (fdp.ConsumeBool() && arr.size() > 0) {
                                    toml::array arr_to_insert;
                                    arr_to_insert.push_back(fdp.ConsumeIntegral<int64_t>());
                                    if (!arr_to_insert.empty()) { // Ensure arr_to_insert is not empty before using iterators
                                       arr.insert(arr.begin() + fdp.ConsumeIntegralInRange<size_t>(0, arr.size()), arr_to_insert.begin(), arr_to_insert.end());
                                    }
                                }
                            }

                            if (!arr.empty()) {
                                (void)arr.front(); (void)arr.back();
                                (void)arr[0]; (void)arr.at(0);
                                (void)arr.get(0); 
                                const toml::array& const_arr_ref = arr; 
                                (void)const_arr_ref.get(0); 
                                if (arr.size() > 1) {
                                     (void)arr.get(1); 
                                     (void)const_arr_ref.get(1); 
                                }
                                (void)arr.get(arr.size()); 
                                (void)const_arr_ref.get(arr.size()); 

                                // Coverage for const versions of at, front, back
                                (void)const_arr_ref.at(0);
                                (void)const_arr_ref.front();
                                (void)const_arr_ref.back();
                                try { (void)const_arr_ref.at(const_arr_ref.size()); } catch (const std::out_of_range&) {}


                                toml::node* first_nonmatch_node = nullptr;
                                (void)arr.is_homogeneous(toml::node_type::none, first_nonmatch_node);
                                (void)arr.is_homogeneous(toml::node_type::integer);
                                // Coverage for is_homogeneous const
                                const toml::node* first_nonmatch_const_node = nullptr;
                                (void)const_arr_ref.is_homogeneous(toml::node_type::string, first_nonmatch_const_node);


                                if (fdp.ConsumeBool()) {
                                    for (auto cit = arr.cbegin(); cit != arr.cend(); ++cit) { (void)cit->type(); }
                                }
                                if (fdp.ConsumeBool()) { 
                                    toml::array arr_copy_for_truncate = arr;
                                    if (!arr_copy_for_truncate.empty())
                                        arr_copy_for_truncate.truncate(fdp.ConsumeIntegralInRange<size_t>(0, arr_copy_for_truncate.size() / 2));
                                }
                                if (fdp.ConsumeBool()) { 
                                    toml::array arr_copy_for_erase_range = arr;
                                    if (arr_copy_for_erase_range.size() >= 2) {
                                        arr_copy_for_erase_range.erase(arr_copy_for_erase_range.begin(), arr_copy_for_erase_range.begin() + 1);
                                    } else if (!arr_copy_for_erase_range.empty()) {
                                        arr_copy_for_erase_range.erase(arr_copy_for_erase_range.begin(), arr_copy_for_erase_range.end());
                                    }
                                }
                            }
                            (void)arr.is_array(); (void)arr.is_table(); (void)arr.is_value();
                            (void)arr.is_number(); 
                            (void)arr.is_date();   // Coverage for array::is_date
                            (void)arr.is_time();   // Coverage for array::is_time
                            (void)arr.is_date_time(); // Coverage for array::is_date_time

                            (void)arr.as_string(); 
                            (void)arr.as_integer(); // Coverage for array::as_integer
                            (void)arr.as_floating_point(); // Coverage for array::as_floating_point
                            (void)arr.as_boolean(); // Coverage for array::as_boolean
                            (void)arr.as_date();    // Coverage for array::as_date
                            (void)arr.as_time();    // Coverage for array::as_time
                            (void)arr.as_date_time(); // Coverage for array::as_date_time


                            (void)arr.as_array(); (void)arr.as_table();
                            { // Const versions of as_*
                                const toml::array& const_arr_ref = arr;
                                (void)const_arr_ref.as_array(); (void)const_arr_ref.as_table();
                                (void)const_arr_ref.as_string(); (void)const_arr_ref.as_integer();
                                (void)const_arr_ref.as_floating_point(); (void)const_arr_ref.as_boolean();
                                (void)const_arr_ref.as_date(); (void)const_arr_ref.as_time(); (void)const_arr_ref.as_date_time();
                            }

                            (void)arr.size(); (void)arr.capacity(); (void)arr.max_size();
                            if (fdp.ConsumeBool()) arr.reserve(arr.size() + fdp.ConsumeIntegralInRange<size_t>(1, 5));
                            
                            // Coverage for rvalue-qualified flatten and prune
                            if (fdp.ConsumeBool()) { toml::array arr_copy_for_flatten = arr; (void)std::move(arr_copy_for_flatten).flatten(); }
                            if (fdp.ConsumeBool()) { toml::array arr_copy_for_prune = arr; (void)std::move(arr_copy_for_prune).prune(fdp.ConsumeBool()); }


                            if (!arr.empty() && fdp.ConsumeBool()) arr.erase(arr.begin());
                            if (!arr.empty() && fdp.ConsumeBool()) arr.pop_back();
                            if (fdp.ConsumeBool()) arr.shrink_to_fit();

                            if (fdp.remaining_bytes() < 100 && fdp.ConsumeBool()) arr.clear();
                            (void)arr.empty();

                            if (fdp.ConsumeBool()) {
                                toml::array arr_assign1; arr_assign1 = arr;
                                if (fdp.ConsumeBool()) { toml::array arr_assign2; arr_assign2 = std::move(arr_assign1); }
                                if (fdp.ConsumeBool()) { 
                                    toml::array arr_compare_target;
                                    if (fdp.ConsumeBool()) arr_compare_target.push_back("compare_val");
                                    (void)(arr_assign1 == arr_compare_target);
                                    (void)(arr_assign1 != arr_compare_target);
                                }
                            }
                            if (fdp.ConsumeBool() && !arr.empty()) { // Coverage for operator<<(ostream&, array const&)
                                std::ostringstream arr_ss;
                                arr_ss << arr;
                            }
                            // --- End of new/enhanced code for array coverage ---
                            tbl.insert_or_assign(k, arr);
                        }
                        break;
                    case 8: // Nested Table
                        {
                            toml::table sub_tbl;
                            if (fdp.ConsumeBool()) sub_tbl.insert("sub_int", fdp.ConsumeIntegral<int64_t>());
                            if (fdp.ConsumeBool()) sub_tbl.insert("sub_str", fdp.ConsumeRandomLengthString(16));
                            tbl.insert_or_assign(k, sub_tbl);
                        }
                        break;
                }
            } catch (const std::exception& /*e*/) {
                // Catch exceptions.
            }
        }
    }

    // --- Start of new/enhanced code for table coverage ---
    if (fdp.ConsumeBool() && !tbl.empty()) {
        auto first_key_node = tbl.begin();
        if (first_key_node != tbl.end()) {
            const toml::key& first_k = first_key_node->first;
            std::string first_key_str = std::string(first_k.str());
            if (!first_key_str.empty()) {
                 (void)tbl.at(first_key_str); (void)tbl[first_key_str];
            }
        }
        toml::node* first_nonmatch_tbl_node = nullptr;
        (void)tbl.is_homogeneous(toml::node_type::none, first_nonmatch_tbl_node);
        (void)tbl.is_homogeneous(toml::node_type::string);
        if (fdp.ConsumeBool()) {
            for (auto cit = tbl.cbegin(); cit != tbl.cend(); ++cit) { (void)cit->second.type(); }
        }
    }
    (void)tbl.is_table(); (void)tbl.is_array(); (void)tbl.is_array_of_tables();
    (void)tbl.is_number();   // Coverage for table::is_number
    (void)tbl.is_date();     // Coverage for table::is_date
    (void)tbl.is_time();     // Coverage for table::is_time
    (void)tbl.is_date_time();// Coverage for table::is_date_time

    (void)tbl.as_table(); (void)tbl.as_array();
    (void)tbl.as_string(); (void)tbl.as_integer(); (void)tbl.as_floating_point(); // Coverage for table::as_* (non-const)
    (void)tbl.as_boolean(); (void)tbl.as_date(); (void)tbl.as_time(); (void)tbl.as_date_time();

    if (!tbl.empty()) { // Coverage for table::as_* (const)
        const auto& const_tbl = tbl;
        (void)const_tbl.as_table(); (void)const_tbl.as_array();
        (void)const_tbl.as_string(); (void)const_tbl.as_integer(); (void)const_tbl.as_floating_point();
        (void)const_tbl.as_boolean(); (void)const_tbl.as_date(); (void)const_tbl.as_time(); (void)const_tbl.as_date_time();
    }


    (void)tbl.size();
    if (fdp.ConsumeBool()) { toml::table tbl_copy_for_prune = tbl; tbl_copy_for_prune.prune(fdp.ConsumeBool()); }
    if (!tbl.empty() && fdp.ConsumeBool()) tbl.erase(tbl.begin());
    if (!tbl.empty() && fdp.ConsumeBool()) {
        auto it_to_erase = tbl.begin();
        if (it_to_erase != tbl.end()) {
             std::string key_to_erase_str = std::string(it_to_erase->first.str());
             if (!key_to_erase_str.empty()) tbl.erase(key_to_erase_str);
        }
    }
    if (!tbl.empty() && fdp.ConsumeBool()) {
        auto search_it = tbl.begin();
        if (search_it != tbl.end()) {
            std::string search_key_str = std::string(search_it->first.str());
            if (!search_key_str.empty()) {
                (void)tbl.find(search_key_str); (void)tbl.lower_bound(search_key_str); (void)tbl.contains(search_key_str);
            }
        }
        std::string non_existent_key = fdp.ConsumeRandomLengthString(32);
        if (!non_existent_key.empty()) { (void)tbl.find(non_existent_key); (void)tbl.contains(non_existent_key); }
    }
    if (fdp.remaining_bytes() < 50 && fdp.ConsumeBool()) tbl.clear();
    (void)tbl.empty();
    if (fdp.ConsumeBool()) {
        toml::table tbl_assign1; tbl_assign1 = tbl;
        if (fdp.ConsumeBool()) { toml::table tbl_assign2; tbl_assign2 = std::move(tbl_assign1); }
    }
    // --- End of new/enhanced code for table coverage ---


    // 3. Path-based Access (at_path)
    if (fdp.ConsumeBool() && !tbl.empty()) {
        std::string path_str = fdp.ConsumeRandomLengthString(128);
        if (!path_str.empty()) {
            try {
                toml::path p(path_str);
                // --- Start of new/enhanced code for path coverage ---
                (void)p.empty(); (void)p.size();
                (void)p.operator bool(); 

                if (!p.empty()) {
                    (void)p[0];
                    const toml::path& const_p = p; 
                    (void)const_p[0]; 

                    for (const toml::path_component& comp : p) {
                        if (comp.type() == toml::path_component_type::key) {
                            (void)comp.key();
                        } else if (comp.type() == toml::path_component_type::array_index) {
                            (void)comp.index();
                        }
                    }
                    for (auto cit = p.cbegin(); cit != p.cend(); ++cit) { 
                        (void)cit->type();
                    }

                    if (fdp.ConsumeBool()) { 
                        toml::path_component pc_move_src;
                        if (fdp.ConsumeBool()) pc_move_src = fdp.ConsumeRandomLengthString(10);
                        else pc_move_src = fdp.ConsumeIntegral<size_t>();
                        
                        toml::path_component pc_move_dest;
                        pc_move_dest = std::move(pc_move_src);

                        // Coverage for path_component copy assignment
                        toml::path_component pc_copy_src;
                         if (fdp.ConsumeBool()) pc_copy_src = fdp.ConsumeRandomLengthString(10);
                        else pc_copy_src = fdp.ConsumeIntegral<size_t>();
                        toml::path_component pc_copy_dest_val;
                        pc_copy_dest_val = pc_copy_src;

                    }
                }
                (void)p.str(); (void)static_cast<std::string>(p);
                if (fdp.ConsumeBool()) { // Coverage for path stream operator
                    std::ostringstream path_ss;
                    path_ss << p;
                }
                if (fdp.ConsumeBool()) {
                    toml::path p2(fdp.ConsumeRandomLengthString(10));
                    toml::path p_combined = p + p2; p += p2;
                    toml::path p_copy = p; p_copy.clear();
                    p_copy.assign(p.str()); 
                }
                if (!p.empty() && fdp.ConsumeBool()) { (void)p.parent(); (void)p.leaf(); }
                if (fdp.ConsumeBool()) { toml::path p_compare(fdp.ConsumeRandomLengthString(30)); (void)(p == p_compare); }
                
                if (fdp.ConsumeBool() && p.size() > 0) { // Coverage for path::truncate
                    toml::path p_trunc = p;
                    p_trunc.truncate(fdp.ConsumeIntegralInRange<size_t>(0, p_trunc.size()));
                }
                if (fdp.ConsumeBool() && p.size() > 1) { // Coverage for path::subpath
                    size_t start_idx = fdp.ConsumeIntegralInRange<size_t>(0, p.size() -1);
                    size_t len = fdp.ConsumeIntegralInRange<size_t>(0, p.size() - start_idx);
                    (void)p.subpath(start_idx, len);
                }

                // --- End of new/enhanced code for path coverage ---

                if (auto nv = tbl.at_path(p)) { 
                    (void)nv.type(); (void)nv.node();
                    if (nv.is_string()) (void)nv.value<std::string>();
                    else if (nv.is_integer()) (void)nv.value<int64_t>();
                    else if (nv.is_floating_point()) (void)nv.value<double>();
                    else if (nv.is_boolean()) (void)nv.value<bool>();
                } else {
                    (void)nv.type(); (void)nv.node();
                }
                
                std::string path_sv_str_direct = fdp.ConsumeRandomLengthString(30);
                 if (!path_sv_str_direct.empty()) {
                    (void)tbl.at_path(std::string_view{path_sv_str_direct});
                 }
                // Coverage for const node at_path
                const toml::table& const_tbl = tbl;
                if (!path_str.empty()) (void)const_tbl.at_path(path_str);
                if (!p.empty()) (void)const_tbl.at_path(p);


            } catch (const toml::parse_error& ) {
            } catch (const std::exception& ) {
            }
        }
    }

    // 4. Formatting
    if (fdp.ConsumeBool()) { 
        try {
            std::ostringstream ss;
            toml::format_flags toml_fmt_flags = toml::format_flags::none;
            if (fdp.ConsumeBool()) toml_fmt_flags |= toml::format_flags::allow_unicode_strings; // Exercise flag operations
            if (fdp.ConsumeBool()) toml_fmt_flags &= ~toml::format_flags::allow_unicode_strings;
            if (fdp.ConsumeBool()) toml_fmt_flags ^= toml::format_flags::indentation;


            toml::toml_formatter formatter{tbl, toml_fmt_flags};
            ss << formatter;
            std::string formatted_toml_string = ss.str();

            if (fdp.ConsumeBool()) { 
                 std::ostringstream ss_rv;
                 toml::toml_formatter formatter_rv{tbl, toml_fmt_flags};
                 ss_rv << std::move(formatter_rv);
                 (void)ss_rv.str();
            }
        } catch (const std::exception& ) { }
    }
    if (fdp.ConsumeBool()) { 
        try {
            std::ostringstream json_ss;
            toml::format_flags json_flags = toml::format_flags::none;
            toml::json_formatter json_formatter{tbl, json_flags};
            json_ss << json_formatter;
            if (fdp.ConsumeBool() && !tbl.empty()) {
                 auto first_item = tbl.begin();
                 if (first_item != tbl.end()) {
                    std::ostringstream json_node_ss;
                    toml::json_formatter node_formatter{first_item->second, json_flags};
                    json_node_ss << node_formatter;
                 }
            }
        } catch (const std::exception& ) { }
    }
    if (fdp.ConsumeBool()) { 
        try {
            std::ostringstream yaml_ss;
            toml::format_flags yaml_flags = toml::format_flags::none;
            toml::yaml_formatter yaml_formatter{tbl, yaml_flags};
            yaml_ss << yaml_formatter;
            if (fdp.ConsumeBool() && !tbl.empty()) {
                 auto first_item = tbl.begin();
                 if (first_item != tbl.end()) {
                    std::ostringstream yaml_node_ss;
                    toml::yaml_formatter node_formatter{first_item->second, yaml_flags};
                    yaml_node_ss << node_formatter;
                 }
            }
        } catch (const std::exception& ) { }
    }


    // 5. source_region::operator=
    if (!tbl.empty() && fdp.ConsumeBool()) {
        auto it = tbl.begin();
        if (it != tbl.end()) {
            const toml::node* node1_ptr = &it->second;
            toml::source_region sr1 = node1_ptr->source();
            toml::source_region sr2;
            sr2 = sr1;
            if (tbl.size() > 1 && fdp.ConsumeBool()) {
                auto it2 = ++tbl.begin();
                 if (it2 != tbl.end()) {
                    const toml::node* node2_ptr = &it2->second;
                    toml::source_region sr3 = node2_ptr->source();
                    sr1 = sr3;
                }
            }
            // --- Start of new code for source_region and source_position coverage ---
            if (fdp.ConsumeBool()) { // Coverage for source_region stream operator
                std::ostringstream sr_ss;
                sr_ss << sr1;
            }
            if (fdp.ConsumeBool()) { // Coverage for source_position operators
                toml::source_position pos1 = sr1.begin;
                toml::source_position pos2 = sr1.end;
                (void)(pos1 == pos2); (void)(pos1 != pos2);
                (void)(pos1 < pos2);  (void)(pos1 <= pos2);
                (void)(pos1 > pos2);  (void)(pos1 >= pos2);
                (void)(!!pos1); // operator bool
                std::ostringstream sp_ss;
                sp_ss << pos1; // stream operator
            }
            // --- End of new code for source_region and source_position coverage ---
        }
    }
    
    // --- Start of new code for toml::get_line coverage ---
    if (fdp.ConsumeBool() && !toml_string.empty()) {
        (void)toml::get_line(toml_string, fdp.ConsumeIntegralInRange<unsigned int>(1, 5));
    }
    // --- End of new code for toml::get_line coverage ---

    return 0;
}