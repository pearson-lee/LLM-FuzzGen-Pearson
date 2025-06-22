#include "/src/tomlplusplus/include/toml++/toml.hpp" // Main TOML++ library header
#include <fuzzer/FuzzedDataProvider.h>
#include <string>
#include <vector>
#include <sstream>    // For std::ostringstream with formatters
#include <optional>   // For toml::time_offset
#include <variant>    // For std::visit (though not directly used for path_component now)

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
    } catch (const toml::parse_error& /*err*/) {
        // Parsing failed, expected.
    } catch (...) {
        // Other unexpected exceptions.
        return 0;
    }

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
                // Test comparison operators for key
                if (fdp.ConsumeBool()) {
                    std::string another_key_str = fdp.ConsumeRandomLengthString(64);
                    if (!another_key_str.empty()) {
                        try {
                            toml::key k2(another_key_str);
                            (void)(k == k2); // Coverage for key comparison
                            (void)(k != k2);
                            (void)(k < k2); 
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
                        if (fdp.ConsumeBool()) { // Test with specific flags for integer formatting coverage
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

                            // --- Start of new code for date coverage ---
                            if (fdp.ConsumeBool()) { // Coverage for date comparison operators
                                toml::date d2{
                                    fdp.ConsumeIntegralInRange<uint16_t>(0, 10000),
                                    fdp.ConsumeIntegralInRange<uint8_t>(0, 15),
                                    fdp.ConsumeIntegralInRange<uint8_t>(0, 35)
                                };
                                (void)(d == d2); (void)(d != d2);
                                (void)(d < d2); (void)(d <= d2);
                                (void)(d > d2); (void)(d >= d2);
                            }
                            if (fdp.ConsumeBool()) { // Coverage for date stream operator
                                std::ostringstream date_ss;
                                date_ss << d; 
                            }
                            // --- End of new code for date coverage ---
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
                             // --- Start of new code for time coverage ---
                            if (fdp.ConsumeBool()) { // Coverage for time comparison operators
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
                            if (fdp.ConsumeBool()) { // Coverage for time stream operator
                                std::ostringstream time_ss;
                                time_ss << t;
                            }
                            // --- End of new code for time coverage ---
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

                            // --- Start of new code for date_time and time_offset coverage ---
                            if (fdp.ConsumeBool()) { // Coverage for date_time comparison
                                toml::date_time dt_val2 = offset ? toml::date_time{dt_d, dt_t, *offset} : toml::date_time{dt_d, dt_t}; // Create similar
                                (void)(dt_val == dt_val2); (void)(dt_val != dt_val2);
                                (void)(dt_val < dt_val2); (void)(dt_val <= dt_val2);
                                (void)(dt_val > dt_val2); (void)(dt_val >= dt_val2);
                            }
                            if (fdp.ConsumeBool()) { // Coverage for date_time stream operator
                                std::ostringstream dt_ss;
                                dt_ss << dt_val;
                            }
                            if (offset && fdp.ConsumeBool()) { // Coverage for time_offset comparison and stream
                                toml::time_offset offset2{fdp.ConsumeIntegralInRange<int8_t>(-23,23), fdp.ConsumeIntegralInRange<int8_t>(0,59)};
                                (void)(*offset == offset2); (void)(*offset != offset2);
                                (void)(*offset < offset2);
                                std::ostringstream offset_ss;
                                offset_ss << *offset;
                            }
                            if (fdp.ConsumeBool()) { // Coverage for date_time constructor from date
                                toml::date_time dt_from_date(dt_d); (void)dt_from_date.date;
                            }
                             if (fdp.ConsumeBool()) { // Coverage for date_time constructor from time
                                toml::date_time dt_from_time(dt_t); (void)dt_from_time.time;
                            }
                            (void)dt_val.is_local(); // Coverage for date_time::is_local()
                            // --- End of new code for date_time and time_offset coverage ---
                        }
                        break;
                    case 7: // Array
                        {
                            toml::array arr;
                            if (fdp.ConsumeBool()) arr.push_back(fdp.ConsumeIntegral<int64_t>());
                            if (fdp.ConsumeBool()) arr.push_back(fdp.ConsumeRandomLengthString(16));
                            if (fdp.ConsumeBool()) arr.push_back(fdp.ConsumeBool());
                            
                            // --- Start of new code for array coverage ---
                            if (!arr.empty()) {
                                (void)arr.front(); (void)arr.back(); // Coverage for arr.front(), arr.back()
                                if (arr.size() > 0) {
                                    (void)arr[0]; (void)arr.at(0); // Coverage for arr.operator[], arr.at()
                                    (void)arr.get(0); // Coverage for arr.get() (true branch)
                                }
                                (void)arr.get(arr.size()); // Coverage for arr.get() (false branch)
                                
                                toml::node* first_nonmatch_node = nullptr; // Coverage for arr.is_homogeneous()
                                (void)arr.is_homogeneous(toml::node_type::none, first_nonmatch_node);
                                (void)arr.is_homogeneous(toml::node_type::integer); 
                                if (fdp.ConsumeBool()) { // Coverage for arr.cbegin(), arr.cend()
                                    for (auto cit = arr.cbegin(); cit != arr.cend(); ++cit) { (void)cit->type(); }
                                }
                            }
                            (void)arr.is_array(); (void)arr.is_table(); (void)arr.is_value(); // Coverage for type checks
                            (void)arr.as_array(); (void)arr.as_table(); // Coverage for as_type()
                            (void)arr.size(); (void)arr.capacity(); (void)arr.max_size(); // Coverage for size/capacity
                            if (fdp.ConsumeBool()) arr.reserve(arr.size() + fdp.ConsumeIntegralInRange<size_t>(1, 5));

                            if (fdp.ConsumeBool()) { toml::array arr_copy_for_flatten = arr; arr_copy_for_flatten.flatten(); } // Coverage for flatten()
                            if (fdp.ConsumeBool()) { toml::array arr_copy_for_prune = arr; arr_copy_for_prune.prune(fdp.ConsumeBool()); } // Coverage for prune()
                            
                            if (!arr.empty() && fdp.ConsumeBool()) arr.erase(arr.begin()); // Coverage for erase()
                            if (!arr.empty() && fdp.ConsumeBool()) arr.pop_back(); // Coverage for pop_back()
                            if (fdp.ConsumeBool()) arr.shrink_to_fit(); // Coverage for shrink_to_fit()
                            
                            if (fdp.remaining_bytes() < 100 && fdp.ConsumeBool()) arr.clear(); // Coverage for clear()
                            (void)arr.empty(); 

                            if (fdp.ConsumeBool()) { // Coverage for array assignment
                                toml::array arr_assign1; arr_assign1 = arr; 
                                if (fdp.ConsumeBool()) { toml::array arr_assign2; arr_assign2 = std::move(arr_assign1); }
                            }
                            // --- End of new code for array coverage ---
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
    
    // --- Start of new code for table coverage ---
    if (fdp.ConsumeBool() && !tbl.empty()) {
        auto first_key_node = tbl.begin();
        if (first_key_node != tbl.end()) {
            const toml::key& first_k = first_key_node->first;
            std::string first_key_str = std::string(first_k.str()); 
            if (!first_key_str.empty()) {
                 (void)tbl.at(first_key_str); (void)tbl[first_key_str]; // Coverage for table at() and operator[]
            }
        }
        toml::node* first_nonmatch_tbl_node = nullptr; // Coverage for table.is_homogeneous()
        (void)tbl.is_homogeneous(toml::node_type::none, first_nonmatch_tbl_node);
        (void)tbl.is_homogeneous(toml::node_type::string); 
        if (fdp.ConsumeBool()) { // Coverage for table.cbegin(), tbl.cend()
            for (auto cit = tbl.cbegin(); cit != tbl.cend(); ++cit) { (void)cit->second.type(); }
        }
    }
    (void)tbl.is_table(); (void)tbl.is_array(); (void)tbl.is_array_of_tables(); // Coverage for table type checks
    (void)tbl.as_table(); (void)tbl.as_array(); // Coverage for table as_type()
    (void)tbl.size(); 
    if (fdp.ConsumeBool()) { toml::table tbl_copy_for_prune = tbl; tbl_copy_for_prune.prune(fdp.ConsumeBool()); } // Coverage for table.prune()
    if (!tbl.empty() && fdp.ConsumeBool()) tbl.erase(tbl.begin()); // Coverage for table.erase(iterator)
    if (!tbl.empty() && fdp.ConsumeBool()) { // Coverage for table.erase(key)
        auto it_to_erase = tbl.begin();
        if (it_to_erase != tbl.end()) {
             std::string key_to_erase_str = std::string(it_to_erase->first.str());
             if (!key_to_erase_str.empty()) tbl.erase(key_to_erase_str);
        }
    }
    if (!tbl.empty() && fdp.ConsumeBool()) { // Coverage for table find, lower_bound, contains
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
    if (fdp.remaining_bytes() < 50 && fdp.ConsumeBool()) tbl.clear(); // Coverage for table.clear()
    (void)tbl.empty(); 
    if (fdp.ConsumeBool()) { // Coverage for table assignment
        toml::table tbl_assign1; tbl_assign1 = tbl; 
        if (fdp.ConsumeBool()) { toml::table tbl_assign2; tbl_assign2 = std::move(tbl_assign1); }
    }
    // --- End of new code for table coverage ---


    // 3. Path-based Access (at_path)
    if (fdp.ConsumeBool() && !tbl.empty()) {
        std::string path_str = fdp.ConsumeRandomLengthString(128);
        if (!path_str.empty()) {
            try {
                toml::path p(path_str); 
                // --- Start of new code for path coverage ---
                (void)p.empty(); (void)p.size(); // Coverage for path empty/size
                if (!p.empty()) {
                    (void)p[0]; 
                    for (const toml::path_component& comp : p) {
                        if (comp.type() == toml::path_component_type::key) {
                            (void)comp.key();
                        } else if (comp.type() == toml::path_component_type::array_index) {
                            (void)comp.index();
                        }
                    }
                     if (p.size() > 0 && fdp.ConsumeBool()) { // Coverage for path_component assignment
                        toml::path_component pc_assign = p[0];
                        if (fdp.ConsumeBool()) pc_assign = fdp.ConsumeRandomLengthString(10);
                        else pc_assign = fdp.ConsumeIntegral<size_t>();
                        toml::path_component pc_assign2; pc_assign2 = pc_assign;
                     }
                }
                (void)p.str(); (void)static_cast<std::string>(p); // Coverage for path string conversion
                if (fdp.ConsumeBool()) { // Coverage for path manipulation
                    toml::path p2(fdp.ConsumeRandomLengthString(10));
                    toml::path p_combined = p + p2; p += p2;
                    toml::path p_copy = p; p_copy.clear();
                }
                if (!p.empty() && fdp.ConsumeBool()) { (void)p.parent(); (void)p.leaf(); } // Coverage for parent/leaf
                if (fdp.ConsumeBool()) { toml::path p_compare(fdp.ConsumeRandomLengthString(30)); (void)(p == p_compare); } // Coverage for path comparison
                // --- End of new code for path coverage ---
                
                if (auto nv = tbl.at_path(p)) {
                    (void)nv.type(); (void)nv.node(); // Coverage for node_view type() and node() (valid node)
                    if (nv.is_string()) (void)nv.value<std::string>();
                    else if (nv.is_integer()) (void)nv.value<int64_t>();
                    else if (nv.is_floating_point()) (void)nv.value<double>();
                    else if (nv.is_boolean()) (void)nv.value<bool>();
                } else { // nv is empty
                    (void)nv.type(); (void)nv.node(); // Coverage for node_view type() and node() (nullptr node)
                }
            } catch (const toml::parse_error& /*pe*/) {
            } catch (const std::exception& /*e*/) {
            }
        }
    }

    // 4. Formatting
    if (fdp.ConsumeBool()) { // TOML Formatter
        try {
            std::ostringstream ss;
            toml::format_flags toml_fmt_flags = toml::format_flags::none; 
            toml::toml_formatter formatter{tbl, toml_fmt_flags}; 
            ss << formatter;                     
            std::string formatted_toml_string = ss.str(); 
        } catch (const std::exception& /*e*/) { }
    }
    // --- Start of new code for json_formatter and yaml_formatter coverage ---
    if (fdp.ConsumeBool()) { // JSON Formatter
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
        } catch (const std::exception& /*e*/) { }
    }
    if (fdp.ConsumeBool()) { // YAML Formatter
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
        } catch (const std::exception& /*e*/) { }
    }
    // --- End of new code for json_formatter and yaml_formatter coverage ---


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
        }
    }

    return 0;
}