#include "/src/tomlplusplus/include/toml++/toml.hpp" // Core tomlplusplus library
#include <fuzzer/FuzzedDataProvider.h> // For FuzzedDataProvider
#include <string> // For std::string
#include <cstdint> // For int64_t
#include <vector> // For std::vector for source_region tests
#include <sstream> // For std::stringstream // Added for toml_formatter test
#include <stdexcept> // For std::out_of_range
#include <limits> // For std::numeric_limits for NaN

// Helper macro to exercise type checking and casting APIs on a toml::node (both const and non-const)
// and on the returned toml::value<T> object.
#define EXERCISE_NODE_AND_VALUE_APIS(node_obj, const_node_obj, type_check_method, type_cast_method, value_type) \
    if (node_obj.type_check_method()) { /* Exercise non-const node APIs */ \
        toml::value<value_type>* val_ptr = node_obj.type_cast_method(); \
        if (val_ptr) { /* Coverage: Hit true branch for non-const node::as_X() */ \
            volatile value_type actual_val = val_ptr->get(); (void)actual_val; \
            /* Exercise some toml::value<value_type>::as_X methods */ \
            volatile auto val_as_str = val_ptr->as_string(); if(val_as_str){} \
            volatile auto val_as_int = val_ptr->as_integer(); if(val_as_int){} \
            volatile auto val_as_flt = val_ptr->as_floating_point(); if(val_as_flt){} \
        } \
    } \
    if (const_node_obj.type_check_method()) { /* Exercise const node APIs */ \
        const toml::value<value_type>* const_val_ptr = const_node_obj.type_cast_method(); \
        if (const_val_ptr) { /* Coverage: Hit true branch for const node::as_X() */ \
            volatile value_type const_actual_val = const_val_ptr->get(); (void)const_actual_val; \
            /* Exercise some const toml::value<value_type>::as_X methods */ \
            volatile auto const_val_as_str = const_val_ptr->as_string(); if(const_val_as_str){} \
            volatile auto const_val_as_int = const_val_ptr->as_integer(); if(const_val_as_int){} \
            volatile auto const_val_as_flt = const_val_ptr->as_floating_point(); if(const_val_as_flt){} \
        } \
    }

// Helper function to exercise type checking and casting APIs on a toml::node
void exercise_node_type_apis(toml::node* p_node) {
    if (!p_node) { // This branch is now covered by calling with nullptr
        return;
    }
    toml::node& node = *p_node;
    const toml::node& const_node = *p_node;

    EXERCISE_NODE_AND_VALUE_APIS(node, const_node, is_string, as_string, std::string)
    EXERCISE_NODE_AND_VALUE_APIS(node, const_node, is_integer, as_integer, int64_t)
    EXERCISE_NODE_AND_VALUE_APIS(node, const_node, is_floating_point, as_floating_point, double)
    EXERCISE_NODE_AND_VALUE_APIS(node, const_node, is_boolean, as_boolean, bool)
    EXERCISE_NODE_AND_VALUE_APIS(node, const_node, is_date, as_date, toml::date)
    EXERCISE_NODE_AND_VALUE_APIS(node, const_node, is_time, as_time, toml::time)
    EXERCISE_NODE_AND_VALUE_APIS(node, const_node, is_date_time, as_date_time, toml::date_time)
}

#undef EXERCISE_NODE_AND_VALUE_APIS


extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    FuzzedDataProvider fdp(data, size);
    
    // Call with nullptr to cover the null check branch in exercise_node_type_apis
    exercise_node_type_apis(nullptr);

    std::string toml_string = fdp.ConsumeRandomLengthString(fdp.ConsumeIntegralInRange<size_t>(0, 1024));

    // Coverage: Attempt to trigger UTF-8 decoding error paths
    if (fdp.ConsumeProbability<double>() < 0.05) {
        toml_string += std::string(1, (char)0xF8); // Invalid UTF-8 start byte (5-byte sequence)
    } else if (fdp.ConsumeProbability<double>() < 0.05) {
        toml_string += std::string(1, (char)0xC2); // Incomplete 2-byte sequence (needs one more byte)
    } else if (fdp.ConsumeProbability<double>() < 0.05) {
        toml_string += std::string("\xF0\x90\x80", 3); // Incomplete 4-byte sequence (missing last byte)
    }

    // === Begin Added Code for Coverage Enhancement (String Augmentation) ===
    // Coverage: Target parse_table_header line 3268+ (promoting implicit table)
    // and ensure specific value types (date, time, datetime) are created to cover their destructors.
    if (fdp.ConsumeProbability<double>() < 0.15) { // Increased probability for better hit rate
        std::string special_toml_constructs = "\n";
        // For parse_table_header line 3268+ (ok=true path: implicit table's children are tables/arrays of tables)
        special_toml_constructs += "promo_ok.sub_table.key = 1\n";
        special_toml_constructs += "promo_ok.sub_array_of_tables = [ { k = 1 } ]\n";
        special_toml_constructs += "[promo_ok]\n";

        // For parse_table_header line 3268+ (ok=false path: implicit table has non-table child)
        special_toml_constructs += "promo_fail.sub_val = 10\n"; // 'sub_val' is an integer
        special_toml_constructs += "[promo_fail]\n";

        // For value<T> destructors and general type coverage
        special_toml_constructs += "fuzz_date = 1988-03-14\n";
        special_toml_constructs += "fuzz_time = 10:20:30.123456\n";
        special_toml_constructs += "fuzz_datetime_z = 1999-12-31T23:59:59Z\n";
        special_toml_constructs += "fuzz_datetime_off = 2001-01-01T01:01:01-05:30\n";
        special_toml_constructs += "fuzz_datetime_no_off = 2002-02-02T02:02:02\n"; // Local date-time
        special_toml_constructs += "fuzz_bool_for_fmt = true\n"; // Coverage: Ensure boolean is available for formatter tests
        
        // Add a small chance for these constructs to be at the beginning of the string
        if (fdp.ConsumeBool()) {
            toml_string = special_toml_constructs + toml_string;
        } else {
            toml_string += special_toml_constructs;
        }
    }
    // === End Added Code for Coverage Enhancement (String Augmentation) ===

    // === Begin Added Code for Coverage Enhancement (Stream Parsing) ===
    // Coverage: Parse from std::istream to cover toml::parse(std::istream&, ...) overloads
    // and related internal functions like utf8_reader for streams.
    if (fdp.ConsumeProbability<double>() < 0.05) { // Low probability due to additional processing
        std::string toml_string_for_stream = fdp.ConsumeRandomLengthString(fdp.ConsumeIntegralInRange<size_t>(0, 256)); // Shorter string for stream parse
        std::stringstream ss_parse(toml_string_for_stream);
        std::string stream_source_path;
        if (fdp.ConsumeBool()) { // Optionally provide a source path
            stream_source_path = fdp.ConsumeRandomLengthString(10);
        }
        try {
            if (stream_source_path.empty()) {
                // Memory safety: toml::parse returns a toml::table by value. Its lifetime is managed by RAII.
                [[maybe_unused]] auto tbl_from_stream = toml::parse(ss_parse);
            } else {
                // Memory safety: Similar to above, source_path is moved.
                [[maybe_unused]] auto tbl_from_stream = toml::parse(ss_parse, std::move(stream_source_path));
            }
        } catch (const toml::parse_error&) {
            // Parsing can fail, this is expected.
        } catch (const std::exception&) {
            // Catch other potential exceptions from stream operations.
        }
    }
    // === End Added Code for Coverage Enhancement (Stream Parsing) ===


    try {
        toml::table root_table = toml::parse(toml_string);
        const auto& const_root_table = root_table; // Create const ref for const API coverage

        // Coverage: Insert potentially empty table/array to test prune functionality
        if (fdp.ConsumeBool()) {
            root_table.insert("potentially_empty_table", toml::table{});
        }
        if (fdp.ConsumeBool()) {
            root_table.insert("potentially_empty_array", toml::array{});
        }

        // Coverage: Call table::prune() to cover this API
        root_table.prune(true);  // Test recursive pruning
        root_table.prune(false); // Test non-recursive pruning

        // === Begin Added Code for Coverage Enhancement ===

        // Coverage: Add an array of tables to root_table to hit line 198 `if (element_node.is_table())`
        if (fdp.ConsumeBool()) {
            toml::array array_of_tables;
            array_of_tables.emplace_back(toml::table{}); 
            if (fdp.ConsumeBool()) {
                toml::table inner_tbl;
                inner_tbl.insert("foo", "bar");
                array_of_tables.emplace_back(std::move(inner_tbl));
            }
            // Coverage: toml::array::emplace_back<toml::table>()
            // Memory safety: Default constructed table is managed by the array.
            array_of_tables.emplace_back<toml::table>(); 
            if (fdp.ConsumeBool()) {
                toml::table t_inner_emplace; t_inner_emplace.insert("emplaced_k", "emplaced_v");
                // Memory safety: t_inner_emplace is moved into the array.
                array_of_tables.emplace_back<toml::table>(std::move(t_inner_emplace));
            }
            root_table.insert("array_of_tables_key", std::move(array_of_tables));
        }

        // Coverage: Add a table with a nested array to root_table to hit line 245 `if (sub_node_view_inner.is_array())`
        if (fdp.ConsumeBool()) {
            toml::table table_with_nested_array;
            table_with_nested_array.insert("nested_array_key", toml::array{});
            if (fdp.ConsumeBool()) {
                toml::array inner_arr;
                inner_arr.emplace_back(fdp.ConsumeRandomLengthString(10));
                table_with_nested_array.insert("another_nested_array_key", std::move(inner_arr));
            }
            root_table.insert("table_with_nested_array_key", std::move(table_with_nested_array));
        }
        
        // Coverage: Specific test for toml::array::prune() with nested arrays/tables (targets lines 325-330 in array.inl)
        if (fdp.ConsumeBool()) {
            toml::array array_for_prune_test;
            if (fdp.ConsumeBool()) {
                array_for_prune_test.emplace_back(toml::array{}); // Add an empty nested array
            }
            if (fdp.ConsumeBool()) {
                toml::array nested_arr_with_table;
                if (fdp.ConsumeBool()) {
                    nested_arr_with_table.emplace_back(toml::table{}); 
                }
                array_for_prune_test.emplace_back(std::move(nested_arr_with_table));
            }
            if (fdp.ConsumeBool()) {
                toml::array non_empty_nested_array;
                non_empty_nested_array.emplace_back(fdp.ConsumeIntegral<int64_t>());
                array_for_prune_test.emplace_back(std::move(non_empty_nested_array));
            }
            array_for_prune_test.prune(true);  // Test recursive pruning
            array_for_prune_test.prune(false); // Test non-recursive pruning
            
            if (fdp.ConsumeBool()) {
                 toml::array temp_copy = array_for_prune_test; 
                 [[maybe_unused]] auto pruned_rval_arr = std::move(temp_copy).prune(fdp.ConsumeBool());
            }
            [[maybe_unused]] volatile size_t final_size_prune_test = array_for_prune_test.size();
        }

        // Coverage: Target array::prune line 334 (recursive=false, element is table)
        if (fdp.ConsumeProbability<double>() < 0.2) { 
            toml::array array_with_direct_table;
            if (fdp.ConsumeBool()) { 
                array_with_direct_table.emplace_back(toml::table{});
            }
            if (fdp.ConsumeBool()) { 
                toml::table non_empty_table;
                non_empty_table.insert("k", fdp.ConsumeRandomLengthString(5));
                array_with_direct_table.emplace_back(std::move(non_empty_table));
            }
            if (!array_with_direct_table.empty()) { 
                array_with_direct_table.prune(false); 
            }
            [[maybe_unused]] volatile size_t final_size_direct_table_prune = array_with_direct_table.size();
        }
        
        // Coverage: Exercise toml::source_region assignment operator
        if (fdp.ConsumeBool()) {
            toml::source_region src_region1;
            src_region1.begin = {fdp.ConsumeIntegral<uint32_t>(), fdp.ConsumeIntegral<uint32_t>()};
            src_region1.end = {fdp.ConsumeIntegral<uint32_t>(), fdp.ConsumeIntegral<uint32_t>()};
            if (fdp.ConsumeBool()) {
                 src_region1.path = std::make_shared<const std::string>(fdp.ConsumeRandomLengthString(20));
            }
            toml::source_region src_region2;
            src_region2 = src_region1; // Coverage: source_region::operator=
            [[maybe_unused]] volatile uint32_t line = src_region2.begin.line; 
        }

        // === Begin Added Code for Coverage Enhancement (Formatter and std::length_error) ===
        // Coverage: Target toml::toml_formatter constructor/destructor and formatting logic.
        // Also targets toml::impl::formatter::print(value<bool>) and print(value<time>)
        // and branches within print(value<time>)
        if (fdp.ConsumeBool()) { 
            toml::table special_format_table; // Memory safety: stack object
            special_format_table.insert("fuzz_bool_fmt", fdp.ConsumeBool());
            special_format_table.insert("fuzz_time_fmt", toml::time{fdp.ConsumeIntegralInRange<uint8_t>(0,23),0,0});

            std::ostringstream ss_toml_fmt1;
            // Memory safety: toml_formatter created on stack, its lifetime is managed.
            toml::toml_formatter fmt1{special_format_table}; // Default flags
            ss_toml_fmt1 << fmt1;
            [[maybe_unused]] volatile auto str_fmt1 = ss_toml_fmt1.str();

            std::ostringstream ss_toml_fmt2;
            // Memory safety: toml_formatter created on stack.
            // Coverage: Hit branch for format_flags::quote_dates_and_times in formatter
            toml::toml_formatter fmt2{special_format_table, toml::format_flags::quote_dates_and_times};
            ss_toml_fmt2 << fmt2;
            [[maybe_unused]] volatile auto str_fmt2 = ss_toml_fmt2.str();
        }


        // Coverage: Attempt to trigger std::length_error by inserting a very large string.
        if (fdp.ConsumeProbability<double>() < 0.01) { 
            try {
                std::string very_long_string = fdp.ConsumeRandomLengthString(1 * 1024 * 1024); 
                if (!very_long_string.empty()) { 
                    root_table.insert("fuzz_very_long_string", very_long_string);
                }
            } catch (const std::length_error& ) {
            } catch (const std::bad_alloc& ) {
            }
        }
        // === End Added Code for Coverage Enhancement (Formatter and std::length_error) ===

        // === Begin Added Code for Coverage Enhancement (Path, AtPath, Array Homogeneous, Formatters) ===
        // Coverage: Exercise toml::path, toml::node::at_path, and toml::table::at_path (targets toml-path.inl, toml-node.inl)
        if (fdp.ConsumeBool()) {
            toml::table path_test_table; 
            path_test_table.insert("key1", "value1");
            toml::table nested_table_for_path; nested_table_for_path.insert("subkey1", 123);
            path_test_table.insert("table1", nested_table_for_path);
            toml::array arr_for_path; arr_for_path.emplace_back(10);
            toml::table inner_tbl_in_arr_for_path; inner_tbl_in_arr_for_path.insert("iat_key", "iat_val");
            arr_for_path.emplace_back(inner_tbl_in_arr_for_path);
            path_test_table.insert("array1", arr_for_path);
            const auto& const_path_test_table = path_test_table;

            std::vector<std::string> path_strings_to_test;
            path_strings_to_test.push_back("key1");
            path_strings_to_test.push_back("table1.subkey1");
            path_strings_to_test.push_back("array1[0]");
            path_strings_to_test.push_back("array1[1].iat_key");
            path_strings_to_test.push_back("nonexistent.key");
            path_strings_to_test.push_back(""); 
            path_strings_to_test.push_back("table1..subkey"); 

            for (const std::string& p_str : path_strings_to_test) {
                [[maybe_unused]] auto node_v_str = path_test_table.at_path(p_str);
                [[maybe_unused]] auto const_node_v_str = const_path_test_table.at_path(p_str);
                try {
                    toml::path path_obj(p_str); 
                    [[maybe_unused]] volatile auto p_str_val = path_obj.str();
                    [[maybe_unused]] auto node_v_path = path_test_table.at_path(path_obj);
                    [[maybe_unused]] auto const_node_v_path = const_path_test_table.at_path(path_obj);
                    if (!path_obj.empty()) { [[maybe_unused]] const auto& comp = path_obj[0]; } 
                    
                    toml::path p_copy = path_obj; 
                    [[maybe_unused]] bool eq_p = (p_copy == path_obj);
                    [[maybe_unused]] bool neq_p = (p_copy != path_obj); 
                    toml::path p_assign_copy; p_assign_copy = path_obj;
                    toml::path p_assign_move; p_assign_move = std::move(p_copy); 
                    p_assign_move.assign(p_str); 
                    if(p_str == p_assign_copy.str()) p_assign_move.assign(p_assign_copy); 
                    if(p_str == p_assign_move.str()) { toml::path temp_p(p_str); p_assign_move.assign(std::move(temp_p));} 


                    toml::path path_append_test(fdp.ConsumeRandomLengthString(5));
                    path_append_test.append(p_str); 
                    path_append_test += toml::path(fdp.ConsumeRandomLengthString(3)); 
                    toml::path temp_append_path(fdp.ConsumeRandomLengthString(3));
                    path_append_test.append(std::move(temp_append_path)); 

                    toml::path path_prepend_test(fdp.ConsumeRandomLengthString(5));
                    path_prepend_test.prepend(p_str); 
                    path_prepend_test.prepend(toml::path(fdp.ConsumeRandomLengthString(3))); 
                    toml::path temp_prepend_path(fdp.ConsumeRandomLengthString(3));
                    path_prepend_test.prepend(std::move(temp_prepend_path)); 


                    if (!path_append_test.empty()) {
                        [[maybe_unused]] auto parent_p = path_append_test.parent();
                        [[maybe_unused]] auto leaf_p = path_append_test.leaf();
                        path_append_test.truncate(1); 
                    }
                    path_append_test.clear();
                    [[maybe_unused]] volatile bool p_empty_check = path_append_test.empty();
                    [[maybe_unused]] volatile bool p_bool_check = static_cast<bool>(path_append_test);

                    for ([[maybe_unused]] const auto& comp : p_assign_copy) {} 
                    for (auto it = p_assign_copy.begin(); it != p_assign_copy.end(); ++it) { 
                         [[maybe_unused]] volatile bool is_k = (it->type() == toml::path_component_type::key);
                    }
                    const toml::path& const_p_ac = p_assign_copy; 
                    for (auto it = const_p_ac.cbegin(); it != const_p_ac.cend(); ++it) { 
                         [[maybe_unused]] volatile bool is_k = (it->type() == toml::path_component_type::key);
                    }

                    if (!p_assign_copy.empty()) {
                        toml::path_component pc = p_assign_copy[0]; 
                        toml::path_component pc_copy_ctor = pc; 
                        toml::path_component pc_move_ctor = std::move(pc_copy_ctor); 
                        pc_move_ctor = p_assign_copy[0]; 
                        toml::path_component temp_pc_move_assign = p_assign_copy[0];
                        pc_move_ctor = std::move(temp_pc_move_assign); 
                        if (pc.type() == toml::path_component_type::key) {
                            [[maybe_unused]] volatile const auto& k_pc = pc.key(); 
                            [[maybe_unused]] volatile auto sv_pc = std::string_view(pc.key()); 
                        } else { 
                            [[maybe_unused]] volatile auto i_pc = pc.index(); 
                            [[maybe_unused]] volatile auto ul_pc = static_cast<unsigned long>(pc.index()); 
                        }
                        toml::path_component pc2_default_ctor; 
                        if (!p_assign_copy.empty()) pc2_default_ctor = p_assign_copy[0];
                        [[maybe_unused]] volatile bool pc_eq = (pc == pc2_default_ctor); 
                        [[maybe_unused]] volatile bool pc_neq = (pc != pc2_default_ctor); 
                    }
                    
                    [[maybe_unused]] std::string path_as_std_string = static_cast<std::string>(p_assign_copy); 
                    std::ostringstream path_s; path_s << p_assign_copy; [[maybe_unused]] volatile auto path_str_out = path_s.str(); 

                    if (p_assign_copy.size() > 1) {
                        [[maybe_unused]] auto sub_p1 = p_assign_copy.subpath(0,1);
                        [[maybe_unused]] auto sub_p2 = p_assign_copy.subpath(p_assign_copy.cbegin(), p_assign_copy.cbegin()+1); 
                    }

                    // Coverage: node::operator[](toml::path const&) and const version
                    if (!path_test_table.empty() && !path_obj.empty()) {
                        // path_test_table is a toml::table, which is a toml::node
                        [[maybe_unused]] toml::node_view<toml::node> node_idx_op = static_cast<toml::node&>(path_test_table)[path_obj];
                        [[maybe_unused]] toml::node_view<const toml::node> const_node_idx_op = static_cast<const toml::node&>(const_path_test_table)[path_obj];
                    }

                } catch (const toml::parse_error&) {} 
            }
            using namespace toml::literals;
            [[maybe_unused]] auto path_lit_example = "fixed.path.example[0]"_tpath;

            toml::key test_key(fdp.ConsumeRandomLengthString(10)); 
            [[maybe_unused]] volatile auto key_sv = static_cast<std::string_view>(test_key); 
            [[maybe_unused]] volatile size_t key_l = test_key.length(); // Coverage: toml::key::length()
            [[maybe_unused]] volatile bool key_empty_check = test_key.empty(); 
            [[maybe_unused]] volatile const char* key_data_ptr = test_key.data(); // Coverage: toml::key::data()
            toml::key test_key2(fdp.ConsumeRandomLengthString(10));
            [[maybe_unused]] volatile bool key_eq_check = (test_key == test_key2); 
            [[maybe_unused]] volatile bool key_neq_check = (test_key != test_key2); 
            
            std::string sv_for_key_cmp_std_str = fdp.ConsumeRandomLengthString(10);

            [[maybe_unused]] volatile bool key_lt_check = (test_key < test_key2);
            [[maybe_unused]] volatile bool key_lte_check = (test_key <= test_key2);
            [[maybe_unused]] volatile bool key_gt_check = (test_key > test_key2);
            [[maybe_unused]] volatile bool key_gte_check = (test_key >= test_key2);

            [[maybe_unused]] volatile bool key_sv_eq_check = (test_key == sv_for_key_cmp_std_str);
            [[maybe_unused]] volatile bool key_sv_neq_check = (test_key != sv_for_key_cmp_std_str);
            [[maybe_unused]] volatile bool key_sv_lt_check = (test_key < sv_for_key_cmp_std_str);
            [[maybe_unused]] volatile bool key_sv_lte_check = (test_key <= sv_for_key_cmp_std_str);
            [[maybe_unused]] volatile bool key_sv_gt_check = (test_key > sv_for_key_cmp_std_str);
            [[maybe_unused]] volatile bool key_sv_gte_check = (test_key >= sv_for_key_cmp_std_str);
            [[maybe_unused]] volatile bool sv_key_eq_check = (sv_for_key_cmp_std_str == test_key);
            [[maybe_unused]] volatile bool sv_key_neq_check = (sv_for_key_cmp_std_str != test_key);
            [[maybe_unused]] volatile bool sv_key_lt_check = (sv_for_key_cmp_std_str < test_key);
            [[maybe_unused]] volatile bool sv_key_lte_check = (sv_for_key_cmp_std_str <= test_key);
            [[maybe_unused]] volatile bool sv_key_gt_check = (sv_for_key_cmp_std_str > test_key);
            [[maybe_unused]] volatile bool sv_key_gte_check = (sv_for_key_cmp_std_str >= test_key);

            std::ostringstream key_os; key_os << test_key; [[maybe_unused]] volatile auto key_str_from_stream = key_os.str(); 
            for([[maybe_unused]] char c : test_key) {} 
        }


        // Coverage: Exercise specific toml::array methods (is_homogeneous, at, front, back, etc.)
        if (fdp.ConsumeBool()) { 
            toml::array arr_method_test;
            if (fdp.ConsumeBool()) {
                toml::value<int64_t> val_obj(fdp.ConsumeIntegral<int64_t>());
                val_obj.flags(static_cast<toml::value_flags>(fdp.ConsumeIntegralInRange(0,7)));
                arr_method_test.emplace_back(std::move(val_obj));
            }
            if (fdp.ConsumeBool()) {
                toml::value<std::string> val_obj(fdp.ConsumeRandomLengthString(5));
                val_obj.flags(static_cast<toml::value_flags>(fdp.ConsumeIntegralInRange(0,7)));
                arr_method_test.emplace_back(std::move(val_obj));
            }
            
            const auto& const_arr_method_test = arr_method_test; 
            toml::node* first_nonmatch = nullptr; const toml::node* const_first_nonmatch = nullptr; 

            [[maybe_unused]] volatile bool h_empty = arr_method_test.is_homogeneous(toml::node_type::none, first_nonmatch); 
            
            if (!arr_method_test.empty()) { 
                [[maybe_unused]] volatile bool h_none = arr_method_test.is_homogeneous(toml::node_type::none, first_nonmatch); 
                [[maybe_unused]] volatile bool h_int = arr_method_test.is_homogeneous(toml::node_type::integer, first_nonmatch); 
                [[maybe_unused]] volatile bool h_const_none = const_arr_method_test.is_homogeneous(toml::node_type::none, const_first_nonmatch); 

                [[maybe_unused]] auto& front_n = arr_method_test.front(); 
                [[maybe_unused]] auto& back_n = arr_method_test.back(); 
                [[maybe_unused]] auto& at_n = arr_method_test.at(0); 
                [[maybe_unused]] auto get_n = arr_method_test.get(0); 
                // Coverage: toml::array::get(unsigned long) const
                [[maybe_unused]] const auto get_const_val = const_arr_method_test.get(0);


                [[maybe_unused]] auto& op_idx_n = arr_method_test[0];
                [[maybe_unused]] const auto& const_at_n = const_arr_method_test.at(0);
                [[maybe_unused]] const auto& const_front_n = const_arr_method_test.front();
                [[maybe_unused]] const auto& const_back_n = const_arr_method_test.back();
                [[maybe_unused]] const auto const_get_n = const_arr_method_test.get(0);

                if (arr_method_test.front().is_integer()) arr_method_test.front().as_integer()->flags(toml::value_flags::format_as_hexadecimal);
                else if (arr_method_test.front().is_string()) arr_method_test.front().as_string()->flags(toml::value_flags::none);

                if (fdp.ConsumeBool() && !arr_method_test.empty()) {
                     arr_method_test.erase(arr_method_test.cbegin());
                }
                if (fdp.ConsumeBool() && arr_method_test.size() >= 2) { 
                     arr_method_test.erase(arr_method_test.cbegin(), arr_method_test.cbegin() + 1);
                }
                try {
                    if (!arr_method_test.empty()) [[maybe_unused]] volatile auto& oor_at = arr_method_test.at(arr_method_test.size()); 
                    else [[maybe_unused]] volatile auto& oor_at_empty = arr_method_test.at(0); 
                } catch (const std::out_of_range&) { }

                if(!arr_method_test.empty()) arr_method_test.pop_back(); 
            }
            // Coverage: toml::array::insert(const_iterator, ...)
            if (fdp.ConsumeBool() && !arr_method_test.empty()) {
                arr_method_test.insert(arr_method_test.cbegin(), fdp.ConsumeIntegral<int64_t>());
            } else if (fdp.ConsumeBool()) {
                 arr_method_test.insert(arr_method_test.end(), fdp.ConsumeRandomLengthString(3));
            }
            if (fdp.ConsumeBool()) { // Insert value at random valid position
                toml::value<double> val_to_insert(fdp.ConsumeFloatingPoint<double>());
                // Memory safety: val_to_insert is moved into the array.
                arr_method_test.insert(arr_method_test.begin() + fdp.ConsumeIntegralInRange<size_t>(0, arr_method_test.size()), std::move(val_to_insert));
            }
            // Coverage: toml::array::as_table() and const version
            [[maybe_unused]] auto arr_as_tbl_ptr = arr_method_test.as_table();
            [[maybe_unused]] auto const_arr_as_tbl_ptr = const_arr_method_test.as_table();


            for(auto it = arr_method_test.cbegin(); it != arr_method_test.cend(); ++it) {
                [[maybe_unused]] volatile auto node_type = it->type();
            }
            for(auto it = const_arr_method_test.cbegin(); it != const_arr_method_test.cend(); ++it) {
                [[maybe_unused]] volatile auto node_type = it->type();
            }

            [[maybe_unused]] volatile size_t arr_max_s = arr_method_test.max_size(); 
            
            arr_method_test.shrink_to_fit();
            if (!arr_method_test.empty()) arr_method_test.truncate(fdp.ConsumeIntegralInRange<size_t>(0, arr_method_test.size()/2));


            toml::array arr_method_test2; arr_method_test2.emplace_back(1); 
            [[maybe_unused]] volatile bool arr_eq = (arr_method_test == arr_method_test2); 
            [[maybe_unused]] volatile bool arr_neq = (arr_method_test != arr_method_test2);

            toml::array arr_assign_copy_src;
            arr_assign_copy_src.emplace_back(fdp.ConsumeRandomLengthString(3));
            arr_method_test2 = arr_assign_copy_src; 
            toml::array arr_assign_move_src;
            arr_assign_move_src.emplace_back(fdp.ConsumeIntegral<int64_t>());
            arr_method_test2 = std::move(arr_assign_move_src); 


            toml::array arr_flatten_test;
            arr_flatten_test.emplace_back(10);
            toml::array nested_arr_for_flatten; nested_arr_for_flatten.emplace_back(20); nested_arr_for_flatten.emplace_back(30);
            arr_flatten_test.emplace_back(std::move(nested_arr_for_flatten));
            arr_flatten_test.emplace_back(40);
            [[maybe_unused]] toml::array flattened_arr_ref = arr_flatten_test.flatten(); 

            toml::array arr_flatten_test_move;
            arr_flatten_test_move.emplace_back(50);
            toml::array nested_arr_for_flatten_move; nested_arr_for_flatten_move.emplace_back(60);
            arr_flatten_test_move.emplace_back(std::move(nested_arr_for_flatten_move));
            [[maybe_unused]] toml::array flattened_arr_rval = std::move(arr_flatten_test_move).flatten(); 


            std::ostringstream arr_s; 
            arr_s << arr_method_test; 
            [[maybe_unused]] volatile auto arr_str_out = arr_s.str();

            arr_method_test.clear(); 

            // Coverage: toml::array::array(std::initializer_list)
            if (fdp.ConsumeBool()) {
                // Memory safety: Elements are created and managed by the array.
                toml::array arr_init_list{fdp.ConsumeIntegral<int64_t>(), fdp.ConsumeRandomLengthString(5), fdp.ConsumeBool()};
                [[maybe_unused]] volatile size_t s = arr_init_list.size(); 
            }
            if (fdp.ConsumeBool()) {
                toml::array arr_empty_init_list{}; // Test empty initializer list
                [[maybe_unused]] volatile size_t s = arr_empty_init_list.size();
            }
        }


        // Coverage: Exercise JSON and YAML formatters (targets json_formatter.inl, yaml_formatter.inl)
        // Also targets rvalue operator<< for formatters.
        if (fdp.ConsumeBool()) {
            std::ostringstream json_s;
            toml::json_formatter jf{ root_table }; 
            json_s << std::move(jf); // Coverage: Call operator<<(ostream, json_formatter&&)
            [[maybe_unused]] volatile auto json_str = json_s.str();
        }
        if (fdp.ConsumeBool()) {
            std::ostringstream yaml_s;
            toml::yaml_formatter yf{ root_table };
            yaml_s << std::move(yf); // Coverage: Call operator<<(ostream, yaml_formatter&&)
            [[maybe_unused]] volatile auto yaml_str = yaml_s.str();
        }
        // === End Added Code for Coverage Enhancement (Path, AtPath, Array Homogeneous, Formatters) ===

        // === Begin Added Code for Coverage Enhancement (Date/Time/DateTime/TimeOffset) ===
        if (fdp.ConsumeBool()) {
            toml::date d1{fdp.ConsumeIntegralInRange<int16_t>(1, 9999), 
                          fdp.ConsumeIntegralInRange<uint8_t>(1,12), 
                          fdp.ConsumeIntegralInRange<uint8_t>(1,28)}; 
            toml::date d2{fdp.ConsumeIntegralInRange<int16_t>(1, 9999), 
                          fdp.ConsumeIntegralInRange<uint8_t>(1,12), 
                          fdp.ConsumeIntegralInRange<uint8_t>(1,28)};
            [[maybe_unused]] volatile bool d_eq = (d1 == d2); 
            [[maybe_unused]] volatile bool d_neq = (d1 != d2); 
            [[maybe_unused]] volatile bool d_lt = (d1 < d2);   
            [[maybe_unused]] volatile bool d_lte = (d1 <= d2); 
            [[maybe_unused]] volatile bool d_gt = (d1 > d2);   
            [[maybe_unused]] volatile bool d_gte = (d1 >= d2); 
            std::ostringstream date_s; date_s << d1; [[maybe_unused]] volatile auto date_str = date_s.str(); 

            toml::time t1{fdp.ConsumeIntegralInRange<uint8_t>(0,23), 
                          fdp.ConsumeIntegralInRange<uint8_t>(0,59), 
                          fdp.ConsumeIntegralInRange<uint8_t>(0,59), 
                          fdp.ConsumeIntegralInRange<uint32_t>(0,999999999)};
            toml::time t2{fdp.ConsumeIntegralInRange<uint8_t>(0,23), 
                          fdp.ConsumeIntegralInRange<uint8_t>(0,59), 
                          fdp.ConsumeIntegralInRange<uint8_t>(0,59), 
                          fdp.ConsumeIntegralInRange<uint32_t>(0,999999999)};
            [[maybe_unused]] volatile bool t_eq = (t1 == t2);   
            [[maybe_unused]] volatile bool t_neq = (t1 != t2); 
            [[maybe_unused]] volatile bool t_lt = (t1 < t2);   
            [[maybe_unused]] volatile bool t_lte = (t1 <= t2); 
            [[maybe_unused]] volatile bool t_gt = (t1 > t2);   
            [[maybe_unused]] volatile bool t_gte = (t1 >= t2); 
            std::ostringstream time_s; time_s << t1; [[maybe_unused]] volatile auto time_str = time_s.str(); 

            int16_t total_minutes1 = fdp.ConsumeIntegralInRange<int16_t>(-23*60, 23*60);
            int16_t offset_hours1 = total_minutes1 / 60;
            int16_t offset_minutes1 = total_minutes1 % 60;
            toml::time_offset to1{offset_hours1, offset_minutes1};

            int16_t total_minutes2 = fdp.ConsumeIntegralInRange<int16_t>(-23*60, 23*60);
            int16_t offset_hours2 = total_minutes2 / 60;
            int16_t offset_minutes2 = total_minutes2 % 60;
            toml::time_offset to2{offset_hours2, offset_minutes2};

            [[maybe_unused]] volatile bool to_eq = (to1 == to2);   
            [[maybe_unused]] volatile bool to_neq = (to1 != to2); 
            [[maybe_unused]] volatile bool to_lt = (to1 < to2);   
            [[maybe_unused]] volatile bool to_lte = (to1 <= to2); 
            [[maybe_unused]] volatile bool to_gt = (to1 > to2);   
            [[maybe_unused]] volatile bool to_gte = (to1 >= to2); 
            std::ostringstream time_offset_s; time_offset_s << to1; [[maybe_unused]] volatile auto to_str = time_offset_s.str(); 
            
            toml::date_time dt1{d1, t1}; 
            toml::date_time dt2{d2, t2, to1}; 
            [[maybe_unused]] volatile bool dt_is_local1 = dt1.is_local(); 
            [[maybe_unused]] volatile bool dt_is_local2 = dt2.is_local();
            if(dt2.offset) { [[maybe_unused]] volatile auto off_val = *dt2.offset; } 
            [[maybe_unused]] volatile bool dt_eq = (dt1 == dt2);   
            [[maybe_unused]] volatile bool dt_neq = (dt1 != dt2); 
            [[maybe_unused]] volatile bool dt_lt = (dt1 < dt2);   
            [[maybe_unused]] volatile bool dt_lte = (dt1 <= dt2); 
            [[maybe_unused]] volatile bool dt_gt = (dt1 > dt2);   
            [[maybe_unused]] volatile bool dt_gte = (dt1 >= dt2); 
            std::ostringstream date_time_s; date_time_s << dt1; [[maybe_unused]] volatile auto dt_str = date_time_s.str(); 

            [[maybe_unused]] toml::date_time dt_from_d(d1); 
            [[maybe_unused]] toml::date_time dt_from_t(t1); 
        }
        // === End Added Code for Coverage Enhancement (Date/Time/DateTime/TimeOffset) ===

        // === Begin Added Code for Coverage Enhancement (Literals and Table Ops) ===
        if (fdp.ConsumeBool()) {
            using namespace toml::literals;
            try {
                [[maybe_unused]] auto parsed_from_lit = "fixed_key = 123"_toml;
            } catch (const toml::parse_error&) { }

            toml::table tbl_eq1, tbl_eq2;
            if (fdp.ConsumeBool()) tbl_eq1.insert("a", 1);
            if (fdp.ConsumeBool()) tbl_eq2.insert("a", (fdp.ConsumeBool() ? 1 : 2) );
            if (fdp.ConsumeBool()) tbl_eq1.insert("b", fdp.ConsumeRandomLengthString(4));
            if (fdp.ConsumeBool()) tbl_eq2.insert("b", (fdp.ConsumeBool() ? tbl_eq1["b"].value_or<std::string>("") : fdp.ConsumeRandomLengthString(3)) );
            
            [[maybe_unused]] volatile bool table_is_equal = (tbl_eq1 == tbl_eq2); 
            [[maybe_unused]] volatile bool table_is_not_equal = (tbl_eq1 != tbl_eq2); 

            // Coverage: table::table(std::initializer_list)
            // Memory safety: Elements are created and managed by the table.
            toml::table tbl_init_list{
                {fdp.ConsumeRandomLengthString(5), toml::value{fdp.ConsumeIntegral<int64_t>()}},
                {fdp.ConsumeRandomLengthString(5), toml::value{fdp.ConsumeRandomLengthString(5)}}
            };
            if (fdp.ConsumeBool()) { // Add a nested table/array
                 if (fdp.ConsumeBool()) tbl_init_list.insert(fdp.ConsumeRandomLengthString(4), toml::table{});
                 else tbl_init_list.insert(fdp.ConsumeRandomLengthString(4), toml::array{});
            }
            [[maybe_unused]] volatile size_t s_tbl_init = tbl_init_list.size();
            if (fdp.ConsumeBool()) {
                toml::table tbl_empty_init_list{}; // Test empty initializer list
                [[maybe_unused]] volatile size_t s_tbl_empty_init = tbl_empty_init_list.size();
            }
        }
        // === End Added Code for Coverage Enhancement (Literals and Table Ops) ===
        
        // === Begin Added Code for Coverage Enhancement (Table const methods and rvalue prune) ===
        // Coverage: table const methods
        if (!const_root_table.empty()) {
            auto first_key_node_const_iter = const_root_table.cbegin(); // Renamed to avoid conflict
            if (first_key_node_const_iter != const_root_table.cend()) {
                 std::string_view key_sv_const = first_key_node_const_iter->first;
                 [[maybe_unused]] auto get_node_const = const_root_table.get(key_sv_const);
                 [[maybe_unused]] auto lower_b_const = const_root_table.lower_bound(key_sv_const);
                 [[maybe_unused]] volatile bool contains_const = const_root_table.contains(key_sv_const); 
                 [[maybe_unused]] auto bracket_const = const_root_table[key_sv_const]; 
                 [[maybe_unused]] auto find_const_iter = const_root_table.find(key_sv_const); // Coverage: const table::find
                 if (find_const_iter != const_root_table.cend()) { /* use it */ }
            }
        }
        [[maybe_unused]] volatile size_t size_const = const_root_table.size(); 

        // Coverage: table::prune(bool)&&
        if (fdp.ConsumeBool()) {
            toml::table temp_copy_tbl = root_table; // Memory safety: deep copy
            // Memory safety: std::move invalidates temp_copy_tbl, pruned_rval_tbl takes ownership.
            [[maybe_unused]] auto pruned_rval_tbl = std::move(temp_copy_tbl).prune(fdp.ConsumeBool());
        }
        // === End Added Code for Coverage Enhancement (Table const methods and rvalue prune) ===

        // === Begin Added Code for Coverage Enhancement (node to node_view implicit conversion) ===
        // Coverage: node implicit conversion to node_view
        if (fdp.ConsumeBool() && !root_table.empty()) {
            toml::node& first_node_ref = root_table.begin()->second; 
            toml::node_view<toml::node> nv_implicit(first_node_ref); // Explicit constructor call
            [[maybe_unused]] volatile auto nv_type_impl = nv_implicit.type();

            const toml::node& const_first_node_ref = const_root_table.cbegin()->second;
            toml::node_view<const toml::node> const_nv_implicit(const_first_node_ref); // Explicit constructor call
            [[maybe_unused]] volatile auto const_nv_type_impl = const_nv_implicit.type();
        }
        // === End Added Code for Coverage Enhancement (node to node_view implicit conversion) ===

        // === Begin Added Code for Coverage Enhancement (value<T> specific methods) ===
        // Coverage: value<T>::is_homogeneous with mismatch pointer
        if (fdp.ConsumeBool()) {
            toml::value<int64_t> val_int_hom(fdp.ConsumeIntegral<int64_t>());
            toml::node* mismatch_node = nullptr;
            const toml::node* const_mismatch_node = nullptr;

            [[maybe_unused]] volatile bool hom_check_val1 = val_int_hom.is_homogeneous(toml::node_type::integer, mismatch_node); 
            [[maybe_unused]] volatile bool hom_check_val2 = val_int_hom.is_homogeneous(toml::node_type::string, mismatch_node);  
            if (mismatch_node == &val_int_hom) { [[maybe_unused]] volatile auto mt = mismatch_node->type(); }
            
            const toml::value<std::string> const_val_str_hom(fdp.ConsumeRandomLengthString(5));
            [[maybe_unused]] volatile bool hom_check_val3 = const_val_str_hom.is_homogeneous(toml::node_type::string, const_mismatch_node); 
            [[maybe_unused]] volatile bool hom_check_val4 = const_val_str_hom.is_homogeneous(toml::node_type::boolean, const_mismatch_node); 
            if (const_mismatch_node == &const_val_str_hom) { [[maybe_unused]] volatile auto cmt = const_mismatch_node->type(); }
        }
        // Coverage: value<T>::value(const value<T>&, value_flags)
        if (fdp.ConsumeBool()) { // For int64_t (existing)
            toml::value<int64_t> v_orig(fdp.ConsumeIntegral<int64_t>());
            v_orig.flags(fdp.ConsumeBool() ? toml::value_flags::format_as_hexadecimal : toml::value_flags::none);
            // Memory safety: v_copy_preserve and v_copy_new_flags are new objects, copying data from v_orig.
            toml::value<int64_t> v_copy_preserve(v_orig, toml::preserve_source_value_flags);
            [[maybe_unused]] volatile auto vcp_f = v_copy_preserve.flags();
            toml::value_flags new_flags = static_cast<toml::value_flags>(fdp.ConsumeIntegralInRange(0,2)); 
            if (new_flags == toml::preserve_source_value_flags) new_flags = toml::value_flags::none;
            toml::value<int64_t> v_copy_new_flags(v_orig, new_flags);
            [[maybe_unused]] volatile auto vcnf_f = v_copy_new_flags.flags();
        }
        // Coverage: value<T>::value(const value<T>&, value_flags) for bool
        if (fdp.ConsumeBool()) { 
            toml::value<bool> v_orig_b(fdp.ConsumeBool());
            v_orig_b.flags(fdp.ConsumeBool() ? toml::value_flags::format_as_binary : toml::value_flags::none); // binary doesn't apply but tests flags
            toml::value<bool> v_copy_preserve_b(v_orig_b, toml::preserve_source_value_flags); // Memory safety: new object
            [[maybe_unused]] volatile auto vcp_f_b = v_copy_preserve_b.flags();
            toml::value_flags new_flags_b = static_cast<toml::value_flags>(fdp.ConsumeIntegralInRange(0,2));
            if (new_flags_b == toml::preserve_source_value_flags) new_flags_b = toml::value_flags::none;
            toml::value<bool> v_copy_new_flags_b(v_orig_b, new_flags_b); // Memory safety: new object
            [[maybe_unused]] volatile auto vcnf_f_b = v_copy_new_flags_b.flags();
        }
        // Coverage: value<T>::value(const value<T>&, value_flags) for time
        if (fdp.ConsumeBool()) { 
            toml::time t_src{fdp.ConsumeIntegralInRange<uint8_t>(0,23), fdp.ConsumeIntegralInRange<uint8_t>(0,59), fdp.ConsumeIntegralInRange<uint8_t>(0,59)};
            toml::value<toml::time> v_orig_t(t_src);
            v_orig_t.flags(toml::value_flags::none); // Time values don't have specific format flags like hex/bin
            toml::value<toml::time> v_copy_preserve_t(v_orig_t, toml::preserve_source_value_flags); // Memory safety: new object
            [[maybe_unused]] volatile auto vcp_f_t = v_copy_preserve_t.flags();
            toml::value_flags new_flags_t = static_cast<toml::value_flags>(fdp.ConsumeIntegralInRange(0,2)); 
             if (new_flags_t == toml::preserve_source_value_flags) new_flags_t = toml::value_flags::none;
            toml::value<toml::time> v_copy_new_flags_t(v_orig_t, new_flags_t); // Memory safety: new object
            [[maybe_unused]] volatile auto vcnf_f_t = v_copy_new_flags_t.flags();
        }
        // === End Added Code for Coverage Enhancement (value<T> specific methods) ===
        
        // === Begin Added Code for Coverage Enhancement (value<bool> methods) ===
        if (fdp.ConsumeBool()) {
            toml::value<bool> bool_val(fdp.ConsumeBool()); // Memory safety: stack object
            const auto& const_bool_val = bool_val;

            [[maybe_unused]] volatile auto b_type = bool_val.type(); // Coverage: value<bool>::type()
            [[maybe_unused]] volatile bool b_is_table = bool_val.is_table(); // Coverage: value<bool>::is_table()
            [[maybe_unused]] volatile bool b_is_array = bool_val.is_array(); // Coverage: value<bool>::is_array()
            [[maybe_unused]] volatile bool b_is_val = bool_val.is_value();   // Coverage: value<bool>::is_value()
            [[maybe_unused]] volatile bool b_is_str = bool_val.is_string();
            [[maybe_unused]] volatile bool b_is_int = bool_val.is_integer();
            [[maybe_unused]] volatile bool b_is_fp = bool_val.is_floating_point();
            [[maybe_unused]] volatile bool b_is_bool = bool_val.is_boolean(); 
            [[maybe_unused]] volatile bool b_is_date = bool_val.is_date();
            [[maybe_unused]] volatile bool b_is_time = bool_val.is_time();
            [[maybe_unused]] volatile bool b_is_dt = bool_val.is_date_time();

            [[maybe_unused]] volatile auto b_as_str = bool_val.as_string(); if(b_as_str){} // Coverage: value<bool>::as_string()
            [[maybe_unused]] volatile auto b_as_int = bool_val.as_integer(); if(b_as_int){} // Coverage: value<bool>::as_integer()
            [[maybe_unused]] volatile auto b_as_fp = bool_val.as_floating_point(); if(b_as_fp){} // Coverage: value<bool>::as_floating_point()
            [[maybe_unused]] volatile auto b_as_bool = bool_val.as_boolean(); if(b_as_bool){ volatile bool b_get = b_as_bool->get(); (void)b_get; }

            [[maybe_unused]] volatile auto const_b_type = const_bool_val.type();
            [[maybe_unused]] volatile auto const_b_as_bool = const_bool_val.as_boolean(); if(const_b_as_bool){ volatile bool cb_get = const_b_as_bool->get(); (void)cb_get; }

            volatile bool bool_get_val = bool_val.get(); (void)bool_get_val; // Coverage: value<bool>::get()
            volatile bool bool_op_star_val = *bool_val; (void)bool_op_star_val; // Coverage: value<bool>::operator*()
            volatile bool const_bool_get_val = const_bool_val.get(); (void)const_bool_get_val;
            volatile bool const_bool_op_star_val = *const_bool_val; (void)const_bool_op_star_val;

            bool_val.flags(toml::value_flags::none); // Coverage: value<bool>::flags(value_flags)
        }
        // === End Added Code for Coverage Enhancement (value<bool> methods) ===

        // === Begin Added Code for Coverage Enhancement (value<string> specific as_X methods) ===
        if (fdp.ConsumeBool()) {
            toml::value<std::string> str_val(fdp.ConsumeRandomLengthString(10)); // Memory safety: stack object
            [[maybe_unused]] volatile auto sv_as_bool = str_val.as_boolean(); if(sv_as_bool){} // Coverage
            [[maybe_unused]] volatile auto sv_as_date = str_val.as_date(); if(sv_as_date){}       // Coverage
            [[maybe_unused]] volatile auto sv_as_time = str_val.as_time(); if(sv_as_time){}       // Coverage
            [[maybe_unused]] volatile auto sv_as_dt = str_val.as_date_time(); if(sv_as_dt){}   // Coverage
        }
        // === End Added Code for Coverage Enhancement (value<string> specific as_X methods) ===


        // === Begin Added Code for Coverage Enhancement (Bitwise flag operators) ===
        // Coverage: Bitwise operators for value_flags and format_flags
        if (fdp.ConsumeBool()) {
            toml::value_flags vf1 = static_cast<toml::value_flags>(fdp.ConsumeIntegralInRange(0,7));
            toml::value_flags vf2 = static_cast<toml::value_flags>(fdp.ConsumeIntegralInRange(0,7));
            [[maybe_unused]] volatile auto vf_or = vf1 | vf2;
            [[maybe_unused]] volatile auto vf_and = vf1 & vf2;
            [[maybe_unused]] volatile auto vf_xor = vf1 ^ vf2;
            [[maybe_unused]] volatile auto vf_not = ~vf1;
            vf1 |= vf2; [[maybe_unused]] volatile auto vf1a = vf1;
            vf1 &= vf2; [[maybe_unused]] volatile auto vf1b = vf1;
            vf1 ^= vf2; [[maybe_unused]] volatile auto vf1c = vf1;

            toml::format_flags ff1 = static_cast<toml::format_flags>(fdp.ConsumeIntegralInRange(0,3));
            toml::format_flags ff2 = static_cast<toml::format_flags>(fdp.ConsumeIntegralInRange(0,3));
            [[maybe_unused]] volatile auto ff_or = ff1 | ff2;
            [[maybe_unused]] volatile auto ff_and = ff1 & ff2;
            [[maybe_unused]] volatile auto ff_xor = ff1 ^ ff2;
            [[maybe_unused]] volatile auto ff_not = ~ff1;
            ff1 |= ff2; [[maybe_unused]] volatile auto ff1a = ff1;
            ff1 &= ff2; [[maybe_unused]] volatile auto ff1b = ff1;
            ff1 ^= ff2; [[maybe_unused]] volatile auto ff1c = ff1;
        }
        // === End Added Code for Coverage Enhancement (Bitwise flag operators) ===

        // === Begin Added Code for Coverage Enhancement (Table operations: clear, assign, erase, find, is_homogeneous) ===
        if (fdp.ConsumeBool() && !root_table.empty()) {
            toml::table copy_for_clear = root_table; // Memory safety: deep copy
            copy_for_clear.clear(); // Coverage: table::clear()
            [[maybe_unused]] volatile size_t s = copy_for_clear.size(); 
        }
        if (fdp.ConsumeBool()) {
            toml::table tbl_assign_src1, tbl_assign_dest1; // Memory safety: stack objects
            tbl_assign_src1.insert("k1", "v1");
            tbl_assign_dest1 = tbl_assign_src1; // Coverage: table copy assignment
            [[maybe_unused]] volatile size_t s1 = tbl_assign_dest1.size();

            toml::table tbl_assign_src2, tbl_assign_dest2; // Memory safety: stack objects
            tbl_assign_src2.insert("k2", 123);
            tbl_assign_dest2 = std::move(tbl_assign_src2); // Coverage: table move assignment
            [[maybe_unused]] volatile size_t s2 = tbl_assign_dest2.size();
        }
        if (fdp.ConsumeBool() && !root_table.empty()) {
            toml::table tbl_erase_test = root_table; // Memory safety: deep copy
            if (!tbl_erase_test.empty()) {
                auto it_erase = tbl_erase_test.begin();
                tbl_erase_test.erase(it_erase); // Coverage: table::erase(iterator)
            }
            if (tbl_erase_test.size() >= 2) { // Re-check size after potential erase
                auto it_erase_begin = tbl_erase_test.begin();
                auto it_erase_end = std::next(it_erase_begin);
                tbl_erase_test.erase(it_erase_begin, it_erase_end); // Coverage: table::erase(iterator, iterator)
            }
             if (!tbl_erase_test.empty()) { // Re-check size
                std::string key_to_erase = std::string(tbl_erase_test.begin()->first);
                [[maybe_unused]] size_t erased_count = tbl_erase_test.erase(key_to_erase); // Coverage: table::erase(key_type)
            }
        }
        if (fdp.ConsumeBool() && !root_table.empty()) {
            toml::table tbl_erase_const_test = root_table; // Memory safety: deep copy
            if (!tbl_erase_const_test.empty()) {
                auto cit_erase = tbl_erase_const_test.cbegin();
                tbl_erase_const_test.erase(cit_erase); // Coverage: table::erase(const_iterator)
            }
             if (tbl_erase_const_test.size() >=2) { // Re-check size
                auto cit_erase_begin = tbl_erase_const_test.cbegin();
                auto cit_erase_end = std::next(cit_erase_begin);
                tbl_erase_const_test.erase(cit_erase_begin, cit_erase_end); // Coverage: table::erase(const_iterator, const_iterator)
            }
        }
        if (!root_table.empty()) { // Non-const find
            auto first_key_node_iter = root_table.begin();
            if (first_key_node_iter != root_table.end()) {
                std::string_view key_sv = first_key_node_iter->first;
                [[maybe_unused]] auto find_iter = root_table.find(key_sv); // Coverage: non-const table::find
                if (find_iter != root_table.end()) { /* use it */ }
            }
        }
        if (fdp.ConsumeBool() && !root_table.empty()) { // table::is_homogeneous
            toml::node* first_mismatch_tbl = nullptr;
            const toml::node* const_first_mismatch_tbl = nullptr;
            [[maybe_unused]] volatile bool tbl_hom_none = root_table.is_homogeneous(toml::node_type::none, first_mismatch_tbl);
            [[maybe_unused]] volatile bool tbl_hom_int = root_table.is_homogeneous(toml::node_type::integer, first_mismatch_tbl);
            [[maybe_unused]] volatile bool const_tbl_hom_none = const_root_table.is_homogeneous(toml::node_type::none, const_first_mismatch_tbl);
            [[maybe_unused]] volatile bool const_tbl_hom_val = const_root_table.is_homogeneous(toml::node_type::string); 
        }
        // === End Added Code for Coverage Enhancement (Table operations) ===


        // Coverage: std::out_of_range from table::at()
        if (!root_table.empty() && fdp.ConsumeBool()) {
            try {
                [[maybe_unused]] volatile auto& oor_tbl_at = root_table.at(fdp.ConsumeRandomLengthString(15) + "_non_existent_");
            } catch (const std::out_of_range&) { }
        }


        volatile bool root_is_date = root_table.is_date();
        volatile bool const_root_is_date = const_root_table.is_date(); 

        volatile toml::value<toml::time>* root_as_time = root_table.as_time();
        if (root_as_time) { }
        volatile const toml::value<toml::time>* const_root_as_time = const_root_table.as_time(); 
        if (const_root_as_time) {}


        volatile bool root_is_integer = root_table.is_integer();
        volatile bool const_root_is_integer = const_root_table.is_integer(); 


        volatile bool root_is_string = root_table.is_string(); 
        volatile toml::value<std::string>* root_as_string = root_table.as_string(); 
        if (root_as_string) {} 
        volatile bool const_root_is_string = const_root_table.is_string(); 
        volatile auto const_root_as_string_ptr = const_root_table.as_string(); if(const_root_as_string_ptr){} 

        volatile bool root_is_fp = root_table.is_floating_point(); 
        volatile toml::value<double>* root_as_fp = root_table.as_floating_point(); 
        if (root_as_fp) {}
        volatile bool const_root_is_fp = const_root_table.is_floating_point(); 
        volatile auto const_root_as_fp_ptr = const_root_table.as_floating_point(); if(const_root_as_fp_ptr){} 


        volatile bool root_is_bool = root_table.is_boolean(); 
        volatile toml::value<bool>* root_as_bool = root_table.as_boolean(); 
        if (root_as_bool) {}
        volatile bool const_root_is_bool = const_root_table.is_boolean(); 
        volatile auto const_root_as_bool_ptr = const_root_table.as_boolean(); if(const_root_as_bool_ptr){} 

        volatile bool root_is_datetime = root_table.is_date_time(); 
        volatile toml::value<toml::date_time>* root_as_datetime = root_table.as_date_time(); 
        if (root_as_datetime) {}
        volatile bool const_root_is_datetime = const_root_table.is_date_time(); 
        volatile auto const_root_as_datetime_ptr = const_root_table.as_date_time(); if(const_root_as_datetime_ptr){} 

        volatile bool root_is_time_check = root_table.is_time(); 
        volatile toml::value<toml::date>* root_as_date = root_table.as_date(); 
        if (root_as_date) {}
        volatile bool const_root_is_time_check = const_root_table.is_time(); 
        volatile auto const_root_as_date_ptr = const_root_table.as_date(); if(const_root_as_date_ptr){} 


        for (auto&& [key, node_view] : root_table) {
            exercise_node_type_apis(&node_view); 

            if (node_view.is_array()) { 
                toml::array* arr = node_view.as_array();
                if (arr) {
                    const toml::array* const_arr = arr; 

                    [[maybe_unused]] volatile bool arr_is_tbl = arr->is_table();
                    [[maybe_unused]] volatile bool arr_is_val = arr->is_value();
                    [[maybe_unused]] toml::table* arr_as_tbl = arr->as_table(); 
                    [[maybe_unused]] volatile bool const_arr_is_tbl = const_arr->is_table();
                    [[maybe_unused]] volatile bool const_arr_is_val = const_arr->is_value();
                    [[maybe_unused]] const toml::table* const_arr_as_tbl = const_arr->as_table(); 


                    volatile bool arr_is_number = arr->is_number();
                    volatile toml::value<int64_t>* arr_as_integer = arr->as_integer();
                    if (arr_as_integer) { }
                    volatile bool const_arr_is_number = const_arr->is_number(); 
                    volatile auto const_arr_as_integer_ptr = const_arr->as_integer(); if(const_arr_as_integer_ptr){} 


                    volatile bool arr_is_string = arr->is_string(); 
                    volatile toml::value<std::string>* arr_as_string = arr->as_string(); 
                    if (arr_as_string) {}
                    volatile bool const_arr_is_string = const_arr->is_string(); 
                    volatile auto const_arr_as_string_ptr = const_arr->as_string(); if(const_arr_as_string_ptr){} 


                    volatile bool arr_is_fp = arr->is_floating_point(); 
                    volatile toml::value<double>* arr_as_fp = arr->as_floating_point(); 
                    if (arr_as_fp) {}
                    volatile bool const_arr_is_fp = const_arr->is_floating_point(); 
                    volatile auto const_arr_as_fp_ptr = const_arr->as_floating_point(); if(const_arr_as_fp_ptr){} 

                    volatile bool arr_is_bool = arr->is_boolean(); 
                    volatile toml::value<bool>* arr_as_bool = arr->as_boolean(); 
                    if (arr_as_bool) {}
                    volatile bool const_arr_is_bool = const_arr->is_boolean(); 
                    volatile auto const_arr_as_bool_ptr = const_arr->as_boolean(); if(const_arr_as_bool_ptr){} 

                    volatile bool arr_is_datetime = arr->is_date_time(); 
                    volatile toml::value<toml::date_time>* arr_as_datetime = arr->as_date_time(); 
                    if (arr_as_datetime) {}
                    volatile bool const_arr_is_datetime = const_arr->is_date_time(); 
                    volatile auto const_arr_as_datetime_ptr = const_arr->as_date_time(); if(const_arr_as_datetime_ptr){} 
                    
                    volatile bool arr_is_time = arr->is_time(); 
                    volatile bool arr_is_date = arr->is_date(); 
                    volatile toml::value<toml::time>* arr_as_time = arr->as_time(); 
                    if (arr_as_time) {}
                    volatile toml::value<toml::date>* arr_as_date_val = arr->as_date(); 
                    if (arr_as_date_val) {}
                    volatile bool const_arr_is_time = const_arr->is_time(); 
                    volatile bool const_arr_is_date = const_arr->is_date(); 
                    volatile auto const_arr_as_time_ptr = const_arr->as_time(); if(const_arr_as_time_ptr){} 
                    volatile auto const_arr_as_date_ptr_val = const_arr->as_date(); if(const_arr_as_date_ptr_val){} 


                    for (toml::node& element_node : *arr) { 
                        exercise_node_type_apis(&element_node); 
                        if (element_node.is_table()) { 
                            toml::table* nested_table = element_node.as_table();
                            if (nested_table) {
                                const toml::table* const_nested_table = nested_table; 

                                volatile bool nested_tbl_is_date = nested_table->is_date();
                                volatile toml::value<toml::time>* nested_tbl_as_time = nested_table->as_time();
                                volatile bool nested_tbl_is_integer = nested_table->is_integer();
                                volatile bool const_nested_tbl_is_date = const_nested_table->is_date(); 
                                volatile auto const_nested_tbl_as_time = const_nested_table->as_time(); if(const_nested_tbl_as_time){}
                                volatile bool const_nested_tbl_is_integer = const_nested_table->is_integer();


                                volatile bool nt_is_string = nested_table->is_string(); 
                                volatile auto nt_as_string = nested_table->as_string(); 
                                if (nt_as_string) {}
                                volatile bool const_nt_is_string = const_nested_table->is_string(); 
                                volatile auto const_nt_as_string = const_nested_table->as_string(); if(const_nt_as_string){}

                            }
                        }
                    }
                }
            } else if (node_view.is_table()) { 
                toml::table* sub_table = node_view.as_table();
                if (sub_table) {
                    const toml::table* const_sub_table = sub_table; 

                    volatile bool sub_tbl_is_date = sub_table->is_date();
                    volatile toml::value<toml::time>* sub_tbl_as_time = sub_table->as_time();
                    volatile bool sub_tbl_is_integer = sub_table->is_integer();
                    volatile bool const_sub_tbl_is_date = const_sub_table->is_date(); 
                    volatile auto const_sub_tbl_as_time = const_sub_table->as_time(); if(const_sub_tbl_as_time){}
                    volatile bool const_sub_tbl_is_integer = const_sub_table->is_integer();

                    volatile bool st_is_string = sub_table->is_string(); 
                    volatile auto st_as_string = sub_table->as_string(); 
                    if (st_as_string) {}
                    volatile bool const_st_is_string = const_sub_table->is_string(); 
                    volatile auto const_st_as_string = const_sub_table->as_string(); if(const_st_as_string){}


                     for (auto&& [sub_key, sub_node_view_inner] : *sub_table) { 
                        exercise_node_type_apis(&sub_node_view_inner); 
                        if (sub_node_view_inner.is_array()) { 
                            toml::array* nested_arr = sub_node_view_inner.as_array();
                            if (nested_arr) {
                                const toml::array* const_nested_arr = nested_arr; 

                                volatile bool nested_arr_is_number = nested_arr->is_number();
                                volatile toml::value<int64_t>* nested_arr_as_integer = nested_arr->as_integer();
                                volatile bool const_nested_arr_is_number = const_nested_arr->is_number(); 
                                volatile auto const_nested_arr_as_integer = const_nested_arr->as_integer(); if(const_nested_arr_as_integer){}

                                volatile bool na_is_string = nested_arr->is_string(); 
                                volatile auto na_as_string = nested_arr->as_string(); 
                                if (na_as_string) {}
                                volatile bool const_na_is_string = const_nested_arr->is_string(); 
                                volatile auto const_na_as_string = const_nested_arr->as_string(); if(const_na_as_string){}

                                for (toml::node& inner_element_node : *nested_arr) { 
                                    exercise_node_type_apis(&inner_element_node); 
                                }
                            }
                        }
                    }
                }
            }
        }

    } catch (const toml::parse_error& err) {
        [[maybe_unused]] volatile auto desc = err.description();
        [[maybe_unused]] volatile auto src = err.source();
        std::ostringstream err_s; err_s << err;
        [[maybe_unused]] volatile auto err_str_out = err_s.str();
    } catch (const std::exception& ) {
    }
    return 0;
}