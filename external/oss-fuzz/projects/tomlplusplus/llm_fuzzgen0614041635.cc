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
            /* Coverage: Exercise toml::value<value_type>::is_X methods */ \
            [[maybe_unused]] volatile bool v_is_tbl = val_ptr->is_table(); \
            [[maybe_unused]] volatile bool v_is_arr = val_ptr->is_array(); \
            [[maybe_unused]] volatile bool v_is_aot = val_ptr->is_array_of_tables(); \
            [[maybe_unused]] volatile bool v_is_val = val_ptr->is_value(); \
            [[maybe_unused]] volatile bool v_is_str_node = val_ptr->is_string(); \
            [[maybe_unused]] volatile bool v_is_int_node = val_ptr->is_integer(); \
            [[maybe_unused]] volatile bool v_is_fp_node = val_ptr->is_floating_point(); \
            [[maybe_unused]] volatile bool v_is_num_node = val_ptr->is_number(); \
            [[maybe_unused]] volatile bool v_is_bool_node = val_ptr->is_boolean(); \
            [[maybe_unused]] volatile bool v_is_date_node = val_ptr->is_date(); \
            [[maybe_unused]] volatile bool v_is_time_node = val_ptr->is_time(); \
            [[maybe_unused]] volatile bool v_is_dt_node = val_ptr->is_date_time(); \
            /* Coverage: Exercise toml::value<value_type>::as_X methods */ \
            [[maybe_unused]] volatile auto v_as_str = val_ptr->as_string(); if(v_as_str){} \
            [[maybe_unused]] volatile auto v_as_int = val_ptr->as_integer(); if(v_as_int){} \
            [[maybe_unused]] volatile auto v_as_flt = val_ptr->as_floating_point(); if(v_as_flt){} \
            [[maybe_unused]] volatile auto v_as_bool = val_ptr->as_boolean(); if(v_as_bool){} \
            [[maybe_unused]] volatile auto v_as_date = val_ptr->as_date(); if(v_as_date){} \
            [[maybe_unused]] volatile auto v_as_time = val_ptr->as_time(); if(v_as_time){} \
            [[maybe_unused]] volatile auto v_as_datetime = val_ptr->as_date_time(); if(v_as_datetime){} \
            [[maybe_unused]] volatile auto v_as_tbl_ptr = val_ptr->as_table(); if(v_as_tbl_ptr){} \
            [[maybe_unused]] volatile auto v_as_arr_ptr = val_ptr->as_array(); if(v_as_arr_ptr){} \
        } \
    } \
    if (const_node_obj.type_check_method()) { /* Exercise const node APIs */ \
        const toml::value<value_type>* const_val_ptr = const_node_obj.type_cast_method(); \
        if (const_val_ptr) { /* Coverage: Hit true branch for const node::as_X() */ \
            volatile value_type const_actual_val = const_val_ptr->get(); (void)const_actual_val; \
            /* Coverage: Exercise const toml::value<value_type>::is_X methods */ \
            [[maybe_unused]] volatile bool cv_is_tbl = const_val_ptr->is_table(); \
            [[maybe_unused]] volatile bool cv_is_arr = const_val_ptr->is_array(); \
            [[maybe_unused]] volatile bool cv_is_aot = const_val_ptr->is_array_of_tables(); \
            [[maybe_unused]] volatile bool cv_is_val = const_val_ptr->is_value(); \
            [[maybe_unused]] volatile bool cv_is_str_node = const_val_ptr->is_string(); \
            [[maybe_unused]] volatile bool cv_is_int_node = const_val_ptr->is_integer(); \
            [[maybe_unused]] volatile bool cv_is_fp_node = const_val_ptr->is_floating_point(); \
            [[maybe_unused]] volatile bool cv_is_num_node = const_val_ptr->is_number(); \
            [[maybe_unused]] volatile bool cv_is_bool_node = const_val_ptr->is_boolean(); \
            [[maybe_unused]] volatile bool cv_is_date_node = const_val_ptr->is_date(); \
            [[maybe_unused]] volatile bool cv_is_time_node = const_val_ptr->is_time(); \
            [[maybe_unused]] volatile bool cv_is_dt_node = const_val_ptr->is_date_time(); \
            /* Coverage: Exercise const toml::value<value_type>::as_X methods */ \
            [[maybe_unused]] volatile auto cv_as_str = const_val_ptr->as_string(); if(cv_as_str){} \
            [[maybe_unused]] volatile auto cv_as_int = const_val_ptr->as_integer(); if(cv_as_int){} \
            [[maybe_unused]] volatile auto cv_as_flt = const_val_ptr->as_floating_point(); if(cv_as_flt){} \
            [[maybe_unused]] volatile auto cv_as_bool = const_val_ptr->as_boolean(); if(cv_as_bool){} \
            [[maybe_unused]] volatile auto cv_as_date = const_val_ptr->as_date(); if(cv_as_date){} \
            [[maybe_unused]] volatile auto cv_as_time = const_val_ptr->as_time(); if(cv_as_time){} \
            [[maybe_unused]] volatile auto cv_as_datetime = const_val_ptr->as_date_time(); if(cv_as_datetime){} \
            [[maybe_unused]] volatile auto cv_as_tbl_ptr = const_val_ptr->as_table(); if(cv_as_tbl_ptr){} \
            [[maybe_unused]] volatile auto cv_as_arr_ptr = const_val_ptr->as_array(); if(cv_as_arr_ptr){} \
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

        // === Begin Added Code for Coverage Enhancement (table is_X/as_X methods) ===
        // Coverage: Exercise toml::table::is_X() methods
        [[maybe_unused]] volatile bool tbl_is_arr_node = root_table.is_array();
        [[maybe_unused]] volatile bool tbl_is_aot_node = root_table.is_array_of_tables();
        [[maybe_unused]] volatile bool tbl_is_str_node = root_table.is_string();
        [[maybe_unused]] volatile bool tbl_is_int_node = root_table.is_integer();
        [[maybe_unused]] volatile bool tbl_is_fp_node = root_table.is_floating_point();
        [[maybe_unused]] volatile bool tbl_is_num_node = root_table.is_number();
        [[maybe_unused]] volatile bool tbl_is_bool_node = root_table.is_boolean();
        [[maybe_unused]] volatile bool tbl_is_date_node = root_table.is_date();
        [[maybe_unused]] volatile bool tbl_is_time_node = root_table.is_time();
        [[maybe_unused]] volatile bool tbl_is_dt_node = root_table.is_date_time();
        // Coverage: Exercise toml::table::as_X() methods (most return nullptr for table)
        [[maybe_unused]] auto tbl_as_str_ptr = root_table.as_string(); if(tbl_as_str_ptr){}
        [[maybe_unused]] auto tbl_as_int_ptr = root_table.as_integer(); if(tbl_as_int_ptr){}
        [[maybe_unused]] auto tbl_as_fp_ptr = root_table.as_floating_point(); if(tbl_as_fp_ptr){}
        [[maybe_unused]] auto tbl_as_bool_ptr = root_table.as_boolean(); if(tbl_as_bool_ptr){}
        [[maybe_unused]] auto tbl_as_date_ptr = root_table.as_date(); if(tbl_as_date_ptr){}
        [[maybe_unused]] auto tbl_as_time_ptr = root_table.as_time(); if(tbl_as_time_ptr){}
        [[maybe_unused]] auto tbl_as_dt_ptr = root_table.as_date_time(); if(tbl_as_dt_ptr){}
        // Const versions
        [[maybe_unused]] volatile bool const_tbl_is_arr_node = const_root_table.is_array();
        [[maybe_unused]] volatile bool const_tbl_is_aot_node = const_root_table.is_array_of_tables();
        [[maybe_unused]] volatile bool const_tbl_is_str_node = const_root_table.is_string();
        // ... (other const is_X for table)
        [[maybe_unused]] const auto* const_tbl_as_tbl_ptr = const_root_table.as_table(); // Specific for as_table() const
        if (const_tbl_as_tbl_ptr == &const_root_table) { /* use it to ensure not optimized out */ }
        [[maybe_unused]] auto const_tbl_as_arr_ptr = const_root_table.as_array(); if(const_tbl_as_arr_ptr){}
        [[maybe_unused]] auto const_tbl_as_str_ptr = const_root_table.as_string(); if(const_tbl_as_str_ptr){}
         // ... (other const as_X for table)
        // === End Added Code for Coverage Enhancement (table is_X/as_X methods) ===


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
            // Coverage: Add more integer and float types for print_integer_to_stream/print_floating_point_to_stream
            special_format_table.insert("fuzz_schar_fmt", static_cast<signed char>(fdp.ConsumeIntegral<int8_t>()));
            special_format_table.insert("fuzz_short_fmt", static_cast<short>(fdp.ConsumeIntegral<int16_t>()));
            special_format_table.insert("fuzz_int_fmt", fdp.ConsumeIntegral<int32_t>());
            special_format_table.insert("fuzz_ullong_fmt", fdp.ConsumeIntegral<int64_t>()); // Changed uint64_t to int64_t
            special_format_table.insert("fuzz_float_fmt", fdp.ConsumeFloatingPoint<float>());
            if (fdp.ConsumeBool()) special_format_table.insert("fuzz_float_inf_fmt", std::numeric_limits<float>::infinity());
            if (fdp.ConsumeBool()) special_format_table.insert("fuzz_float_nan_fmt", std::numeric_limits<float>::quiet_NaN());
            // === Begin Added Code for Coverage Enhancement (value<double>::flags) ===
            special_format_table.insert("fuzz_double_for_flags_fmt", fdp.ConsumeFloatingPoint<double>());
            if (auto v_dbl_flags = special_format_table["fuzz_double_for_flags_fmt"].as_floating_point()) {
                 // Coverage: value<double>::flags(value_flags)
                v_dbl_flags->flags(fdp.ConsumeBool() ? toml::value_flags::format_as_hexadecimal : toml::value_flags::none);
            }
            // === End Added Code for Coverage Enhancement (value<double>::flags) ===
            
            // Coverage: Set formatting flags for integers
            if (auto v = special_format_table["fuzz_int_fmt"].as_integer()) {
                v->flags(static_cast<toml::value_flags>(fdp.ConsumeIntegralInRange(0,7))); // bin, oct, hex
            }
             if (auto v = special_format_table["fuzz_schar_fmt"].as_integer()) { // Assuming schar promotes to int64_t value
                v->flags(static_cast<toml::value_flags>(fdp.ConsumeIntegralInRange(0,7)));
            }

            // === Begin Added Code for Coverage Enhancement (toml_formatter table printing for pending_table_separator) ===
            // Create a nested table structure to try and trigger pending_table_separator logic
            toml::table table_for_fmt_sep;
            toml::table inner_table_fmt_sep; inner_table_fmt_sep.insert("a",1);
            table_for_fmt_sep.insert("nested_fmt_table", std::move(inner_table_fmt_sep));
            table_for_fmt_sep.insert("key_after_nested_fmt_table", true);
            special_format_table.insert("complex_table_structure", std::move(table_for_fmt_sep));
            // === End Added Code for Coverage Enhancement (toml_formatter table printing for pending_table_separator) ===


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
                    if (!path_obj.empty()) { 
                        toml::path_component pc_ref = path_obj[0]; // Non-const ref if path_obj is non-const
                        // Coverage: toml::path_component::operator=(unsigned long) and operator=(string_view)
                        if (fdp.ConsumeBool()) {
                            pc_ref = fdp.ConsumeIntegral<unsigned long>();
                        } else {
                            std::string temp_sv_str = fdp.ConsumeRandomLengthString(5);
                            pc_ref = std::string_view(temp_sv_str);
                        }
                        [[maybe_unused]] const auto& comp = path_obj[0]; 
                        // Coverage: toml::path::operator[](unsigned long) const
                        const toml::path const_path_obj_for_idx(p_str);
                        if (!const_path_obj_for_idx.empty()) {
                             [[maybe_unused]] const auto& comp_const_idx = const_path_obj_for_idx[0uL];
                        }
                    } 
                    
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
                    // Coverage: path::append(const path&)
                    const toml::path const_path_to_append(fdp.ConsumeRandomLengthString(2));
                    path_append_test.append(const_path_to_append);


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
                            // Coverage: toml::path_component::operator const std::string&() const
                            [[maybe_unused]] const std::string& pc_as_str_ref = static_cast<const std::string&>(pc); (void)pc_as_str_ref;
                        } else { 
                            [[maybe_unused]] volatile auto i_pc = pc.index(); 
                            // Coverage: path_component::operator unsigned long() const
                            [[maybe_unused]] volatile unsigned long ul_pc_op = static_cast<unsigned long>(pc); (void)ul_pc_op;
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
            // Coverage: toml::key::data() const - ensure key is not empty for meaningful test
            if (!test_key.empty()) {
                 [[maybe_unused]] volatile const char* key_data_ptr = test_key.data(); (void)key_data_ptr;
            } else { // if key is empty, data() might return nullptr or empty string's data()
                 toml::key non_empty_key_for_data("ne");
                 [[maybe_unused]] volatile const char* key_data_ptr_ne = non_empty_key_for_data.data();  (void)key_data_ptr_ne;
            }
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

            // === Begin Added Code for Coverage Enhancement (key constructors with source_region) ===
            // Coverage: toml::key constructors taking source_region
            if (fdp.ConsumeBool()) {
                toml::source_region src_reg_for_key; // Memory safety: stack object
                src_reg_for_key.begin = {1,1}; src_reg_for_key.end = {1, (uint32_t)fdp.ConsumeIntegralInRange(1,20)};
                if (fdp.ConsumeBool()) {
                    // Memory safety: shared_ptr manages lifetime of string.
                    src_reg_for_key.path = std::make_shared<const std::string>(fdp.ConsumeRandomLengthString(10));
                }

                std::string temp_str_for_key_ctor = fdp.ConsumeRandomLengthString(fdp.ConsumeIntegralInRange<size_t>(0, 15));
                std::string_view sv_for_key_ctor(temp_str_for_key_ctor);
                // Memory safety: toml::key copies string_view data. src_reg_for_key is copied.
                toml::key key_from_sv_sr(sv_for_key_ctor, src_reg_for_key); 

                std::string str_for_key_ctor = fdp.ConsumeRandomLengthString(fdp.ConsumeIntegralInRange<size_t>(0, 15));
                // Memory safety: toml::key moves string data. src_reg_for_key is copied.
                toml::key key_from_str_move_sr(std::move(str_for_key_ctor), src_reg_for_key);

                std::string cstr_holder = fdp.ConsumeRandomLengthString(fdp.ConsumeIntegralInRange<size_t>(0,15));
                // Memory safety: toml::key copies c-string data. src_reg_for_key is copied.
                toml::key key_from_cstr_sr(cstr_holder.c_str(), src_reg_for_key); 
            }
            // === End Added Code for Coverage Enhancement (key constructors with source_region) ===
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
            
            toml::array arr_method_test2; 
            arr_method_test2.emplace_back(fdp.ConsumeIntegral<int64_t>()); // Initialize to compare against
            // === Begin Added Code for Coverage Enhancement (array::equal lambda for various types) ===
            // Coverage: toml::array::equal lambda for various element types.
            // Memory safety: All created objects (tables, arrays, values) are managed by arr_method_test and arr_method_test2.
            if (fdp.ConsumeBool()) { // table
                toml::table t1, t2; t1.insert("k",1); t2.insert("k",fdp.ConsumeBool()? 1 : 2); // t2 might be different
                arr_method_test.emplace_back(std::move(t1)); arr_method_test2.emplace_back(std::move(t2));
            }
            if (fdp.ConsumeBool()) { // array
                toml::array a1, a2; a1.emplace_back(1); a2.emplace_back(fdp.ConsumeBool()? 1 : 0);
                arr_method_test.emplace_back(std::move(a1)); arr_method_test2.emplace_back(std::move(a2));
            }
            if (fdp.ConsumeBool()) { // value<string>
                std::string s_arr1 = fdp.ConsumeRandomLengthString(3); std::string s_arr2 = fdp.ConsumeBool() ? s_arr1 : fdp.ConsumeRandomLengthString(3);
                arr_method_test.emplace_back(s_arr1); arr_method_test2.emplace_back(s_arr2);
            }
            if (fdp.ConsumeBool()) { // value<double>
                double d_arr1 = fdp.ConsumeFloatingPoint<double>(); double d_arr2 = fdp.ConsumeBool() ? d_arr1 : fdp.ConsumeFloatingPoint<double>();
                arr_method_test.emplace_back(d_arr1); arr_method_test2.emplace_back(d_arr2);
            }
            if (fdp.ConsumeBool()) { // value<bool>
                bool b_arr1 = fdp.ConsumeBool(); bool b_arr2 = fdp.ConsumeBool() ? b_arr1 : fdp.ConsumeBool();
                arr_method_test.emplace_back(b_arr1); arr_method_test2.emplace_back(b_arr2);
            }
            if (fdp.ConsumeBool()) { // value<date>
                toml::date date_arr1{2023,1,1}; toml::date date_arr2 = fdp.ConsumeBool() ? date_arr1 : toml::date{2023,1,2};
                arr_method_test.emplace_back(date_arr1); arr_method_test2.emplace_back(date_arr2);
            }
            if (fdp.ConsumeBool()) { // value<time>
                toml::time time_arr1{10,0,0}; toml::time time_arr2 = fdp.ConsumeBool() ? time_arr1 : toml::time{10,0,1};
                arr_method_test.emplace_back(time_arr1); arr_method_test2.emplace_back(time_arr2);
            }
            if (fdp.ConsumeBool()) { // value<date_time>
                toml::date_time dt_arr1{toml::date{2023,1,1}, toml::time{10,0,0}};
                toml::date_time dt_arr2 = fdp.ConsumeBool() ? dt_arr1 : toml::date_time{toml::date{2023,1,1}, toml::time{10,0,1}};
                arr_method_test.emplace_back(dt_arr1); arr_method_test2.emplace_back(dt_arr2);
            }
             // Ensure arrays are not empty for comparison if elements were added, and make sizes potentially equal for full comparison
            while(fdp.ConsumeBool() && arr_method_test.size() < arr_method_test2.size()) arr_method_test.emplace_back(0);
            while(fdp.ConsumeBool() && arr_method_test2.size() < arr_method_test.size()) arr_method_test2.emplace_back(0);
            if (arr_method_test.empty() && arr_method_test2.empty() && fdp.ConsumeBool()) { // Case for two empty arrays
                 /* do nothing, already empty */
            } else if (arr_method_test.empty() && fdp.ConsumeBool()) { // Make both non-empty if one was populated
                 arr_method_test.emplace_back(0); if(arr_method_test2.empty()) arr_method_test2.emplace_back(0);
            } else if (arr_method_test2.empty() && fdp.ConsumeBool()) {
                 arr_method_test2.emplace_back(0); if(arr_method_test.empty()) arr_method_test.emplace_back(0);
            }
            // === End Added Code for Coverage Enhancement (array::equal lambda for various types) ===
            
            const auto& const_arr_method_test = arr_method_test; 
            toml::node* first_nonmatch = nullptr; const toml::node* const_first_nonmatch = nullptr; 

            [[maybe_unused]] volatile bool h_empty = arr_method_test.is_homogeneous(toml::node_type::none, first_nonmatch); 
            // === Begin Added Code for Coverage Enhancement (array::is_homogeneous(node_type) const) ===
            // Coverage: toml::array::is_homogeneous(toml::node_type) const overload
            [[maybe_unused]] volatile bool h_empty_no_out = arr_method_test.is_homogeneous(toml::node_type::none);
            // === End Added Code for Coverage Enhancement (array::is_homogeneous(node_type) const) ===
            
            if (!arr_method_test.empty()) { 
                [[maybe_unused]] volatile bool h_none = arr_method_test.is_homogeneous(toml::node_type::none, first_nonmatch); 
                [[maybe_unused]] volatile bool h_int = arr_method_test.is_homogeneous(toml::node_type::integer, first_nonmatch); 
                [[maybe_unused]] volatile bool h_const_none = const_arr_method_test.is_homogeneous(toml::node_type::none, const_first_nonmatch); 
                // === Begin Added Code for Coverage Enhancement (array::is_homogeneous(node_type) const) ===
                [[maybe_unused]] volatile bool h_int_no_out = arr_method_test.is_homogeneous(toml::node_type::integer);
                [[maybe_unused]] volatile bool h_str_no_out = arr_method_test.is_homogeneous(toml::node_type::string);
                [[maybe_unused]] volatile bool ch_int_no_out = const_arr_method_test.is_homogeneous(toml::node_type::integer);
                // === End Added Code for Coverage Enhancement (array::is_homogeneous(node_type) const) ===


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
                [[maybe_unused]] const auto const_get_n = const_arr_method_test.get(0); // Re-added for clarity, should be covered
                // === Begin Added Code for Coverage Enhancement (array::as_array() const) ===
                // Coverage: toml::array::as_array() const
                [[maybe_unused]] const toml::array* arr_as_arr_const = const_arr_method_test.as_array();
                if (arr_as_arr_const == &const_arr_method_test) { /* self check to ensure usage */ }
                // === End Added Code for Coverage Enhancement (array::as_array() const) ===


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
            
            // === Begin Added Code for Coverage Enhancement (array is_X/as_X methods and specific uncovered as_X) ===
            // Coverage: Exercise toml::array::is_X() methods
            [[maybe_unused]] volatile bool arr_is_tbl_node = arr_method_test.is_table();
            [[maybe_unused]] volatile bool arr_is_arr_node = arr_method_test.is_array(); // Should be true
            [[maybe_unused]] volatile bool arr_is_aot_node = arr_method_test.is_array_of_tables();
            [[maybe_unused]] volatile bool arr_is_val_node = arr_method_test.is_value(); // Should be false
            [[maybe_unused]] volatile bool arr_is_str_node = arr_method_test.is_string();
            [[maybe_unused]] volatile bool arr_is_int_node = arr_method_test.is_integer();
            [[maybe_unused]] volatile bool arr_is_fp_node = arr_method_test.is_floating_point();
            [[maybe_unused]] volatile bool arr_is_num_node = arr_method_test.is_number();
            [[maybe_unused]] volatile bool arr_is_bool_node = arr_method_test.is_boolean();
            [[maybe_unused]] volatile bool arr_is_date_node = arr_method_test.is_date();
            [[maybe_unused]] volatile bool arr_is_time_node = arr_method_test.is_time();
            [[maybe_unused]] volatile bool arr_is_dt_node = arr_method_test.is_date_time();
            // Coverage: Exercise toml::array::as_X() methods (most return nullptr for array)
            // These are specifically listed as uncovered in the report.
            [[maybe_unused]] volatile auto* arr_as_tbl_ptr_v = arr_method_test.as_table(); (void)arr_as_tbl_ptr_v;
            [[maybe_unused]] volatile auto* arr_as_fp_ptr_v = arr_method_test.as_floating_point(); (void)arr_as_fp_ptr_v;
            [[maybe_unused]] volatile auto* arr_as_bool_ptr_v = arr_method_test.as_boolean(); (void)arr_as_bool_ptr_v;
            [[maybe_unused]] volatile auto* arr_as_date_ptr_v = arr_method_test.as_date(); (void)arr_as_date_ptr_v;
            [[maybe_unused]] volatile auto* arr_as_time_ptr_v = arr_method_test.as_time(); (void)arr_as_time_ptr_v;
            [[maybe_unused]] volatile auto* arr_as_dt_ptr_v = arr_method_test.as_date_time(); (void)arr_as_dt_ptr_v;
            // Specifically target uncovered array::as_string() and array::as_integer()
            [[maybe_unused]] volatile auto* arr_as_str_ptr_direct = arr_method_test.as_string(); (void)arr_as_str_ptr_direct;
            [[maybe_unused]] volatile auto* arr_as_int_ptr_direct = arr_method_test.as_integer(); (void)arr_as_int_ptr_direct;

            // Const versions
            [[maybe_unused]] volatile bool const_arr_is_tbl_node = const_arr_method_test.is_table();
            [[maybe_unused]] volatile bool const_arr_is_arr_node = const_arr_method_test.is_array();
            // ... (other const is_X for array are already covered or similar to above)
            // Coverage: Exercise const toml::array::as_X() methods
            [[maybe_unused]] volatile const auto* const_arr_as_tbl_ptr_v = const_arr_method_test.as_table(); (void)const_arr_as_tbl_ptr_v;
            [[maybe_unused]] volatile const auto* const_arr_as_int_ptr_v = const_arr_method_test.as_integer(); (void)const_arr_as_int_ptr_v;
            [[maybe_unused]] volatile const auto* const_arr_as_fp_ptr_v = const_arr_method_test.as_floating_point(); (void)const_arr_as_fp_ptr_v;
            [[maybe_unused]] volatile const auto* const_arr_as_bool_ptr_v = const_arr_method_test.as_boolean(); (void)const_arr_as_bool_ptr_v;
            [[maybe_unused]] volatile const auto* const_arr_as_date_ptr_v = const_arr_method_test.as_date(); (void)const_arr_as_date_ptr_v;
            [[maybe_unused]] volatile const auto* const_arr_as_time_ptr_v = const_arr_method_test.as_time(); (void)const_arr_as_time_ptr_v;
            [[maybe_unused]] volatile const auto* const_arr_as_dt_ptr_v = const_arr_method_test.as_date_time(); (void)const_arr_as_dt_ptr_v;
            // Specifically target uncovered const array::as_string()
            [[maybe_unused]] volatile const auto* const_arr_as_str_ptr_direct = const_arr_method_test.as_string(); (void)const_arr_as_str_ptr_direct;
            // === End Added Code for Coverage Enhancement (array is_X/as_X methods and specific uncovered as_X) ===


            for(auto it = arr_method_test.cbegin(); it != arr_method_test.cend(); ++it) {
                [[maybe_unused]] volatile auto node_type = it->type();
            }
            for(auto it = const_arr_method_test.cbegin(); it != const_arr_method_test.cend(); ++it) {
                [[maybe_unused]] volatile auto node_type = it->type();
            }

            [[maybe_unused]] volatile size_t arr_max_s = arr_method_test.max_size(); 
            
            arr_method_test.shrink_to_fit();
            if (!arr_method_test.empty()) arr_method_test.truncate(fdp.ConsumeIntegralInRange<size_t>(0, arr_method_test.size()/2));


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
            // === Begin Added Code for Coverage Enhancement (table::equal lambda for various types) ===
            // Coverage: toml::table::equal lambda for various element types.
            // Memory safety: All created objects are managed by tbl_eq1 and tbl_eq2.
            if (fdp.ConsumeBool()) { // array (already in existing fuzzer)
                toml::array a1, a2; a1.emplace_back(fdp.ConsumeIntegral<int>()); a2.emplace_back(fdp.ConsumeBool() ? a1[0].value_or(0) : 0);
                tbl_eq1.insert("arr_key_lambda", std::move(a1)); tbl_eq2.insert("arr_key_lambda", std::move(a2));
            }
            if (fdp.ConsumeBool()) { // table
                toml::table t1_lambda, t2_lambda; t1_lambda.insert("k_lambda",1); t2_lambda.insert("k_lambda",fdp.ConsumeBool()? 1 : 2);
                tbl_eq1.insert("tbl_key_lambda", std::move(t1_lambda)); tbl_eq2.insert("tbl_key_lambda", std::move(t2_lambda));
            }
            if (fdp.ConsumeBool()) { // value<double>
                double d_tbl1 = fdp.ConsumeFloatingPoint<double>(); double d_tbl2 = fdp.ConsumeBool() ? d_tbl1 : fdp.ConsumeFloatingPoint<double>();
                tbl_eq1.insert("dbl_key_lambda", d_tbl1); tbl_eq2.insert("dbl_key_lambda", d_tbl2);
            }
            if (fdp.ConsumeBool()) { // value<bool>
                bool b_tbl1 = fdp.ConsumeBool(); bool b_tbl2 = fdp.ConsumeBool() ? b_tbl1 : fdp.ConsumeBool();
                tbl_eq1.insert("bool_key_lambda", b_tbl1); tbl_eq2.insert("bool_key_lambda", b_tbl2);
            }
            if (fdp.ConsumeBool()) { // value<date>
                toml::date date_tbl1{2023,1,1}; toml::date date_tbl2 = fdp.ConsumeBool() ? date_tbl1 : toml::date{2023,1,2};
                tbl_eq1.insert("date_key_lambda", date_tbl1); tbl_eq2.insert("date_key_lambda", date_tbl2);
            }
            if (fdp.ConsumeBool()) { // value<time>
                toml::time time_tbl1{10,0,0}; toml::time time_tbl2 = fdp.ConsumeBool() ? time_tbl1 : toml::time{10,0,1};
                tbl_eq1.insert("time_key_lambda", time_tbl1); tbl_eq2.insert("time_key_lambda", time_tbl2);
            }
            if (fdp.ConsumeBool()) { // value<date_time>
                toml::date_time dt_tbl1{toml::date{2023,1,1}, toml::time{10,0,0}};
                toml::date_time dt_tbl2 = fdp.ConsumeBool() ? dt_tbl1 : toml::date_time{toml::date{2023,1,1}, toml::time{10,0,1}};
                tbl_eq1.insert("dt_key_lambda", dt_tbl1); tbl_eq2.insert("dt_key_lambda", dt_tbl2);
            }
            // === End Added Code for Coverage Enhancement (table::equal lambda for various types) ===
            [[maybe_unused]] volatile bool table_is_equal = (tbl_eq1 == tbl_eq2); 
            [[maybe_unused]] volatile bool table_is_not_equal = (tbl_eq1 != tbl_eq2); 

            // Coverage: table::table(std::initializer_list)
            // Memory safety: Elements are created and managed by the table.
            toml::table tbl_init_list{
                {fdp.ConsumeRandomLengthString(5), toml::value{fdp.ConsumeIntegral<int64_t>()}},
                {fdp.ConsumeRandomLengthString(5), toml::value{fdp.ConsumeRandomLengthString(5)}}
            };
            if (fdp.ConsumeBool()) { 
                // Intentionally empty or add a small operation if needed for the corrected 'if (fd' part
            }
        } // Closes the "if (fdp.ConsumeBool())" for "Literals and Table Ops"
        // === End Added Code for Coverage Enhancement (Literals and Table Ops) ===

    } catch (const toml::parse_error& e) {
        // Parsing can fail, this is expected.
    } catch (const std::out_of_range& e) {
        // Expected for at() calls on empty containers or out of bounds access
    } catch (const std::length_error& e) {
        // Expected for very long string operations
    } catch (const std::bad_alloc& e) {
        // Expected for very large allocations
    } catch (const std::exception& e) { 
        // Catch any other std::exception
    }

    return 0;
}