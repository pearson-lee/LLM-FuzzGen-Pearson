#include "/src/tomlplusplus/include/toml++/toml.hpp" // Core tomlplusplus library
#include <fuzzer/FuzzedDataProvider.h> // For FuzzedDataProvider
#include <string> // For std::string
#include <cstdint> // For int64_t
#include <vector> // For std::vector for source_region tests
#include <sstream> // For std::stringstream // Added for toml_formatter test
#include <stdexcept> // For std::out_of_range

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
        
        // Add a small chance for these constructs to be at the beginning of the string
        if (fdp.ConsumeBool()) {
            toml_string = special_toml_constructs + toml_string;
        } else {
            toml_string += special_toml_constructs;
        }
    }
    // === End Added Code for Coverage Enhancement (String Augmentation) ===


    try {
        toml::table root_table = toml::parse(toml_string);
        const auto& const_root_table = root_table; // Create const ref for const API coverage

        // Coverage: Insert potentially empty table/array to test prune functionality
        if (fdp.ConsumeBool()) {
            // Memory safety: toml::table{} creates a temporary, which is then moved or copied into root_table.
            // The temporary is destroyed, and root_table manages the lifetime of the inserted element.
            root_table.insert("potentially_empty_table", toml::table{});
        }
        if (fdp.ConsumeBool()) {
            // Memory safety: toml::array{} creates a temporary, which is then moved or copied into root_table.
            // The temporary is destroyed, and root_table manages the lifetime of the inserted element.
            root_table.insert("potentially_empty_array", toml::array{});
        }

        // Coverage: Call table::prune() to cover this API
        // prune() modifies the table in-place, removing empty tables/arrays. Memory is managed by the table.
        root_table.prune(true);  // Test recursive pruning
        root_table.prune(false); // Test non-recursive pruning

        // === Begin Added Code for Coverage Enhancement ===

        // Coverage: Add an array of tables to root_table to hit line 198 `if (element_node.is_table())`
        if (fdp.ConsumeBool()) {
            toml::array array_of_tables;
            // Memory safety: toml::table{} creates a temporary.
            // array_of_tables.emplace_back creates a new node (owning the temporary's content)
            // and manages its lifetime within 'array_of_tables'.
            array_of_tables.emplace_back(toml::table{}); 
            if (fdp.ConsumeBool()) {
                toml::table inner_tbl;
                inner_tbl.insert("foo", "bar");
                // Memory safety: 'inner_tbl' is moved into a new node managed by 'array_of_tables'.
                array_of_tables.emplace_back(std::move(inner_tbl));
            }
            // Memory safety: 'array_of_tables' is moved into a new node managed by 'root_table'.
            root_table.insert("array_of_tables_key", std::move(array_of_tables));
        }

        // Coverage: Add a table with a nested array to root_table to hit line 245 `if (sub_node_view_inner.is_array())`
        if (fdp.ConsumeBool()) {
            toml::table table_with_nested_array;
            // Memory safety: toml::array{} creates a temporary.
            // table_with_nested_array.insert creates a new node (owning the temporary's content)
            // and manages its lifetime within 'table_with_nested_array'.
            table_with_nested_array.insert("nested_array_key", toml::array{});
            if (fdp.ConsumeBool()) {
                toml::array inner_arr;
                inner_arr.emplace_back(fdp.ConsumeRandomLengthString(10));
                // Memory safety: 'inner_arr' is moved into a new node managed by 'table_with_nested_array'.
                table_with_nested_array.insert("another_nested_array_key", std::move(inner_arr));
            }
            // Memory safety: 'table_with_nested_array' is moved into a new node managed by 'root_table'.
            root_table.insert("table_with_nested_array_key", std::move(table_with_nested_array));
        }
        
        // Coverage: Specific test for toml::array::prune() with nested arrays/tables (targets lines 325-330 in array.inl)
        if (fdp.ConsumeBool()) {
            toml::array array_for_prune_test;
            if (fdp.ConsumeBool()) {
                // Memory safety: toml::array{} creates a temporary.
                // array_for_prune_test.emplace_back creates a new node (owning the temporary's content)
                // and manages its lifetime within 'array_for_prune_test'.
                array_for_prune_test.emplace_back(toml::array{}); // Add an empty nested array
            }
            if (fdp.ConsumeBool()) {
                toml::array nested_arr_with_table;
                if (fdp.ConsumeBool()) {
                    // Memory safety: toml::table{} creates a temporary.
                    // nested_arr_with_table.emplace_back creates a new node (owning the temporary's content)
                    // and manages its lifetime within 'nested_arr_with_table'.
                    nested_arr_with_table.emplace_back(toml::table{}); 
                }
                // Memory safety: 'nested_arr_with_table' is moved into a new node managed by 'array_for_prune_test'.
                array_for_prune_test.emplace_back(std::move(nested_arr_with_table));
            }
            if (fdp.ConsumeBool()) {
                toml::array non_empty_nested_array;
                non_empty_nested_array.emplace_back(fdp.ConsumeIntegral<int64_t>());
                // Memory safety: 'non_empty_nested_array' is moved into a new node managed by 'array_for_prune_test'.
                array_for_prune_test.emplace_back(std::move(non_empty_nested_array));
            }
            // Memory safety: array_for_prune_test is stack-allocated; its elements are managed by unique_ptrs.
            // prune() modifies the array in-place.
            array_for_prune_test.prune(true);  // Test recursive pruning
            array_for_prune_test.prune(false); // Test non-recursive pruning
            
            // Coverage: toml::array::prune(bool)&&
            // array_for_prune_test might be empty here if all elements were pruned.
            if (fdp.ConsumeBool()) {
                 toml::array temp_copy = array_for_prune_test; // Copy before move for potential rvalue prune
                 [[maybe_unused]] auto pruned_rval_arr = std::move(temp_copy).prune(fdp.ConsumeBool());
                 // temp_copy is now in a moved-from state.
            }
            // Ensure array_for_prune_test is used and its destructor is covered for its elements:
            [[maybe_unused]] volatile size_t final_size_prune_test = array_for_prune_test.size();
        }

        // Coverage: Target array::prune line 334 (recursive=false, element is table)
        // This ensures the 'if (recursive)' condition at line 334 in array.inl is false when the element is a table.
        if (fdp.ConsumeProbability<double>() < 0.2) { // Add this block with 20% probability
            toml::array array_with_direct_table;
            if (fdp.ConsumeBool()) { // Add an empty table
                // Memory safety: toml::table{} creates a temporary.
                // emplace_back creates a new node owning the table's content, managed by unique_ptr.
                array_with_direct_table.emplace_back(toml::table{});
            }
            if (fdp.ConsumeBool()) { // Add a non-empty table
                toml::table non_empty_table;
                non_empty_table.insert("k", fdp.ConsumeRandomLengthString(5));
                // Memory safety: non_empty_table is moved into a new node, managed by unique_ptr.
                array_with_direct_table.emplace_back(std::move(non_empty_table));
            }
            if (!array_with_direct_table.empty()) { // Only prune if not empty to avoid no-op
                // Memory safety: prune() modifies in-place. Elements are unique_ptrs.
                array_with_direct_table.prune(false); // Call with recursive = false
            }
            // Ensure array is used to cover its destructor and element destructors.
            [[maybe_unused]] volatile size_t final_size_direct_table_prune = array_with_direct_table.size();
        }
        
        // Coverage: Exercise toml::source_region assignment operator
        // This targets `struct source_region & toml::v3::source_region::operator=(struct source_region *, const struct source_region &)`
        // which has 0% coverage.
        if (fdp.ConsumeBool()) {
            toml::source_region src_region1;
            src_region1.begin = {fdp.ConsumeIntegral<uint32_t>(), fdp.ConsumeIntegral<uint32_t>()};
            src_region1.end = {fdp.ConsumeIntegral<uint32_t>(), fdp.ConsumeIntegral<uint32_t>()};
            if (fdp.ConsumeBool()) {
                 src_region1.path = std::make_shared<const std::string>(fdp.ConsumeRandomLengthString(20));
            }

            toml::source_region src_region2;
            src_region2 = src_region1; // Assignment operator called here.
                                       // Memory safety: Both regions manage their own shared_ptr to path if any.
                                       // Assignment involves shared_ptr assignment, which is memory safe.
            [[maybe_unused]] volatile uint32_t line = src_region2.begin.line; // Use the assigned value
        }

        // === Begin Added Code for Coverage Enhancement (Formatter and std::length_error) ===
        // Coverage: Target toml::toml_formatter constructor/destructor and formatting logic.
        // This should cover void toml::v3::toml_formatter::~~toml_formatter() which was at 0% coverage.
        // Also targets non-virtualthunktostd::__1::basic_stringstream<...>::~basic_stringstream() (0% coverage).
        if (fdp.ConsumeBool()) { 
            std::stringstream ss;
            ss << root_table; // Default formatter (toml::toml_formatter) is used here.
                              // Memory safety: std::stringstream manages its internal buffer.
                              // toml_formatter is created as a temporary and destroyed.
            std::string formatted_output = ss.str();
            // Ensure the formatted output is used to prevent optimization.
            [[maybe_unused]] volatile size_t formatted_len = formatted_output.length();
        }

        // Coverage: Attempt to trigger std::length_error by inserting a very large string.
        // This might cover void std::length_error::length_error(const char *) (0% coverage).
        if (fdp.ConsumeProbability<double>() < 0.01) { // Low probability due to potential slowness/memory usage.
            try {
                // Max string length for FDP is usually smaller, but this expresses intent.
                std::string very_long_string = fdp.ConsumeRandomLengthString(1 * 1024 * 1024); // 1MB
                if (!very_long_string.empty()) { // Only insert if string is non-empty.
                     // Memory safety: root_table will manage the lifetime of the inserted string value.
                    root_table.insert("fuzz_very_long_string", very_long_string);
                }
            } catch (const std::length_error& /*le*/) {
                // Successfully triggered and caught std::length_error.
            } catch (const std::bad_alloc& /*ba*/) {
                // Successfully triggered and caught std::bad_alloc (also a possible outcome).
            }
        }
        // === End Added Code for Coverage Enhancement (Formatter and std::length_error) ===

        // === Begin Added Code for Coverage Enhancement (Path, AtPath, Array Homogeneous, Formatters) ===
        // Coverage: Exercise toml::path, toml::node::at_path, and toml::table::at_path (targets toml-path.inl, toml-node.inl)
        if (fdp.ConsumeBool()) {
            toml::table path_test_table; // Create a local table for path testing
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
            path_strings_to_test.push_back(""); // Empty path
            path_strings_to_test.push_back("table1..subkey"); // Empty key part

            for (const std::string& p_str : path_strings_to_test) {
                // Memory safety: at_path returns node_view (non-owning). path_obj manages its own memory.
                [[maybe_unused]] auto node_v_str = path_test_table.at_path(p_str);
                [[maybe_unused]] auto const_node_v_str = const_path_test_table.at_path(p_str);
                try {
                    toml::path path_obj(p_str); // Covers path constructor
                    [[maybe_unused]] volatile auto p_str_val = path_obj.str();
                    [[maybe_unused]] auto node_v_path = path_test_table.at_path(path_obj);
                    [[maybe_unused]] auto const_node_v_path = const_path_test_table.at_path(path_obj);
                    if (!path_obj.empty()) { [[maybe_unused]] const auto& comp = path_obj[0]; } // Covers path::operator[]
                    
                    // Coverage: toml::path copy constructor and operator==, operator!=
                    toml::path p_copy = path_obj; 
                    [[maybe_unused]] bool eq_p = (p_copy == path_obj);
                    [[maybe_unused]] bool neq_p = (p_copy != path_obj); // Covers path::operator!=
                    // Coverage: toml::path copy assignment, move assignment, assign methods
                    toml::path p_assign_copy; p_assign_copy = path_obj;
                    toml::path p_assign_move; p_assign_move = std::move(p_copy); // p_copy is now moved-from
                    p_assign_move.assign(p_str); // Covers path::assign(string_view)
                    if(p_str == p_assign_copy.str()) p_assign_move.assign(p_assign_copy); // Covers path::assign(path const&)
                    if(p_str == p_assign_move.str()) { toml::path temp_p(p_str); p_assign_move.assign(std::move(temp_p));} // Covers path::assign(path&&)


                    toml::path path_append_test(fdp.ConsumeRandomLengthString(5));
                    // Coverage: toml::path::append and operator+=
                    path_append_test.append(p_str); // Covers path::append(string_view)
                    path_append_test += toml::path(fdp.ConsumeRandomLengthString(3)); // Covers path::operator+=(path const&)
                    toml::path temp_append_path(fdp.ConsumeRandomLengthString(3));
                    path_append_test.append(std::move(temp_append_path)); // Covers path::append(path&&)

                    toml::path path_prepend_test(fdp.ConsumeRandomLengthString(5));
                    // Coverage: toml::path::prepend
                    path_prepend_test.prepend(p_str); // Covers path::prepend(string_view)
                    path_prepend_test.prepend(toml::path(fdp.ConsumeRandomLengthString(3))); // Covers path::prepend(path const&)
                    toml::path temp_prepend_path(fdp.ConsumeRandomLengthString(3));
                    path_prepend_test.prepend(std::move(temp_prepend_path)); // Covers path::prepend(path&&)


                    if (!path_append_test.empty()) {
                        // Coverage: toml::path::parent(), leaf(), truncate()
                        [[maybe_unused]] auto parent_p = path_append_test.parent();
                        [[maybe_unused]] auto leaf_p = path_append_test.leaf();
                        path_append_test.truncate(1); // Truncates from the end
                    }
                    // Coverage: toml::path::clear(), empty(), operator bool()
                    path_append_test.clear();
                    [[maybe_unused]] volatile bool p_empty_check = path_append_test.empty();
                    [[maybe_unused]] volatile bool p_bool_check = static_cast<bool>(path_append_test);

                    // Coverage: toml::path iterators (begin, end, cbegin, cend)
                    for ([[maybe_unused]] const auto& comp : p_assign_copy) {} // begin()/end() const
                    for (auto it = p_assign_copy.begin(); it != p_assign_copy.end(); ++it) { // begin()/end() non-const
                         [[maybe_unused]] volatile bool is_k = (it->type() == toml::path_component_type::key);
                    }
                    const toml::path& const_p_ac = p_assign_copy; // Use a const ref for cbegin/cend
                    for (auto it = const_p_ac.cbegin(); it != const_p_ac.cend(); ++it) { // cbegin()/cend()
                         [[maybe_unused]] volatile bool is_k = (it->type() == toml::path_component_type::key);
                    }

                    // Coverage: toml::path_component methods
                    if (!p_assign_copy.empty()) {
                        toml::path_component pc = p_assign_copy[0]; // path::operator[]
                        toml::path_component pc_copy_ctor = pc; // path_component copy ctor
                        toml::path_component pc_move_ctor = std::move(pc_copy_ctor); // path_component move ctor
                        pc_move_ctor = p_assign_copy[0]; // path_component copy assign
                        toml::path_component temp_pc_move_assign = p_assign_copy[0];
                        pc_move_ctor = std::move(temp_pc_move_assign); // path_component move assign
                        if (pc.type() == toml::path_component_type::key) {
                            [[maybe_unused]] volatile const auto& k_pc = pc.key(); // key()
                            [[maybe_unused]] volatile auto sv_pc = std::string_view(pc.key()); // operator string_view()
                        } else { // is array_index
                            [[maybe_unused]] volatile auto i_pc = pc.index(); // index()
                            [[maybe_unused]] volatile auto ul_pc = static_cast<unsigned long>(pc.index()); // operator unsigned long()
                        }
                        toml::path_component pc2_default_ctor; // default ctor
                        if (!p_assign_copy.empty()) pc2_default_ctor = p_assign_copy[0];
                        [[maybe_unused]] volatile bool pc_eq = (pc == pc2_default_ctor); // operator==
                        [[maybe_unused]] volatile bool pc_neq = (pc != pc2_default_ctor); // operator!=
                    }
                    
                    // Coverage: toml::path string conversion and stream operator
                    [[maybe_unused]] std::string path_as_std_string = static_cast<std::string>(p_assign_copy); // operator std::string()
                    std::ostringstream path_s; path_s << p_assign_copy; [[maybe_unused]] volatile auto path_str_out = path_s.str(); // operator<<

                    // Coverage: toml::path subpath
                    if (p_assign_copy.size() > 1) {
                        [[maybe_unused]] auto sub_p1 = p_assign_copy.subpath(0,1);
                        [[maybe_unused]] auto sub_p2 = p_assign_copy.subpath(p_assign_copy.cbegin(), p_assign_copy.cbegin()+1); // Use cbegin for const version
                    }

                } catch (const toml::parse_error&) {} // Catch errors from invalid path strings
            }
            // Coverage: toml::literals::operator"" _tpath (fixed string due to compile-time nature)
            using namespace toml::literals;
            [[maybe_unused]] auto path_lit_example = "fixed.path.example[0]"_tpath;

            // Coverage: toml::key methods
            toml::key test_key(fdp.ConsumeRandomLengthString(10)); // key(string_view)
            [[maybe_unused]] volatile auto key_sv = static_cast<std::string_view>(test_key); // operator string_view()
            [[maybe_unused]] volatile bool key_empty_check = test_key.empty(); // empty()
            [[maybe_unused]] volatile const char* key_data_ptr = test_key.data(); // data()
            toml::key test_key2(fdp.ConsumeRandomLengthString(10));
            [[maybe_unused]] volatile bool key_eq_check = (test_key == test_key2); // operator==
            [[maybe_unused]] volatile bool key_neq_check = (test_key != test_key2); // operator!=
            [[maybe_unused]] volatile bool key_lt_check = (test_key < test_key2); // operator<
            // ... other key comparisons can be added if needed ...
            std::ostringstream key_os; key_os << test_key; [[maybe_unused]] volatile auto key_str_from_stream = key_os.str(); // operator<<
            for([[maybe_unused]] char c : test_key) {} // begin()/end() via range-for
        }


        // Coverage: Exercise specific toml::array methods (is_homogeneous, at, front, back, etc.)
        if (fdp.ConsumeBool()) { 
            toml::array arr_method_test;
            // Coverage: Test toml::value constructor with flags and value::flags(value_flags)
            // Memory safety: toml::value objects are constructed and then moved into the array.
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

                // Coverage: toml::array::operator[] (non-const)
                [[maybe_unused]] auto& op_idx_n = arr_method_test[0];
                // Coverage: toml::array::at() const, front() const, back() const, get() const
                [[maybe_unused]] const auto& const_at_n = const_arr_method_test.at(0);
                [[maybe_unused]] const auto& const_front_n = const_arr_method_test.front();
                [[maybe_unused]] const auto& const_back_n = const_arr_method_test.back();
                [[maybe_unused]] const auto const_get_n = const_arr_method_test.get(0);

                // Coverage: toml::value::flags(value_flags)
                // Memory safety: as_integer()/as_string() return pointers to value objects owned by the node.
                if (arr_method_test.front().is_integer()) arr_method_test.front().as_integer()->flags(toml::value_flags::format_as_hexadecimal);
                else if (arr_method_test.front().is_string()) arr_method_test.front().as_string()->flags(toml::value_flags::none);

                // Coverage: toml::array::erase(const_iterator)
                if (fdp.ConsumeBool() && !arr_method_test.empty()) {
                     arr_method_test.erase(arr_method_test.cbegin());
                }
                // Coverage: toml::array::erase(const_iterator, const_iterator)
                if (fdp.ConsumeBool() && arr_method_test.size() >= 2) { // Ensure at least two elements to erase a range of 1
                     arr_method_test.erase(arr_method_test.cbegin(), arr_method_test.cbegin() + 1);
                }
                 // Coverage: std::out_of_range from array::at()
                try {
                    if (!arr_method_test.empty()) [[maybe_unused]] volatile auto& oor_at = arr_method_test.at(arr_method_test.size()); // Deliberate out of bounds
                    else [[maybe_unused]] volatile auto& oor_at_empty = arr_method_test.at(0); // Out of bounds for empty
                } catch (const std::out_of_range&) { /* covered std::out_of_range for array::at */ }

                if(!arr_method_test.empty()) arr_method_test.pop_back(); 
            }
            // Coverage: toml::array::cbegin(), cend()
            for(auto it = arr_method_test.cbegin(); it != arr_method_test.cend(); ++it) {
                [[maybe_unused]] volatile auto node_type = it->type();
            }
            for(auto it = const_arr_method_test.cbegin(); it != const_arr_method_test.cend(); ++it) {
                [[maybe_unused]] volatile auto node_type = it->type();
            }

            [[maybe_unused]] volatile size_t arr_max_s = arr_method_test.max_size(); 
            
            // Coverage: toml::array::shrink_to_fit()
            arr_method_test.shrink_to_fit();
            // Coverage: toml::array::truncate()
            if (!arr_method_test.empty()) arr_method_test.truncate(fdp.ConsumeIntegralInRange<size_t>(0, arr_method_test.size()/2));


            toml::array arr_method_test2; arr_method_test2.emplace_back(1); 
            [[maybe_unused]] volatile bool arr_eq = (arr_method_test == arr_method_test2); 
            // Coverage: toml::array::operator!=
            [[maybe_unused]] volatile bool arr_neq = (arr_method_test != arr_method_test2);

            // Coverage: toml::array copy and move assignment
            // Memory safety: arr_assign_copy and arr_assign_move are stack allocated. Assignment involves deep copies or moves of elements.
            toml::array arr_assign_copy_src;
            arr_assign_copy_src.emplace_back(fdp.ConsumeRandomLengthString(3));
            arr_method_test2 = arr_assign_copy_src; // Copy assignment
            toml::array arr_assign_move_src;
            arr_assign_move_src.emplace_back(fdp.ConsumeIntegral<int64_t>());
            arr_method_test2 = std::move(arr_assign_move_src); // Move assignment (arr_assign_move_src is now moved-from)


            // Coverage: toml::array::flatten() & and &&
            // Memory safety: Elements are moved or copied, managed by unique_ptrs within arrays.
            toml::array arr_flatten_test;
            arr_flatten_test.emplace_back(10);
            toml::array nested_arr_for_flatten; nested_arr_for_flatten.emplace_back(20); nested_arr_for_flatten.emplace_back(30);
            arr_flatten_test.emplace_back(std::move(nested_arr_for_flatten));
            arr_flatten_test.emplace_back(40);
            [[maybe_unused]] toml::array flattened_arr_ref = arr_flatten_test.flatten(); // flatten &

            toml::array arr_flatten_test_move;
            arr_flatten_test_move.emplace_back(50);
            toml::array nested_arr_for_flatten_move; nested_arr_for_flatten_move.emplace_back(60);
            arr_flatten_test_move.emplace_back(std::move(nested_arr_for_flatten_move));
            [[maybe_unused]] toml::array flattened_arr_rval = std::move(arr_flatten_test_move).flatten(); // flatten &&


            // Coverage: operator<<(ostream&, array const&)
            std::ostringstream arr_s; 
            arr_s << arr_method_test; 
            [[maybe_unused]] volatile auto arr_str_out = arr_s.str();

            arr_method_test.clear(); 
        }


        // Coverage: Exercise JSON and YAML formatters (targets json_formatter.inl, yaml_formatter.inl)
        if (fdp.ConsumeBool()) {
            std::ostringstream json_s;
            // Memory safety: json_formatter temporary, root_table by const ref. json_s manages buffer.
            toml::json_formatter jf{ root_table }; 
            // Coverage: toml::v3::impl::formatter::indent(int) - Removed as it's private
            // jf.indent(fdp.ConsumeIntegralInRange(0,4));
            json_s << jf; 
            [[maybe_unused]] volatile auto json_str = json_s.str();
        }
        if (fdp.ConsumeBool()) {
            std::ostringstream yaml_s;
            // Memory safety: yaml_formatter temporary. yaml_s manages buffer.
            toml::yaml_formatter yf{ root_table };
            // Coverage: toml::v3::impl::formatter::indent(int) - Removed as it's private
            // yf.indent(fdp.ConsumeIntegralInRange(0,4));
            yaml_s << yf;
            [[maybe_unused]] volatile auto yaml_str = yaml_s.str();
        }
        // === End Added Code for Coverage Enhancement (Path, AtPath, Array Homogeneous, Formatters) ===

        // === Begin Added Code for Coverage Enhancement (Date/Time/DateTime/TimeOffset) ===
        if (fdp.ConsumeBool()) {
            // Memory safety: All date/time objects are stack-allocated.
            // toml::date
            toml::date d1{fdp.ConsumeIntegralInRange<int16_t>(1, 9999), 
                          fdp.ConsumeIntegralInRange<uint8_t>(1,12), 
                          fdp.ConsumeIntegralInRange<uint8_t>(1,28)}; // Simplified day range for validity
            toml::date d2{fdp.ConsumeIntegralInRange<int16_t>(1, 9999), 
                          fdp.ConsumeIntegralInRange<uint8_t>(1,12), 
                          fdp.ConsumeIntegralInRange<uint8_t>(1,28)};
            [[maybe_unused]] volatile bool d_eq = (d1 == d2); // Covers operator==(date,date)
            [[maybe_unused]] volatile bool d_neq = (d1 != d2); // Covers operator!=(date,date)
            [[maybe_unused]] volatile bool d_lt = (d1 < d2);   // Covers operator<(date,date) and date::pack
            [[maybe_unused]] volatile bool d_lte = (d1 <= d2); // Covers operator<=(date,date)
            [[maybe_unused]] volatile bool d_gt = (d1 > d2);   // Covers operator>(date,date)
            [[maybe_unused]] volatile bool d_gte = (d1 >= d2); // Covers operator>=(date,date)
            std::ostringstream date_s; date_s << d1; [[maybe_unused]] volatile auto date_str = date_s.str(); // Covers operator<<(ostream, date)

            // toml::time
            toml::time t1{fdp.ConsumeIntegralInRange<uint8_t>(0,23), 
                          fdp.ConsumeIntegralInRange<uint8_t>(0,59), 
                          fdp.ConsumeIntegralInRange<uint8_t>(0,59), 
                          fdp.ConsumeIntegralInRange<uint32_t>(0,999999999)};
            toml::time t2{fdp.ConsumeIntegralInRange<uint8_t>(0,23), 
                          fdp.ConsumeIntegralInRange<uint8_t>(0,59), 
                          fdp.ConsumeIntegralInRange<uint8_t>(0,59), 
                          fdp.ConsumeIntegralInRange<uint32_t>(0,999999999)};
            [[maybe_unused]] volatile bool t_eq = (t1 == t2);   // Covers operator==(time,time)
            [[maybe_unused]] volatile bool t_neq = (t1 != t2); // Covers operator!=(time,time)
            [[maybe_unused]] volatile bool t_lt = (t1 < t2);   // Covers operator<(time,time) and time::pack
            [[maybe_unused]] volatile bool t_lte = (t1 <= t2); // Covers operator<=(time,time)
            [[maybe_unused]] volatile bool t_gt = (t1 > t2);   // Covers operator>(time,time)
            [[maybe_unused]] volatile bool t_gte = (t1 >= t2); // Covers operator>=(time,time)
            std::ostringstream time_s; time_s << t1; [[maybe_unused]] volatile auto time_str = time_s.str(); // Covers operator<<(ostream, time)

            // toml::time_offset
            int16_t total_minutes1 = fdp.ConsumeIntegralInRange<int16_t>(-23*60, 23*60);
            int16_t offset_hours1 = total_minutes1 / 60;
            int16_t offset_minutes1 = total_minutes1 % 60;
            toml::time_offset to1{offset_hours1, offset_minutes1};

            int16_t total_minutes2 = fdp.ConsumeIntegralInRange<int16_t>(-23*60, 23*60);
            int16_t offset_hours2 = total_minutes2 / 60;
            int16_t offset_minutes2 = total_minutes2 % 60;
            toml::time_offset to2{offset_hours2, offset_minutes2};

            [[maybe_unused]] volatile bool to_eq = (to1 == to2);   // Covers operator==(time_offset,time_offset)
            [[maybe_unused]] volatile bool to_neq = (to1 != to2); // Covers operator!=(time_offset,time_offset)
            [[maybe_unused]] volatile bool to_lt = (to1 < to2);   // Covers operator<(time_offset,time_offset)
            [[maybe_unused]] volatile bool to_lte = (to1 <= to2); // Covers operator<=(time_offset,time_offset)
            [[maybe_unused]] volatile bool to_gt = (to1 > to2);   // Covers operator>(time_offset,time_offset)
            [[maybe_unused]] volatile bool to_gte = (to1 >= to2); // Covers operator>=(time_offset,time_offset)
            std::ostringstream time_offset_s; time_offset_s << to1; [[maybe_unused]] volatile auto to_str = time_offset_s.str(); // Covers operator<<(ostream, time_offset)
            
            // toml::date_time
            toml::date_time dt1{d1, t1}; // Local
            toml::date_time dt2{d2, t2, to1}; // With offset
            [[maybe_unused]] volatile bool dt_is_local1 = dt1.is_local(); // Covers date_time::is_local()
            [[maybe_unused]] volatile bool dt_is_local2 = dt2.is_local();
            if(dt2.offset) { [[maybe_unused]] volatile auto off_val = *dt2.offset; } // Covers optional::operator*
            [[maybe_unused]] volatile bool dt_eq = (dt1 == dt2);   // Covers operator==(date_time,date_time)
            [[maybe_unused]] volatile bool dt_neq = (dt1 != dt2); // Covers operator!=(date_time,date_time)
            [[maybe_unused]] volatile bool dt_lt = (dt1 < dt2);   // Covers operator<(date_time,date_time)
            [[maybe_unused]] volatile bool dt_lte = (dt1 <= dt2); // Covers operator<=(date_time,date_time)
            [[maybe_unused]] volatile bool dt_gt = (dt1 > dt2);   // Covers operator>(date_time,date_time)
            [[maybe_unused]] volatile bool dt_gte = (dt1 >= dt2); // Covers operator>=(date_time,date_time)
            std::ostringstream date_time_s; date_time_s << dt1; [[maybe_unused]] volatile auto dt_str = date_time_s.str(); // Covers operator<<(ostream, date_time)

            // Coverage: toml::date_time constructors from date and time
            [[maybe_unused]] toml::date_time dt_from_d(d1); // Covers date_time(date)
            [[maybe_unused]] toml::date_time dt_from_t(t1); // Covers date_time(time)
        }
        // === End Added Code for Coverage Enhancement (Date/Time/DateTime/TimeOffset) ===

        // === Begin Added Code for Coverage Enhancement (Literals and Table Ops) ===
        if (fdp.ConsumeBool()) {
            using namespace toml::literals;
            // Coverage: toml::literals::operator"" _toml (fixed string due to compile-time nature)
            try {
                [[maybe_unused]] auto parsed_from_lit = "fixed_key = 123"_toml;
            } catch (const toml::parse_error&) { /* literal parsing can fail */ }

            // Coverage: Exercise toml::table::operator== and operator!=
            // Memory safety: Tables are stack-allocated, elements managed internally.
            toml::table tbl_eq1, tbl_eq2;
            if (fdp.ConsumeBool()) tbl_eq1.insert("a", 1);
            if (fdp.ConsumeBool()) tbl_eq2.insert("a", (fdp.ConsumeBool() ? 1 : 2) );
            if (fdp.ConsumeBool()) tbl_eq1.insert("b", fdp.ConsumeRandomLengthString(4));
            if (fdp.ConsumeBool()) tbl_eq2.insert("b", (fdp.ConsumeBool() ? tbl_eq1["b"].value_or<std::string>("") : fdp.ConsumeRandomLengthString(3)) );
            
            [[maybe_unused]] volatile bool table_is_equal = (tbl_eq1 == tbl_eq2); // Covers table::equal and its internal visit
            [[maybe_unused]] volatile bool table_is_not_equal = (tbl_eq1 != tbl_eq2); // Covers table::operator!=
        }
        // === End Added Code for Coverage Enhancement (Literals and Table Ops) ===

        // Coverage: std::out_of_range from table::at()
        if (!root_table.empty() && fdp.ConsumeBool()) {
            try {
                // Attempt to access a key that is unlikely to exist.
                [[maybe_unused]] volatile auto& oor_tbl_at = root_table.at(fdp.ConsumeRandomLengthString(15) + "_non_existent_");
            } catch (const std::out_of_range&) { /* covered std::out_of_range for table::at */ }
        }


        // API 1: bool toml::v3::table::is_date()
        volatile bool root_is_date = root_table.is_date();
        volatile bool const_root_is_date = const_root_table.is_date(); // Coverage: Call const is_date on table

        // API 2: value<toml::v3::time> * toml::v3::table::as_time()
        volatile toml::value<toml::time>* root_as_time = root_table.as_time();
        if (root_as_time) {
            // This branch is unlikely to be hit for a table node itself.
        }
        volatile const toml::value<toml::time>* const_root_as_time = const_root_table.as_time(); // Coverage: Call const as_time on table
        if (const_root_as_time) {}


        // API 5: bool toml::v3::table::is_integer()
        volatile bool root_is_integer = root_table.is_integer();
        volatile bool const_root_is_integer = const_root_table.is_integer(); // Coverage: Call const is_integer on table


        // Added calls to uncovered functions for toml::table on root_table
        volatile bool root_is_string = root_table.is_string(); 
        volatile toml::value<std::string>* root_as_string = root_table.as_string(); 
        if (root_as_string) {} 
        volatile bool const_root_is_string = const_root_table.is_string(); // Coverage: Call const is_string on table
        volatile auto const_root_as_string_ptr = const_root_table.as_string(); if(const_root_as_string_ptr){} // Coverage: Call const as_string on table

        volatile bool root_is_fp = root_table.is_floating_point(); 
        volatile toml::value<double>* root_as_fp = root_table.as_floating_point(); 
        if (root_as_fp) {}
        volatile bool const_root_is_fp = const_root_table.is_floating_point(); // Coverage: Call const is_floating_point on table
        volatile auto const_root_as_fp_ptr = const_root_table.as_floating_point(); if(const_root_as_fp_ptr){} // Coverage: Call const as_floating_point on table


        volatile bool root_is_bool = root_table.is_boolean(); 
        volatile toml::value<bool>* root_as_bool = root_table.as_boolean(); 
        if (root_as_bool) {}
        volatile bool const_root_is_bool = const_root_table.is_boolean(); // Coverage: Call const is_boolean on table
        volatile auto const_root_as_bool_ptr = const_root_table.as_boolean(); if(const_root_as_bool_ptr){} // Coverage: Call const as_boolean on table

        volatile bool root_is_datetime = root_table.is_date_time(); 
        volatile toml::value<toml::date_time>* root_as_datetime = root_table.as_date_time(); 
        if (root_as_datetime) {}
        volatile bool const_root_is_datetime = const_root_table.is_date_time(); // Coverage: Call const is_date_time on table
        volatile auto const_root_as_datetime_ptr = const_root_table.as_date_time(); if(const_root_as_datetime_ptr){} // Coverage: Call const as_date_time on table

        volatile bool root_is_time_check = root_table.is_time(); 
        volatile toml::value<toml::date>* root_as_date = root_table.as_date(); 
        if (root_as_date) {}
        volatile bool const_root_is_time_check = const_root_table.is_time(); // Coverage: Call const is_time on table
        volatile auto const_root_as_date_ptr = const_root_table.as_date(); if(const_root_as_date_ptr){} // Coverage: Call const as_date on table


        for (auto&& [key, node_view] : root_table) {
            // If node_view is toml::node& due to table iteration behavior, pass its address.
            // If node_view is toml::node_view, then node_view.node() returns toml::node*.
            // The error message suggests node_view is treated as toml::node.
            exercise_node_type_apis(&node_view); 

            if (node_view.is_array()) { // Assuming node_view is toml::node&, this is a valid call
                toml::array* arr = node_view.as_array();
                if (arr) {
                    const toml::array* const_arr = arr; // Create const ref for const API coverage

                    // === Begin Added Code for Coverage Enhancement (Array type queries) ===
                    // Coverage: toml::array::is_table(), is_value(), as_table() (and const versions)
                    [[maybe_unused]] volatile bool arr_is_tbl = arr->is_table();
                    [[maybe_unused]] volatile bool arr_is_val = arr->is_value();
                    [[maybe_unused]] toml::table* arr_as_tbl = arr->as_table(); // Covers toml::array::as_table()
                    [[maybe_unused]] volatile bool const_arr_is_tbl = const_arr->is_table();
                    [[maybe_unused]] volatile bool const_arr_is_val = const_arr->is_value();
                    [[maybe_unused]] const toml::table* const_arr_as_tbl = const_arr->as_table(); // Covers toml::array::as_table() const
                    // === End Added Code for Coverage Enhancement (Array type queries) ===


                    volatile bool arr_is_number = arr->is_number();
                    volatile toml::value<int64_t>* arr_as_integer = arr->as_integer();
                    if (arr_as_integer) { }
                    volatile bool const_arr_is_number = const_arr->is_number(); // Coverage: Call const is_number on array
                    volatile auto const_arr_as_integer_ptr = const_arr->as_integer(); if(const_arr_as_integer_ptr){} // Coverage: Call const as_integer on array


                    volatile bool arr_is_string = arr->is_string(); 
                    volatile toml::value<std::string>* arr_as_string = arr->as_string(); 
                    if (arr_as_string) {}
                    volatile bool const_arr_is_string = const_arr->is_string(); // Coverage: Call const is_string on array
                    volatile auto const_arr_as_string_ptr = const_arr->as_string(); if(const_arr_as_string_ptr){} // Coverage: Call const as_string on array


                    volatile bool arr_is_fp = arr->is_floating_point(); 
                    volatile toml::value<double>* arr_as_fp = arr->as_floating_point(); 
                    if (arr_as_fp) {}
                    volatile bool const_arr_is_fp = const_arr->is_floating_point(); // Coverage: Call const is_floating_point on array
                    volatile auto const_arr_as_fp_ptr = const_arr->as_floating_point(); if(const_arr_as_fp_ptr){} // Coverage: Call const as_floating_point on array

                    volatile bool arr_is_bool = arr->is_boolean(); 
                    volatile toml::value<bool>* arr_as_bool = arr->as_boolean(); 
                    if (arr_as_bool) {}
                    volatile bool const_arr_is_bool = const_arr->is_boolean(); // Coverage: Call const is_boolean on array
                    volatile auto const_arr_as_bool_ptr = const_arr->as_boolean(); if(const_arr_as_bool_ptr){} // Coverage: Call const as_boolean on array

                    volatile bool arr_is_datetime = arr->is_date_time(); 
                    volatile toml::value<toml::date_time>* arr_as_datetime = arr->as_date_time(); 
                    if (arr_as_datetime) {}
                    volatile bool const_arr_is_datetime = const_arr->is_date_time(); // Coverage: Call const is_date_time on array
                    volatile auto const_arr_as_datetime_ptr = const_arr->as_date_time(); if(const_arr_as_datetime_ptr){} // Coverage: Call const as_date_time on array
                    
                    volatile bool arr_is_time = arr->is_time(); 
                    volatile bool arr_is_date = arr->is_date(); 
                    volatile toml::value<toml::time>* arr_as_time = arr->as_time(); 
                    if (arr_as_time) {}
                    volatile toml::value<toml::date>* arr_as_date_val = arr->as_date(); 
                    if (arr_as_date_val) {}
                    volatile bool const_arr_is_time = const_arr->is_time(); // Coverage: Call const is_time on array
                    volatile bool const_arr_is_date = const_arr->is_date(); // Coverage: Call const is_date on array
                    volatile auto const_arr_as_time_ptr = const_arr->as_time(); if(const_arr_as_time_ptr){} // Coverage: Call const as_time on array
                    volatile auto const_arr_as_date_ptr_val = const_arr->as_date(); if(const_arr_as_date_ptr_val){} // Coverage: Call const as_date on array


                    for (toml::node& element_node : *arr) { // Target for line 198: element_node.is_table()
                        exercise_node_type_apis(&element_node); 
                        if (element_node.is_table()) { // This branch is targeted by new code inserting arrays of tables
                            toml::table* nested_table = element_node.as_table();
                            if (nested_table) {
                                const toml::table* const_nested_table = nested_table; // Coverage: Create const ref

                                volatile bool nested_tbl_is_date = nested_table->is_date();
                                volatile toml::value<toml::time>* nested_tbl_as_time = nested_table->as_time();
                                volatile bool nested_tbl_is_integer = nested_table->is_integer();
                                volatile bool const_nested_tbl_is_date = const_nested_table->is_date(); // Coverage: Call const table methods
                                volatile auto const_nested_tbl_as_time = const_nested_table->as_time(); if(const_nested_tbl_as_time){}
                                volatile bool const_nested_tbl_is_integer = const_nested_table->is_integer();


                                volatile bool nt_is_string = nested_table->is_string(); 
                                volatile auto nt_as_string = nested_table->as_string(); 
                                if (nt_as_string) {}
                                volatile bool const_nt_is_string = const_nested_table->is_string(); // Coverage: Call const table methods
                                volatile auto const_nt_as_string = const_nested_table->as_string(); if(const_nt_as_string){}

                                // ... (similar const calls for other types on nested_table) ...
                            }
                        }
                    }
                }
            } else if (node_view.is_table()) { // Assuming node_view is toml::node&
                toml::table* sub_table = node_view.as_table();
                if (sub_table) {
                    const toml::table* const_sub_table = sub_table; // Coverage: Create const ref

                    volatile bool sub_tbl_is_date = sub_table->is_date();
                    volatile toml::value<toml::time>* sub_tbl_as_time = sub_table->as_time();
                    volatile bool sub_tbl_is_integer = sub_table->is_integer();
                    volatile bool const_sub_tbl_is_date = const_sub_table->is_date(); // Coverage: Call const table methods
                    volatile auto const_sub_tbl_as_time = const_sub_table->as_time(); if(const_sub_tbl_as_time){}
                    volatile bool const_sub_tbl_is_integer = const_sub_table->is_integer();

                    // ... (original calls for sub_table) ...
                    volatile bool st_is_string = sub_table->is_string(); 
                    volatile auto st_as_string = sub_table->as_string(); 
                    if (st_as_string) {}
                    volatile bool const_st_is_string = const_sub_table->is_string(); // Coverage: Call const table methods
                    volatile auto const_st_as_string = const_sub_table->as_string(); if(const_st_as_string){}
                    // ... (similar const calls for other types on sub_table) ...


                     for (auto&& [sub_key, sub_node_view_inner] : *sub_table) { // Target for line 245: sub_node_view_inner.is_array()
                        exercise_node_type_apis(&sub_node_view_inner); 
                        if (sub_node_view_inner.is_array()) { // This branch is targeted by new code inserting tables with nested arrays
                            toml::array* nested_arr = sub_node_view_inner.as_array();
                            if (nested_arr) {
                                const toml::array* const_nested_arr = nested_arr; // Coverage: Create const ref

                                volatile bool nested_arr_is_number = nested_arr->is_number();
                                volatile toml::value<int64_t>* nested_arr_as_integer = nested_arr->as_integer();
                                volatile bool const_nested_arr_is_number = const_nested_arr->is_number(); // Coverage: Call const array methods
                                volatile auto const_nested_arr_as_integer = const_nested_arr->as_integer(); if(const_nested_arr_as_integer){}

                                // ... (original calls for nested_arr) ...
                                volatile bool na_is_string = nested_arr->is_string(); 
                                volatile auto na_as_string = nested_arr->as_string(); 
                                if (na_as_string) {}
                                volatile bool const_na_is_string = const_nested_arr->is_string(); // Coverage: Call const array methods
                                volatile auto const_na_as_string = const_nested_arr->as_string(); if(const_na_as_string){}
                                // ... (similar const calls for other types on nested_arr) ...

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
        // Parsing can fail with malformed input; this is expected in fuzzing.
        // Coverage: toml::parse_error::description(), source(), operator<<
        [[maybe_unused]] volatile auto desc = err.description();
        [[maybe_unused]] volatile auto src = err.source();
        std::ostringstream err_s; err_s << err;
        [[maybe_unused]] volatile auto err_str_out = err_s.str();
    } catch (const std::exception& /*ex*/) {
        // Catch any other C++ standard library exceptions that might occur.
    }
    return 0;
}