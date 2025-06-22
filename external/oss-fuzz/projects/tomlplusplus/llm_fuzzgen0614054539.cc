// Generated fuzz target for tomlplusplus
#include "toml++/toml.hpp" // Core tomlplusplus library: parsing, tables, arrays, nodes, values, etc.
                           // This header is expected to include necessary sub-headers like table.hpp, array.hpp, node.hpp, etc.
#include "toml++/impl/json_formatter.hpp" // For toml::json_formatter for serializing to JSON.
#include "toml++/impl/toml_formatter.hpp" // For toml::toml_formatter for serializing to TOML.
#include "toml++/impl/yaml_formatter.hpp" // For toml::yaml_formatter for serializing to YAML.


#include <fuzzer/FuzzedDataProvider.h>
#include <string>
#include <sstream> // For std::ostringstream used with formatters
#include <vector>  // For potential internal use, though not directly by fuzzer logic here.
#include <iostream> // For potential debugging, not used in final fuzzer logic.
#include <stdexcept> // For std::out_of_range

// Memory Management Note:
// tomlplusplus uses RAII extensively (Resource Acquisition Is Initialization).
// - toml::table, toml::array, and toml::value<T> manage their own memory.
// - Nodes within tables and arrays are typically stored as std::unique_ptr<toml::node> (toml::node_ptr),
//   ensuring automatic cleanup when the owning table/array goes out of scope.
// - This fuzzer creates toml::table and toml::array instances primarily on the stack.
//   Their destructors will handle the deallocation of any dynamically allocated memory they own.
// - std::string objects also manage their own memory.
// - node_view is a non-owning view.
// This approach ensures memory safety without manual new/delete.

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size) {
    FuzzedDataProvider fdp(Data, Size);

    // API 1: toml::parse - Parse a TOML string
    std::string toml_string_input = fdp.ConsumeRandomLengthString(1024);
    toml::table parsed_table; // Will hold the parsed result or remain empty on failure
    bool parsed_successfully = false;
    try {
        // Attempt to parse the fuzzer-generated TOML string.
        // This function can throw toml::parse_error on syntax errors.
        parsed_table = toml::parse(toml_string_input);
        parsed_successfully = true;
        // If successful, parsed_table now owns the parsed TOML data structure.
    } catch (const toml::parse_error& err) {
        // Successfully caught a parse error. This is a valid fuzzing path.
        // The error object (err) contains details about the parsing failure (err.description(), err.source()).
        // parsed_table remains default-constructed (empty).
        // Coverage: Exercise parse_error methods and its streaming operator.
        std::ostringstream err_ss;
        err_ss << err; // Exercises operator<<(ostream, parse_error), description(), source(), and source_region printing.
        (void)err.description(); // Explicit call to cover description() if not fully covered by stream.
        if (err.source().path) { // Check if source path exists
             (void)err.source().path->length(); // Access source_region's path if it exists
        }
        (void)err.source().begin.line; // Access source_region members
    } catch (const std::exception& ex) {
        // Catch any other standard exceptions that might occur during parsing.
    }


    // Create a table to be populated by the fuzzer, independent of parsing result.
    // This allows testing table/array manipulation APIs even if parsing fails.
    toml::table constructed_table;

    // API 2: toml::table::emplace - Populate a toml::table
    // Exercises table modification and toml::key creation/handling.
    int num_table_elements = fdp.ConsumeIntegralInRange<int>(0, 5);
    for (int i = 0; i < num_table_elements; ++i) {
        std::string key_str = fdp.ConsumeRandomLengthString(30); // Key for the table entry

        // Coverage: Extended type_choice to include date/time types (0-5 original, 6-8 new)
        uint8_t type_choice = fdp.ConsumeIntegralInRange<uint8_t>(0, 8);
        try {
            switch (type_choice) {
                case 0: // String value
                    constructed_table.emplace(key_str, fdp.ConsumeRandomLengthString(50));
                    break;
                case 1: // Integer value
                    constructed_table.emplace(key_str, fdp.ConsumeIntegral<int64_t>());
                    break;
                case 2: // Floating-point value
                    constructed_table.emplace(key_str, fdp.ConsumeFloatingPoint<double>());
                    break;
                case 3: // Boolean value
                    constructed_table.emplace(key_str, fdp.ConsumeBool());
                    break;
                case 4: { // Array value
                    // API 3: toml::array::emplace_back - Populate a toml::array
                    toml::array arr; // Create an array to be emplaced
                    int num_arr_elements = fdp.ConsumeIntegralInRange<int>(0, 3);
                    // Coverage: Extended arr_type_choice for date/time in arrays (0-3 original, 4-6 new)
                    uint8_t common_arr_type = fdp.ConsumeIntegralInRange<uint8_t>(0, 6);
                    bool make_homogeneous = fdp.ConsumeBool();

                    for (int j = 0; j < num_arr_elements; ++j) {
                        uint8_t arr_type_choice = make_homogeneous ? common_arr_type : fdp.ConsumeIntegralInRange<uint8_t>(0, 6);
                        try {
                             switch (arr_type_choice) {
                                case 0: arr.emplace_back(fdp.ConsumeRandomLengthString(20)); break;
                                case 1: arr.emplace_back(fdp.ConsumeIntegral<int64_t>()); break;
                                case 2: arr.emplace_back(fdp.ConsumeFloatingPoint<double>()); break;
                                case 3: arr.emplace_back(fdp.ConsumeBool()); break;
                                case 4: // Coverage: Add date to array
                                    arr.emplace_back(toml::date{
                                        fdp.ConsumeIntegralInRange<uint16_t>(1, 9999), // year
                                        fdp.ConsumeIntegralInRange<uint8_t>(1, 12),   // month
                                        fdp.ConsumeIntegralInRange<uint8_t>(1, 28)    // day
                                    });
                                    break;
                                case 5: // Coverage: Add time to array
                                    arr.emplace_back(toml::time{
                                        fdp.ConsumeIntegralInRange<uint8_t>(0, 23),   // hour
                                        fdp.ConsumeIntegralInRange<uint8_t>(0, 59),   // minute
                                        fdp.ConsumeIntegralInRange<uint8_t>(0, 59),   // second
                                        fdp.ConsumeIntegralInRange<uint32_t>(0, 999999999) // nanosecond
                                    });
                                    break;
                                case 6: // Coverage: Add date_time to array
                                    {
                                        toml::date d_arr{
                                            fdp.ConsumeIntegralInRange<uint16_t>(1, 9999),
                                            fdp.ConsumeIntegralInRange<uint8_t>(1, 12),
                                            fdp.ConsumeIntegralInRange<uint8_t>(1, 28)
                                        };
                                        toml::time t_arr{
                                            fdp.ConsumeIntegralInRange<uint8_t>(0, 23),
                                            fdp.ConsumeIntegralInRange<uint8_t>(0, 59),
                                            fdp.ConsumeIntegralInRange<uint8_t>(0, 59),
                                            fdp.ConsumeIntegralInRange<uint32_t>(0, 999999999)
                                        };
                                        if (fdp.ConsumeBool()) { // Optionally add offset
                                            toml::time_offset offset_arr{
                                                fdp.ConsumeIntegralInRange<int8_t>(-23, 23), // offset hours
                                                fdp.ConsumeIntegralInRange<int8_t>(0, 59)    // offset minutes
                                            };
                                            arr.emplace_back(toml::date_time{d_arr, t_arr, offset_arr});
                                        } else {
                                            arr.emplace_back(toml::date_time{d_arr, t_arr});
                                        }
                                    }
                                    break;
                            }
                        } catch (const std::exception&) { /* Ignore exceptions during array element emplace */ }
                    }

                    // Coverage: Exercise basic toml::array type check methods (is_X) that were uncovered or had low coverage.
                    // These methods return false for an array, exercising those paths.
                    if (fdp.ConsumeBool()) (void)arr.is_table();
                    if (fdp.ConsumeBool()) (void)arr.is_value();
                    if (fdp.ConsumeBool()) (void)arr.is_string();
                    if (fdp.ConsumeBool()) (void)arr.is_integer();
                    if (fdp.ConsumeBool()) (void)arr.is_floating_point();
                    if (fdp.ConsumeBool()) (void)arr.is_number();
                    if (fdp.ConsumeBool()) (void)arr.is_boolean();
                    if (fdp.ConsumeBool()) (void)arr.is_date();
                    if (fdp.ConsumeBool()) (void)arr.is_time();
                    if (fdp.ConsumeBool()) (void)arr.is_date_time();
                    // Coverage: arr.is_array() returns true.
                    if (fdp.ConsumeBool()) (void)arr.is_array();


                    // Coverage: Exercise const accessor methods for toml::array.
                    if (!arr.empty()) {
                        const toml::array& const_arr_ref = arr; // Create const reference to call const methods.
                        size_t arr_idx = fdp.ConsumeIntegralInRange<size_t>(0, arr.size() - 1); // Safe index.
                        if (fdp.ConsumeBool()) { try { (void)const_arr_ref.at(arr_idx); } catch(const std::out_of_range&){} } // Call const at().
                        if (fdp.ConsumeBool()) (void)const_arr_ref.get(arr_idx); // Call const get().
                        // Coverage: Call const get() with out-of-bounds index to cover false branch of 'index < elems_.size()'
                        if (fdp.ConsumeBool()) (void)const_arr_ref.get(const_arr_ref.size());
                        if (fdp.ConsumeBool()) (void)const_arr_ref.front(); // Call const front().
                        if (fdp.ConsumeBool()) (void)const_arr_ref.back(); // Call const back().
                        if (fdp.ConsumeBool()) (void)const_arr_ref[arr_idx]; // Call const operator[].
                    } else {
                        // Coverage: Call const get() on empty array
                        const toml::array& const_arr_ref = arr;
                        if (fdp.ConsumeBool()) (void)const_arr_ref.get(0);
                    }


                    // Coverage: Exercise is_homogeneous branches for toml::array.
                    // Memory Safety: empty_arr_for_homogeneous_test is stack-allocated; RAII handles cleanup.
                    toml::array empty_arr_for_homogeneous_test;
                    if (fdp.ConsumeBool()) (void)empty_arr_for_homogeneous_test.is_homogeneous(toml::node_type::string); // Branch: empty array.
                    if (fdp.ConsumeBool()) (void)arr.is_homogeneous(toml::node_type::none); // Branch: ntype == node_type::none.
                    // Other branches of is_homogeneous are implicitly tested by how `arr` is populated (homogeneously or heterogeneously).


                    // Coverage: Exercise some toml::array methods (at, operator[]) that were uncovered (non-const versions already present).
                    if (!arr.empty()) {
                        size_t arr_idx = fdp.ConsumeIntegralInRange<size_t>(0, arr.size() - 1); // Safe index
                        if (fdp.ConsumeBool()) { try { (void)arr.at(arr_idx); } catch(const std::out_of_range&){} }
                        if (fdp.ConsumeBool()) { (void)arr[arr_idx]; }
                        // Coverage: Call non-const get() with out-of-bounds index
                        if (fdp.ConsumeBool()) (void)arr.get(arr.size());
                    } else {
                         // Coverage: Call non-const get() on empty array
                        if (fdp.ConsumeBool()) (void)arr.get(0);
                    }


                    // Emplace the constructed array into the table. std::move transfers ownership.
                    constructed_table.emplace(key_str, std::move(arr));
                    break;
                }
                case 5: { // Nested table value
                    toml::table nested_tbl;
                    if (fdp.ConsumeBool()) { // Optionally add an element to the nested table
                       std::string nested_key = fdp.ConsumeRandomLengthString(20);
                       nested_tbl.emplace(nested_key, fdp.ConsumeIntegral<int64_t>());
                    }
                    // Emplace the nested table. std::move transfers ownership.
                    constructed_table.emplace(key_str, std::move(nested_tbl));
                    break;
                }
                // Coverage: Add date, time, date_time cases for table emplace
                case 6: // Date
                    {
                        toml::date d_val{
                            fdp.ConsumeIntegralInRange<uint16_t>(1, 9999),
                            fdp.ConsumeIntegralInRange<uint8_t>(1, 12),
                            fdp.ConsumeIntegralInRange<uint8_t>(1, 28)
                        };
                        constructed_table.emplace(key_str, d_val);
                        // Coverage: Exercise date comparison and streaming
                        if (fdp.ConsumeBool()) { toml::date d_cmp = d_val; (void)(d_val == d_cmp); (void)(d_val != d_cmp); (void)(d_val < d_cmp); }
                        if (fdp.ConsumeBool()) { std::ostringstream d_s; d_s << d_val; (void)d_s.str(); }
                    }
                    break;
                case 7: // Time
                    {
                        toml::time t_val{
                            fdp.ConsumeIntegralInRange<uint8_t>(0, 23),
                            fdp.ConsumeIntegralInRange<uint8_t>(0, 59),
                            fdp.ConsumeIntegralInRange<uint8_t>(0, 59),
                            fdp.ConsumeIntegralInRange<uint32_t>(0, 999999999)
                        };
                        constructed_table.emplace(key_str, t_val);
                        // Coverage: Exercise time comparison and streaming
                        if (fdp.ConsumeBool()) { toml::time t_cmp = t_val; (void)(t_val == t_cmp); (void)(t_val != t_cmp); (void)(t_val > t_cmp); }
                        if (fdp.ConsumeBool()) { std::ostringstream t_s; t_s << t_val; (void)t_s.str(); }
                    }
                    break;
                case 8: // DateTime
                    {
                        toml::date d_tbl{
                            fdp.ConsumeIntegralInRange<uint16_t>(1, 9999),
                            fdp.ConsumeIntegralInRange<uint8_t>(1, 12),
                            fdp.ConsumeIntegralInRange<uint8_t>(1, 28)
                        };
                        toml::time t_tbl{
                            fdp.ConsumeIntegralInRange<uint8_t>(0, 23),
                            fdp.ConsumeIntegralInRange<uint8_t>(0, 59),
                            fdp.ConsumeIntegralInRange<uint8_t>(0, 59),
                            fdp.ConsumeIntegralInRange<uint32_t>(0, 999999999)
                        };
                        toml::date_time dt_val_no_offset{d_tbl, t_tbl}; // Coverage: date_time(date, time) constructor
                        // Coverage: date_time(date) and date_time(time) constructors
                        if (fdp.ConsumeBool()) { toml::date_time dt_from_d(d_tbl); (void)dt_from_d; }
                        if (fdp.ConsumeBool()) { toml::date_time dt_from_t(t_tbl); (void)dt_from_t; }


                        if (fdp.ConsumeBool()) { // Optionally add offset
                             toml::time_offset offset_tbl{
                                fdp.ConsumeIntegralInRange<int8_t>(-23, 23),
                                fdp.ConsumeIntegralInRange<int8_t>(0, 59)
                            };
                            toml::date_time dt_val{d_tbl, t_tbl, offset_tbl};
                            constructed_table.emplace(key_str, dt_val);
                            // Coverage: Exercise date_time comparison, streaming, and is_local()
                            if (fdp.ConsumeBool()) { toml::date_time dt_cmp = dt_val; (void)(dt_val == dt_cmp); (void)(dt_val >= dt_cmp); }
                            if (fdp.ConsumeBool()) { std::ostringstream dt_s; dt_s << dt_val; (void)dt_s.str(); }
                            if (fdp.ConsumeBool()) (void)dt_val.is_local();
                        } else {
                            constructed_table.emplace(key_str, dt_val_no_offset);
                            // Coverage: Exercise date_time comparison, streaming, and is_local()
                            if (fdp.ConsumeBool()) { toml::date_time dt_cmp = dt_val_no_offset; (void)(dt_val_no_offset == dt_cmp); (void)(dt_val_no_offset <= dt_cmp); }
                            if (fdp.ConsumeBool()) { std::ostringstream dt_s; dt_s << dt_val_no_offset; (void)dt_s.str(); }
                            if (fdp.ConsumeBool()) (void)dt_val_no_offset.is_local();
                        }
                    }
                    break;
            }
        } catch (const std::exception&) {
            // Catch exceptions from table.emplace (e.g., if an invalid key somehow causes issues, though unlikely for basic types).
            // Note: toml::table::emplace overwrites if key exists, doesn't throw for duplicates.
        }
    }

    // Choose a table to operate on for path and visit operations: either the parsed one or the constructed one.
    toml::table& target_table_for_ops = parsed_successfully ? parsed_table : constructed_table;

    // API 4: toml::node::at_path (via toml::table) - Access elements using a TOML path
    if (fdp.ConsumeBool() && !target_table_for_ops.empty()) {
        std::string path_str = fdp.ConsumeRandomLengthString(40); // Path string to query
        try {
            toml::node_view<toml::node> node_v = target_table_for_ops.at_path(path_str);
            if (node_v) { // Check if the node_view points to a valid node
                // Successfully found a node. Try to get its value or visit it.
                if (fdp.ConsumeBool()) {
                    auto val_as_string = node_v.value<std::string>(); // Attempt to get as string
                } else {
                    auto val_as_int = node_v.value_or<int64_t>(0LL); // Get as int or default
                }

                // API 5: toml::node::visit - Visit the node to interact with its specific type
                node_v.visit([&fdp](auto&& visited_node) {
                    // visited_node is a reference to the actual underlying toml::value<T>, toml::array, or toml::table.
                    // This exercises type dispatch within the library.
                    using concrete_node_type = std::decay_t<decltype(visited_node)>;
                    if constexpr (toml::is_string<concrete_node_type>) {
                        std::string s_val = *visited_node; // Access string value
                        (void)s_val; // Suppress unused warning
                    } else if constexpr (toml::is_integer<concrete_node_type>) {
                        int64_t i_val = *visited_node; // Access integer value
                        (void)i_val; // Suppress unused warning
                    } else if constexpr (toml::is_floating_point<concrete_node_type>) { // Added for completeness
                        double f_val = *visited_node;
                        (void)f_val;
                    } else if constexpr (toml::is_boolean<concrete_node_type>) { // Added for completeness
                        bool b_val = *visited_node;
                        (void)b_val;
                    // Coverage: Add visit branches for date/time types based on coverage report
                    } else if constexpr (toml::is_date<concrete_node_type>) {
                        toml::date d_val = *visited_node;
                        (void)d_val;
                    } else if constexpr (toml::is_time<concrete_node_type>) {
                        toml::time t_val = *visited_node;
                        (void)t_val;
                    } else if constexpr (toml::is_date_time<concrete_node_type>) {
                        toml::date_time dt_val = *visited_node;
                        (void)dt_val;
                    } else if constexpr (toml::is_array<concrete_node_type>) {
                        // visited_node is a toml::array&
                        if (!visited_node.empty()) {
                             // Coverage: Exercise array methods (get, front, back) if node is an array
                             if (fdp.ConsumeBool()) (void)visited_node.get(0);
                             if (fdp.ConsumeBool()) (void)visited_node.front();
                             if (fdp.ConsumeBool()) (void)visited_node.back();
                        }
                        // Coverage: Test is_array_of_tables and is_homogeneous for arrays from coverage report
                        if (fdp.ConsumeBool()) (void)visited_node.is_array_of_tables();
                        if (fdp.ConsumeBool()) (void)visited_node.is_homogeneous(toml::node_type::integer); // Test with a fixed type
                    } else if constexpr (toml::is_table<concrete_node_type>) {
                        // visited_node is a toml::table&
                        if (!visited_node.empty() && fdp.ConsumeBool()) {
                            // Coverage: Iterate first element of the table and try to get a key to cover table iteration and get
                            for (const auto& [tbl_k, tbl_v_node] : visited_node) {
                                (void)tbl_k; (void)tbl_v_node; // Access key and value
                                break;
                            }
                            if (fdp.ConsumeBool()) {
                                std::string fuzzed_key_str = fdp.ConsumeRandomLengthString(10);
                                (void)visited_node.get(fuzzed_key_str); // Call get() on table
                            }
                        }
                        // Coverage: Call is_inline for tables from coverage report
                        if (fdp.ConsumeBool()) (void)visited_node.is_inline();
                    }
                });
            }
        } catch (const toml::parse_error&) {
            // at_path can throw toml::parse_error for invalid path syntax.
        } catch (const std::out_of_range&) {
            // at_path can throw std::out_of_range if path is syntactically valid but element not found.
        } catch (const std::exception&) {
            // Other potential exceptions during path access.
        }
    }

    // Coverage: Exercise toml::path and toml::path_component
    std::string p_str_for_path = fdp.ConsumeRandomLengthString(30);
    try {
        toml::path toml_p(p_str_for_path); // Constructor from string_view
        if (fdp.ConsumeBool()) (void)toml_p.empty();
        if (fdp.ConsumeBool()) (void)toml_p.size();
        if (fdp.ConsumeBool()) { std::ostringstream path_ss; path_ss << toml_p; (void)path_ss.str(); } // Covers print_to via operator<<
        if (fdp.ConsumeBool()) { (void)toml_p.str(); } // Covers str()

        for (const auto& component : toml_p) { // Covers iterators
            if (component.type() == toml::path_component_type::key) { (void)component.key(); }
            else if (component.type() == toml::path_component_type::array_index) { (void)component.index(); }
        }
        if (!target_table_for_ops.empty() && !toml_p.empty()) {
             // Coverage: Exercise table::at_path(const toml::path&)
            (void)target_table_for_ops.at_path(toml_p);
            const toml::table& const_target_table = target_table_for_ops;
             // Coverage: Exercise table::at_path(const toml::path&) const
            (void)const_target_table.at_path(toml_p);
        }
    } catch (const std::exception&) {
        // Path construction can throw for invalid syntax
    }


    // API: Formatting
    if (fdp.ConsumeBool()) { // JSON Formatter (already present)
        try {
            std::ostringstream ss;
            ss << toml::json_formatter{target_table_for_ops};
            std::string json_output = ss.str();
            (void)json_output;
        } catch (const std::exception&) {}
    }
    if (fdp.ConsumeBool()) { // Coverage: Add TOML Formatter
        try {
            std::ostringstream ss;
            ss << toml::toml_formatter{target_table_for_ops};
            std::string toml_output = ss.str();
            (void)toml_output;
        } catch (const std::exception&) {}
    }
    if (fdp.ConsumeBool()) { // Coverage: Add YAML Formatter
        try {
            std::ostringstream ss;
            ss << toml::yaml_formatter{target_table_for_ops};
            std::string yaml_output = ss.str();
            (void)yaml_output;
        } catch (const std::exception&) {}
    }


    // All tomlplusplus objects (table, array, value) manage their memory via RAII.
    // When they go out of scope here, their destructors will free associated resources.
    return 0;
}