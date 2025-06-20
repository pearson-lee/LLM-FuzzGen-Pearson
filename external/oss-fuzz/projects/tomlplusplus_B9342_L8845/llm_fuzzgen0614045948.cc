// Generated fuzz target for tomlplusplus
#include "toml++/toml.hpp" // Core tomlplusplus library: parsing, tables, arrays, nodes, values, etc.
                           // This header is expected to include necessary sub-headers like table.hpp, array.hpp, node.hpp, etc.
#include "toml++/impl/json_formatter.hpp" // For toml::json_formatter for serializing to JSON.

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
                    
                    // Coverage: Exercise basic toml::array type check methods that were uncovered
                    if(fdp.ConsumeBool()) (void)arr.is_table(); 
                    if(fdp.ConsumeBool()) (void)arr.is_array();

                    // Coverage: Exercise some toml::array methods (at, operator[]) that were uncovered
                    if (!arr.empty()) {
                        size_t arr_idx = fdp.ConsumeIntegralInRange<size_t>(0, arr.size() - 1); // Safe index
                        if (fdp.ConsumeBool()) { try { (void)arr.at(arr_idx); } catch(const std::out_of_range&){} }
                        if (fdp.ConsumeBool()) { (void)arr[arr_idx]; } 
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
                    constructed_table.emplace(key_str, toml::date{
                        fdp.ConsumeIntegralInRange<uint16_t>(1, 9999),
                        fdp.ConsumeIntegralInRange<uint8_t>(1, 12),
                        fdp.ConsumeIntegralInRange<uint8_t>(1, 28)
                    });
                    break;
                case 7: // Time
                    constructed_table.emplace(key_str, toml::time{
                        fdp.ConsumeIntegralInRange<uint8_t>(0, 23),
                        fdp.ConsumeIntegralInRange<uint8_t>(0, 59),
                        fdp.ConsumeIntegralInRange<uint8_t>(0, 59),
                        fdp.ConsumeIntegralInRange<uint32_t>(0, 999999999)
                    });
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
                        if (fdp.ConsumeBool()) { // Optionally add offset
                             toml::time_offset offset_tbl{
                                fdp.ConsumeIntegralInRange<int8_t>(-23, 23),
                                fdp.ConsumeIntegralInRange<int8_t>(0, 59)
                            };
                            constructed_table.emplace(key_str, toml::date_time{d_tbl, t_tbl, offset_tbl});
                        } else {
                            constructed_table.emplace(key_str, toml::date_time{d_tbl, t_tbl});
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

    // Bonus API: Formatting (e.g., toml::json_formatter)
    // This also implicitly uses node visiting logic.
    if (fdp.ConsumeBool()) {
        try {
            std::ostringstream ss;
            // Format the target_table_for_ops (either parsed or constructed) as JSON.
            ss << toml::json_formatter{target_table_for_ops};
            std::string json_output = ss.str(); // The resulting JSON string.
            (void)json_output; // Suppress unused variable warning if not used.
        } catch (const std::exception&) {
            // Formatting might throw exceptions for various reasons (e.g., deeply nested structures, specific value types).
        }
    }
    
    // All tomlplusplus objects (table, array, value) manage their memory via RAII.
    // When they go out of scope here, their destructors will free associated resources.
    return 0;
}