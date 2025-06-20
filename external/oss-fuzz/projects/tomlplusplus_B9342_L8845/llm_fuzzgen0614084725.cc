#include "/src/tomlplusplus/include/toml++/toml.hpp" // Main TOML++ library header
#include <fuzzer/FuzzedDataProvider.h>
#include <string>
#include <vector>
#include <sstream>    // For std::ostringstream with formatters
#include <optional>   // For toml::time_offset

// Target APIs:
// 1. toml::parse(std::string_view): Core TOML parsing.
// 2. toml::table::insert_or_assign(toml::key&&, ValueType&&): Table manipulation with various types. (Corrected from emplace_or_assign)
// 3. toml::node::at_path(const toml::path&): Path-based node access.
// 4. toml::toml_formatter and its usage (operator<<): Serializing TOML data. This also covers its destructor.
// 5. toml::source_region::operator=(const toml::source_region&): Assignment of source_region objects.

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size) {
    FuzzedDataProvider fdp(Data, Size);

    // All memory is managed by RAII (tomlplusplus objects, std::string, std::vector, etc.)
    // No manual new/delete or malloc/free is needed.

    // 1. Parsing TOML input
    // Generate a TOML string from fuzzer data.
    std::string toml_string = fdp.ConsumeRandomLengthString(2048);
    toml::table tbl;
    try {
        tbl = toml::parse(toml_string);
        // tbl is now either a parsed table or an empty table if parsing failed but recovered.
    } catch (const toml::parse_error& /*err*/) {
        // Parsing failed, which is an expected outcome for fuzzed input.
        // tbl might be in a default (empty) state or an incompletely parsed state.
        // We can proceed with the (potentially empty) table.
    } catch (...) {
        // Catch any other unexpected exceptions during parsing.
        // In this case, we might not have a valid tbl to work with, so return.
        return 0;
    }

    // 2. Table Manipulation (insert_or_assign)
    // Randomly decide whether to manipulate the table.
    if (fdp.ConsumeBool()) {
        // Generate a key for insertion.
        std::string key_str = fdp.ConsumeRandomLengthString(64);
        // TOML keys cannot be empty.
        if (!key_str.empty()) {
            try {
                toml::key k(key_str); // Construct a TOML key. Can throw if key_str is invalid.

                // Consume a type selector to decide what type of value to emplace.
                uint8_t type_selector = fdp.ConsumeIntegralInRange<uint8_t>(0, 8);
                switch (type_selector) {
                    case 0: // String
                        tbl.insert_or_assign(k, fdp.ConsumeRandomLengthString(128));
                        break;
                    case 1: // Integer
                        tbl.insert_or_assign(k, fdp.ConsumeIntegral<int64_t>());
                        break;
                    case 2: // Float
                        tbl.insert_or_assign(k, fdp.ConsumeFloatingPoint<double>());
                        break;
                    case 3: // Boolean
                        tbl.insert_or_assign(k, fdp.ConsumeBool());
                        break;
                    case 4: // Date
                        // Construct toml::date with fuzzed values.
                        // The toml::date constructor should handle invalid values (e.g., by throwing).
                        tbl.insert_or_assign(k, toml::date{
                            fdp.ConsumeIntegralInRange<uint16_t>(0, 10000), // year (0 and >9999 can be invalid)
                            fdp.ConsumeIntegralInRange<uint8_t>(0, 15),   // month (0, 13-15 invalid)
                            fdp.ConsumeIntegralInRange<uint8_t>(0, 35)    // day (0, 32-35 invalid)
                        });
                        break;
                    case 5: // Time
                        // Construct toml::time with fuzzed values.
                        tbl.insert_or_assign(k, toml::time{
                            fdp.ConsumeIntegralInRange<uint8_t>(0, 25),   // hour (24-25 invalid)
                            fdp.ConsumeIntegralInRange<uint8_t>(0, 65),   // minute (60-65 invalid)
                            fdp.ConsumeIntegralInRange<uint8_t>(0, 65),   // second (60-65 invalid)
                            fdp.ConsumeIntegralInRange<uint32_t>(0, 1000000000) // nanosecond (>999,999,999 invalid)
                        });
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
                            if (fdp.ConsumeBool()) {
                                offset.emplace(
                                    fdp.ConsumeIntegralInRange<int8_t>(-23, 23), // hours
                                    fdp.ConsumeIntegralInRange<int8_t>(0, 59)    // minutes
                                );
                            }
                            if (offset) {
                                tbl.insert_or_assign(k, toml::date_time{dt_d, dt_t, *offset});
                            } else {
                                tbl.insert_or_assign(k, toml::date_time{dt_d, dt_t});
                            }
                        }
                        break;
                    case 7: // Array
                        {
                            toml::array arr;
                            if (fdp.ConsumeBool()) arr.push_back(fdp.ConsumeIntegral<int64_t>());
                            if (fdp.ConsumeBool()) arr.push_back(fdp.ConsumeRandomLengthString(16));
                            if (fdp.ConsumeBool()) arr.push_back(fdp.ConsumeBool());
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
                // Catch exceptions from key construction or insert_or_assign (e.g. invalid date/time values).
                // This is an expected outcome with fuzzed data.
            }
        }
    }

    // 3. Path-based Access (at_path)
    // Randomly decide to access elements by path.
    if (fdp.ConsumeBool() && !tbl.empty()) {
        std::string path_str = fdp.ConsumeRandomLengthString(128);
        if (!path_str.empty()) {
            try {
                toml::path p(path_str); // Construct toml::path. Can throw for malformed path string.
                
                // Use toml::table::at_path (or toml::node::at_path).
                // It returns a node_view, which is empty (evaluates to false) if path not found.
                if (auto nv = tbl.at_path(p)) {
                    // Successfully retrieved node_view, interact with it.
                    (void)nv.type(); // Get the type of the node.
                    // Try to get value based on type (optional).
                    if (nv.is_string()) (void)nv.value<std::string>();
                    else if (nv.is_integer()) (void)nv.value<int64_t>();
                    else if (nv.is_floating_point()) (void)nv.value<double>();
                    else if (nv.is_boolean()) (void)nv.value<bool>();
                }
            } catch (const toml::parse_error& /*pe*/) {
                // Malformed path string for toml::path constructor.
            } catch (const std::exception& /*e*/) {
                // Other exceptions, e.g., from value<T>() if type mismatch (though we check with is_type).
            }
        }
    }

    // 4. Formatting (toml_formatter)
    // Randomly decide to format the table to a string.
    // This also exercises the toml_formatter destructor when 'formatter' goes out of scope.
    if (fdp.ConsumeBool()) {
        try {
            std::ostringstream ss;
            toml::toml_formatter formatter{tbl}; // Create formatter for the table.
            ss << formatter;                     // Serialize the table to the stream.
            std::string formatted_toml_string = ss.str(); // Get the formatted string.
            // (void)formatted_toml_string; // "Use" the string to prevent optimization.
        } catch (const std::exception& /*e*/) {
            // Handle exceptions during formatting.
        }
    }

    // 5. source_region::operator=
    // Test assignment of source_region objects.
    // source_region objects are obtained from nodes after parsing.
    if (!tbl.empty() && fdp.ConsumeBool()) {
        auto it = tbl.begin();
        if (it != tbl.end()) {
            const toml::node* node1_ptr = &it->second; // Get pointer to the node from the table.
            toml::source_region sr1 = node1_ptr->source(); // Get its source_region.
            toml::source_region sr2;                   // Default-construct another source_region.

            // Perform assignment. This calls `toml::source_region::operator=`.
            sr2 = sr1; 

            // Assign from another node's source_region if available.
            if (tbl.size() > 1 && fdp.ConsumeBool()) {
                auto it2 = ++tbl.begin(); // Get the second element.
                 if (it2 != tbl.end()) {
                    const toml::node* node2_ptr = &it2->second; // Get pointer to the second node.
                    toml::source_region sr3 = node2_ptr->source();
                    sr1 = sr3; // Another assignment.
                }
            }
        }
    }

    return 0;
}