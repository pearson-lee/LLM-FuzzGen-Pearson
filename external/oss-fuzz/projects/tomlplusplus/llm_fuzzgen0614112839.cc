#include <cstddef>
#include <cstdint>
#include <string>
#include <sstream> // Required for std::ostringstream

// Main header for tomlplusplus, expected to be in a "toml++" subdirectory
// This should provide access to all necessary toml types and functions.
#include "toml++/toml.hpp" 
#include <fuzzer/FuzzedDataProvider.h>

// This fuzz target aims to exercise the following 0%-coverage APIs (or their effects)
// by creating and manipulating TOML objects and structures:
// 1. `toml::v3::key::~key(...)` - Exercised by creating toml::key objects.
// 2. `toml::v3::value<std::string>::~value(...)` (and other value types) - Exercised by creating toml::value objects.
// 3. `toml::v3::ex::parse_error::~~parse_error()` - Exercised by the try-catch block around toml::parse.
// 4. `toml::v3::toml_formatter::~~toml_formatter()` - Exercised by creating and using toml::toml_formatter.
// 5. `struct source_region & toml::v3::source_region::operator=(...)` - Exercised by assigning toml::source_region objects.
//
// Additionally, creating toml::array and toml::table and adding elements to them will
// indirectly exercise `toml::v3::impl::array_init_elem::~array_init_elem` and
// `toml::v3::impl::table_init_pair::~table_init_pair` respectively.

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size) {
    FuzzedDataProvider fdp(Data, Size);

    // Consume data to generate a TOML string for parsing.
    std::string toml_string = fdp.ConsumeRandomLengthString(Size); // Use a portion for the string
    
    toml::table tbl;
    bool parsed_ok = false;

    // 1. Attempt to parse the TOML string.
    // This will exercise parsing logic and, if an error occurs, the creation
    // and destruction of `toml::parse_error` (targeting `toml::v3::ex::parse_error::~~parse_error()`).
    // It also provides an opportunity to use `toml::source_region`.
    try {
        tbl = toml::parse(toml_string);
        parsed_ok = true;
    } catch (const toml::parse_error& err) {
        // `err` object is created and will be destroyed when it goes out of scope.
        // Exercise `toml::source_region::operator=` using the error's source.
        if (fdp.ConsumeBool()) {
            toml::source_region sr1 = err.source(); // Copy construction
            toml::source_region sr2;
            sr2 = sr1; // Assignment operator (targets `source_region::operator=`)
                       // Memory for sr1 and sr2 is managed by their destructors.
        }
    } catch (...) {
        // Catch any other exceptions to prevent crashes.
    }

    // 2. Exercise `toml::key` creation and destruction (targets `toml::v3::key::~key`).
    if (fdp.ConsumeBool()) {
        std::string key_name = fdp.ConsumeRandomLengthString(32);
        if (!key_name.empty()) { // Ensure key is not empty if library requires
             toml::key k(key_name); 
             // `k` is stack-allocated; its destructor is called automatically upon scope exit.
        }
    }

    // 3. Exercise `toml::value` creation and destruction for various types
    // (targets `toml::v3::value<T>::~value` for different T).
    if (fdp.ConsumeBool()) {
        std::string str_val = fdp.ConsumeRandomLengthString(64);
        toml::value<std::string> v_str(str_val); // Destructor called on scope exit.
    }
    if (fdp.ConsumeBool()) {
        toml::value<int64_t> v_int(fdp.ConsumeIntegral<int64_t>()); // Destructor called.
    }
    if (fdp.ConsumeBool()) {
        toml::value<double> v_double(fdp.ConsumeFloatingPoint<double>()); // Destructor called.
    }
    if (fdp.ConsumeBool()) {
        toml::value<bool> v_bool(fdp.ConsumeBool()); // Destructor called.
    }
    // Create date, time, datetime values
    if (fdp.ConsumeBool()) {
        toml::value<toml::date> v_date(
            fdp.ConsumeIntegralInRange<uint16_t>(1, 9999), 
            fdp.ConsumeIntegralInRange<uint8_t>(1, 12), 
            fdp.ConsumeIntegralInRange<uint8_t>(1, 28) // Keep day simple
        );
    }
    if (fdp.ConsumeBool()) {
        toml::value<toml::time> v_time(
            fdp.ConsumeIntegralInRange<uint8_t>(0, 23), 
            fdp.ConsumeIntegralInRange<uint8_t>(0, 59), 
            fdp.ConsumeIntegralInRange<uint8_t>(0, 59),
            fdp.ConsumeIntegralInRange<uint32_t>(0, 999999999)
        );
    }
     if (fdp.ConsumeBool()) {
        toml::value<toml::date_time> v_datetime(
            toml::date{fdp.ConsumeIntegralInRange<uint16_t>(1, 9999), 
                       fdp.ConsumeIntegralInRange<uint8_t>(1, 12), 
                       fdp.ConsumeIntegralInRange<uint8_t>(1, 28)},
            toml::time{fdp.ConsumeIntegralInRange<uint8_t>(0, 23), 
                       fdp.ConsumeIntegralInRange<uint8_t>(0, 59), 
                       fdp.ConsumeIntegralInRange<uint8_t>(0, 59)}
        );
    }


    // If parsing was successful, interact with the parsed table.
    // Otherwise, we might use a default-constructed or minimally populated table for formatters.
    if (parsed_ok) {
        // 5. Exercise `source_region::operator=` via a node's source, if table is not empty.
        if (!tbl.empty() && fdp.ConsumeBool()) {
            auto it = tbl.begin(); // Get an iterator to the first element
            if (it != tbl.end()) {
                const toml::node* n_ptr = &(it->second); // Get the node
                if (n_ptr) {
                    toml::source_region sr_node1 = n_ptr->source(); // Copy construction
                    toml::source_region sr_node2;
                    sr_node2 = sr_node1; // Assignment operator
                                         // sr_node1, sr_node2 destructors called on scope exit.
                }
            }
        }

        // Add elements to the table to exercise table/array/value creation/destruction.
        // This indirectly exercises internal destructors like `array_init_elem` and `table_init_pair`.
        if (fdp.ConsumeBool()) {
            std::string new_key_str = fdp.ConsumeRandomLengthString(10);
            if (!new_key_str.empty()) { // Ensure key is valid
                tbl.insert_or_assign(new_key_str, fdp.ConsumeRandomLengthString(20));
                // Nodes created here are managed by the table.
            }
        }
        if (fdp.ConsumeBool()) {
            std::string arr_key_str = fdp.ConsumeRandomLengthString(10);
            if (!arr_key_str.empty()) { // Ensure key is valid
                toml::array arr; // Stack-allocated array
                if (fdp.ConsumeBool()) arr.push_back(fdp.ConsumeIntegral<int64_t>());
                if (fdp.ConsumeBool()) arr.push_back(fdp.ConsumeRandomLengthString(5));
                tbl.insert_or_assign(arr_key_str, arr); 
                // `arr` is copied into the table; its own destructor and elements' destructors
                // are called when `arr` goes out of scope. Nodes in table managed by table.
            }
        }
    } else {
        // If parsing failed, populate the table with some basic data for formatters.
        if (fdp.ConsumeBool()) {
            std::string key1 = fdp.ConsumeRandomLengthString(5);
            if (!key1.empty()) {
                 tbl.insert_or_assign(key1, "default_value");
            }
        }
    }

    // 4. Exercise `toml::toml_formatter` creation, usage, and destruction
    // (targets `toml::v3::toml_formatter::~~toml_formatter()`).
    if (fdp.ConsumeBool()) {
        std::ostringstream ss;
        toml::toml_formatter formatter{tbl}; // Formatter created on stack.
        ss << formatter;                     // Use the formatter.
        // `formatter` destructor called automatically on scope exit.
    }
    
    // Exercise other formatters for functional diversity.
    // Their destructors would also be called if they were 0% and targeted.
    if (fdp.ConsumeBool()) {
        std::ostringstream ss;
        toml::json_formatter json_fmt{tbl}; // Stack-allocated.
        ss << json_fmt;                     // Destructor called on scope exit.
    }
    if (fdp.ConsumeBool()) {
        std::ostringstream ss;
        toml::yaml_formatter yaml_fmt{tbl}; // Stack-allocated.
        ss << yaml_fmt;                     // Destructor called on scope exit.
    }

    // All stack-allocated TOML objects (tbl, keys, values, formatters, source_regions, arrays)
    // will have their destructors called automatically when they go out of scope.
    // The `toml::table` (tbl) manages the memory of the nodes it contains.
    return 0;
}