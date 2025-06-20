#include "/src/tomlplusplus/include/toml++/toml.h" // Main library header for tomlplusplus
#include <fuzzer/FuzzedDataProvider.h>
#include <string>
#include <vector>    // For std::vector to hold node_type options
#include <exception> // Required for std::exception

// Entry point for the fuzzer
extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    FuzzedDataProvider fdp(data, size);

    // Consume data for TOML input. This string will be parsed by the library.
    std::string toml_string = fdp.ConsumeRemainingBytesAsString();

    // Define available node types to test with is_homogeneous.
    // These represent the different types of values a TOML node can hold.
    const std::vector<toml::node_type> node_types = {
        toml::node_type::none,          toml::node_type::string,
        toml::node_type::integer,       toml::node_type::floating_point,
        toml::node_type::boolean,       toml::node_type::date,
        toml::node_type::time,          toml::node_type::date_time,
        toml::node_type::array,         toml::node_type::table
    };

    try {
        // API 1: Parse the TOML string using toml::parse.
        // This is a primary input processing API that constructs the TOML data structure.
        // The toml::table object (toml_doc) manages its own memory via RAII.
        // When toml_doc goes out of scope at the end of this function, or if an
        // exception occurs, its destructor is automatically called. This destructor
        // is responsible for freeing all memory allocated for the TOML document,
        // including all contained nodes, arrays, and tables, thus preventing memory leaks.
        toml::table toml_doc = toml::parse(toml_string);

        // API 5 (on table): Call node::type() via table.
        // Tables are a type of node, so this retrieves its type (should be toml::node_type::table).
        (void)toml_doc.type();

        // API 2: Test toml::table::is_homogeneous.
        // This function checks if all key-value pairs in the table have values of the same specified node_type.
        if (!node_types.empty() && fdp.remaining_bytes() > 0) {
            toml::node_type type_for_table_homo = node_types[fdp.ConsumeIntegralInRange<size_t>(0, node_types.size() - 1)];
            (void)toml_doc.is_homogeneous(type_for_table_homo);

            // Test the overload of is_homogeneous that can return the first non-matching node.
            // The pointer first_mismatch_node_table is passed by reference to be potentially set by the function.
            toml::node* first_mismatch_node_table = nullptr; // Must be initialized
            (void)toml_doc.is_homogeneous(type_for_table_homo, first_mismatch_node_table);
        }

        // Iterate through the parsed TOML table to access its elements (key-value pairs).
        for (auto &&[key, val_node] : toml_doc) {
            (void)key; // Suppress unused variable warning if key is not directly used.

            // API 5 (on node): Call node::type() on each value node in the table.
            (void)val_node.type();

            // Check if the current node is an array to test array-specific APIs.
            if (val_node.is_array()) {
                toml::array *arr = val_node.as_array(); // Get a pointer to the array.
                if (arr) {
                    // API 5 (on array): Call node::type() via array.
                    // Arrays are also nodes.
                    (void)arr->type();

                    // API 4: Test toml::array::is_array_of_tables.
                    // This checks if the array exclusively contains tables.
                    (void)arr->is_array_of_tables();

                    // API 3: Test toml::array::is_homogeneous.
                    // Checks if all elements in the array are of the same specified node_type.
                    if (!node_types.empty() && fdp.remaining_bytes() > 0) {
                        toml::node_type type_for_array_homo = node_types[fdp.ConsumeIntegralInRange<size_t>(0, node_types.size() - 1)];
                        (void)arr->is_homogeneous(type_for_array_homo);
                        
                        // Test the overload for array::is_homogeneous.
                        toml::node* first_mismatch_node_array = nullptr; // Must be initialized
                        (void)arr->is_homogeneous(type_for_array_homo, first_mismatch_node_array);
                    }

                    // Iterate through the array elements for further checks.
                    for (const auto& arr_el_node : *arr) {
                        // API 5 (on node): Call node::type() on each node in the array.
                         (void)arr_el_node.type();

                         // If an array element is itself a table, test its properties.
                         if (arr_el_node.is_table()) {
                             const toml::table* nested_tbl_in_arr = arr_el_node.as_table();
                             if (nested_tbl_in_arr && !node_types.empty() && fdp.remaining_bytes() > 0) {
                                 // API 5 (on table)
                                 (void)nested_tbl_in_arr->type();
                                 // API 2 (on nested table)
                                 toml::node_type type_for_nested_tbl = node_types[fdp.ConsumeIntegralInRange<size_t>(0, node_types.size() - 1)];
                                 (void)nested_tbl_in_arr->is_homogeneous(type_for_nested_tbl);
                                 // For const table, the is_homogeneous overload taking node*& might not be available
                                 // or might require a const node*&. Let's use the simpler overload.
                                 // toml::node* first_mismatch_nested_tbl_arr = nullptr; 
                                 // (void)nested_tbl_in_arr->is_homogeneous(type_for_nested_tbl, first_mismatch_nested_tbl_arr);
                             }
                         }
                    }
                }
            } else if (val_node.is_table()) { // Check if the node is a nested table.
                 toml::table *nested_tbl = val_node.as_table(); // Get a pointer to the nested table.
                 if (nested_tbl) {
                    // API 5 (on table): Call node::type() via table.
                    (void)nested_tbl->type();

                    // API 2: Test toml::table::is_homogeneous on the nested table.
                    if (!node_types.empty() && fdp.remaining_bytes() > 0) {
                        toml::node_type type_for_nested_table_homo = node_types[fdp.ConsumeIntegralInRange<size_t>(0, node_types.size() - 1)];
                        (void)nested_tbl->is_homogeneous(type_for_nested_table_homo);

                        toml::node* first_mismatch_node_nested_table = nullptr; // Must be initialized
                        (void)nested_tbl->is_homogeneous(type_for_nested_table_homo, first_mismatch_node_nested_table);
                    }
                 }
            }
        }

    } catch (const toml::parse_error &) {
        // Gracefully handle TOML parsing errors. This is an expected outcome for invalid fuzzer inputs.
        // Memory safety is maintained by RAII; if toml::parse throws, toml_doc is not fully constructed,
        // or if it was partially constructed, its resources are cleaned up.
    } catch (const std::exception &) {
        // Catch any other standard library exceptions to prevent the fuzzer from crashing.
    } catch (...) {
        // Catch any other unknown exceptions to ensure fuzzer stability.
    }

    // All C++ objects with automatic storage duration (like toml_doc) are destroyed here
    // when they go out of scope. The destructors of toml::table, toml::array, and toml::node
    // ensure that all dynamically allocated memory associated with the TOML structure is freed.
    return 0; // Required by LLVMFuzzerTestOneInput, indicates successful execution of the fuzz case.
}