#include "/src/tomlplusplus/include/toml++/toml.hpp" // Core tomlplusplus library
#include <fuzzer/FuzzedDataProvider.h> // For FuzzedDataProvider
#include <string> // For std::string
#include <cstdint> // For int64_t

// Target APIs (all have 0% coverage from the provided list):
// 1. bool toml::v3::table::is_date()
// 2. value<toml::v3::time> * toml::v3::table::as_time()
// 3. bool toml::v3::array::is_number()
// 4. value<long> * toml::v3::array::as_integer() (maps to toml::value<int64_t>*)
// 5. bool toml::v3::table::is_integer()
// Implicitly: void toml::v3::key::~key(...) by table creation/destruction.

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    FuzzedDataProvider fdp(data, size);
    std::string toml_string = fdp.ConsumeRemainingBytesAsString();

    try {
        // Attempt to parse the TOML string.
        // toml::parse() returns a toml::table on success (via toml::parse_result).
        // The 'root_table' object (toml::table) manages the lifetime of the parsed TOML data.
        // All memory for nodes, values, and keys is reclaimed when 'root_table' goes out of scope due to RAII.
        // This ensures that toml::v3::key::~key is called for keys within the table.
        toml::table root_table = toml::parse(toml_string);

        // Exercise APIs on the root_table itself.
        // A toml::table is a toml::node, so it has type-checking and casting methods.
        // These calls test how a table node responds to these type queries.

        // API 1: bool toml::v3::table::is_date()
        // Checks if the table node itself is a date.
        volatile bool root_is_date = root_table.is_date();

        // API 2: value<toml::v3::time> * toml::v3::table::as_time()
        // Attempts to cast the table node to a time value. Returns nullptr on failure.
        // The returned pointer is non-owning and valid as long as root_table is alive.
        volatile toml::value<toml::time>* root_as_time = root_table.as_time();
        if (root_as_time) {
            // If cast is successful (unlikely for a table node), we could access root_as_time->get()
            // For fuzzing, simply calling the API is sufficient to exercise it.
        }

        // API 5: bool toml::v3::table::is_integer()
        // Checks if the table node itself is an integer.
        volatile bool root_is_integer = root_table.is_integer();

        // Iterate through the elements of the root_table to find arrays and sub-tables
        // to exercise the other targeted APIs.
        for (auto&& [key, node_view] : root_table) {
            // 'key' is a toml::key object. Its lifetime is managed by the table.
            // 'node_view' is a toml::node_view, a non-owning view of a node in the table.

            if (node_view.is_array()) {
                toml::array* arr = node_view.as_array(); // Non-owning pointer to the array
                if (arr) {
                    // An array is also a toml::node.
                    // API 3: bool toml::v3::array::is_number()
                    // Checks if the array node itself is a number.
                    volatile bool arr_is_number = arr->is_number();

                    // API 4: value<long> * toml::v3::array::as_integer()
                    // Attempts to cast the array node to an integer value.
                    // tomlplusplus uses int64_t for integers.
                    // The returned pointer is non-owning.
                    volatile toml::value<int64_t>* arr_as_integer = arr->as_integer();
                    if (arr_as_integer) {
                        // If successful, could access arr_as_integer->get()
                    }

                    // Iterate through array elements to find nested tables to apply table APIs
                    for (toml::node& element_node : *arr) {
                        if (element_node.is_table()) {
                            toml::table* nested_table = element_node.as_table(); // Non-owning
                            if (nested_table) {
                                // Call table APIs on nested tables found in arrays
                                volatile bool nested_tbl_is_date = nested_table->is_date();
                                volatile toml::value<toml::time>* nested_tbl_as_time = nested_table->as_time();
                                volatile bool nested_tbl_is_integer = nested_table->is_integer();
                            }
                        }
                    }
                }
            } else if (node_view.is_table()) {
                toml::table* sub_table = node_view.as_table(); // Non-owning pointer
                if (sub_table) {
                    // Apply table-specific APIs to sub-tables as well.
                    volatile bool sub_tbl_is_date = sub_table->is_date();
                    volatile toml::value<toml::time>* sub_tbl_as_time = sub_table->as_time();
                    volatile bool sub_tbl_is_integer = sub_table->is_integer();

                    // Iterate through sub-table elements to find nested arrays to apply array APIs
                     for (auto&& [sub_key, sub_node_view] : *sub_table) {
                        if (sub_node_view.is_array()) {
                            toml::array* nested_arr = sub_node_view.as_array(); // Non-owning
                            if (nested_arr) {
                                // Call array APIs on nested arrays found in sub-tables
                                volatile bool nested_arr_is_number = nested_arr->is_number();
                                volatile toml::value<int64_t>* nested_arr_as_integer = nested_arr->as_integer();
                            }
                        }
                    }
                }
            }
        }

    } catch (const toml::parse_error& /*err*/) {
        // Parsing can fail with malformed input; this is expected in fuzzing.
        // The toml::parse_error object is RAII-managed and will be destroyed.
        // No specific action needed here other than catching to prevent fuzzer exit.
    } catch (const std::exception& /*ex*/) {
        // Catch any other C++ standard library exceptions that might occur.
    }

    // All dynamically allocated memory within the tomlplusplus library (e.g., for the
    // parsed table structure) is managed by the library itself, primarily through the
    // toml::table object's RAII semantics. When 'root_table' (if created) goes out of
    // scope, all its owned resources are automatically deallocated.
    // Pointers obtained via as_array(), as_table(), as_time(), as_integer() are non-owning
    // views and do not require manual deletion by this fuzzer.
    return 0;
}