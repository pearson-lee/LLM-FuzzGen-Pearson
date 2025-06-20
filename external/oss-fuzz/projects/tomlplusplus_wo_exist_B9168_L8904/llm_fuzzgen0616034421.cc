#include <cstddef>
#include <cstdint>
#include <string>
#include <vector>
// #include <optional> // Not strictly used in the final version, but can be useful
#include <iterator> // For std::advance
#include <sstream>  // Required for std::ostringstream, used for operator<< coverage

// Fuzzer include for FuzzedDataProvider
#include <fuzzer/FuzzedDataProvider.h>

// Main library header for tomlplusplus.
// This header is expected to provide definitions for toml::parse, toml::table,
// toml::array, toml::node, toml::value, and their associated methods and iterators.
#include "/src/tomlplusplus/include/toml++/toml.hpp"

// Extern "C" to ensure C linkage for the fuzzer entry point.
extern "C" int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size) {
    FuzzedDataProvider fdp(Data, Size);

    // Consume a portion of the input data as a string for TOML parsing.
    // The length is also fuzzed to test handling of various input sizes.
    std::string toml_string = fdp.ConsumeRandomLengthString(Size);

    try {
        // Attempt to parse the TOML string.
        // toml::parse returns a toml::table.
        // TOML++ uses RAII; memory for the parsed data is managed by the 'tbl' object.
        toml::table tbl = toml::parse(toml_string);

        // API 1: bool toml::v3::table::is_value()
        // This method is inherited from toml::node. For a table, it checks if the table itself
        // is a simple value type (e.g., string, int), which should be false.
        // Called randomly to exercise this path.
        if (fdp.ConsumeBool()) {
            // Use volatile to discourage the compiler from optimizing out the call.
            volatile bool table_is_value_result = tbl.is_value();
            (void)table_is_value_result; // Suppress unused variable warning.
        }

        // API 2: value<long> * toml::v3::table::as_integer()
        // This method is inherited from toml::node. It attempts to cast the table node to an integer.
        // For a table, this will likely return nullptr.
        // The returned pointer points to memory managed by the 'tbl' object; no explicit delete is needed.
        if (fdp.ConsumeBool()) {
            toml::value<int64_t>* table_as_int_ptr = tbl.as_integer();
            (void)table_as_int_ptr; // Suppress unused variable warning.
        }

        // Coverage: Call toml::node::at_path (via table) to exercise toml::impl::parse_path in at_path.inl
        // This function has many uncovered branches related to path parsing logic.
        if (fdp.ConsumeBool()) {
            std::string path_str = fdp.ConsumeRandomLengthString(50); // Generate a random path string
            toml::node_view<toml::node> nv_at_path = tbl.at_path(path_str);
            (void)nv_at_path; // Suppress unused variable warning.
                               // Memory for node_view is managed by the underlying node (tbl).
        }

        // Coverage: Call operator<< for toml::table to exercise toml_formatter
        // This helps cover many formatting functions in print_to_stream.inl and toml_formatter.hpp/inl.
        if (fdp.ConsumeBool()) {
            std::ostringstream oss;
            oss << tbl; // Exercises table formatting logic.
            std::string tbl_formatted_str = oss.str();
            (void)tbl_formatted_str; // Suppress unused variable warning.
                                     // oss and tbl_formatted_str manage their own memory (RAII).
        }


        // Iterate through the key-value pairs in the parsed table.
        // This allows access to nested structures like arrays or other tables.
        for (auto&& [key_view, node_view] : tbl) {
            // Check if the current node_view represents an array.
            if (node_view.is_array()) {
                // Get a pointer to the toml::array. Memory is managed by the parent 'tbl'.
                toml::array* arr = node_view.as_array();
                if (arr) { // Ensure the cast to array was successful.

                    // API 3: bool toml::v3::array::is_number()
                    // This method is inherited from toml::node. For an array, it checks if the array
                    // itself can be interpreted as a number, which should be false.
                    if (fdp.ConsumeBool()) {
                        volatile bool array_is_number_result = arr->is_number();
                        (void)array_is_number_result;
                    }

                    // API 4: iterator toml::v3::array::erase(const_iterator)
                    // This method modifies the array by removing an element at the iterator's position.
                    // Memory of the erased element is managed internally by the toml::array.
                    if (!arr->empty() && fdp.ConsumeBool()) {
                        // Select a random valid index to erase.
                        size_t erase_idx = fdp.ConsumeIntegralInRange<size_t>(0, arr->size() - 1);
                        auto it = arr->begin(); // Get a non-const iterator.
                        std::advance(it, erase_idx); // Advance iterator to the element to be erased.
                                                     // 'it' is valid and not arr->end() due to erase_idx range.
                        arr->erase(it); // Erase the element. Iterators may be invalidated.
                    }

                    // API 5: array_iterator<true> & toml::v3::impl::array_iterator<true>::operator+=(ptrdiff_t)
                    // This specific signature refers to the operator+= on a const_iterator.
                    // It's invoked by using `+=` on a `toml::array::const_iterator`.
                    // This tests iterator arithmetic.
                    if (!arr->empty() && fdp.ConsumeBool()) {
                        toml::array::const_iterator cit = arr->cbegin(); // Obtain a const_iterator.
                        
                        // Determine a random starting position for the iterator within the array.
                        size_t start_node_idx = fdp.ConsumeIntegralInRange<size_t>(0, arr->size() - 1);
                        cit = arr->cbegin(); // Reset iterator to the beginning.
                        std::advance(cit, start_node_idx); // Advance to the fuzzed starting position.

                        // Calculate valid range for the offset to ensure iterator stays within bounds.
                        // Max backward movement: from current position to cbegin().
                        ptrdiff_t max_backward_offset = -static_cast<ptrdiff_t>(start_node_idx);
                        // Max forward movement: from current position to the last element (cend() - 1).
                        ptrdiff_t max_forward_offset = static_cast<ptrdiff_t>(arr->size() - 1 - start_node_idx);
                        
                        // Ensure max_forward_offset is not negative if cit is already at the last element.
                        if (max_forward_offset < 0) max_forward_offset = 0; 

                        if (max_backward_offset <= max_forward_offset) { // Check if the range is valid.
                            ptrdiff_t offset_val = fdp.ConsumeIntegralInRange<ptrdiff_t>(max_backward_offset, max_forward_offset);
                            cit += offset_val; // Call operator+=. This modifies the iterator 'cit'.
                        }
                    }

                    // Coverage: Call toml::array::is_array_of_tables() to exercise it and toml::array::is_homogeneous.
                    // This helps cover branches in is_homogeneous related to empty arrays, type checking, and iteration.
                    if (fdp.ConsumeBool()) {
                        volatile bool is_aot = arr->is_array_of_tables();
                        (void)is_aot;
                    }

                    // Coverage: Call operator<< for toml::array to exercise toml_formatter
                    // This helps cover array formatting logic.
                    if (fdp.ConsumeBool()) {
                        std::ostringstream oss_arr;
                        oss_arr << (*arr); // Exercises array formatting logic.
                        std::string arr_formatted_str = oss_arr.str();
                        (void)arr_formatted_str; // Suppress unused variable warning.
                                                 // oss_arr and arr_formatted_str manage their own memory (RAII).
                    }
                }
            }
        }

    } catch (const toml::parse_error& /*err*/) {
        // Catch parsing errors. These are expected when fuzzing a parser library
        // with arbitrary inputs. The fuzzer should continue running.
        // The error message (err.what()) could be logged if needed for debugging.
    } catch (const std::exception& /*ex*/) {
        // Catch other standard C++ exceptions that might be thrown by the library
        // during operations other than parsing.
    } catch (...) {
        // Catch any other types of exceptions to prevent the fuzzer from crashing,
        // ensuring robust fuzzing.
    }

    // All memory allocated by toml::parse (and held by 'tbl') is automatically
    // deallocated when 'tbl' goes out of scope, thanks to TOML++'s use of RAII.
    // No manual memory cleanup is required for 'tbl' or nodes/arrays/values obtained from it.
    return 0; // Indicate successful execution of the fuzz test case.
}