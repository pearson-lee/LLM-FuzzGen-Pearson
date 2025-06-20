#include <fuzzer/FuzzedDataProvider.h>
#include "/src/tomlplusplus/include/toml++/toml.hpp" // Main library header for tomlplusplus_wo_exist

#include <string>
#include <stdexcept> // For std::out_of_range
#include <iterator>  // For std::advance
#include <vector>    // For std::vector (used internally by toml++)

// Target APIs:
// 1. toml::parse (implicitly via input, forms the basis of interaction)
// 2. toml::v3::table::contains(string_view)
// 3. toml::v3::table::at(string_view)
// 4. toml::v3::node::is_<type>() and toml::v3::node::as_<type>() (for various TOML types)
// 5. toml::v3::array::erase(const_iterator)
// Additional targets based on coverage:
// 6. toml::v3::array::clear()
// 7. toml::v3::array::pop_back()
// 8. toml::v3::array::erase(const_iterator, const_iterator) (range erase)
// 9. toml::v3::array::erase(const_iterator) (const_iterator overload)
// 10. toml::v3::array::front(), toml::v3::array::back() (non-const)
// 11. toml::v3::array::at(unsigned long) (non-const)
// 12. toml::v3::array::is_homogeneous()

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    FuzzedDataProvider fdp(data, size);
    // Consume the input data as a string to be parsed as TOML.
    std::string toml_string = fdp.ConsumeRemainingBytesAsString();

    try {
        // 1. Attempt to parse the TOML string. This is the primary entry point.
        // The 'tbl' object is stack-allocated. Its destructor will automatically manage
        // the memory of the entire parsed TOML structure (nodes, values, arrays, etc.)
        // ensuring no leaks, following RAII principles.
        toml::table tbl = toml::parse(toml_string);

        // Perform a small number of operations to exercise different API aspects.
        int num_ops = fdp.ConsumeIntegralInRange<int>(1, 5);
        for (int op_count = 0; op_count < num_ops; ++op_count) {
            if (tbl.empty() && fdp.ConsumeBool()) { // Stop early if table is empty and fuzzer decides
                break;
            }

            // Generate a key for table operations.
            // It can be a completely random string or an existing key from the table.
            std::string key_for_ops_str;
            if (!tbl.empty() && fdp.ConsumeBool()) {
                // Try to pick an existing key.
                size_t random_idx = fdp.ConsumeIntegralInRange<size_t>(0, tbl.size() - 1);
                auto it = tbl.begin();
                std::advance(it, random_idx); // Advance iterator to the random_idx-th element.
                key_for_ops_str = std::string(it->first.str()); // toml::key to std::string
            } else {
                // Generate a random key string.
                key_for_ops_str = fdp.ConsumeRandomLengthString(32);
            }
            
            // 2. Exercise toml::v3::table::contains(string_view)
            if (fdp.ConsumeBool()) {
                bool key_exists = tbl.contains(key_for_ops_str);
                // Use the result to prevent it from being optimized out.
                if (key_exists && fdp.ConsumeBool()) { /* Trivial operation */ }
            }

            // 3. Exercise toml::v3::table::at(string_view)
            // 4. Exercise toml::v3::node::is_<type>() and toml::v3::node::as_<type>()
            // Check if the key is likely to exist before calling 'at' to reduce frequent exceptions,
            // but still allow 'at' to be called with non-existent keys sometimes.
            if (fdp.ConsumeBool() || tbl.contains(key_for_ops_str)) {
                try {
                    // 'at' returns a const reference to the node.
                    // Memory is managed by the parent 'tbl'.
                    const toml::node& node_val = tbl.at(key_for_ops_str);

                    // Exercise node type checks (is_*) and type casts (as_*)
                    switch (node_val.type()) {
                        case toml::node_type::string:
                            if (node_val.is_string()) {
                                auto val_ptr = node_val.as_string(); // Returns const toml::value<string>*
                                if (val_ptr) { std::string s_val = val_ptr->get(); (void)s_val; }
                            }
                            break;
                        case toml::node_type::integer:
                            if (node_val.is_integer()) {
                                auto val_ptr = node_val.as_integer(); // const toml::value<int64_t>*
                                if (val_ptr) { int64_t i_val = val_ptr->get(); (void)i_val; }
                            }
                            break;
                        case toml::node_type::floating_point:
                            if (node_val.is_floating_point()) {
                                auto val_ptr = node_val.as_floating_point(); // const toml::value<double>*
                                if (val_ptr) { double d_val = val_ptr->get(); (void)d_val; }
                            }
                            break;
                        case toml::node_type::boolean:
                            if (node_val.is_boolean()) {
                                auto val_ptr = node_val.as_boolean(); // const toml::value<bool>*
                                if (val_ptr) { bool b_val = val_ptr->get(); (void)b_val; }
                            }
                            break;
                        case toml::node_type::date:
                            if (node_val.is_date()) {
                                auto val_ptr = node_val.as_date(); // const toml::value<toml::date>*
                                if (val_ptr) { toml::date date_val = val_ptr->get(); (void)date_val; }
                            }
                            break;
                        case toml::node_type::time:
                            if (node_val.is_time()) {
                                auto val_ptr = node_val.as_time(); // const toml::value<toml::time>*
                                if (val_ptr) { toml::time time_val = val_ptr->get(); (void)time_val; }
                            }
                            break;
                        case toml::node_type::date_time:
                            if (node_val.is_date_time()) {
                                auto val_ptr = node_val.as_date_time(); // const toml::value<toml::date_time>*
                                if (val_ptr) { toml::date_time dt_val = val_ptr->get(); (void)dt_val; }
                            }
                            break;
                        case toml::node_type::array:
                            if (node_val.is_array()) {
                                const toml::array* arr_const_ptr = node_val.as_array();
                                if (arr_const_ptr) { (void)arr_const_ptr->size(); }
                                // Array erase is handled below with non-const access.
                            }
                            break;
                        case toml::node_type::table:
                            if (node_val.is_table()) {
                                const toml::table* sub_tbl_const_ptr = node_val.as_table();
                                if (sub_tbl_const_ptr) { (void)sub_tbl_const_ptr->size(); }
                            }
                            break;
                        case toml::node_type::none:
                            // This case should ideally not be hit if 'at' succeeds for an existing key.
                            break;
                    }
                } catch (const std::out_of_range& oor_ex) {
                    // 'at' throws std::out_of_range if the key is not found. This is expected.
                }
            }

            // 5. Exercise toml::v3::array::erase(const_iterator) - single element (original)
            if (fdp.ConsumeBool()) { 
                for (auto&& [current_key_sv, current_node_ref] : tbl) { 
                    toml::node* current_node_ptr = &current_node_ref; 
                    if (current_node_ptr && current_node_ptr->is_array()) {
                        toml::array* arr_ptr = current_node_ptr->as_array(); 
                        if (arr_ptr && !arr_ptr->empty()) {
                            size_t erase_idx = fdp.ConsumeIntegralInRange<size_t>(0, arr_ptr->size() - 1);
                            auto it_to_erase = arr_ptr->begin();
                            std::advance(it_to_erase, erase_idx); 
                            arr_ptr->erase(it_to_erase);
                            if (fdp.ConsumeBool()) break; 
                        }
                    }
                    if (fdp.ConsumeFloatingPointInRange<double>(0.0, 1.0) < 0.1) break; 
                }
            }

            // === BEGINNING OF NEW ARRAY OPERATIONS (Coverage Enhancement) ===
            if (fdp.ConsumeBool()) { // Randomly decide to exercise more array operations
                for (auto it = tbl.begin(); it != tbl.end(); ++it) { // Iterate to find an array
                    toml::node* current_node_ptr = &(it->second);
                    if (current_node_ptr && current_node_ptr->is_array()) {
                        toml::array* arr_ptr = current_node_ptr->as_array();
                        if (arr_ptr) { // arr_ptr can be empty or non-empty

                            // Target: toml::v3::array::clear()
                            // Coverage: Calls clear() on an array.
                            if (!arr_ptr->empty() && fdp.ConsumeBool()) {
                                arr_ptr->clear(); // Clears the array, memory managed by tbl.
                            }

                            // Target: toml::v3::array::pop_back()
                            // Coverage: Calls pop_back() on an array.
                            if (!arr_ptr->empty() && fdp.ConsumeBool()) {
                                arr_ptr->pop_back(); // Removes last element, memory managed by tbl.
                            }
                            
                            // Target: toml::v3::array::erase(const_iterator) - const_iterator overload
                            // Coverage: Calls erase with a const_iterator.
                            if (!arr_ptr->empty() && fdp.ConsumeBool()) {
                                size_t erase_idx_const = fdp.ConsumeIntegralInRange<size_t>(0, arr_ptr->size() - 1);
                                auto cit_to_erase = arr_ptr->cbegin(); 
                                std::advance(cit_to_erase, erase_idx_const);
                                arr_ptr->erase(cit_to_erase); // Modifies array, memory managed by tbl.
                            }

                            // Target: toml::v3::array::erase(const_iterator, const_iterator) - Range erase
                            // Coverage: Calls range erase on an array.
                            if (arr_ptr->size() >= 2 && fdp.ConsumeBool()) {
                                size_t first_idx = fdp.ConsumeIntegralInRange<size_t>(0, arr_ptr->size() - 2);
                                // Ensure count is at least 1 and last_iter is valid and >= first_iter
                                size_t max_count = arr_ptr->size() - first_idx;
                                size_t count = fdp.ConsumeIntegralInRange<size_t>(1, max_count);
                                
                                auto first_iter = arr_ptr->begin();
                                std::advance(first_iter, first_idx);
                                auto last_iter = first_iter; // Initialize last_iter to first_iter
                                std::advance(last_iter, count); // Advance to form the range [first_iter, last_iter)
                                
                                arr_ptr->erase(first_iter, last_iter); // Modifies array, memory managed by tbl.
                            }
                            
                            // Target: toml::v3::array::front() (non-const)
                            // Coverage: Accesses the first element of an array (non-const).
                            if (!arr_ptr->empty() && fdp.ConsumeBool()) {
                                toml::node& front_node = arr_ptr->front();
                                (void)front_node.type(); 
                            }

                            // Target: toml::v3::array::back() (non-const)
                            // Coverage: Accesses the last element of an array (non-const).
                            if (!arr_ptr->empty() && fdp.ConsumeBool()) {
                                toml::node& back_node = arr_ptr->back();
                                (void)back_node.type(); 
                            }
                            
                            // Target: toml::v3::array::at(unsigned long) (non-const)
                            // Coverage: Accesses element by index (non-const), including bounds checking.
                            if (!arr_ptr->empty() && fdp.ConsumeBool()) {
                                try {
                                    size_t random_idx = fdp.ConsumeIntegralInRange<size_t>(0, arr_ptr->size() -1);
                                    toml::node& at_node = arr_ptr->at(random_idx);
                                    (void)at_node.type(); 
                                } catch (const std::out_of_range& oor_ex) {
                                    // Expected
                                }
                            }

                            // Target: toml::v3::array::is_homogeneous()
                            // Coverage: Tests homogeneity of an array, exercising different branches.
                            if (fdp.ConsumeBool()) { 
                                toml::node* first_mismatch = nullptr;
                                bool is_homog = arr_ptr->is_homogeneous(toml::node_type::none, first_mismatch);
                                (void)is_homog;
                                if (first_mismatch) { (void)first_mismatch->type(); }

                                if (!arr_ptr->empty()) { 
                                    toml::node_type specific_type_to_test = arr_ptr->front().type(); 
                                    first_mismatch = nullptr; 
                                    is_homog = arr_ptr->is_homogeneous(specific_type_to_test, first_mismatch);
                                     (void)is_homog;
                                     if (first_mismatch) { (void)first_mismatch->type(); }
                                }
                            }
                            if (fdp.ConsumeBool()) break; 
                        }
                    }
                }
            }
            // === END OF NEW ARRAY OPERATIONS ===

        } // End of operations loop

    } catch (const toml::parse_error& parse_ex) {
        // TOML parsing failed. This is a valid outcome for fuzzer-generated input.
    } catch (const std::exception& std_ex) {
        // Catch other standard library exceptions
    } catch (...) {
        // Catch any other unknown exceptions
    }
    return 0; 
}