#include "/src/tomlplusplus/include/toml++/toml.h" // Main library header for tomlplusplus
#include <fuzzer/FuzzedDataProvider.h>
#include <string>
#include <vector>    // For std::vector to hold node_type options
#include <exception> // Required for std::exception

// Entry point for the fuzzer
extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    FuzzedDataProvider fdp(data, size);

    std::string toml_string = fdp.ConsumeRemainingBytesAsString();

    const std::vector<toml::node_type> node_types = {
        toml::node_type::none,          toml::node_type::string,
        toml::node_type::integer,       toml::node_type::floating_point,
        toml::node_type::boolean,       toml::node_type::date,
        toml::node_type::time,          toml::node_type::date_time,
        toml::node_type::array,         toml::node_type::table
    };

    try {
        toml::table toml_doc = toml::parse(toml_string);

        // === Coverage for toml::table (toml_doc) ===
        // Coverage: Call toml_doc.empty() and toml_doc.size()
        (void)toml_doc.empty();
        (void)toml_doc.size();

        // Coverage: Call is_homogeneous on table with node_type::none to cover specific branch
        (void)toml_doc.is_homogeneous(toml::node_type::none);
        toml::node* first_mismatch_doc_none = nullptr;
        (void)toml_doc.is_homogeneous(toml::node_type::none, first_mismatch_doc_none);
        
        // Coverage: Call various is_X() and as_X() methods on toml_doc (table)
        {
            const auto& n = static_cast<const toml::node&>(toml_doc);
            (void)n.is_table(); (void)n.is_array(); (void)n.is_value();
            (void)n.is_string(); (void)n.is_integer(); (void)n.is_floating_point();
            (void)n.is_number(); (void)n.is_boolean(); (void)n.is_date();
            (void)n.is_time(); (void)n.is_date_time(); (void)n.is_array_of_tables();
            (void)n.as_table(); (void)n.as_array(); (void)n.as_string();
            (void)n.as_integer(); (void)n.as_floating_point(); (void)n.as_boolean();
            (void)n.as_date(); (void)n.as_time(); (void)n.as_date_time();
        }
        {
            auto& n = static_cast<toml::node&>(toml_doc);
            (void)n.as_table(); (void)n.as_array(); (void)n.as_string();
            (void)n.as_integer(); (void)n.as_floating_point(); (void)n.as_boolean();
            (void)n.as_date(); (void)n.as_time(); (void)n.as_date_time();
        }


        if (fdp.ConsumeBool()) { // Conditionally exercise these table operations
            std::string key_str_for_table_ops;
            if (!toml_doc.empty() && fdp.ConsumeBool()) { // Try to use an existing key
                key_str_for_table_ops = std::string(toml_doc.begin()->first.str());
                // Coverage: Call toml_doc.get(key), at(key), contains(key) with an existing key
                (void)toml_doc.get(key_str_for_table_ops);
                try { (void)toml_doc.at(key_str_for_table_ops); } catch (const std::out_of_range&) { /* Should not happen */ }
                (void)toml_doc.contains(key_str_for_table_ops);
            } else if (fdp.remaining_bytes() > 0) { // Use a fuzzed key
                key_str_for_table_ops = fdp.ConsumeRandomLengthString(10);
                // Coverage: Call toml_doc.get(key), at(key), contains(key) with potentially non-existent key
                (void)toml_doc.get(key_str_for_table_ops);
                try { (void)toml_doc.at(key_str_for_table_ops); } catch (const std::out_of_range&) { /* Expected */ }
                (void)toml_doc.contains(key_str_for_table_ops);
            }
        }

        // API 5 (on table): Call node::type() via table.
        (void)toml_doc.type();

        // API 2: Test toml::table::is_homogeneous.
        if (!node_types.empty() && fdp.remaining_bytes() > 0) {
            toml::node_type type_for_table_homo = node_types[fdp.ConsumeIntegralInRange<size_t>(0, node_types.size() - 1)];
            (void)toml_doc.is_homogeneous(type_for_table_homo);
            toml::node* first_mismatch_node_table = nullptr; 
            (void)toml_doc.is_homogeneous(type_for_table_homo, first_mismatch_node_table);
        }

        // Iterate through the parsed TOML table using a copy of keys for safety if toml_doc is modified later.
        std::vector<std::string> keys_in_doc; 
        for (auto&& kvp : toml_doc) {
            keys_in_doc.push_back(std::string(kvp.first.str()));
        }

        for (const auto& key_str : keys_in_doc) {
            toml::node* val_node_ptr = toml_doc.get(key_str);
            if (!val_node_ptr) continue;
            toml::node& val_node = *val_node_ptr;

            // API 5 (on node): Call node::type() on each value node in the table.
            (void)val_node.type();

            // Coverage: Call is_homogeneous on any node (value, array, or table)
            (void)val_node.is_homogeneous(toml::node_type::none); // Covers ntype == node_type::none
            (void)val_node.is_homogeneous(val_node.type());      // Covers ntype == self-type
            toml::node* mismatch_val_node_none = nullptr;
            (void)val_node.is_homogeneous(toml::node_type::none, mismatch_val_node_none);
            if (!node_types.empty() && fdp.remaining_bytes() > 0) {
                toml::node_type random_type = node_types[fdp.ConsumeIntegralInRange<size_t>(0, node_types.size() - 1)];
                (void)val_node.is_homogeneous(random_type); // Covers ntype != self-type (potentially)
                toml::node* mismatch_val_node_rand = nullptr;
                (void)val_node.is_homogeneous(random_type, mismatch_val_node_rand);
            }
            // Coverage: Call various is_X() and as_X() methods on val_node
            {
                const auto& n = static_cast<const toml::node&>(val_node);
                (void)n.is_table(); (void)n.is_array(); (void)n.is_value();
                (void)n.is_string(); (void)n.is_integer(); (void)n.is_floating_point();
                (void)n.is_number(); (void)n.is_boolean(); (void)n.is_date();
                (void)n.is_time(); (void)n.is_date_time(); (void)n.is_array_of_tables();
                (void)n.as_table(); (void)n.as_array(); (void)n.as_string();
                (void)n.as_integer(); (void)n.as_floating_point(); (void)n.as_boolean();
                (void)n.as_date(); (void)n.as_time(); (void)n.as_date_time();
            }
            {
                auto& n = static_cast<toml::node&>(val_node);
                (void)n.as_table(); (void)n.as_array(); (void)n.as_string();
                (void)n.as_integer(); (void)n.as_floating_point(); (void)n.as_boolean();
                (void)n.as_date(); (void)n.as_time(); (void)n.as_date_time();
            }


            if (val_node.is_array()) {
                toml::array *arr = val_node.as_array();
                if (arr) {
                    // API 5 (on array): Call node::type() via array.
                    (void)arr->type();

                    // === Coverage for toml::array (arr) ===
                    // Coverage: Call arr->empty() and arr->size()
                    (void)arr->empty();
                    (void)arr->size();

                    // Coverage: Call is_homogeneous on array with node_type::none
                    (void)arr->is_homogeneous(toml::node_type::none);
                    toml::node* first_mismatch_arr_none = nullptr;
                    (void)arr->is_homogeneous(toml::node_type::none, first_mismatch_arr_none);
                    
                    // API 4: Test toml::array::is_array_of_tables.
                    (void)arr->is_array_of_tables(); // Covered by exercise_node_type_methods on val_node if it's an array

                    if (!arr->empty()) {
                        // Coverage: Call arr->front(), arr->back() (non-const and const)
                        (void)arr->front();
                        (void)arr->back();
                        const toml::array* const_arr_ptr = arr;
                        (void)const_arr_ptr->front();
                        (void)const_arr_ptr->back();


                        // Coverage: Call arr->at(0), arr->operator[](0), arr->get(0)
                        size_t access_idx = 0; 
                        if (arr->size() > access_idx) { // Check if index 0 is valid
                             try {
                                (void)arr->at(access_idx); // non-const
                                (void)const_arr_ptr->at(access_idx); // const
                            } catch (const std::out_of_range&) { /* Expected */ }
                            (void)arr->operator[](access_idx); // non-const
                            (void)const_arr_ptr->operator[](access_idx); // const
                            (void)arr->get(access_idx); // non-const
                            (void)const_arr_ptr->get(access_idx); // const
                        }
                    }
                    
                    // API 3: Test toml::array::is_homogeneous.
                    if (!node_types.empty() && fdp.remaining_bytes() > 0) {
                        toml::node_type type_for_array_homo = node_types[fdp.ConsumeIntegralInRange<size_t>(0, node_types.size() - 1)];
                        (void)arr->is_homogeneous(type_for_array_homo);
                        toml::node* first_mismatch_node_array = nullptr; 
                        (void)arr->is_homogeneous(type_for_array_homo, first_mismatch_node_array);
                    }

                    // Iterate through the array elements for further checks using a copy of pointers
                    std::vector<toml::node*> arr_elements_ptrs;
                    for(size_t i = 0; i < arr->size(); ++i) {
                        arr_elements_ptrs.push_back(arr->get(i));
                    }

                    for (toml::node* arr_el_node_ptr : arr_elements_ptrs) {
                        if (!arr_el_node_ptr) continue;
                        toml::node& arr_el_node = *arr_el_node_ptr;

                        // API 5 (on node): Call node::type() on each node in the array.
                         (void)arr_el_node.type();

                        // Coverage: Call is_homogeneous on array element node
                        (void)arr_el_node.is_homogeneous(toml::node_type::none);
                        (void)arr_el_node.is_homogeneous(arr_el_node.type());
                        toml::node* mismatch_arr_el_none = nullptr;
                        (void)arr_el_node.is_homogeneous(toml::node_type::none, mismatch_arr_el_none);
                        if (!node_types.empty() && fdp.remaining_bytes() > 0) {
                             toml::node_type random_type_arr_el = node_types[fdp.ConsumeIntegralInRange<size_t>(0, node_types.size() - 1)];
                            (void)arr_el_node.is_homogeneous(random_type_arr_el);
                            toml::node* mismatch_arr_el_rand = nullptr;
                            (void)arr_el_node.is_homogeneous(random_type_arr_el, mismatch_arr_el_rand);
                        }
                        // Coverage: Call various is_X() and as_X() methods on arr_el_node
                        {
                            const auto& n = static_cast<const toml::node&>(arr_el_node);
                            (void)n.is_table(); (void)n.is_array(); (void)n.is_value();
                            (void)n.is_string(); (void)n.is_integer(); (void)n.is_floating_point();
                            (void)n.is_number(); (void)n.is_boolean(); (void)n.is_date();
                            (void)n.is_time(); (void)n.is_date_time(); (void)n.is_array_of_tables();
                            (void)n.as_table(); (void)n.as_array(); (void)n.as_string();
                            (void)n.as_integer(); (void)n.as_floating_point(); (void)n.as_boolean();
                            (void)n.as_date(); (void)n.as_time(); (void)n.as_date_time();
                        }
                        {
                            auto& n = static_cast<toml::node&>(arr_el_node);
                            (void)n.as_table(); (void)n.as_array(); (void)n.as_string();
                            (void)n.as_integer(); (void)n.as_floating_point(); (void)n.as_boolean();
                            (void)n.as_date(); (void)n.as_time(); (void)n.as_date_time();
                        }


                         if (arr_el_node.is_table()) {
                             toml::table* nested_tbl_in_arr = arr_el_node.as_table();
                             if (nested_tbl_in_arr && !node_types.empty() && fdp.remaining_bytes() > 0) {
                                 // API 5 (on table)
                                 (void)nested_tbl_in_arr->type();
                                 // API 2 (on nested table)
                                 toml::node_type type_for_nested_tbl = node_types[fdp.ConsumeIntegralInRange<size_t>(0, node_types.size() - 1)];
                                 (void)nested_tbl_in_arr->is_homogeneous(type_for_nested_tbl);
                             }
                         }
                    } // End of loop over array elements

                    // Coverage: Modifying operations for array, after iteration over its elements
                    if (fdp.ConsumeBool() && !arr->empty()) {
                        // Coverage: Call arr->pop_back() to test array modification
                        arr->pop_back(); // Memory safe: elements are unique_ptrs, properly destroyed.
                    }
                    if (fdp.ConsumeBool()) {
                        // Coverage: Call arr->clear() to test array modification
                        arr->clear(); // Memory safe: elements are unique_ptrs, properly destroyed.
                    }

                }
            } else if (val_node.is_table()) {
                 toml::table *nested_tbl = val_node.as_table();
                 if (nested_tbl) {
                    // API 5 (on table): Call node::type() via table.
                    (void)nested_tbl->type();

                    // === Coverage for nested toml::table (nested_tbl) ===
                    // Coverage: Call empty() and size() on nested table
                    (void)nested_tbl->empty();
                    (void)nested_tbl->size();
                    // Coverage: Call is_homogeneous on nested table with node_type::none
                    (void)nested_tbl->is_homogeneous(toml::node_type::none);
                    toml::node* first_mismatch_nested_tbl_none = nullptr;
                    (void)nested_tbl->is_homogeneous(toml::node_type::none, first_mismatch_nested_tbl_none);
                    // is_X and as_X methods already covered by exercise_node_type_methods_non_const(val_node, ...)

                    // API 2: Test toml::table::is_homogeneous on the nested table.
                    if (!node_types.empty() && fdp.remaining_bytes() > 0) {
                        toml::node_type type_for_nested_table_homo = node_types[fdp.ConsumeIntegralInRange<size_t>(0, node_types.size() - 1)];
                        (void)nested_tbl->is_homogeneous(type_for_nested_table_homo);
                        toml::node* first_mismatch_node_nested_table = nullptr; 
                        (void)nested_tbl->is_homogeneous(type_for_nested_table_homo, first_mismatch_node_nested_table);
                    }
                 }
            }
        } // End of loop over toml_doc elements

        // Coverage: Modifying operations for toml_doc, after iteration over its elements
        if (fdp.ConsumeBool()) {
            // Coverage: Call toml_doc.clear() to test table modification
            toml_doc.clear(); // Memory safe: underlying nodes are RAII managed.
        }

    } catch (const toml::parse_error &) {
        // Gracefully handle TOML parsing errors.
    } catch (const std::exception &) {
        // Catch any other standard library exceptions.
    } catch (...) {
        // Catch any other unknown exceptions.
    }

    return 0;
}