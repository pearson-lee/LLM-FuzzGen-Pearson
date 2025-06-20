#include "/src/tomlplusplus/include/toml++/toml.h" // Main library header for tomlplusplus
#include <fuzzer/FuzzedDataProvider.h>
#include <string>
#include <vector>    // For std::vector to hold node_type options
#include <exception> // Required for std::exception
#include <string_view> // For std::string_view

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
        const auto& const_toml_doc = static_cast<const toml::table&>(toml_doc);

        // === Coverage for toml::table (toml_doc) ===
        // Coverage: Call toml_doc.empty() and toml_doc.size()
        (void)toml_doc.empty();
        (void)toml_doc.size();
        (void)const_toml_doc.empty(); // Coverage: Call const version of empty()
        (void)const_toml_doc.size();   // Coverage: Call const version of size()


        // Coverage: Call is_homogeneous on table with node_type::none to cover specific branch
        (void)toml_doc.is_homogeneous(toml::node_type::none);
        toml::node* first_mismatch_doc_none = nullptr;
        (void)toml_doc.is_homogeneous(toml::node_type::none, first_mismatch_doc_none);
        // Coverage: Call const version of is_homogeneous on table
        const toml::node* first_mismatch_doc_none_const = nullptr;
        (void)const_toml_doc.is_homogeneous(toml::node_type::none, first_mismatch_doc_none_const);
        
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
        // Coverage: Direct calls to table's is_X and as_X methods shown as 0% covered
        (void)toml_doc.is_value();
        (void)toml_doc.as_array(); // non-const
        (void)const_toml_doc.is_value(); // const
        (void)const_toml_doc.as_array(); // const

        // Coverage: table::is_X() methods (most return false for table)
        (void)toml_doc.is_string(); (void)const_toml_doc.is_string();
        (void)toml_doc.is_integer(); (void)const_toml_doc.is_integer();
        (void)toml_doc.is_floating_point(); (void)const_toml_doc.is_floating_point();
        (void)toml_doc.is_number(); (void)const_toml_doc.is_number();
        (void)toml_doc.is_boolean(); (void)const_toml_doc.is_boolean();
        (void)toml_doc.is_date(); (void)const_toml_doc.is_date();
        (void)toml_doc.is_time(); (void)const_toml_doc.is_time();
        (void)toml_doc.is_date_time(); (void)const_toml_doc.is_date_time();

        // Coverage: table::as_X() methods (most return nullptr for table)
        (void)toml_doc.as_string(); (void)const_toml_doc.as_string();
        (void)toml_doc.as_integer(); (void)const_toml_doc.as_integer();
        (void)toml_doc.as_floating_point(); (void)const_toml_doc.as_floating_point();
        (void)toml_doc.as_boolean(); (void)const_toml_doc.as_boolean();
        (void)toml_doc.as_date(); (void)const_toml_doc.as_date();
        (void)toml_doc.as_time(); (void)const_toml_doc.as_time();
        (void)toml_doc.as_date_time(); (void)const_toml_doc.as_date_time();


        if (fdp.ConsumeBool()) { // Conditionally exercise these table operations
            std::string key_str_for_table_ops;
            if (!toml_doc.empty() && fdp.ConsumeBool()) { // Try to use an existing key
                key_str_for_table_ops = std::string(toml_doc.begin()->first.str());
            } else if (fdp.remaining_bytes() > 0) { // Use a fuzzed key
                key_str_for_table_ops = fdp.ConsumeRandomLengthString(10);
            }

            if (!key_str_for_table_ops.empty()) {
                 // Coverage: Call toml_doc.get(key), at(key), contains(key) with an existing/fuzzed key (std::string)
                (void)toml_doc.get(key_str_for_table_ops);
                (void)const_toml_doc.get(key_str_for_table_ops); 
                try { (void)toml_doc.at(key_str_for_table_ops); } catch (const std::out_of_range&) { /* Expected */ }
                try { (void)const_toml_doc.at(key_str_for_table_ops); } catch (const std::out_of_range&) { /* Expected */ } 
                (void)toml_doc.contains(key_str_for_table_ops);
                (void)const_toml_doc.contains(key_str_for_table_ops);

                // Coverage: Call toml_doc.at(string_view) and contains(string_view)
                std::string_view sv_key = key_str_for_table_ops;
                (void)toml_doc.get(sv_key); 
                (void)const_toml_doc.get(sv_key);
                try { (void)toml_doc.at(sv_key); } catch (const std::out_of_range&) { /* Expected for non-existent key */ }
                try { (void)const_toml_doc.at(sv_key); } catch (const std::out_of_range&) { /* Expected for non-existent key */ }
                (void)toml_doc.contains(sv_key); // Non-const version
                (void)const_toml_doc.contains(sv_key); // Const version (already in original fuzzer but good to ensure it's here)
            }
            // Coverage: Attempt to trigger std::out_of_range from table::at() for a non-existent key
            std::string definitely_not_a_key = "___this_key_should_not_exist_in_fuzzed_toml_" + fdp.ConsumeRandomLengthString(5);
            try { (void)toml_doc.at(definitely_not_a_key); } catch (const std::out_of_range&) { /* Expected, to cover throw path */ }
            try { (void)toml_doc.at(std::string_view(definitely_not_a_key)); } catch (const std::out_of_range&) { /* Expected, string_view overload */ }
        }

        // API 5 (on table): Call node::type() via table.
        (void)toml_doc.type();

        // API 2: Test toml::table::is_homogeneous.
        if (!node_types.empty() && fdp.remaining_bytes() > 0) {
            toml::node_type type_for_table_homo = node_types[fdp.ConsumeIntegralInRange<size_t>(0, node_types.size() - 1)];
            (void)toml_doc.is_homogeneous(type_for_table_homo);
            toml::node* first_mismatch_node_table = nullptr; 
            (void)toml_doc.is_homogeneous(type_for_table_homo, first_mismatch_node_table);
            // Coverage: Call const version of is_homogeneous on table
            const toml::node* first_mismatch_node_table_const = nullptr;
            (void)const_toml_doc.is_homogeneous(type_for_table_homo, first_mismatch_node_table_const);
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
            const toml::node& const_val_node = val_node; // For const methods

            // API 5 (on node): Call node::type() on each value node in the table.
            (void)val_node.type();

            // Coverage: Call is_homogeneous on any node (value, array, or table)
            (void)val_node.is_homogeneous(toml::node_type::none); 
            (void)val_node.is_homogeneous(val_node.type());      
            toml::node* mismatch_val_node_none = nullptr;
            (void)val_node.is_homogeneous(toml::node_type::none, mismatch_val_node_none);
            // Coverage: Call const version of is_homogeneous on node
            const toml::node* mismatch_val_node_none_const = nullptr;
            (void)const_val_node.is_homogeneous(toml::node_type::none, mismatch_val_node_none_const);

            if (!node_types.empty() && fdp.remaining_bytes() > 0) {
                toml::node_type random_type = node_types[fdp.ConsumeIntegralInRange<size_t>(0, node_types.size() - 1)];
                (void)val_node.is_homogeneous(random_type); 
                toml::node* mismatch_val_node_rand = nullptr;
                (void)val_node.is_homogeneous(random_type, mismatch_val_node_rand);
                // Coverage: Call const version of is_homogeneous on node with random type
                const toml::node* mismatch_val_node_rand_const = nullptr;
                (void)const_val_node.is_homogeneous(random_type, mismatch_val_node_rand_const);
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
                    const auto& const_arr = static_cast<const toml::array&>(*arr);
                    // API 5 (on array): Call node::type() via array.
                    (void)arr->type();

                    // === Coverage for toml::array (arr) ===
                    // Coverage: Call arr->empty() and arr->size()
                    (void)arr->empty();
                    (void)arr->size();
                    (void)const_arr.empty(); // Coverage: const empty for array
                    (void)const_arr.size();  // Coverage: const size for array
                    (void)arr->max_size(); // Coverage: array::max_size()
                    (void)const_arr.max_size(); // Coverage: array::max_size() const


                    // Coverage: Call is_homogeneous on array with node_type::none
                    (void)arr->is_homogeneous(toml::node_type::none);
                    toml::node* first_mismatch_arr_none = nullptr;
                    (void)arr->is_homogeneous(toml::node_type::none, first_mismatch_arr_none);
                    // Coverage: Call const version of is_homogeneous on array
                    const toml::node* first_mismatch_arr_none_const = nullptr;
                    (void)const_arr.is_homogeneous(toml::node_type::none, first_mismatch_arr_none_const);
                    if (!node_types.empty()) { // Ensure node_types is not empty for random selection
                         toml::node_type type_for_const_arr_homo = node_types[fdp.ConsumeIntegralInRange<size_t>(0, node_types.size() - 1)];
                        (void)const_arr.is_homogeneous(type_for_const_arr_homo); // Coverage: const version of is_homogeneous (single arg)
                        (void)const_arr.is_homogeneous(toml::node_type::none); // Coverage: const version with none (single arg)
                    }
                    
                    // API 4: Test toml::array::is_array_of_tables.
                    (void)arr->is_array_of_tables(); 
                    (void)const_arr.is_array_of_tables(); // Coverage: const version of is_array_of_tables

                    // Coverage: Direct calls to array's is_X and as_X methods
                    (void)arr->is_value(); (void)const_arr.is_value();
                    (void)arr->as_array(); (void)const_arr.as_array(); 
                    // Coverage: array::is_X() methods (most return false for array)
                    (void)arr->is_string(); (void)const_arr.is_string();
                    (void)arr->is_integer(); (void)const_arr.is_integer();
                    (void)arr->is_floating_point(); (void)const_arr.is_floating_point();
                    (void)arr->is_number(); (void)const_arr.is_number();
                    (void)arr->is_boolean(); (void)const_arr.is_boolean();
                    (void)arr->is_date(); (void)const_arr.is_date();
                    (void)arr->is_time(); (void)const_arr.is_time();
                    (void)arr->is_date_time(); (void)const_arr.is_date_time();

                    // Coverage: array::as_X() methods (most return nullptr for array)
                    (void)arr->as_table(); (void)const_arr.as_table();
                    (void)arr->as_string(); (void)const_arr.as_string();
                    (void)arr->as_integer(); (void)const_arr.as_integer();
                    (void)arr->as_floating_point(); (void)const_arr.as_floating_point();
                    (void)arr->as_boolean(); (void)const_arr.as_boolean();
                    (void)arr->as_date(); (void)const_arr.as_date();
                    (void)arr->as_time(); (void)const_arr.as_time();
                    (void)arr->as_date_time(); (void)const_arr.as_date_time();


                    if (!arr->empty()) {
                        // Coverage: Call arr->front(), arr->back() (non-const and const)
                        (void)arr->front();
                        (void)arr->back();
                        (void)const_arr.front(); // Coverage: const front
                        (void)const_arr.back();  // Coverage: const back


                        // Coverage: Call arr->at(0), arr->operator[](0), arr->get(0)
                        size_t access_idx = 0; 
                        if (arr->size() > access_idx) { 
                             try {
                                (void)arr->at(access_idx); 
                                (void)const_arr.at(access_idx); // Coverage: const at for array
                            } catch (const std::out_of_range&) { /* Expected */ }
                            (void)arr->operator[](access_idx); 
                            (void)const_arr[access_idx]; // Coverage: const operator[] for array
                            (void)arr->get(access_idx); 
                            (void)const_arr.get(access_idx); // Coverage: const get for array
                        }

                        // Coverage: const iterators for array
                        for (auto it = const_arr.begin(); it != const_arr.end(); ++it) { (void)*it; } // Covers begin() const, end() const
                        for (auto it = const_arr.cbegin(); it != const_arr.cend(); ++it) { (void)*it; } // Covers cbegin() const, cend() const
                    }
                    
                    // API 3: Test toml::array::is_homogeneous.
                    if (!node_types.empty() && fdp.remaining_bytes() > 0) {
                        toml::node_type type_for_array_homo = node_types[fdp.ConsumeIntegralInRange<size_t>(0, node_types.size() - 1)];
                        (void)arr->is_homogeneous(type_for_array_homo);
                        toml::node* first_mismatch_node_array = nullptr; 
                        (void)arr->is_homogeneous(type_for_array_homo, first_mismatch_node_array);
                        // Coverage: Call const version of is_homogeneous on array
                        const toml::node* first_mismatch_node_array_const = nullptr;
                        (void)const_arr.is_homogeneous(type_for_array_homo, first_mismatch_node_array_const);
                    }

                    // Iterate through the array elements for further checks using a copy of pointers
                    std::vector<toml::node*> arr_elements_ptrs;
                    for(size_t i = 0; i < arr->size(); ++i) {
                        arr_elements_ptrs.push_back(arr->get(i));
                    }

                    for (toml::node* arr_el_node_ptr : arr_elements_ptrs) {
                        if (!arr_el_node_ptr) continue;
                        toml::node& arr_el_node = *arr_el_node_ptr;
                        const toml::node& const_arr_el_node = arr_el_node; // For const methods

                        // API 5 (on node): Call node::type() on each node in the array.
                         (void)arr_el_node.type();

                        // Coverage: Call is_homogeneous on array element node
                        (void)arr_el_node.is_homogeneous(toml::node_type::none);
                        (void)arr_el_node.is_homogeneous(arr_el_node.type());
                        toml::node* mismatch_arr_el_none = nullptr;
                        (void)arr_el_node.is_homogeneous(toml::node_type::none, mismatch_arr_el_none);
                        // Coverage: Call const version of is_homogeneous on array element node
                        const toml::node* mismatch_arr_el_none_const = nullptr;
                        (void)const_arr_el_node.is_homogeneous(toml::node_type::none, mismatch_arr_el_none_const);

                        if (!node_types.empty() && fdp.remaining_bytes() > 0) {
                             toml::node_type random_type_arr_el = node_types[fdp.ConsumeIntegralInRange<size_t>(0, node_types.size() - 1)];
                            (void)arr_el_node.is_homogeneous(random_type_arr_el);
                            toml::node* mismatch_arr_el_rand = nullptr;
                            (void)arr_el_node.is_homogeneous(random_type_arr_el, mismatch_arr_el_rand);
                            // Coverage: Call const version of is_homogeneous on array element node with random type
                            const toml::node* mismatch_arr_el_rand_const = nullptr;
                            (void)const_arr_el_node.is_homogeneous(random_type_arr_el, mismatch_arr_el_rand_const);
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
                        // Coverage: Call arr->erase(iterator) to test array modification. Memory safe.
                        arr->erase(arr->begin());
                    }
                    if (fdp.ConsumeBool() && arr->size() >= 2) { // Ensure at least 2 elements for range erase
                        // Coverage: Call arr->erase(iterator, iterator) to test array modification. Memory safe.
                        arr->erase(arr->begin(), arr->begin() + 1);
                    }

                    if (!arr->empty()) { // pop_back requires non-empty
                        // Coverage: Call arr->pop_back() to test array modification, made more likely to hit
                        arr->pop_back(); // Memory safe: elements are unique_ptrs, properly destroyed.
                    }
                    if (fdp.ConsumeBool()) { // Keep clear() conditional to vary behavior
                        // Coverage: Call arr->clear() to test array modification
                        arr->clear(); // Memory safe: elements are unique_ptrs, properly destroyed.
                    }

                }
            } else if (val_node.is_table()) {
                 toml::table *nested_tbl = val_node.as_table();
                 if (nested_tbl) {
                    const auto& const_nested_tbl = static_cast<const toml::table&>(*nested_tbl);
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
                    // Coverage: Call const version of is_homogeneous on nested table
                    const toml::node* first_mismatch_nested_tbl_none_const = nullptr;
                    (void)const_nested_tbl.is_homogeneous(toml::node_type::none, first_mismatch_nested_tbl_none_const);


                    // API 2: Test toml::table::is_homogeneous on the nested table.
                    if (!node_types.empty() && fdp.remaining_bytes() > 0) {
                        toml::node_type type_for_nested_table_homo = node_types[fdp.ConsumeIntegralInRange<size_t>(0, node_types.size() - 1)];
                        (void)nested_tbl->is_homogeneous(type_for_nested_table_homo);
                        toml::node* first_mismatch_node_nested_table = nullptr; 
                        (void)nested_tbl->is_homogeneous(type_for_nested_table_homo, first_mismatch_node_nested_table);
                        // Coverage: Call const version of is_homogeneous on nested table
                        const toml::node* first_mismatch_node_nested_table_const = nullptr;
                        (void)const_nested_tbl.is_homogeneous(type_for_nested_table_homo, first_mismatch_node_nested_table_const);
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
    } catch (const std::out_of_range &) { // Catch out_of_range from at()
        // Gracefully handle out-of-range errors from at().
    } catch (const std::exception &) {
        // Catch any other standard library exceptions.
    } catch (...) {
        // Catch any other unknown exceptions.
    }
    
    // Test is_homogeneous on empty array to cover specific branches
    // This is placed outside the main try-catch to ensure it runs even if parsing fails early,
    // or if the parsed document doesn't produce arrays.
    toml::array empty_arr_for_homo_test;
    (void)empty_arr_for_homo_test.is_homogeneous(toml::node_type::string); // non-const version
    const auto& const_empty_arr_for_homo_test = static_cast<const toml::array&>(empty_arr_for_homo_test);
    (void)const_empty_arr_for_homo_test.is_homogeneous(toml::node_type::table); // const version

    return 0;
}