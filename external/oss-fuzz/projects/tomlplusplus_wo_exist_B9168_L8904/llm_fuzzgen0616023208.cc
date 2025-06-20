#include <cstddef>
#include <cstdint>
#include <string>
#include <string_view> // Added for std::string_view
#include <vector>
#include <iterator> // For std::advance
#include <sstream> // For std::ostringstream, std::istringstream
#include <optional> // For std::optional in date_time if used later

// Fuzzer include for FuzzedDataProvider
#include <fuzzer/FuzzedDataProvider.h>

// Main library header for tomlplusplus.
#include "/src/tomlplusplus/include/toml++/toml.hpp"

// Extern "C" to ensure C linkage for the fuzzer entry point.
extern "C" int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size) {
    FuzzedDataProvider fdp(Data, Size);

    std::string toml_string = fdp.ConsumeRandomLengthString(Size);
    toml::table tbl; // Declare tbl outside the try block to use it in multiple sections

    try {
        tbl = toml::parse(toml_string);
        const toml::table& const_tbl_ref_main = tbl; // Const reference for main table

        // BEGIN MODIFICATION: Ensure creation and destruction of all value types
        // Rationale: Target 0% coverage for toml::value<T>::~value() destructors.
        // Emplacing these values into the table ensures they are created.
        // They will be destroyed when 'tbl' goes out of scope, triggering destructors.
        // Memory is managed by toml::table.
        if (fdp.ConsumeIntegralInRange(0,5) == 0) tbl.emplace("fuzz_str_val", fdp.ConsumeRandomLengthString(10)); // Increased probability
        if (fdp.ConsumeIntegralInRange(0,5) == 0) tbl.emplace("fuzz_int_val", fdp.ConsumeIntegral<int64_t>()); // Increased probability
        if (fdp.ConsumeIntegralInRange(0,5) == 0) tbl.emplace("fuzz_flt_val", fdp.ConsumeFloatingPoint<double>()); // Increased probability
        if (fdp.ConsumeIntegralInRange(0,5) == 0) tbl.emplace("fuzz_bool_val", fdp.ConsumeBool()); // Increased probability
        if (fdp.ConsumeIntegralInRange(0,5) == 0) tbl.emplace("fuzz_date_val", toml::date{fdp.ConsumeIntegralInRange<uint16_t>(1,2500),fdp.ConsumeIntegralInRange<uint8_t>(1,12),fdp.ConsumeIntegralInRange<uint8_t>(1,28)}); // Increased probability
        if (fdp.ConsumeIntegralInRange(0,5) == 0) tbl.emplace("fuzz_time_val", toml::time{fdp.ConsumeIntegralInRange<uint8_t>(0,23),fdp.ConsumeIntegralInRange<uint8_t>(0,59),fdp.ConsumeIntegralInRange<uint8_t>(0,59),fdp.ConsumeIntegralInRange<uint32_t>(0,999999999u)}); // Increased probability
        if (fdp.ConsumeIntegralInRange(0,5) == 0) { // Increased probability
            toml::date d{fdp.ConsumeIntegralInRange<uint16_t>(1,2500),fdp.ConsumeIntegralInRange<uint8_t>(1,12),fdp.ConsumeIntegralInRange<uint8_t>(1,28)};
            toml::time t{fdp.ConsumeIntegralInRange<uint8_t>(0,23),fdp.ConsumeIntegralInRange<uint8_t>(0,59),fdp.ConsumeIntegralInRange<uint8_t>(0,59),fdp.ConsumeIntegralInRange<uint32_t>(0,999999999u)};
            if (fdp.ConsumeBool()) {
                int16_t total_minutes_offset = fdp.ConsumeIntegralInRange<int16_t>(-720, 720);
                int8_t offset_hours = static_cast<int8_t>(total_minutes_offset / 60);
                int8_t offset_minutes_component = static_cast<int8_t>(total_minutes_offset % 60);
                tbl.emplace("fuzz_dt_offset", toml::date_time{d, t, toml::time_offset{offset_hours, offset_minutes_component}});
            }
            else tbl.emplace("fuzz_dt_local", toml::date_time{d, t});
        }
        // END MODIFICATION

        // BEGIN MODIFICATION: Call toml::at_path to cover it and impl::parse_path branches
        // Rationale: Target 0% coverage for toml::at_path and its underlying parse_path.
        // node_view is non-owning, so memory safety is maintained.
        if (fdp.ConsumeBool()) {
            std::string path_str = fdp.PickValueInArray<std::string>({
                "", "key", "table.key", "[0]", "array[1]", "key[0].subkey", "a..b", ".leadingdot", "trailingdot."
            });
            if (fdp.ConsumeBool()) path_str = fdp.ConsumeRandomLengthString(10); // Add some random paths too

            if (fdp.ConsumeBool()) { // Test non-const version
                volatile toml::node_view nv = toml::at_path(tbl, path_str);
                (void)nv;
            } else { // Test const version
                const toml::table& const_tbl_ref_for_path = tbl;
                volatile toml::node_view<const toml::node> nv_const = toml::at_path(const_tbl_ref_for_path, path_str);
                (void)nv_const;
            }
        }
        // END MODIFICATION

        // BEGIN MODIFICATION: Call node::at_path with toml::path
        // Rationale: Target 0% coverage for node::at_path(toml::path) and node::operator[](toml::path).
        // node_view is non-owning, so memory safety is maintained.
        if (fdp.ConsumeBool() && !tbl.empty()) {
            std::string path_str_data_node = fdp.PickValueInArray<std::string>({
                "fuzz_str_val", "fuzz_int_val", "fuzz_dt_local", "nonexistent.key"
            });
            if (fdp.ConsumeBool()) path_str_data_node = fdp.ConsumeRandomLengthString(10);
            toml::path p_node(path_str_data_node);

            if (!p_node.empty()) { // Ensure path is not empty for meaningful access
                if (fdp.ConsumeBool()) { // Test non-const version node.at_path(path)
                    volatile toml::node_view nv = tbl.at_path(p_node);
                    (void)nv;
                } else { // Test const version node.at_path(path)
                    const toml::table& const_tbl_ref_for_node_path = tbl;
                    volatile toml::node_view<const toml::node> nv_const = const_tbl_ref_for_node_path.at_path(p_node);
                    (void)nv_const;
                }

                if (fdp.ConsumeBool()) { // Test non-const version node[path]
                    volatile toml::node_view nv = tbl[p_node];
                    (void)nv;
                } else { // Test const version node[path]
                    const toml::table& const_tbl_ref_for_node_path_op = tbl;
                    volatile toml::node_view<const toml::node> nv_const = const_tbl_ref_for_node_path_op[p_node];
                    (void)nv_const;
                }
            }
        }
        // END MODIFICATION


        // BEGIN MODIFICATION: Call table::operator[] for main table
        // Rationale: Target uncovered table accessor operator[].
        // node_view is non-owning, so memory safety is maintained.
        if (fdp.ConsumeBool()) {
            std::string key_for_op_sq = fdp.ConsumeRandomLengthString(5);
            if (tbl.contains(key_for_op_sq) || fdp.ConsumeBool()) {
                 volatile toml::node_view nv_op_sq = tbl[key_for_op_sq];
                 (void)nv_op_sq;
            }
        }
        if (fdp.ConsumeBool()) { // Const version for main table
            std::string key_for_op_sq_const = fdp.ConsumeRandomLengthString(5);
             if (const_tbl_ref_main.contains(key_for_op_sq_const) || fdp.ConsumeBool()) {
                volatile toml::node_view<const toml::node> nv_op_sq_const = const_tbl_ref_main[key_for_op_sq_const];
                (void)nv_op_sq_const;
            }
        }
        // END MODIFICATION

        // BEGIN MODIFICATION: Call specific uncovered table is_X/as_X methods for main table
        // Rationale: Target specific 0% coverage functions for toml::table. These typically return false/nullptr.
        // Memory safe as as_X() for scalar types return nullptr, or 'this' for as_table().
        if (fdp.ConsumeBool()) { volatile bool r = tbl.is_string(); (void)r; }
        if (fdp.ConsumeBool()) { volatile toml::value<std::string>* r = tbl.as_string(); (void)r; }
        if (fdp.ConsumeBool()) { volatile bool r = tbl.is_integer(); (void)r; }
        // tbl.as_integer() is already called in existing fuzzer.
        if (fdp.ConsumeBool()) { volatile bool r = tbl.is_floating_point(); (void)r; }
        if (fdp.ConsumeBool()) { volatile toml::value<double>* r = tbl.as_floating_point(); (void)r; } // API list 0%
        if (fdp.ConsumeBool()) { volatile bool r = tbl.is_boolean(); (void)r; }
        if (fdp.ConsumeBool()) { volatile toml::value<bool>* r = tbl.as_boolean(); (void)r; } // API list 0%
        if (fdp.ConsumeBool()) { volatile bool r = tbl.is_date(); (void)r; }
        if (fdp.ConsumeBool()) { volatile toml::value<toml::date>* r = tbl.as_date(); (void)r; } // API list 0%
        if (fdp.ConsumeBool()) { volatile bool r = tbl.is_time(); (void)r; }
        if (fdp.ConsumeBool()) { volatile toml::value<toml::time>* r = tbl.as_time(); (void)r; } // API list 0%
        if (fdp.ConsumeBool()) { volatile bool r = tbl.is_date_time(); (void)r; }
        if (fdp.ConsumeBool()) { volatile toml::value<toml::date_time>* r = tbl.as_date_time(); (void)r; } // API list 0%
        if (fdp.ConsumeBool()) { volatile toml::table* r = tbl.as_table(); (void)r; } // Returns this
        if (fdp.ConsumeBool()) { volatile toml::array* r = tbl.as_array(); (void)r; } // Returns nullptr

        if (fdp.ConsumeBool()) { volatile bool r = const_tbl_ref_main.is_string(); (void)r; }
        if (fdp.ConsumeBool()) { volatile const toml::value<std::string>* r = const_tbl_ref_main.as_string(); (void)r; }
        if (fdp.ConsumeBool()) { volatile const toml::value<toml::date>* r = const_tbl_ref_main.as_date(); (void)r; } // API list 0%
        if (fdp.ConsumeBool()) { volatile const toml::value<toml::date_time>* r = const_tbl_ref_main.as_date_time(); (void)r; } // API list 0%
        if (fdp.ConsumeBool()) { volatile const toml::table* r = const_tbl_ref_main.as_table(); (void)r; } // API list 0%
        if (fdp.ConsumeBool()) { volatile const toml::array* r = const_tbl_ref_main.as_array(); (void)r; }
        // END MODIFICATION

        // BEGIN MODIFICATION: Call table::is_homogeneous and its branches
        // Rationale: Target uncovered branches in toml::table::is_homogeneous.
        // This includes calls on empty tables, with specific types, and node_type::none.
        // Memory safe as first_mismatch pointers are handled correctly.
        if (fdp.ConsumeBool()) {
            toml::node* first_mismatch = nullptr;
            if (fdp.ConsumeBool()) {
                volatile bool r = tbl.is_homogeneous(toml::node_type::string, first_mismatch); (void)r;
            }
            if (fdp.ConsumeBool()) {
                volatile bool r = tbl.is_homogeneous(toml::node_type::none, first_mismatch); (void)r;
            }
            if (fdp.ConsumeBool()) {
                volatile bool r = const_tbl_ref_main.is_homogeneous(toml::node_type::integer); (void)r;
            }
            if (fdp.ConsumeBool()) {
                const toml::node* first_mismatch_const = nullptr;
                volatile bool r = const_tbl_ref_main.is_homogeneous(toml::node_type::array, first_mismatch_const); (void)r;
            }
            if (fdp.ConsumeBool()) {
                toml::table empty_tbl;
                toml::node* fm_empty = nullptr;
                volatile bool r_empty = empty_tbl.is_homogeneous(toml::node_type::string, fm_empty); (void)r_empty;
                const toml::table& const_empty_tbl_ref = empty_tbl;
                volatile bool r_empty_const = const_empty_tbl_ref.is_homogeneous(toml::node_type::string); (void)r_empty_const;
            }
        }
        // END MODIFICATION


        if (fdp.ConsumeBool()) {
            volatile bool table_is_value_result = tbl.is_value();
            (void)table_is_value_result;
        }

        if (fdp.ConsumeBool()) {
            toml::value<int64_t>* table_as_int_ptr = tbl.as_integer();
            (void)table_as_int_ptr;
        }

        // BEGIN MODIFICATION: Call table_iterator::operator--()
        // Rationale: Target uncovered API `table_iterator<false> & toml::v3::impl::table_iterator<false>::operator--()`
        if (!tbl.empty() && fdp.ConsumeBool()) {
            auto it = tbl.end(); // non-const iterator
            if (it != tbl.begin()) {
                --it; // This should call the target operator--
                volatile std::string_view key_check = it->first; // Use the iterator to prevent optimization
                (void)key_check;
            }
        }
        // END MODIFICATION

        for (auto&& [key_view, node_view] : tbl) {
            // Test node_view's as_date() to cover value<T>::as_date() for various T
            // Rationale: Targets various `toml::v3::value<T>::as_date()` functions (0% coverage for many T)
            if (node_view.is_value() && fdp.ConsumeBool()) {
                 volatile auto val_as_date = node_view.as_date();
                 (void)val_as_date;
            }


            if (node_view.is_array()) {
                toml::array* arr = node_view.as_array();
                if (arr) {
                    const toml::array& const_arr_ref = *arr; // For const methods

                    // BEGIN MODIFICATION: Call array front() and back()
                    // Rationale: Target uncovered array front() and back() methods. Memory safe as checks for empty are made.
                    if (!arr->empty() && fdp.ConsumeBool()) {
                        volatile toml::node& front_node = arr->front(); (void)front_node;
                        volatile toml::node& back_node = arr->back(); (void)back_node;
                    }
                    if (!const_arr_ref.empty() && fdp.ConsumeBool()) { // Const versions
                        volatile const toml::node& const_front_node = const_arr_ref.front(); (void)const_front_node;
                        volatile const toml::node& const_back_node = const_arr_ref.back(); (void)const_back_node;
                    }
                    // END MODIFICATION

                    // BEGIN MODIFICATION: Call array::get() and array::operator[]
                    // Rationale: Target uncovered array accessors: get(), operator[].
                    // Memory safe as get() returns a non-owning pointer or nullptr,
                    // and operator[] is called with a valid index.
                    if (!arr->empty() && fdp.ConsumeBool()) {
                        size_t valid_idx = fdp.ConsumeIntegralInRange<size_t>(0, arr->size() - 1);
                        volatile toml::node* get_node_ptr = arr->get(valid_idx); (void)get_node_ptr;
                        volatile toml::node* get_node_ptr_oof = arr->get(arr->size()); (void)get_node_ptr_oof;
                        volatile toml::node& op_sq_node_ref = (*arr)[valid_idx]; (void)op_sq_node_ref;
                    }
                    if (!const_arr_ref.empty() && fdp.ConsumeBool()) { // Const versions
                        size_t valid_idx_const = fdp.ConsumeIntegralInRange<size_t>(0, const_arr_ref.size() - 1);
                        volatile const toml::node* get_node_ptr_const = const_arr_ref.get(valid_idx_const); (void)get_node_ptr_const;
                        volatile const toml::node* get_node_ptr_oof_const = const_arr_ref.get(const_arr_ref.size()); (void)get_node_ptr_oof_const;
                        volatile const toml::node& op_sq_node_ref_const = const_arr_ref[valid_idx_const]; (void)op_sq_node_ref_const;
                    }
                    // END MODIFICATION


                    if (fdp.ConsumeBool()) {
                        volatile bool array_is_number_result = arr->is_number();
                        (void)array_is_number_result;
                    }

                    if (!arr->empty() && fdp.ConsumeBool()) {
                        size_t erase_idx = fdp.ConsumeIntegralInRange<size_t>(0, arr->size() - 1);
                        auto it = arr->begin();
                        std::advance(it, erase_idx);
                        arr->erase(it);
                    }

                    if (!arr->empty() && fdp.ConsumeBool()) {
                        toml::array::const_iterator cit = arr->cbegin();
                        size_t start_node_idx = fdp.ConsumeIntegralInRange<size_t>(0, arr->size() - 1);
                        cit = arr->cbegin();
                        std::advance(cit, start_node_idx);

                        ptrdiff_t max_backward_offset = -static_cast<ptrdiff_t>(start_node_idx);
                        ptrdiff_t max_forward_offset = static_cast<ptrdiff_t>(arr->size() - 1 - start_node_idx);

                        if (max_forward_offset < 0) max_forward_offset = 0;

                        if (max_backward_offset <= max_forward_offset) {
                            ptrdiff_t offset_val = fdp.ConsumeIntegralInRange<ptrdiff_t>(max_backward_offset, max_forward_offset);
                            cit += offset_val;
                        }
                    }

                    // BEGIN MODIFICATION: Call array::is_homogeneous
                    // Rationale: Target uncovered function `toml::v3::array::is_homogeneous` and its branches.
                    if (fdp.ConsumeBool()) {
                        volatile bool homogeneous_check_specific_type = arr->is_homogeneous(toml::node_type::string);
                        (void)homogeneous_check_specific_type;
                    }
                    if (fdp.ConsumeBool()) {
                        // Test with node_type::none to cover a specific branch in is_homogeneous
                        volatile bool homogeneous_check_none_type = arr->is_homogeneous(toml::node_type::none);
                        (void)homogeneous_check_none_type;
                    }
                    if (fdp.ConsumeBool()) {
                        const toml::node* first_nonmatch_const = nullptr;
                        volatile bool homogeneous_check_const_overload = const_arr_ref.is_homogeneous(toml::node_type::table, first_nonmatch_const);
                        (void)homogeneous_check_const_overload;
                    }
                    // END MODIFICATION

                    // BEGIN MODIFICATION: Call array::at()
                    // Rationale: Target uncovered function `toml::v3::array::at()` and its exception path.
                    if (!arr->empty() && fdp.ConsumeBool()) {
                        size_t at_idx = fdp.ConsumeIntegralInRange<size_t>(0, arr->size()); // Up to arr->size() for out-of-bounds test
                        try {
                            if (at_idx < arr->size()) { // Valid index
                                volatile toml::node& node_at_ref = arr->at(at_idx);
                                (void)node_at_ref;
                            } else if (arr->size() > 0) { // Specifically test one past the end if array is not empty
                                volatile toml::node& node_at_ref_throw = arr->at(arr->size()); // Should throw
                                (void)node_at_ref_throw;
                            }
                        } catch (const std::out_of_range&) { /* Expected for out-of-bounds access */ }
                    }
                    if (!const_arr_ref.empty() && fdp.ConsumeBool()) {
                        size_t at_idx_const = fdp.ConsumeIntegralInRange<size_t>(0, const_arr_ref.size());
                        try {
                             if (at_idx_const < const_arr_ref.size()) {
                                volatile const toml::node& node_at_const_ref = const_arr_ref.at(at_idx_const);
                                (void)node_at_const_ref;
                            } else if (const_arr_ref.size() > 0) {
                                volatile const toml::node& node_at_const_ref_throw = const_arr_ref.at(const_arr_ref.size()); // Should throw
                                (void)node_at_const_ref_throw;
                            }
                        } catch (const std::out_of_range&) { /* Expected for out-of-bounds access */ }
                    }
                    // END MODIFICATION

                    // BEGIN MODIFICATION: Call array_iterator operator+
                    // Rationale: Target uncovered API `array_iterator<false> toml::v3::impl::operator+(const array_iterator<false> &, ptrdiff_t)`
                    if (!arr->empty() && fdp.ConsumeBool()) {
                        toml::array::iterator it = arr->begin(); // non-const iterator
                        if (arr->size() > 1) { // Ensure there's room to offset without necessarily going out of bounds
                             ptrdiff_t offset = fdp.ConsumeIntegralInRange<ptrdiff_t>(0, static_cast<ptrdiff_t>(arr->size() -1));
                             toml::array::iterator it2 = it + offset; // Calls free function operator+(iterator, ptrdiff_t)
                             (void)it2; // Use the iterator
                        }
                    }
                    // END MODIFICATION

                    // BEGIN MODIFICATION: Call specific uncovered array is_X/as_X methods
                    // Rationale: Target specific 0% coverage functions for toml::array.
                    // These typically return false/nullptr as an array isn't a scalar.
                    // Memory safe as as_X() for scalar types return nullptr, or 'this' for as_array().
                    if (fdp.ConsumeBool()) { volatile bool r = arr->is_array_of_tables(); (void)r; } // Already present
                    if (fdp.ConsumeBool()) { volatile toml::table* r = arr->as_table(); (void)r; } // Already present
                    if (fdp.ConsumeBool()) { volatile bool r = arr->is_string(); (void)r; }
                    if (fdp.ConsumeBool()) { volatile toml::value<std::string>* r = arr->as_string(); (void)r; } // API list 0%
                    if (fdp.ConsumeBool()) { volatile bool r = arr->is_integer(); (void)r; } // API list 0%
                    if (fdp.ConsumeBool()) { volatile toml::value<int64_t>* r = arr->as_integer(); (void)r; } // API list 0%
                    if (fdp.ConsumeBool()) { volatile bool r = arr->is_floating_point(); (void)r; }
                    if (fdp.ConsumeBool()) { volatile toml::value<double>* r = arr->as_floating_point(); (void)r; } // API list 0%
                    if (fdp.ConsumeBool()) { volatile bool r = arr->is_boolean(); (void)r; }
                    if (fdp.ConsumeBool()) { volatile toml::value<bool>* r = arr->as_boolean(); (void)r; } // API list 0%
                    if (fdp.ConsumeBool()) { volatile bool r = arr->is_date(); (void)r; } // API list 0%
                    if (fdp.ConsumeBool()) { volatile toml::value<toml::date>* r = arr->as_date(); (void)r; } // API list 0%
                    if (fdp.ConsumeBool()) { volatile bool r = arr->is_time(); (void)r; }
                    if (fdp.ConsumeBool()) { volatile toml::value<toml::time>* r = arr->as_time(); (void)r; } // API list 0%
                    if (fdp.ConsumeBool()) { volatile bool r = arr->is_date_time(); (void)r; } // API list 0%
                    if (fdp.ConsumeBool()) { volatile toml::value<toml::date_time>* r = arr->as_date_time(); (void)r; } // API list 0%
                    if (fdp.ConsumeBool()) { volatile toml::array* r = arr->as_array(); (void)r; } // Returns this
                    // Const versions
                    if (fdp.ConsumeBool()) { volatile bool r = const_arr_ref.is_string(); (void)r; }
                    if (fdp.ConsumeBool()) { volatile const toml::value<std::string>* r = const_arr_ref.as_string(); (void)r; } // API list 0%
                    if (fdp.ConsumeBool()) { volatile const toml::array* r = const_arr_ref.as_array(); (void)r; } // API list 0%
                    if (fdp.ConsumeBool()) { volatile const toml::table* r = const_arr_ref.as_table(); (void)r; } // API list 0%
                    // END MODIFICATION
                }
            } else if (node_view.is_table()) {
                toml::table* inner_tbl = node_view.as_table();
                if (inner_tbl) {
                    const toml::table& const_inner_tbl_ref = *inner_tbl;

                    // BEGIN MODIFICATION: Call table::operator[] for inner table
                    // Rationale: Target uncovered table accessor operator[] on inner tables.
                    // node_view is non-owning, so memory safety is maintained.
                    if (fdp.ConsumeBool()) {
                        std::string key_for_inner_op_sq = fdp.ConsumeRandomLengthString(5);
                        if (inner_tbl->contains(key_for_inner_op_sq) || fdp.ConsumeBool()) {
                            volatile toml::node_view nv_inner_op_sq = (*inner_tbl)[key_for_inner_op_sq];
                            (void)nv_inner_op_sq;
                        }
                    }
                    if (fdp.ConsumeBool()) { // Const version for inner table
                        std::string key_for_inner_op_sq_const = fdp.ConsumeRandomLengthString(5);
                        if (const_inner_tbl_ref.contains(key_for_inner_op_sq_const) || fdp.ConsumeBool()) {
                            volatile toml::node_view<const toml::node> nv_inner_op_sq_const = const_inner_tbl_ref[key_for_inner_op_sq_const];
                            (void)nv_inner_op_sq_const;
                        }
                    }
                    // END MODIFICATION
                    
                    // BEGIN MODIFICATION: Call specific uncovered table is_X/as_X methods
                    // Rationale: Target specific 0% coverage functions for toml::table.
                    if (fdp.ConsumeBool()) { volatile bool r = inner_tbl->is_date(); (void)r; } // Already present
                    if (fdp.ConsumeBool()) { volatile toml::value<toml::date>* r = inner_tbl->as_date(); (void)r; } // Already present
                    if (fdp.ConsumeBool()) { volatile const toml::value<toml::date>* r = const_inner_tbl_ref.as_date(); (void)r; } // Const version, already present
                    
                    if (fdp.ConsumeBool()) { volatile bool r = inner_tbl->is_string(); (void)r; }
                    if (fdp.ConsumeBool()) { volatile toml::value<std::string>* r = inner_tbl->as_string(); (void)r; }
                    if (fdp.ConsumeBool()) { volatile bool r = inner_tbl->is_integer(); (void)r; }
                    if (fdp.ConsumeBool()) { volatile toml::value<int64_t>* r = inner_tbl->as_integer(); (void)r; }
                    if (fdp.ConsumeBool()) { volatile bool r = inner_tbl->is_floating_point(); (void)r; }
                    if (fdp.ConsumeBool()) { volatile toml::value<double>* r = inner_tbl->as_floating_point(); (void)r; }
                    if (fdp.ConsumeBool()) { volatile bool r = inner_tbl->is_boolean(); (void)r; }
                    if (fdp.ConsumeBool()) { volatile toml::value<bool>* r = inner_tbl->as_boolean(); (void)r; }
                    if (fdp.ConsumeBool()) { volatile bool r = inner_tbl->is_time(); (void)r; }
                    if (fdp.ConsumeBool()) { volatile toml::value<toml::time>* r = inner_tbl->as_time(); (void)r; }
                    if (fdp.ConsumeBool()) { volatile bool r = inner_tbl->is_date_time(); (void)r; }
                    if (fdp.ConsumeBool()) { volatile toml::value<toml::date_time>* r = inner_tbl->as_date_time(); (void)r; }
                    if (fdp.ConsumeBool()) { volatile toml::table* r = inner_tbl->as_table(); (void)r; } // Returns this
                    if (fdp.ConsumeBool()) { volatile toml::array* r = inner_tbl->as_array(); (void)r; } // Returns nullptr
                    // Const versions for inner_tbl
                    if (fdp.ConsumeBool()) { volatile bool r = const_inner_tbl_ref.is_string(); (void)r; }
                    if (fdp.ConsumeBool()) { volatile const toml::value<std::string>* r = const_inner_tbl_ref.as_string(); (void)r; }
                    if (fdp.ConsumeBool()) { volatile const toml::table* r = const_inner_tbl_ref.as_table(); (void)r; }
                    if (fdp.ConsumeBool()) { volatile const toml::array* r = const_inner_tbl_ref.as_array(); (void)r; }
                    // END MODIFICATION
                }
            }
        }

        // BEGIN MODIFICATION: Serialize to TOML and JSON strings
        // Rationale: Target 0% coverage for toml_formatter, json_formatter, and various print_to_stream functions.
        // Memory safe as ostringstream manages its own buffer.
        if (fdp.ConsumeBool()) {
            std::ostringstream toml_oss;
            toml_oss << tbl; // Uses toml_formatter by default for tables
            std::string formatted_toml_string = toml_oss.str();
            (void)formatted_toml_string;
        }
        if (fdp.ConsumeBool()) {
            std::ostringstream json_oss;
            json_oss << toml::json_formatter{tbl};
            std::string formatted_json_string = json_oss.str();
            (void)formatted_json_string;
        }
        // END MODIFICATION

        // BEGIN MODIFICATION: Call node::visit
        // Rationale: Target 0% coverage for various toml::v3::node::visit and do_visit specializations.
        // Memory safe as it operates on existing nodes within 'tbl'.
        if (fdp.ConsumeBool() && !tbl.empty()) {
            int visit_count = 0;
            for (auto&& [key, node_val_ref] : tbl) { 
                if (visit_count++ >= 5) break; // MODIFICATION: Increased visit count

                toml::node& actual_node = node_val_ref; 
                // MODIFICATION: Expanded lambda to cover more types and do_visit branches
                actual_node.visit([&fdp](auto&& concrete_node) { 
                    volatile toml::node_type t = concrete_node.type();
                    (void)t;
                    if constexpr (toml::is_value<typename std::remove_cv<typename std::remove_reference<decltype(concrete_node)>::type>::type>) {
                         if (concrete_node.template is<std::string>()) { volatile auto s = concrete_node.template as<std::string>()->get(); (void)s;}
                         else if (concrete_node.template is<int64_t>()) { volatile auto i = concrete_node.template as<int64_t>()->get(); (void)i;}
                         else if (concrete_node.template is<double>()) { volatile auto d_val = concrete_node.template as<double>()->get(); (void)d_val; }
                         else if (concrete_node.template is<bool>()) { volatile auto b_val = concrete_node.template as<bool>()->get(); (void)b_val; }
                         else if (concrete_node.template is<toml::date>()) { volatile auto date_val = concrete_node.template as<toml::date>()->get(); (void)date_val; }
                         else if (concrete_node.template is<toml::time>()) { volatile auto time_val = concrete_node.template as<toml::time>()->get(); (void)time_val; }
                         else if (concrete_node.template is<toml::date_time>()) { volatile auto dt_val = concrete_node.template as<toml::date_time>()->get(); (void)dt_val; }
                    } else if constexpr (toml::is_array<typename std::remove_cv<typename std::remove_reference<decltype(concrete_node)>::type>::type>) {
                        volatile size_t arr_size = concrete_node.size(); (void)arr_size; 
                        if (!concrete_node.empty() && fdp.ConsumeBool()){ // Access element to trigger more code paths
                           volatile auto& el = concrete_node[0]; (void)el;
                        }
                    } else if constexpr (toml::is_table<typename std::remove_cv<typename std::remove_reference<decltype(concrete_node)>::type>::type>) {
                        volatile size_t tbl_size = concrete_node.size(); (void)tbl_size; 
                         if (!concrete_node.empty() && fdp.ConsumeBool()){ // Access element
                           volatile auto& el_tbl = concrete_node.cbegin()->second; (void)el_tbl;
                        }
                    }
                });

                const toml::node& const_actual_node = node_val_ref;
                // MODIFICATION: Expanded const lambda similarly
                const_actual_node.visit([&fdp](auto&& concrete_node) {
                    volatile toml::node_type t = concrete_node.type();
                    (void)t;
                     if constexpr (toml::is_value<typename std::remove_cv<typename std::remove_reference<decltype(concrete_node)>::type>::type>) {
                         if (concrete_node.template is<std::string>()) { volatile auto s = concrete_node.template as<std::string>()->get(); (void)s;}
                         // Add other types if specific const paths need targeting
                    } else if constexpr (toml::is_array<typename std::remove_cv<typename std::remove_reference<decltype(concrete_node)>::type>::type>) {
                        volatile size_t arr_size = concrete_node.size(); (void)arr_size;
                         if (!concrete_node.empty() && fdp.ConsumeBool()){
                           volatile auto& el = concrete_node[0]; (void)el;
                        }
                    } else if constexpr (toml::is_table<typename std::remove_cv<typename std::remove_reference<decltype(concrete_node)>::type>::type>) {
                        volatile size_t tbl_size = concrete_node.size(); (void)tbl_size;
                        if (!concrete_node.empty() && fdp.ConsumeBool()){
                           volatile auto& el_tbl = concrete_node.cbegin()->second; (void)el_tbl;
                        }
                    }
                });
            }
        }
        // END MODIFICATION


    } catch (const toml::parse_error& /*err*/) {
        // Catch parsing errors.
    } catch (const std::out_of_range& /*oor*/) {
        // Catch out_of_range errors, e.g. from arr.at().
    } catch (const std::exception& /*ex*/) {
        // Catch other standard C++ exceptions.
    } catch (...) {
        // Catch any other types of exceptions.
    }

    // BEGIN MODIFICATION: Parse TOML from an std::istream
    // Rationale: Target 0% coverage for stream parsing codepaths (e.g., utf8_reader<std::istream>).
    // Memory safe as istringstream manages its buffer.
    if (fdp.ConsumeBool()) {
      std::string stream_toml_data = fdp.ConsumeRandomLengthString(Size > 256 ? 256 : Size); // Limit size
      std::istringstream toml_istream(stream_toml_data);
      try {
        volatile toml::table stream_tbl = toml::parse(toml_istream, std::string_view{"fuzz_stream_input"});
        (void)stream_tbl;
      } catch (const toml::parse_error&) { /* Expected for malformed input */ }
        catch (const std::exception&) { /* Catch other potential exceptions from stream operations */ }
    }
    // END MODIFICATION

    // BEGIN MODIFICATION: Test toml::array specific constructors and methods
    // Rationale: Cover array initializer_list constructor, get(), operator==, operator=, clear(), pop_back().
    // Memory is managed by toml::array.
    if (fdp.ConsumeBool()) {
        toml::array arr_test;
        if (fdp.ConsumeBool()) arr_test.push_back(fdp.ConsumeIntegral<int64_t>());
        if (fdp.ConsumeBool()) arr_test.push_back(fdp.ConsumeRandomLengthString(5));
        const toml::array& const_arr_test = arr_test;

        volatile toml::node* n_get1 = arr_test.get(0); (void)n_get1; 
        volatile const toml::node* cn_get1 = const_arr_test.get(0); (void)cn_get1;
        if (!arr_test.empty()) { 
            volatile toml::node* n_get2 = arr_test.get(arr_test.size() -1); (void)n_get2;
            volatile const toml::node* cn_get2 = const_arr_test.get(const_arr_test.size() -1); (void)cn_get2;
        }
        volatile toml::node* n_get_oof = arr_test.get(arr_test.size()); (void)n_get_oof; 
        volatile const toml::node* cn_get_oof = const_arr_test.get(const_arr_test.size()); (void)cn_get_oof;

        toml::array arr_il{fdp.ConsumeIntegral<int64_t>(), fdp.ConsumeRandomLengthString(3), fdp.ConsumeBool()}; 
        (void)arr_il;

        toml::array arr_cmp1, arr_cmp2;
        if (fdp.ConsumeBool()) arr_cmp1.push_back(123);
        if (fdp.ConsumeBool()) arr_cmp2.push_back(fdp.ConsumeBool() ? 123 : 456);
        volatile bool arr_are_eq = (arr_cmp1 == arr_cmp2); (void)arr_are_eq; 
        volatile bool arr_are_neq = (arr_cmp1 != arr_cmp2); (void)arr_are_neq; 

        toml::array arr_assign1; if (fdp.ConsumeBool()) arr_assign1.push_back(1);
        toml::array arr_assign2; arr_assign2 = arr_assign1; 
        toml::array arr_assign3 = arr_assign1; 
        arr_assign2 = std::move(arr_assign1); 
        toml::array arr_assign4 = std::move(arr_assign3); 
        (void)arr_assign2; (void)arr_assign4;

        if (fdp.ConsumeBool() && !arr_test.empty()) arr_test.pop_back(); 
        if (fdp.ConsumeBool()) arr_test.clear(); 
    }
    // END MODIFICATION

    // BEGIN MODIFICATION: Call _toml literal operator
    // Rationale: Target 0% coverage for toml::v3::literals::lit_ex::operator"" _toml.
    // This uses a fixed string to ensure the operator itself is invoked.
    if (fdp.ConsumeBool()) { 
        using namespace toml::literals;
        try {
            volatile auto fixed_tbl_literal = "[section]\nkey = \"value\""_toml;
            (void)fixed_tbl_literal; 
        } catch (const toml::parse_error&) { /* Should not happen for a valid fixed string */ }
          catch (...) { /* Catch any other unexpected errors */ }
    }
    // END MODIFICATION

    // BEGIN MODIFICATION: Target toml::array::get() branches
    // Rationale: Ensure coverage for both true and false paths of the branch in array::get() (array.hpp:687).
    // Memory safe as get() returns a non-owning pointer or nullptr.
    if (fdp.ConsumeBool()) {
        toml::array arr_get_test;
        // Test 1: Empty array, get(0) -> should hit false path (index >= size)
        volatile toml::node* r1 = arr_get_test.get(0); (void)r1;

        arr_get_test.push_back(123); // Now array has one element
        // Test 2: Non-empty array, get(0) -> should hit true path (index < size)
        volatile toml::node* r2 = arr_get_test.get(0); (void)r2;
        // Test 3: Non-empty array, get(1) (out of bounds) -> should hit false path (index >= size)
        volatile toml::node* r3 = arr_get_test.get(1); (void)r3;

        const toml::array& const_arr_get_test = arr_get_test;
        // Test 4: Const non-empty array, get(0) -> should hit true path
        volatile const toml::node* r4 = const_arr_get_test.get(0); (void)r4;
        // Test 5: Const non-empty array, get(1) (out of bounds) -> should hit false path
        volatile const toml::node* r5 = const_arr_get_test.get(1); (void)r5;

        toml::array empty_arr_const_test;
        const toml::array& const_empty_arr_get_test = empty_arr_const_test;
        // Test 6: Const empty array, get(0) -> should hit false path
        volatile const toml::node* r6 = const_empty_arr_get_test.get(0); (void)r6;
    }
    // END MODIFICATION

    // BEGIN MODIFICATION: Target date/time/datetime/time_offset operators
    // Rationale: Cover comparison and stream operators for date, time, date_time, and time_offset types.
    // These have multiple uncovered branches in their comparison logic (e.g. date_time.hpp:41).
    // Memory safe as these are stack-allocated objects and ostringstream manages its buffer.
    if (fdp.ConsumeBool()) {
        toml::date d1{fdp.ConsumeIntegralInRange<uint16_t>(1,2500),fdp.ConsumeIntegralInRange<uint8_t>(1,12),fdp.ConsumeIntegralInRange<uint8_t>(1,28)};
        toml::date d2{fdp.ConsumeIntegralInRange<uint16_t>(1,2500),fdp.ConsumeIntegralInRange<uint8_t>(1,12),fdp.ConsumeIntegralInRange<uint8_t>(1,28)};
        volatile bool date_eq = (d1 == d2); (void)date_eq;
        volatile bool date_neq = (d1 != d2); (void)date_neq; 
        volatile bool date_lt = (d1 < d2); (void)date_lt;
        volatile bool date_lte = (d1 <= d2); (void)date_lte;
        volatile bool date_gt = (d1 > d2); (void)date_gt;
        volatile bool date_gte = (d1 >= d2); (void)date_gte;
        std::ostringstream d_oss; d_oss << d1; (void)d_oss.str();

        toml::time t1{fdp.ConsumeIntegralInRange<uint8_t>(0,23),fdp.ConsumeIntegralInRange<uint8_t>(0,59),fdp.ConsumeIntegralInRange<uint8_t>(0,59),fdp.ConsumeIntegralInRange<uint32_t>(0,999999999u)};
        toml::time t2{fdp.ConsumeIntegralInRange<uint8_t>(0,23),fdp.ConsumeIntegralInRange<uint8_t>(0,59),fdp.ConsumeIntegralInRange<uint8_t>(0,59),fdp.ConsumeIntegralInRange<uint32_t>(0,999999999u)};
        volatile bool time_eq = (t1 == t2); (void)time_eq;
        volatile bool time_neq = (t1 != t2); (void)time_neq;
        volatile bool time_lt = (t1 < t2); (void)time_lt;
        volatile bool time_lte = (t1 <= t2); (void)time_lte;
        volatile bool time_gt = (t1 > t2); (void)time_gt;
        volatile bool time_gte = (t1 >= t2); (void)time_gte;
        std::ostringstream t_oss; t_oss << t1; (void)t_oss.str();

        toml::time_offset to1{fdp.ConsumeIntegralInRange<int8_t>(-23,23), fdp.ConsumeIntegralInRange<int8_t>(0,59)};
        toml::time_offset to2{fdp.ConsumeIntegralInRange<int8_t>(-23,23), fdp.ConsumeIntegralInRange<int8_t>(0,59)};
        volatile bool to_eq = (to1 == to2); (void)to_eq;
        volatile bool to_neq = (to1 != to2); (void)to_neq;
        volatile bool to_lt = (to1 < to2); (void)to_lt;
        volatile bool to_lte = (to1 <= to2); (void)to_lte;
        volatile bool to_gt = (to1 > to2); (void)to_gt;
        volatile bool to_gte = (to1 >= to2); (void)to_gte;
        std::ostringstream to_oss; to_oss << to1; (void)to_oss.str();

        toml::date_time dt1 = fdp.ConsumeBool() ? toml::date_time{d1, t1, to1} : toml::date_time{d1, t1};
        toml::date_time dt2 = fdp.ConsumeBool() ? toml::date_time{d2, t2, to2} : toml::date_time{d2, t2};
        volatile bool dt_eq = (dt1 == dt2); (void)dt_eq;
        volatile bool dt_neq = (dt1 != dt2); (void)dt_neq;
        volatile bool dt_lt = (dt1 < dt2); (void)dt_lt;
        volatile bool dt_lte = (dt1 <= dt2); (void)dt_lte;
        volatile bool dt_gt = (dt1 > dt2); (void)dt_gt;
        volatile bool dt_gte = (dt1 >= dt2); (void)dt_gte;
        std::ostringstream dt_oss; dt_oss << dt1; (void)dt_oss.str();

        if (fdp.ConsumeBool()) {
            toml::date_time dt_from_date(d1); (void)dt_from_date; // Cover date_time(date) constructor
            volatile bool is_local_check1 = dt_from_date.is_local(); (void)is_local_check1; // Cover is_local
        }
        if (fdp.ConsumeBool()) {
            toml::date_time dt_from_time(t1); (void)dt_from_time; // Cover date_time(time) constructor
            volatile bool is_local_check2 = dt_from_time.is_local(); (void)is_local_check2;
        }
        volatile bool is_local_check3 = dt1.is_local(); (void)is_local_check3;
    }
    // END MODIFICATION

    // BEGIN MODIFICATION: Target toml::array is_X/as_X and other uncovered methods
    // Rationale: Cover various 0%-covered toml::array methods like as_string, is_integer, cend, max_size, etc.
    // These are called on a standalone array to ensure they are exercised.
    // Memory safe: array manages its own elements. as_X methods return nullptr for non-matching types or 'this'.
    if (fdp.ConsumeBool()) {
        toml::array standalone_arr;
        if (fdp.ConsumeBool()) standalone_arr.push_back(fdp.ConsumeRandomLengthString(5));
        if (fdp.ConsumeBool()) standalone_arr.push_back(fdp.ConsumeIntegral<int64_t>());
        if (fdp.ConsumeBool()) standalone_arr.push_back(fdp.ConsumeBool());

        const toml::array& const_standalone_arr = standalone_arr;

        // is_X methods
        if (fdp.ConsumeBool()) { volatile bool r = standalone_arr.is_string(); (void)r; }
        if (fdp.ConsumeBool()) { volatile bool r = standalone_arr.is_integer(); (void)r; } 
        if (fdp.ConsumeBool()) { volatile bool r = standalone_arr.is_floating_point(); (void)r; }
        if (fdp.ConsumeBool()) { volatile bool r = standalone_arr.is_boolean(); (void)r; }
        if (fdp.ConsumeBool()) { volatile bool r = standalone_arr.is_date(); (void)r; } 
        if (fdp.ConsumeBool()) { volatile bool r = standalone_arr.is_time(); (void)r; }
        if (fdp.ConsumeBool()) { volatile bool r = standalone_arr.is_date_time(); (void)r; } 
        if (fdp.ConsumeBool()) { volatile bool r = const_standalone_arr.is_table(); (void)r; } 
        if (fdp.ConsumeBool()) { volatile bool r = const_standalone_arr.is_array(); (void)r; }


        // as_X methods (non-const)
        if (fdp.ConsumeBool()) { volatile toml::value<std::string>* r = standalone_arr.as_string(); (void)r; } 
        if (fdp.ConsumeBool()) { volatile toml::value<int64_t>* r = standalone_arr.as_integer(); (void)r; } 
        if (fdp.ConsumeBool()) { volatile toml::value<double>* r = standalone_arr.as_floating_point(); (void)r; } 
        if (fdp.ConsumeBool()) { volatile toml::value<bool>* r = standalone_arr.as_boolean(); (void)r; } 
        if (fdp.ConsumeBool()) { volatile toml::value<toml::date>* r = standalone_arr.as_date(); (void)r; } 
        if (fdp.ConsumeBool()) { volatile toml::value<toml::time>* r = standalone_arr.as_time(); (void)r; } 
        if (fdp.ConsumeBool()) { volatile toml::value<toml::date_time>* r = standalone_arr.as_date_time(); (void)r; } 
        if (fdp.ConsumeBool()) { volatile toml::table* r = standalone_arr.as_table(); (void)r; }
        if (fdp.ConsumeBool()) { volatile toml::array* r = standalone_arr.as_array(); (void)r; }


        // as_X methods (const)
        if (fdp.ConsumeBool()) { volatile const toml::value<std::string>* r = const_standalone_arr.as_string(); (void)r; } 
        if (fdp.ConsumeBool()) { volatile const toml::value<int64_t>* r = const_standalone_arr.as_integer(); (void)r; } 
        if (fdp.ConsumeBool()) { volatile const toml::value<double>* r = const_standalone_arr.as_floating_point(); (void)r; } 
        if (fdp.ConsumeBool()) { volatile const toml::value<bool>* r = const_standalone_arr.as_boolean(); (void)r; } 
        if (fdp.ConsumeBool()) { volatile const toml::value<toml::date>* r = const_standalone_arr.as_date(); (void)r; } 
        if (fdp.ConsumeBool()) { volatile const toml::value<toml::time>* r = const_standalone_arr.as_time(); (void)r; } 
        if (fdp.ConsumeBool()) { volatile const toml::value<toml::date_time>* r = const_standalone_arr.as_date_time(); (void)r; } 
        if (fdp.ConsumeBool()) { volatile const toml::table* r = const_standalone_arr.as_table(); (void)r; } 
        if (fdp.ConsumeBool()) { volatile const toml::array* r = const_standalone_arr.as_array(); (void)r; } 

        // Other uncovered methods
        if (fdp.ConsumeBool() && !const_standalone_arr.empty()) { 
            toml::array::const_iterator cit = const_standalone_arr.cend(); // कवर cend
            if (cit != const_standalone_arr.cbegin()) --cit; 
            (void)cit;
        }
        if (fdp.ConsumeBool()) { volatile size_t s = const_standalone_arr.max_size(); (void)s; } 

        if (fdp.ConsumeBool()) { 
            toml::array arr_shrink = standalone_arr; 
            arr_shrink.shrink_to_fit(); // कवर shrink_to_fit
        }
        if (fdp.ConsumeBool() && !standalone_arr.empty()) { 
            toml::array arr_trunc = standalone_arr; 
            arr_trunc.truncate(fdp.ConsumeIntegralInRange<size_t>(0, arr_trunc.size())); // कवर truncate
        }
        if (fdp.ConsumeBool() && standalone_arr.size() >= 2) { 
            toml::array arr_erase_range = standalone_arr; 
            auto it_start = arr_erase_range.begin();
            auto it_end = arr_erase_range.begin();
            std::advance(it_end, fdp.ConsumeIntegralInRange<size_t>(1, arr_erase_range.size()));
            if (it_start < it_end) arr_erase_range.erase(it_start, it_end); // कवर erase(iter, iter)
        }
        // total_leaf_count is private, cannot be called directly.
        // if (fdp.ConsumeBool()) { 
        //    volatile size_t tlc = const_standalone_arr.total_leaf_count(); (void)tlc; 
        // }

        if (fdp.ConsumeBool()) {
            toml::array arr_flat_lval = standalone_arr;
            arr_flat_lval.emplace_back(toml::array{1,2}); 
            arr_flat_lval.flatten(); // कवर flatten() &
            (void)arr_flat_lval;

            toml::array arr_flat_rval = standalone_arr;
            arr_flat_rval.emplace_back(toml::array{3,4});
            volatile toml::array flat_res = std::move(arr_flat_rval).flatten(); // कवर flatten() &&
            (void)flat_res;
        }
        if (fdp.ConsumeBool()) {
            toml::array arr_prune_lval = standalone_arr;
            arr_prune_lval.emplace_back(toml::array{}); 
            arr_prune_lval.prune(fdp.ConsumeBool()); // कवर prune(bool) &
            (void)arr_prune_lval;

            toml::array arr_prune_rval = standalone_arr;
            arr_prune_rval.emplace_back(toml::array{});
            volatile toml::array prune_res = std::move(arr_prune_rval).prune(fdp.ConsumeBool()); // कवर prune(bool) &&
            (void)prune_res;
        }
        if (fdp.ConsumeBool()) { // कवर operator<<(ostream, array)
            std::ostringstream arr_oss;
            arr_oss << standalone_arr;
            (void)arr_oss.str();
        }
    }
    // END MODIFICATION

    // BEGIN MODIFICATION: Target toml::path and toml::path_component methods
    // Rationale: Cover 0%-covered methods in toml::path and toml::path_component (constructors, operators, accessors, modifiers).
    // Memory safe: toml::path manages its components. String operations are on fuzzer-controlled strings.
    if (fdp.ConsumeBool()) {
        std::string p_str1_data = fdp.ConsumeRandomLengthString(20);
        std::string_view p_str1(p_str1_data);
        std::string p_str2_data = fdp.ConsumeRandomLengthString(20);
        std::string_view p_str2(p_str2_data);

        toml::path path1(p_str1); // कवर path(string_view)
        toml::path path2;         // कवर path()
        if (fdp.ConsumeBool()) path2 = p_str2; // कवर operator=(string_view)

        volatile bool p_empty = path1.empty(); (void)p_empty; // कवर empty()
        volatile size_t p_size = path1.size(); (void)p_size; // कवर size()
        if (path1) { volatile bool p_bool = true; (void)p_bool;} // कवर operator bool()

        if (fdp.ConsumeBool()) { std::string s = path1.str(); (void)s; } // कवर str()
        if (fdp.ConsumeBool()) { std::string s = static_cast<std::string>(path1); (void)s; } // कवर operator std::string()
        if (fdp.ConsumeBool()) { std::ostringstream p_oss; p_oss << path1; (void)p_oss.str(); } // कवर operator<<

        volatile bool p_eq = (path1 == path2); (void)p_eq; // कवर operator==(path,path)
        volatile bool p_neq = (path1 != path2); (void)p_neq; // कवर operator!=(path,path)
        volatile bool p_eq_sv = (path1 == p_str2); (void)p_eq_sv; // कवर operator==(path,sv)
        volatile bool sv_eq_p = (p_str1 == path2); (void)sv_eq_p; // कवर operator==(sv,path)
        volatile bool p_neq_sv = (path1 != p_str2); (void)p_neq_sv; // कवर operator!=(path,sv)
        volatile bool sv_neq_p = (p_str1 != path2); (void)sv_neq_p; // कवर operator!=(sv,path)

        if (fdp.ConsumeBool()) { toml::path p3 = path1 + path2; (void)p3; } // कवर operator+(path,path)
        if (fdp.ConsumeBool()) { toml::path p4 = path1 + p_str2; (void)p4; } // कवर operator+(path,sv)
        if (fdp.ConsumeBool()) { toml::path p5 = p_str1 + path2; (void)p5; } // कवर operator+(sv,path)
        
        toml::path path_mut = path1;
        if (fdp.ConsumeBool()) { path_mut += path2; } // कवर operator+=(path)
        else if (fdp.ConsumeBool()) { path_mut += p_str2; } // कवर operator+=(string_view)


        if (!path_mut.empty() && path_mut.size() > 0) {
            volatile const toml::path_component& pc_front = path_mut[0]; (void)pc_front; // कवर operator[](size_t)
            for (const auto& comp : path_mut) { // कवर begin, end, cbegin, cend
                volatile toml::path_component_type pct = comp.type(); (void)pct; // कवर path_component::type()
                if (comp.type() == toml::path_component_type::key) { volatile std::string_view k = comp.key(); (void)k; } // कवर path_component::key()
                else if (comp.type() == toml::path_component_type::array_index) { volatile size_t i = comp.index(); (void)i; } // कवर path_component::index()
            }
        }

        if (fdp.ConsumeBool()) { path_mut.clear(); } // कवर clear()
        if (fdp.ConsumeBool() && !path2.empty()) { path_mut.assign(path2); } // कवर assign(path)
        else if (fdp.ConsumeBool()) { path_mut.assign(p_str1); } // कवर assign(string_view)

        if (fdp.ConsumeBool()) { path_mut.prepend(path2); } // कवर prepend(path)
        else if (fdp.ConsumeBool()) { path_mut.prepend(p_str1); } // कवर prepend(string_view)

        if (fdp.ConsumeBool()) { path_mut.append(path2); } // कवर append(path)
        else if (fdp.ConsumeBool()) { path_mut.append(p_str1); } // कवर append(string_view)

        if (fdp.ConsumeBool() && !path_mut.empty()) {
          path_mut.truncate(fdp.ConsumeIntegralInRange<size_t>(0, path_mut.size())); // कवर truncate()
        }
        if (fdp.ConsumeBool() && !path_mut.empty()) {
          volatile toml::path p_trunc = path_mut.truncated(fdp.ConsumeIntegralInRange<size_t>(0, path_mut.size())); (void)p_trunc; // कवर truncated()
          volatile toml::path p_parent = path_mut.parent(); (void)p_parent; // कवर parent()
        }
         if (fdp.ConsumeBool() && !path_mut.empty()) {
          volatile toml::path p_leaf = path_mut.leaf(fdp.ConsumeIntegralInRange<size_t>(0, path_mut.size())); (void)p_leaf; // कवर leaf()
        }
        if (fdp.ConsumeBool() && path_mut.size() > 1) {
            volatile toml::path p_sub = path_mut.subpath(0,1); (void)p_sub; // कवर subpath()
        }

        if (!path1.empty()) { // path_component specific tests
            toml::path_component pc_orig = path1[0];
            toml::path_component pc = pc_orig; 
            toml::path_component pc2 = pc; 
            pc2 = pc; 

            if (pc.type() == toml::path_component_type::array_index) {
                toml::path_component pc_idx(pc.index()); (void)pc_idx; // कवर path_component(size_t)
                pc2 = pc.index(); // कवर path_component::operator=(size_t)
                volatile size_t idx_val = static_cast<size_t>(pc); (void)idx_val; // कवर path_component::operator size_t()
            } else if (pc.type() == toml::path_component_type::key) {
                toml::path_component pc_key(pc.key()); (void)pc_key; // कवर path_component(string_view)
                pc2 = pc.key(); // कवर path_component::operator=(string_view)
                volatile const std::string& key_val = static_cast<const std::string&>(pc); (void)key_val; // कवर path_component::operator const string&
            }
            toml::path_component pc_moved = std::move(pc2); 
            pc = std::move(pc_moved); 
        }

        if (fdp.ConsumeBool()) { // _tpath literal
            using namespace toml::literals;
            volatile auto p_literal = "a.b[0]"_tpath; // कवर operator""_tpath
            (void)p_literal;
        }
    }
    // END MODIFICATION

    // BEGIN MODIFICATION: Target yaml_formatter
    // Rationale: Cover 0%-covered toml::yaml_formatter and its output generation.
    // Memory safe as ostringstream manages its own buffer.
    if (fdp.ConsumeBool() && !tbl.empty()) { 
        std::ostringstream yaml_oss;
        toml::format_flags y_flags = toml::format_flags::none;
        if (fdp.ConsumeBool()) y_flags |= toml::format_flags::indentation; 
        
        toml::yaml_formatter yf{tbl, y_flags}; 
        yaml_oss << yf; 
        std::string formatted_yaml_string = yaml_oss.str();
        (void)formatted_yaml_string;

        std::ostringstream yaml_oss_default;
        toml::yaml_formatter yf_default{tbl}; 
        yaml_oss_default << yf_default;
        (void)yaml_oss_default.str();

        if (fdp.ConsumeBool()) {
            toml::array arr_for_yaml;
            if (fdp.ConsumeBool()) arr_for_yaml.push_back(1);
            if (fdp.ConsumeBool()) arr_for_yaml.push_back("two");
            if (fdp.ConsumeBool()) arr_for_yaml.emplace_back(toml::table{{"k", "v"}}); // Add table for deeper YAML structure
            std::ostringstream yaml_arr_oss;
            yaml_arr_oss << toml::yaml_formatter{arr_for_yaml};
            (void)yaml_arr_oss.str();
        }
         if (fdp.ConsumeBool()) {
            toml::value val_for_yaml(fdp.ConsumeRandomLengthString(10));
            std::ostringstream yaml_val_oss;
            yaml_val_oss << toml::yaml_formatter{val_for_yaml};
            (void)yaml_val_oss.str();
        }
    }
    // END MODIFICATION

    // BEGIN MODIFICATION: Target print_integer_to_stream specializations
    // Rationale: Cover 0%-covered print_integer_to_stream specializations for various integer types and formatting flags.
    // Memory safe as ostringstream manages its own buffer.
    if (fdp.ConsumeBool()) {
        std::ostringstream int_oss;
        toml::value_flags bin_flags = toml::value_flags::format_as_binary;
        toml::value_flags oct_flags = toml::value_flags::format_as_octal;
        toml::value_flags hex_flags = toml::value_flags::format_as_hexadecimal;
        toml::value_flags dec_flags = toml::value_flags::none;

        signed char sc = fdp.ConsumeIntegral<signed char>();
        if (fdp.ConsumeBool()) toml::impl::print_integer_to_stream(int_oss, sc, bin_flags, 0);
        if (fdp.ConsumeBool()) toml::impl::print_integer_to_stream(int_oss, sc, oct_flags, 0);
        if (fdp.ConsumeBool()) toml::impl::print_integer_to_stream(int_oss, sc, hex_flags, 0);
        if (fdp.ConsumeBool()) toml::impl::print_integer_to_stream(int_oss, sc, dec_flags, fdp.ConsumeIntegralInRange<size_t>(0,3));

        short s_val = fdp.ConsumeIntegral<short>();
        if (fdp.ConsumeBool()) toml::impl::print_integer_to_stream(int_oss, s_val, bin_flags, 0);
        if (fdp.ConsumeBool()) toml::impl::print_integer_to_stream(int_oss, s_val, oct_flags, 0);
        if (fdp.ConsumeBool()) toml::impl::print_integer_to_stream(int_oss, s_val, hex_flags, 0);
        if (fdp.ConsumeBool()) toml::impl::print_integer_to_stream(int_oss, s_val, dec_flags, fdp.ConsumeIntegralInRange<size_t>(0,5));
        
        int i_val = fdp.ConsumeIntegral<int>();
        if (fdp.ConsumeBool()) toml::impl::print_integer_to_stream(int_oss, i_val, bin_flags, 0);
        if (fdp.ConsumeBool()) toml::impl::print_integer_to_stream(int_oss, i_val, oct_flags, 0);
        if (fdp.ConsumeBool()) toml::impl::print_integer_to_stream(int_oss, i_val, hex_flags, 0);
        if (fdp.ConsumeBool()) toml::impl::print_integer_to_stream(int_oss, i_val, dec_flags, fdp.ConsumeIntegralInRange<size_t>(0,10));

        long long ll = fdp.ConsumeIntegral<long long>();
        if (fdp.ConsumeBool()) toml::impl::print_integer_to_stream(int_oss, ll, bin_flags, 0);
        if (fdp.ConsumeBool()) toml::impl::print_integer_to_stream(int_oss, ll, oct_flags, 0);
        if (fdp.ConsumeBool()) toml::impl::print_integer_to_stream(int_oss, ll, hex_flags, 0);
        if (fdp.ConsumeBool()) toml::impl::print_integer_to_stream(int_oss, ll, dec_flags, fdp.ConsumeIntegralInRange<size_t>(0,19));

        unsigned long ul = fdp.ConsumeIntegral<unsigned long>();
        if (fdp.ConsumeBool()) toml::impl::print_integer_to_stream(int_oss, ul, bin_flags, 0);
        if (fdp.ConsumeBool()) toml::impl::print_integer_to_stream(int_oss, ul, oct_flags, 0);
        if (fdp.ConsumeBool()) toml::impl::print_integer_to_stream(int_oss, ul, hex_flags, 0);
        if (fdp.ConsumeBool()) toml::impl::print_integer_to_stream(int_oss, ul, dec_flags, fdp.ConsumeIntegralInRange<size_t>(0,19));
        
        unsigned long long ull = fdp.ConsumeIntegral<unsigned long long>();
        if (fdp.ConsumeBool()) toml::impl::print_integer_to_stream(int_oss, ull, bin_flags, 0);
        if (fdp.ConsumeBool()) toml::impl::print_integer_to_stream(int_oss, ull, oct_flags, 0);
        if (fdp.ConsumeBool()) toml::impl::print_integer_to_stream(int_oss, ull, hex_flags, 0);
        if (fdp.ConsumeBool()) toml::impl::print_integer_to_stream(int_oss, ull, dec_flags, fdp.ConsumeIntegralInRange<size_t>(0,20));

        (void)int_oss.str();
    }
    // END MODIFICATION

    // BEGIN MODIFICATION: Target print_floating_point_to_stream<float>
    // Rationale: Cover 0%-covered print_floating_point_to_stream<float> specialization.
    // Memory safe as ostringstream manages its own buffer.
    if (fdp.ConsumeBool()) {
        std::ostringstream float_oss;
        float f_val = fdp.ConsumeFloatingPoint<float>();
        toml::value_flags hex_f_flags = toml::value_flags::format_as_hexadecimal;
        toml::value_flags dec_f_flags = toml::value_flags::none;
        bool relaxed_precision = fdp.ConsumeBool();

        if (fdp.ConsumeBool()) toml::impl::print_floating_point_to_stream(float_oss, f_val, hex_f_flags, relaxed_precision);
        if (fdp.ConsumeBool()) toml::impl::print_floating_point_to_stream(float_oss, f_val, dec_f_flags, relaxed_precision);
        (void)float_oss.str();
    }
    // END MODIFICATION

    return 0;
}