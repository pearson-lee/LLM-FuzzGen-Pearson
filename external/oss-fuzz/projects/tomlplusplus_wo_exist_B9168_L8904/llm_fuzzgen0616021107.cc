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
        if (fdp.ConsumeIntegralInRange(0,10) == 0) tbl.emplace("fuzz_str_val", fdp.ConsumeRandomLengthString(10));
        if (fdp.ConsumeIntegralInRange(0,10) == 0) tbl.emplace("fuzz_int_val", fdp.ConsumeIntegral<int64_t>());
        if (fdp.ConsumeIntegralInRange(0,10) == 0) tbl.emplace("fuzz_flt_val", fdp.ConsumeFloatingPoint<double>());
        if (fdp.ConsumeIntegralInRange(0,10) == 0) tbl.emplace("fuzz_bool_val", fdp.ConsumeBool());
        if (fdp.ConsumeIntegralInRange(0,10) == 0) tbl.emplace("fuzz_date_val", toml::date{fdp.ConsumeIntegralInRange<uint16_t>(1,2500),fdp.ConsumeIntegralInRange<uint8_t>(1,12),fdp.ConsumeIntegralInRange<uint8_t>(1,28)});
        if (fdp.ConsumeIntegralInRange(0,10) == 0) tbl.emplace("fuzz_time_val", toml::time{fdp.ConsumeIntegralInRange<uint8_t>(0,23),fdp.ConsumeIntegralInRange<uint8_t>(0,59),fdp.ConsumeIntegralInRange<uint8_t>(0,59),fdp.ConsumeIntegralInRange<uint32_t>(0,999999999u)});
        if (fdp.ConsumeIntegralInRange(0,10) == 0) {
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
        if (fdp.ConsumeBool()) { volatile toml::value<double>* r = tbl.as_floating_point(); (void)r; }
        if (fdp.ConsumeBool()) { volatile bool r = tbl.is_boolean(); (void)r; }
        if (fdp.ConsumeBool()) { volatile toml::value<bool>* r = tbl.as_boolean(); (void)r; }
        if (fdp.ConsumeBool()) { volatile bool r = tbl.is_date(); (void)r; }
        if (fdp.ConsumeBool()) { volatile toml::value<toml::date>* r = tbl.as_date(); (void)r; }
        if (fdp.ConsumeBool()) { volatile bool r = tbl.is_time(); (void)r; }
        if (fdp.ConsumeBool()) { volatile toml::value<toml::time>* r = tbl.as_time(); (void)r; }
        if (fdp.ConsumeBool()) { volatile bool r = tbl.is_date_time(); (void)r; }
        if (fdp.ConsumeBool()) { volatile toml::value<toml::date_time>* r = tbl.as_date_time(); (void)r; }
        if (fdp.ConsumeBool()) { volatile toml::table* r = tbl.as_table(); (void)r; } // Returns this
        if (fdp.ConsumeBool()) { volatile toml::array* r = tbl.as_array(); (void)r; } // Returns nullptr

        if (fdp.ConsumeBool()) { volatile bool r = const_tbl_ref_main.is_string(); (void)r; }
        if (fdp.ConsumeBool()) { volatile const toml::value<std::string>* r = const_tbl_ref_main.as_string(); (void)r; }
        // ... (other const versions for main table can be added if needed, following the pattern)
        if (fdp.ConsumeBool()) { volatile const toml::table* r = const_tbl_ref_main.as_table(); (void)r; }
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
                    if (fdp.ConsumeBool()) { volatile toml::value<std::string>* r = arr->as_string(); (void)r; }
                    if (fdp.ConsumeBool()) { volatile bool r = arr->is_integer(); (void)r; }
                    if (fdp.ConsumeBool()) { volatile toml::value<int64_t>* r = arr->as_integer(); (void)r; }
                    if (fdp.ConsumeBool()) { volatile bool r = arr->is_floating_point(); (void)r; }
                    if (fdp.ConsumeBool()) { volatile toml::value<double>* r = arr->as_floating_point(); (void)r; }
                    if (fdp.ConsumeBool()) { volatile bool r = arr->is_boolean(); (void)r; }
                    if (fdp.ConsumeBool()) { volatile toml::value<bool>* r = arr->as_boolean(); (void)r; }
                    if (fdp.ConsumeBool()) { volatile bool r = arr->is_date(); (void)r; }
                    if (fdp.ConsumeBool()) { volatile toml::value<toml::date>* r = arr->as_date(); (void)r; }
                    if (fdp.ConsumeBool()) { volatile bool r = arr->is_time(); (void)r; }
                    if (fdp.ConsumeBool()) { volatile toml::value<toml::time>* r = arr->as_time(); (void)r; }
                    if (fdp.ConsumeBool()) { volatile bool r = arr->is_date_time(); (void)r; }
                    if (fdp.ConsumeBool()) { volatile toml::value<toml::date_time>* r = arr->as_date_time(); (void)r; }
                    if (fdp.ConsumeBool()) { volatile toml::array* r = arr->as_array(); (void)r; } // Returns this
                    // Const versions
                    if (fdp.ConsumeBool()) { volatile bool r = const_arr_ref.is_string(); (void)r; }
                    if (fdp.ConsumeBool()) { volatile const toml::value<std::string>* r = const_arr_ref.as_string(); (void)r; }
                    // ... (other const versions for array can be added if needed)
                    if (fdp.ConsumeBool()) { volatile const toml::array* r = const_arr_ref.as_array(); (void)r; }
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
                    // ... (other const versions for inner table can be added if needed)
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
            for (auto&& [key, node_val_ref] : tbl) { // Use node_val_ref to avoid copying node_view
                if (visit_count++ >= 2) break; 

                toml::node& actual_node = node_val_ref; // Get the actual node
                actual_node.visit([](auto&& concrete_node) { 
                    volatile toml::node_type t = concrete_node.type();
                    (void)t;
                    if constexpr (toml::is_value<typename std::remove_cv<typename std::remove_reference<decltype(concrete_node)>::type>::type>) {
                         if (concrete_node.template is<std::string>()) { volatile auto s = concrete_node.template as<std::string>()->get(); (void)s;}
                         else if (concrete_node.template is<int64_t>()) { volatile auto i = concrete_node.template as<int64_t>()->get(); (void)i;}
                    }
                });

                const toml::node& const_actual_node = node_val_ref;
                const_actual_node.visit([](auto&& concrete_node) {
                    volatile toml::node_type t = concrete_node.type();
                    (void)t;
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

        volatile toml::node* n_get1 = arr_test.get(0); (void)n_get1; // Test get() on first element (or nullptr if empty)
        volatile const toml::node* cn_get1 = const_arr_test.get(0); (void)cn_get1;
        if (!arr_test.empty()) { // Test get() on last element if not empty
            volatile toml::node* n_get2 = arr_test.get(arr_test.size() -1); (void)n_get2;
            volatile const toml::node* cn_get2 = const_arr_test.get(const_arr_test.size() -1); (void)cn_get2;
        }
        volatile toml::node* n_get_oof = arr_test.get(arr_test.size()); (void)n_get_oof; // Test get() out-of-bounds
        volatile const toml::node* cn_get_oof = const_arr_test.get(const_arr_test.size()); (void)cn_get_oof;

        toml::array arr_il{fdp.ConsumeIntegral<int64_t>(), fdp.ConsumeRandomLengthString(3), fdp.ConsumeBool()}; // Initializer list constructor
        (void)arr_il;

        toml::array arr_cmp1, arr_cmp2;
        if (fdp.ConsumeBool()) arr_cmp1.push_back(123);
        if (fdp.ConsumeBool()) arr_cmp2.push_back(fdp.ConsumeBool() ? 123 : 456);
        volatile bool arr_are_eq = (arr_cmp1 == arr_cmp2); (void)arr_are_eq; // operator==
        volatile bool arr_are_neq = (arr_cmp1 != arr_cmp2); (void)arr_are_neq; // operator!=

        toml::array arr_assign1; if (fdp.ConsumeBool()) arr_assign1.push_back(1);
        toml::array arr_assign2; arr_assign2 = arr_assign1; // Copy assignment
        toml::array arr_assign3 = arr_assign1; // Copy constructor
        arr_assign2 = std::move(arr_assign1); // Move assignment
        toml::array arr_assign4 = std::move(arr_assign3); // Move constructor
        (void)arr_assign2; (void)arr_assign4;

        if (fdp.ConsumeBool() && !arr_test.empty()) arr_test.pop_back(); // pop_back()
        if (fdp.ConsumeBool()) arr_test.clear(); // clear()
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

    return 0;
}