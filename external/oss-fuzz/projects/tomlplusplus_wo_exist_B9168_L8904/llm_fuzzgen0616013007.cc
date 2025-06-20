#include <cstddef>
#include <cstdint>
#include <string>
#include <vector>
#include <iterator> // For std::advance

// Fuzzer include for FuzzedDataProvider
#include <fuzzer/FuzzedDataProvider.h>

// Main library header for tomlplusplus.
#include "/src/tomlplusplus/include/toml++/toml.hpp"

// Extern "C" to ensure C linkage for the fuzzer entry point.
extern "C" int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size) {
    FuzzedDataProvider fdp(Data, Size);

    std::string toml_string = fdp.ConsumeRandomLengthString(Size);

    try {
        toml::table tbl = toml::parse(toml_string);

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
                             // The actual check for validity of it + offset is inside the operator+ or subsequent use.
                             // Here we just ensure offset is within a basic range.
                             toml::array::iterator it2 = it + offset; // Calls free function operator+(iterator, ptrdiff_t)
                             (void)it2; // Use the iterator
                        }
                    }
                    // END MODIFICATION

                    // BEGIN MODIFICATION: Call specific uncovered array is_X/as_X methods
                    // Rationale: Target specific 0% coverage functions for toml::array.
                    if (fdp.ConsumeBool()) { volatile bool r = arr->is_array_of_tables(); (void)r; }
                    if (fdp.ConsumeBool()) { volatile toml::table* r = arr->as_table(); (void)r; }
                    // END MODIFICATION
                }
            } else if (node_view.is_table()) {
                toml::table* inner_tbl = node_view.as_table();
                if (inner_tbl) {
                    const toml::table& const_inner_tbl_ref = *inner_tbl;
                    // BEGIN MODIFICATION: Call specific uncovered table is_X/as_X methods
                    // Rationale: Target specific 0% coverage functions for toml::table.
                    if (fdp.ConsumeBool()) { volatile bool r = inner_tbl->is_date(); (void)r; }
                    if (fdp.ConsumeBool()) { volatile toml::value<toml::date>* r = inner_tbl->as_date(); (void)r; }
                    if (fdp.ConsumeBool()) { volatile const toml::value<toml::date>* r = const_inner_tbl_ref.as_date(); (void)r; } // Const version
                    // END MODIFICATION
                }
            }
        }

    } catch (const toml::parse_error& /*err*/) {
        // Catch parsing errors.
    } catch (const std::out_of_range& /*oor*/) {
        // Catch out_of_range errors, e.g. from arr.at().
    } catch (const std::exception& /*ex*/) {
        // Catch other standard C++ exceptions.
    } catch (...) {
        // Catch any other types of exceptions.
    }
    return 0; 
}