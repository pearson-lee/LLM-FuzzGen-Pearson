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

// Additional APIs to target based on coverage report:
// - bool toml::v3::table::is_string()
// - value<std::string>* toml::v3::table::as_string()
// - bool toml::v3::table::is_floating_point()
// - value<double>* toml::v3::table::as_floating_point()
// - bool toml::v3::table::is_boolean()
// - value<bool>* toml::v3::table::as_boolean()
// - bool toml::v3::table::is_date_time()
// - value<toml::date_time>* toml::v3::table::as_date_time()
// - bool toml::v3::table::is_time()
// - value<toml::date>* toml::v3::table::as_date()
// - Similar functions for toml::array

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    FuzzedDataProvider fdp(data, size);
    std::string toml_string = fdp.ConsumeRemainingBytesAsString();

    try {
        toml::table root_table = toml::parse(toml_string);

        // API 1: bool toml::v3::table::is_date()
        volatile bool root_is_date = root_table.is_date();

        // API 2: value<toml::v3::time> * toml::v3::table::as_time()
        volatile toml::value<toml::time>* root_as_time = root_table.as_time();
        if (root_as_time) {
            // This branch is unlikely to be hit for a table node itself.
        }

        // API 5: bool toml::v3::table::is_integer()
        volatile bool root_is_integer = root_table.is_integer();

        // Added calls to uncovered functions for toml::table on root_table
        volatile bool root_is_string = root_table.is_string(); // Coverage: Call is_string on table
        volatile toml::value<std::string>* root_as_string = root_table.as_string(); // Coverage: Call as_string on table
        if (root_as_string) {} // Check pointer, though unlikely for table node

        volatile bool root_is_fp = root_table.is_floating_point(); // Coverage: Call is_floating_point on table
        volatile toml::value<double>* root_as_fp = root_table.as_floating_point(); // Coverage: Call as_floating_point on table
        if (root_as_fp) {}

        volatile bool root_is_bool = root_table.is_boolean(); // Coverage: Call is_boolean on table
        volatile toml::value<bool>* root_as_bool = root_table.as_boolean(); // Coverage: Call as_boolean on table
        if (root_as_bool) {}

        volatile bool root_is_datetime = root_table.is_date_time(); // Coverage: Call is_date_time on table
        volatile toml::value<toml::date_time>* root_as_datetime = root_table.as_date_time(); // Coverage: Call as_date_time on table
        if (root_as_datetime) {}

        volatile bool root_is_time_check = root_table.is_time(); // Coverage: Call is_time on table
        volatile toml::value<toml::date>* root_as_date = root_table.as_date(); // Coverage: Call as_date on table
        if (root_as_date) {}


        for (auto&& [key, node_view] : root_table) {
            if (node_view.is_array()) {
                toml::array* arr = node_view.as_array();
                if (arr) {
                    volatile bool arr_is_number = arr->is_number();
                    volatile toml::value<int64_t>* arr_as_integer = arr->as_integer();
                    if (arr_as_integer) {
                        // This branch is unlikely to be hit for an array node itself.
                    }

                    // Added calls to uncovered functions for toml::array on arr
                    volatile bool arr_is_string = arr->is_string(); // Coverage: Call is_string on array
                    volatile toml::value<std::string>* arr_as_string = arr->as_string(); // Coverage: Call as_string on array
                    if (arr_as_string) {}

                    volatile bool arr_is_fp = arr->is_floating_point(); // Coverage: Call is_floating_point on array
                    volatile toml::value<double>* arr_as_fp = arr->as_floating_point(); // Coverage: Call as_floating_point on array
                    if (arr_as_fp) {}

                    volatile bool arr_is_bool = arr->is_boolean(); // Coverage: Call is_boolean on array
                    volatile toml::value<bool>* arr_as_bool = arr->as_boolean(); // Coverage: Call as_boolean on array
                    if (arr_as_bool) {}

                    volatile bool arr_is_datetime = arr->is_date_time(); // Coverage: Call is_date_time on array
                    volatile toml::value<toml::date_time>* arr_as_datetime = arr->as_date_time(); // Coverage: Call as_date_time on array
                    if (arr_as_datetime) {}
                    
                    volatile bool arr_is_time = arr->is_time(); // Coverage: Call is_time on array
                    volatile bool arr_is_date = arr->is_date(); // Coverage: Call is_date on array
                    volatile toml::value<toml::time>* arr_as_time = arr->as_time(); // Coverage: Call as_time on array
                    if (arr_as_time) {}
                    volatile toml::value<toml::date>* arr_as_date_val = arr->as_date(); // Coverage: Call as_date on array
                    if (arr_as_date_val) {}


                    for (toml::node& element_node : *arr) {
                        if (element_node.is_table()) {
                            toml::table* nested_table = element_node.as_table();
                            if (nested_table) {
                                volatile bool nested_tbl_is_date = nested_table->is_date();
                                volatile toml::value<toml::time>* nested_tbl_as_time = nested_table->as_time();
                                volatile bool nested_tbl_is_integer = nested_table->is_integer();

                                // Added calls to uncovered functions for toml::table on nested_table
                                volatile bool nt_is_string = nested_table->is_string(); // Coverage: Call is_string on table
                                volatile auto nt_as_string = nested_table->as_string(); // Coverage: Call as_string on table
                                if (nt_as_string) {}
                                volatile bool nt_is_fp = nested_table->is_floating_point(); // Coverage: Call is_floating_point on table
                                volatile auto nt_as_fp = nested_table->as_floating_point(); // Coverage: Call as_floating_point on table
                                if (nt_as_fp) {}
                                volatile bool nt_is_bool = nested_table->is_boolean(); // Coverage: Call is_boolean on table
                                volatile auto nt_as_bool = nested_table->as_boolean(); // Coverage: Call as_boolean on table
                                if (nt_as_bool) {}
                                volatile bool nt_is_datetime = nested_table->is_date_time(); // Coverage: Call is_date_time on table
                                volatile auto nt_as_datetime = nested_table->as_date_time(); // Coverage: Call as_date_time on table
                                if (nt_as_datetime) {}
                                volatile bool nt_is_time = nested_table->is_time(); // Coverage: Call is_time on table
                                volatile auto nt_as_date = nested_table->as_date(); // Coverage: Call as_date on table
                                if (nt_as_date) {}
                            }
                        }
                    }
                }
            } else if (node_view.is_table()) {
                toml::table* sub_table = node_view.as_table();
                if (sub_table) {
                    volatile bool sub_tbl_is_date = sub_table->is_date();
                    volatile toml::value<toml::time>* sub_tbl_as_time = sub_table->as_time();
                    volatile bool sub_tbl_is_integer = sub_table->is_integer();

                    // Added calls to uncovered functions for toml::table on sub_table
                    volatile bool st_is_string = sub_table->is_string(); // Coverage: Call is_string on table
                    volatile auto st_as_string = sub_table->as_string(); // Coverage: Call as_string on table
                    if (st_as_string) {}
                    volatile bool st_is_fp = sub_table->is_floating_point(); // Coverage: Call is_floating_point on table
                    volatile auto st_as_fp = sub_table->as_floating_point(); // Coverage: Call as_floating_point on table
                    if (st_as_fp) {}
                    volatile bool st_is_bool = sub_table->is_boolean(); // Coverage: Call is_boolean on table
                    volatile auto st_as_bool = sub_table->as_boolean(); // Coverage: Call as_boolean on table
                    if (st_as_bool) {}
                    volatile bool st_is_datetime = sub_table->is_date_time(); // Coverage: Call is_date_time on table
                    volatile auto st_as_datetime = sub_table->as_date_time(); // Coverage: Call as_date_time on table
                    if (st_as_datetime) {}
                    volatile bool st_is_time = sub_table->is_time(); // Coverage: Call is_time on table
                    volatile auto st_as_date = sub_table->as_date(); // Coverage: Call as_date on table
                    if (st_as_date) {}

                     for (auto&& [sub_key, sub_node_view] : *sub_table) {
                        if (sub_node_view.is_array()) {
                            toml::array* nested_arr = sub_node_view.as_array();
                            if (nested_arr) {
                                volatile bool nested_arr_is_number = nested_arr->is_number();
                                volatile toml::value<int64_t>* nested_arr_as_integer = nested_arr->as_integer();

                                // Added calls to uncovered functions for toml::array on nested_arr
                                volatile bool na_is_string = nested_arr->is_string(); // Coverage: Call is_string on array
                                volatile auto na_as_string = nested_arr->as_string(); // Coverage: Call as_string on array
                                if (na_as_string) {}
                                volatile bool na_is_fp = nested_arr->is_floating_point(); // Coverage: Call is_floating_point on array
                                volatile auto na_as_fp = nested_arr->as_floating_point(); // Coverage: Call as_floating_point on array
                                if (na_as_fp) {}
                                volatile bool na_is_bool = nested_arr->is_boolean(); // Coverage: Call is_boolean on array
                                volatile auto na_as_bool = nested_arr->as_boolean(); // Coverage: Call as_boolean on array
                                if (na_as_bool) {}
                                volatile bool na_is_datetime = nested_arr->is_date_time(); // Coverage: Call is_date_time on array
                                volatile auto na_as_datetime = nested_arr->as_date_time(); // Coverage: Call as_date_time on array
                                if (na_as_datetime) {}
                                volatile bool na_is_time = nested_arr->is_time(); // Coverage: Call is_time on array
                                volatile bool na_is_date = nested_arr->is_date(); // Coverage: Call is_date on array
                                volatile auto na_as_time_val = nested_arr->as_time(); // Coverage: Call as_time on array
                                if (na_as_time_val) {}
                                volatile auto na_as_date_val = nested_arr->as_date(); // Coverage: Call as_date on array
                                if (na_as_date_val) {}
                            }
                        }
                    }
                }
            }
        }

    } catch (const toml::parse_error& /*err*/) {
        // Parsing can fail with malformed input; this is expected in fuzzing.
    } catch (const std::exception& /*ex*/) {
        // Catch any other C++ standard library exceptions that might occur.
    }
    return 0;
}