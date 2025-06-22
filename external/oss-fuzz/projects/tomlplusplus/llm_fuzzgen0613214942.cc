#include <cstddef>
#include <cstdint>
#include <string>
#include <string_view>
#include <fuzzer/FuzzedDataProvider.h>
#include "/src/tomlplusplus/include/toml++/toml.h" // Main TOML++ header, provides toml::parse and core types

// Fuzz target for tomlplusplus library
// This target aims to maximize code coverage by strategically exercising
// up to 5 diverse API functions:
//
// 1. `toml::parse(std::string_view)`: This is the primary input processing API.
//    It's a high-impact function that orchestrates the entire TOML parsing process,
//    internally calling many other parsing-related functions (e.g., `parse_document`,
//    `parse_table_header`, `parse_key_value_pair_and_insert`, `parse_value`,
//    `parse_string`, `parse_integer`, etc.). Fuzzing this function with varied
//    inputs (both valid and invalid TOML) will explore a significant portion
//    of the library's parsing logic and error handling.
//
// 2. `toml::table::is_homogeneous(toml::node_type)`: This function checks if all
//    elements within a TOML table are of a specific type. Exercising this
//    function after parsing helps cover structural analysis code paths.
//
// 3. `toml::array::is_homogeneous(toml::node_type)`: Similar to the table version,
//    this checks homogeneity for TOML arrays. This complements the table
//    homogeneity check and covers array-specific logic.
//
// 4. `toml::node::as_string()`, `toml::node::as_integer()`, `toml::node::as_floating_point()`,
//    `toml::node::as_boolean()`, `toml::node::as_date()`, `toml::node::as_time()`,
//    `toml::node::as_date_time()`: These are type casting/accessor methods for TOML nodes.
//    By attempting to cast nodes to various types after parsing, we exercise the
//    internal type conversion and validation logic, covering different data
//    representation paths.

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size) {
  FuzzedDataProvider fdp(Data, Size);

  // Consume all remaining fuzzed data as a string to be used as TOML input.
  std::string toml_input_string = fdp.ConsumeRemainingBytesAsString();

  try {
    // 1. Exercise `toml::parse()`:
    // This attempts to parse the fuzzed input string into a TOML table.
    // It's crucial for covering the core parsing logic and error handling.
    toml::table parsed_toml = toml::parse(toml_input_string);

    // If parsing is successful, further exercise the API by traversing the
    // parsed TOML structure and calling various methods to maximize coverage.

    // Iterate through all key-value pairs in the top-level TOML table.
    for (auto& [key, node] : parsed_toml) {
      // Attempt to cast nodes to various types and call `is_homogeneous` if applicable.
      // This helps in exercising different branches within the `as_X` and `is_homogeneous` functions.

      if (node.is_table()) {
        // If the node is a table, get a pointer to it.
        // Removed 'const' to target non-const overloads of is_X() and as_X() methods for toml::table,
        // which were identified as having 0% coverage in the report.
        toml::table* table_node = node.as_table();
        if (table_node) {
          // 2. Exercise `toml::table::is_homogeneous()`:
          // Call `is_homogeneous` with different `toml::node_type` enumerations
          // to test various homogeneity checks for tables.
          table_node->is_homogeneous(toml::node_type::string);
          table_node->is_homogeneous(toml::node_type::integer);
          table_node->is_homogeneous(toml::node_type::floating_point);
          table_node->is_homogeneous(toml::node_type::boolean);
          table_node->is_homogeneous(toml::node_type::date);
          table_node->is_homogeneous(toml::node_type::time);
          table_node->is_homogeneous(toml::node_type::date_time);
          table_node->is_homogeneous(toml::node_type::array);
          table_node->is_homogeneous(toml::node_type::table);

          // Added to cover toml::v3::table::is_homogeneous(DW_TAG_enumeration_typenode_type, const node *&)
          const toml::node* first_nonmatch_node = nullptr;
          table_node->is_homogeneous(toml::node_type::string, first_nonmatch_node);
          table_node->is_homogeneous(toml::node_type::integer, first_nonmatch_node);
          table_node->is_homogeneous(toml::node_type::floating_point, first_nonmatch_node);
          table_node->is_homogeneous(toml::node_type::boolean, first_nonmatch_node);
          table_node->is_homogeneous(toml::node_type::date, first_nonmatch_node);
          table_node->is_homogeneous(toml::node_type::time, first_nonmatch_node);
          table_node->is_homogeneous(toml::node_type::date_time, first_nonmatch_node);
          table_node->is_homogeneous(toml::node_type::array, first_nonmatch_node);
          table_node->is_homogeneous(toml::node_type::table, first_nonmatch_node);

          // Added to cover toml::v3::table::is_X() methods (non-const overloads)
          table_node->is_string();
          table_node->is_integer();
          table_node->is_floating_point();
          table_node->is_number();
          table_node->is_boolean();
          table_node->is_date();
          table_node->is_time();
          table_node->is_date_time();

          // Added to cover toml::v3::table::as_X() methods (non-const overloads)
          table_node->as_string();
          table_node->as_integer();
          table_node->as_floating_point();
          table_node->as_boolean();
          table_node->as_date();
          table_node->as_time();
          table_node->as_date_time();
        }
      } else if (node.is_array()) {
        // If the node is an array, get a pointer to it.
        // Removed 'const' to target non-const overloads of is_X() and as_X() methods for toml::array,
        // which were identified as having 0% coverage in the report.
        toml::array* array_node = node.as_array();
        if (array_node) {
          // 3. Exercise `toml::array::is_homogeneous()`:
          // Call `is_homogeneous` with different `toml::node_type` enumerations
          // to test various homogeneity checks for arrays.
          array_node->is_homogeneous(toml::node_type::string);
          array_node->is_homogeneous(toml::node_type::integer);
          array_node->is_homogeneous(toml::node_type::floating_point);
          array_node->is_homogeneous(toml::node_type::boolean);
          array_node->is_homogeneous(toml::node_type::date);
          array_node->is_homogeneous(toml::node_type::time);
          array_node->is_homogeneous(toml::node_type::date_time);
          array_node->is_homogeneous(toml::node_type::array);
          array_node->is_homogeneous(toml::node_type::table);

          // Added to cover toml::v3::array::is_homogeneous(DW_TAG_enumeration_typenode_type, const node *&)
          const toml::node* first_nonmatch_node = nullptr;
          array_node->is_homogeneous(toml::node_type::string, first_nonmatch_node);
          array_node->is_homogeneous(toml::node_type::integer, first_nonmatch_node);
          array_node->is_homogeneous(toml::node_type::floating_point, first_nonmatch_node);
          array_node->is_homogeneous(toml::node_type::boolean, first_nonmatch_node);
          array_node->is_homogeneous(toml::node_type::date, first_nonmatch_node);
          array_node->is_homogeneous(toml::node_type::time, first_nonmatch_node);
          array_node->is_homogeneous(toml::node_type::date_time, first_nonmatch_node);
          array_node->is_homogeneous(toml::node_type::array, first_nonmatch_node);
          array_node->is_homogeneous(toml::node_type::table, first_nonmatch_node);

          // Added to cover toml::v3::array::is_X() methods (non-const overloads)
          array_node->is_string();
          array_node->is_integer();
          array_node->is_floating_point();
          array_node->is_number();
          array_node->is_boolean();
          array_node->is_date();
          array_node->is_time();
          array_node->is_date_time();

          // Added to cover toml::v3::array::as_X() methods (non-const overloads)
          array_node->as_string();
          array_node->as_integer();
          array_node->as_floating_point();
          array_node->as_boolean();
          array_node->as_date();
          array_node->as_time();
          array_node->as_date_time();

          // Recursively process elements within arrays to further explore nested structures.
          for (auto& element : *array_node) {
            // 4. Exercise `toml::node::as_X()` methods on array elements:
            // Attempt to cast each element to various TOML value types.
            element.as_string();
            element.as_integer();
            element.as_floating_point();
            element.as_boolean();
            element.as_date();
            element.as_time();
            element.as_date_time();

            // If nested tables or arrays are found, perform homogeneity checks on them.
            if (element.is_table()) {
              const toml::table* nested_table = element.as_table();
              if (nested_table) {
                nested_table->is_homogeneous(toml::node_type::string);
                // Added to cover toml::v3::table::is_homogeneous(DW_TAG_enumeration_typenode_type, const node *&) for nested tables
                const toml::node* nested_first_nonmatch_node = nullptr;
                nested_table->is_homogeneous(toml::node_type::string, nested_first_nonmatch_node);
              }
            } else if (element.is_array()) {
              const toml::array* nested_array = element.as_array();
              if (nested_array) {
                nested_array->is_homogeneous(toml::node_type::integer);
                // Added to cover toml::v3::array::is_homogeneous(DW_TAG_enumeration_typenode_type, const node *&) for nested arrays
                const toml::node* nested_first_nonmatch_node = nullptr;
                nested_array->is_homogeneous(toml::node_type::integer, nested_first_nonmatch_node);
              }
            } else if (element.is_value()) {
                // Added to cover toml::v3::value<T>::is_homogeneous(DW_TAG_enumeration_typenode_type, const node *&)
                const toml::node* value_first_nonmatch_node = nullptr;
                element.is_homogeneous(toml::node_type::string, value_first_nonmatch_node);
                element.is_homogeneous(toml::node_type::integer, value_first_nonmatch_node);
                element.is_homogeneous(toml::node_type::floating_point, value_first_nonmatch_node);
                element.is_homogeneous(toml::node_type::boolean, value_first_nonmatch_node);
                element.is_homogeneous(toml::node_type::date, value_first_nonmatch_node);
                element.is_homogeneous(toml::node_type::time, value_first_nonmatch_node);
                element.is_homogeneous(toml::node_type::date_time, value_first_nonmatch_node);
            }
          }
        }
      } else if (node.is_value()) {
        // 4. Exercise `toml::node::as_X()` methods on individual value nodes:
        // Attempt to cast the value node to various TOML value types.
        node.as_string();
        node.as_integer();
        node.as_floating_point();
        node.as_boolean();
        node.as_date();
        node.as_time();
        node.as_date_time();

        // Added to cover toml::v3::value<T>::is_homogeneous(DW_TAG_enumeration_typenode_type, const node *&)
        const toml::node* value_first_nonmatch_node = nullptr;
        node.is_homogeneous(toml::node_type::string, value_first_nonmatch_node);
        node.is_homogeneous(toml::node_type::integer, value_first_nonmatch_node);
        node.is_homogeneous(toml::node_type::floating_point, value_first_nonmatch_node);
        node.is_homogeneous(toml::node_type::boolean, value_first_nonmatch_node);
        node.is_homogeneous(toml::node_type::date, value_first_nonmatch_node);
        node.is_homogeneous(toml::node_type::time, value_first_nonmatch_node);
        node.is_homogeneous(toml::node_type::date_time, value_first_nonmatch_node);
      }
    }

    // --- Start of new modifications for improved coverage ---

    // Explicitly create and exercise different toml::value types to hit their as_X() methods and destructors.
    // This targets the 0% coverage for toml::v3::value<T>::as_X() and toml::v3::value<T>::~value() functions.

    // Generate a random string
    std::string random_string = fdp.ConsumeRandomLengthString(100);
    // Create a toml::value<string> and exercise its as_string() method
    toml::value<std::string> string_val(random_string); // Memory managed by RAII
    string_val.as_string(); // Call as_string() on the value itself
    // Call is_homogeneous on the value, targeting both true and false branches
    const toml::node* string_first_nonmatch_node = nullptr;
    string_val.is_homogeneous(toml::node_type::string, string_first_nonmatch_node);
    string_val.is_homogeneous(toml::node_type::integer, string_first_nonmatch_node);

    // Generate a random integer
    long long random_integer = fdp.ConsumeIntegral<long long>();
    // Create a toml::value<long> and exercise its as_integer() method
    toml::value<long> integer_val(random_integer); // Memory managed by RAII
    integer_val.as_integer(); // Call as_integer() on the value itself
    // Call is_homogeneous on the value, targeting both true and false branches
    const toml::node* integer_first_nonmatch_node = nullptr;
    integer_val.is_homogeneous(toml::node_type::integer, integer_first_nonmatch_node);
    integer_val.is_homogeneous(toml::node_type::string, integer_first_nonmatch_node);

    // Generate a random double
    double random_double = fdp.ConsumeFloatingPoint<double>();
    // Create a toml::value<double> and exercise its as_floating_point() method
    toml::value<double> double_val(random_double); // Memory managed by RAII
    double_val.as_floating_point(); // Call as_floating_point() on the value itself
    // Call is_homogeneous on the value, targeting both true and false branches
    const toml::node* double_first_nonmatch_node = nullptr;
    double_val.is_homogeneous(toml::node_type::floating_point, double_first_nonmatch_node);
    double_val.is_homogeneous(toml::node_type::boolean, double_first_nonmatch_node);

    // Generate a random boolean
    bool random_boolean = fdp.ConsumeBool();
    // Create a toml::value<bool> and exercise its as_boolean() method
    toml::value<bool> boolean_val(random_boolean); // Memory managed by RAII
    boolean_val.as_boolean(); // Call as_boolean() on the value itself
    // Call is_homogeneous on the value, targeting both true and false branches
    const toml::node* boolean_first_nonmatch_node = nullptr;
    boolean_val.is_homogeneous(toml::node_type::boolean, boolean_first_nonmatch_node);
    boolean_val.is_homogeneous(toml::node_type::date, boolean_first_nonmatch_node);

    // Generate random date components
    uint16_t year = fdp.ConsumeIntegralInRange<uint16_t>(1900, 2100);
    uint8_t month = fdp.ConsumeIntegralInRange<uint8_t>(1, 12);
    uint8_t day = fdp.ConsumeIntegralInRange<uint8_t>(1, 28); // Keep day low to avoid invalid dates
    toml::date random_date(year, month, day);
    // Create a toml::value<date> and exercise its as_date() method
    toml::value<toml::date> date_val(random_date); // Memory managed by RAII
    date_val.as_date(); // Call as_date() on the value itself
    // Call is_homogeneous on the value, targeting both true and false branches
    const toml::node* date_first_nonmatch_node = nullptr;
    date_val.is_homogeneous(toml::node_type::date, date_first_nonmatch_node);
    date_val.is_homogeneous(toml::node_type::time, date_first_nonmatch_node);

    // Generate random time components
    uint8_t hour = fdp.ConsumeIntegralInRange<uint8_t>(0, 23);
    uint8_t minute = fdp.ConsumeIntegralInRange<uint8_t>(0, 59);
    uint8_t second = fdp.ConsumeIntegralInRange<uint8_t>(0, 59);
    uint32_t nanosecond = fdp.ConsumeIntegralInRange<uint32_t>(0, 999999999);
    toml::time random_time(hour, minute, second, nanosecond);
    // Create a toml::value<time> and exercise its as_time() method
    toml::value<toml::time> time_val(random_time); // Memory managed by RAII
    time_val.as_time(); // Call as_time() on the value itself
    // Call is_homogeneous on the value, targeting both true and false branches
    const toml::node* time_first_nonmatch_node = nullptr;
    time_val.is_homogeneous(toml::node_type::time, time_first_nonmatch_node);
    time_val.is_homogeneous(toml::node_type::floating_point, time_first_nonmatch_node);

    // Generate random date_time components
    toml::date_time random_date_time(random_date, random_time);
    // Create a toml::value<date_time> and exercise its as_date_time() method
    toml::value<toml::date_time> datetime_val(random_date_time); // Memory managed by RAII
    datetime_val.as_date_time(); // Call as_date_time() on the value itself
    // Call is_homogeneous on the value, targeting both true and false branches
    const toml::node* datetime_first_nonmatch_node = nullptr;
    datetime_val.is_homogeneous(toml::node_type::date_time, datetime_first_nonmatch_node);
    datetime_val.is_homogeneous(toml::node_type::string, datetime_first_nonmatch_node);

    // --- End of new modifications ---

  } catch (const toml::parse_error& err) {
    // It is expected that `toml::parse()` will throw `toml::parse_error`
    // for malformed or invalid TOML inputs. Catching this exception
    // gracefully prevents the fuzzer from crashing and allows it to
    // continue exploring other inputs. No further action is needed here.
  } catch (const std::exception& e) {
    // Catch any other standard exceptions that might occur during processing
    // to ensure the fuzzer remains robust and does not crash.
    // This catch block is intended to be covered by fuzzer exploration of diverse inputs.
  }

  // Memory Management:
  // The `tomlplusplus` library is designed with C++ best practices,
  // heavily utilizing RAII (Resource Acquisition Is Initialization) and
  // smart pointers (like `std::unique_ptr`) internally for managing
  // memory and other resources.
  //
  // The `toml::table` object `parsed_toml` (and any nested `toml::array`
  // or `toml::value` objects) will be automatically destructed and their
  // associated memory deallocated when they go out of scope at the end
  // of the `LLVMFuzzerTestOneInput` function.
  //
  // Therefore, explicit memory deallocation calls (e.g., `delete` or `free`)
  // are not required in this fuzz target, ensuring memory safety.

  return 0; // Indicate successful execution to the fuzzer.
}