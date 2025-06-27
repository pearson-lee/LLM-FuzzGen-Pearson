#include <cstddef>
#include <cstdint>
#include <string>
#include <vector>
#include <fuzzer/FuzzedDataProvider.h>
#include <memory> // For std::unique_ptr
#include <cmath> // For fabs in cJSON_Compare tests
#include <algorithm> // For std::max

// Include the cJSON header
#include "/src/cjson/cJSON.h"

// Custom deleter for cJSON items
struct CJSONDeleter {
    void operator()(cJSON* item) const {
        cJSON_Delete(item);
    }
};

// Custom deleter for strings allocated by cJSON_Print*
struct CJSONFreeDeleter {
    void operator()(char* str) const {
        cJSON_free(str);
    }
};

// Helper function to create a random cJSON item
std::unique_ptr<cJSON, CJSONDeleter> CreateRandomCJSONItem(FuzzedDataProvider& fdp, std::vector<std::string>& string_storage) {
    const int item_type = fdp.ConsumeIntegralInRange<int>(0, 7);
    std::unique_ptr<cJSON, CJSONDeleter> item = nullptr;

    switch (item_type) {
        case 0: item.reset(cJSON_CreateNull()); break;
        case 1: item.reset(cJSON_CreateTrue()); break;
        case 2: item.reset(cJSON_CreateFalse()); break;
        case 3: item.reset(cJSON_CreateNumber(fdp.ConsumeFloatingPoint<double>())); break;
        case 4: {
            string_storage.push_back(fdp.ConsumeRandomLengthString());
            item.reset(cJSON_CreateString(string_storage.back().c_str()));
            break;
        }
        case 5: item.reset(cJSON_CreateArray()); break;
        case 6: item.reset(cJSON_CreateObject()); break;
        case 7: {
            string_storage.push_back(fdp.ConsumeRandomLengthString());
            item.reset(cJSON_CreateRaw(string_storage.back().c_str()));
            break;
        }
    }
    return item;
}


extern "C" int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size) {
    FuzzedDataProvider fdp(Data, Size);

    // Use a switch to call different APIs based on fuzzer data to ensure diversity.
    // Increased range to cover new test cases identified from coverage reports.
    // Increased range to 12 to include new test cases.
    const int api_choice = fdp.ConsumeIntegralInRange<int>(0, 12);

    // Create a base JSON item to be used by some functions.
    // Use unique_ptr for automatic memory management.
    std::unique_ptr<cJSON, CJSONDeleter> base_item = nullptr;

    // Vectors to hold string data for keys and array elements to ensure their lifetime
    // extends beyond the loop iteration where they are created.
    std::vector<std::string> object_keys;
    std::vector<std::string> array_strings;


    // Create a base item with varied structure and types if needed by the chosen API.
    // This block is for APIs that operate on an existing item.
    // Cases 3, 6, 7, 8, 9, 10, 11, 12 create items specifically within their blocks.
    if (api_choice == 0 || api_choice == 1 || api_choice == 2 || api_choice == 4) {
         const int base_item_type = fdp.ConsumeIntegralInRange<int>(0, 7);
         switch (base_item_type) {
             case 0: base_item.reset(cJSON_CreateNull()); break;
             case 1: base_item.reset(cJSON_CreateTrue()); break;
             case 2: base_item.reset(cJSON_CreateFalse()); break;
             case 3: base_item.reset(cJSON_CreateNumber(fdp.ConsumeFloatingPoint<double>())); break;
             case 4: {
                 std::string s = fdp.ConsumeRandomLengthString();
                 base_item.reset(cJSON_CreateString(s.c_str()));
                 break;
             }
             case 5: base_item.reset(cJSON_CreateArray()); break;
             case 6: base_item.reset(cJSON_CreateObject()); break;
             case 7: {
                 std::string r = fdp.ConsumeRandomLengthString();
                 base_item.reset(cJSON_CreateRaw(r.c_str()));
                 break;
             }
         }

         // Populate arrays/objects if created to increase complexity, relevant for Print, Duplicate, Compare.
         if (base_item && ((base_item->type & 0xFF) == cJSON_Array || (base_item->type & 0xFF) == cJSON_Object)) {
             int num_elements = fdp.ConsumeIntegralInRange<int>(0, 10); // Keep this limit reasonable
             if ((base_item->type & 0xFF) == cJSON_Array) {
                 array_strings.reserve(num_elements); // Reserve space to avoid reallocations
                 for (int i = 0; i < num_elements; ++i) {
                     const int element_type = fdp.ConsumeIntegralInRange<int>(0, 3);
                     cJSON* element = nullptr;
                     switch (element_type) {
                         case 0: element = cJSON_CreateNull(); break;
                         case 1: element = cJSON_CreateNumber(fdp.ConsumeFloatingPoint<double>()); break;
                         case 2: {
                             array_strings.push_back(fdp.ConsumeRandomLengthString(20));
                             element = cJSON_CreateString(array_strings.back().c_str());
                             break;
                         }
                         case 3: element = cJSON_CreateBool(fdp.ConsumeBool()); break;
                     }
                     if (element) {
                         // cJSON_AddItemToArray takes ownership of the element
                         cJSON_AddItemToArray(base_item.get(), element);
                     }
                 }
             } else { // cJSON_Object
                  object_keys.reserve(num_elements); // Reserve space to avoid reallocations
                  array_strings.reserve(num_elements); // Reserve space for string values in objects
                  for (int i = 0; i < num_elements; ++i) {
                     object_keys.push_back(fdp.ConsumeRandomLengthString(20));
                     const int element_type = fdp.ConsumeIntegralInRange<int>(0, 3);
                     cJSON* element = nullptr;
                     switch (element_type) {
                         case 0: element = cJSON_CreateNull(); break;
                         case 1: element = cJSON_CreateNumber(fdp.ConsumeFloatingPoint<double>()); break;
                         case 2: {
                             array_strings.push_back(fdp.ConsumeRandomLengthString(20));
                             element = cJSON_CreateString(array_strings.back().c_str());
                             break;
                         }
                         case 3: element = cJSON_CreateBool(fdp.ConsumeBool()); break;
                     }
                     if (element) {
                         // Use AddItemToObjectCS to cover case-sensitive version too.
                         // cJSON_AddItemToObjectCS takes ownership of the element.
                         // Pass c_str() from the string stored in object_keys.
                         cJSON_AddItemToObjectCS(base_item.get(), object_keys.back().c_str(), element);
                     }
                 }
             }
         }
    }


    switch (api_choice) {
        case 0: {
            // Fuzz cJSON_ParseWithLengthOpts
            std::string json_string = fdp.ConsumeRemainingBytesAsString();
            // Ensure json_string is null-terminated as expected by cJSON functions
            // cJSON_ParseWithLengthOpts handles non-null-terminated strings if require_null_terminated is false,
            // but adding null terminator here simplifies things and is harmless.
            if (!json_string.empty() && json_string.back() != '\0') {
                 json_string += '\0';
            } else if (json_string.empty()) {
                 json_string += '\0'; // Ensure at least a null terminator for empty input
            }

            const char* return_parse_end = nullptr;
            cJSON_bool require_null_terminated = fdp.ConsumeBool();
            // Pass actual length or a smaller length to test partial parsing
            // Modified to ensure the full length case is hit based on coverage report.
            size_t parse_length;
            if (fdp.ConsumeBool()) {
                parse_length = json_string.length(); // Hit the true branch for full length
            } else {
                parse_length = fdp.ConsumeIntegralInRange<size_t>(0, json_string.length()); // Hit the false branch for partial length
            }

            // Parse the string. The returned item is managed by unique_ptr.
            std::unique_ptr<cJSON, CJSONDeleter> parsed_item(
                cJSON_ParseWithLengthOpts(json_string.c_str(), parse_length, &return_parse_end, require_null_terminated)
            );

            // No explicit deletion needed for parsed_item due to unique_ptr.
            // return_parse_end points into the input string, no memory to free.
            break;
        }
        case 1: {
            // Fuzz cJSON_PrintBuffered (basic case)
            if (base_item) {
                // Test with negative, zero, small, and larger buffer sizes to trigger different paths in ensure.
                int prebuffer_size = fdp.ConsumeIntegralInRange<int>(-10, 4096);
                cJSON_bool format = fdp.ConsumeBool();
                // The returned string is managed by unique_ptr with CJSONFreeDeleter.
                std::unique_ptr<char, CJSONFreeDeleter> printed_string(
                    cJSON_PrintBuffered(base_item.get(), prebuffer_size, format)
                );
                // printed_string will be automatically freed when it goes out of scope.
            }
            break;
        }
        case 2: {
            // Fuzz cJSON_Duplicate (basic case)
            if (base_item) {
                cJSON_bool recurse = fdp.ConsumeBool();
                // The duplicated item is managed by unique_ptr.
                std::unique_ptr<cJSON, CJSONDeleter> duplicated_item(
                    cJSON_Duplicate(base_item.get(), recurse)
                );
                // duplicated_item will be automatically freed.
            }
            break;
        }
        case 3: {
            // Fuzz cJSON_CreateStringArray
            int count = fdp.ConsumeIntegralInRange<int>(0, 20);
            std::vector<std::string> strings_vec; // Manages string data
            strings_vec.reserve(count); // Reserve space to avoid reallocations

            // Option to include NULL strings in the array
            bool include_null = fdp.ConsumeBool();

            // Populate the vector of strings.
            for (int i = 0; i < count; ++i) {
                if (include_null && fdp.ConsumeBool()) {
                    strings_vec.push_back(""); // Placeholder for potential nullptr
                } else {
                    strings_vec.push_back(fdp.ConsumeRandomLengthString(50));
                }
            }

            // Create the vector of const char* pointers from the stable strings_vec.
            std::vector<const char*> strings_c_ptr;
            strings_c_ptr.reserve(count);
            for (int i = 0; i < count; ++i) {
                 // If include_null is true, the string is empty (our placeholder),
                 // and fuzzer data says so, use nullptr. Otherwise, use the c_str().
                 // Note: The fdp.ConsumeBool() here is to add randomness to whether a null is included
                 // even if include_null is true.
                 if (include_null && strings_vec[i].empty() && fdp.ConsumeBool()) {
                     strings_c_ptr.push_back(nullptr);
                 } else {
                     strings_c_ptr.push_back(strings_vec[i].c_str());
                 }
            }

            // Create the string array. The returned item is managed by unique_ptr.
            std::unique_ptr<cJSON, CJSONDeleter> string_array_item(
                cJSON_CreateStringArray(strings_c_ptr.data(), count)
            );
            // string_array_item will be automatically freed.
            // strings_vec ensures the underlying string data remains valid during the call to cJSON_CreateStringArray.
            break;
        }
        case 4: {
            // Fuzz cJSON_SetValuestring (basic case)
            // Need a cJSON item that can have a string value. Create a string item.
            std::unique_ptr<cJSON, CJSONDeleter> string_item(cJSON_CreateString("initial"));
            if (string_item) {
                std::string new_value_string = fdp.ConsumeRandomLengthString();
                // Test setting with a new string or with NULL
                const char* value_to_set = fdp.ConsumeBool() ? nullptr : new_value_string.c_str();
                cJSON_SetValuestring(string_item.get(), value_to_set);
            }
            // string_item will be automatically freed.
            break;
        }
        case 5: {
            // Fuzz cJSON_PrintBuffered with small prebuffer to hit reallocation in ensure.
            // Based on coverage report for ensure, lines related to buffer resizing are missed.
            // Removed the if (!base_item) check to ensure this block always creates a new item
            // specifically for testing PrintBuffered reallocation.
            // if (!base_item) { // Removed based on coverage analysis
                 // Ensure base_item is created for this case if it wasn't already.
                 // Create a potentially large item to force reallocation.
                 base_item.reset(cJSON_CreateObject());
                 if (base_item) {
                     // Reduced the max number of elements to reduce complexity and potential for timeout/memory issues
                     int num_elements = fdp.ConsumeIntegralInRange<int>(10, 30); // Fewer elements than 100
                     object_keys.reserve(num_elements);
                     array_strings.reserve(num_elements);
                     for (int i = 0; i < num_elements; ++i) {
                         object_keys.push_back(fdp.ConsumeRandomLengthString(10)); // Short keys
                         array_strings.push_back(fdp.ConsumeRandomLengthString(50)); // Longer values
                         std::unique_ptr<cJSON, CJSONDeleter> element(cJSON_CreateString(array_strings.back().c_str()));
                         if (element) {
                             cJSON_AddItemToObjectCS(base_item.get(), object_keys.back().c_str(), element.release()); // AddItem takes ownership
                         }
                     }
                 }
            // } // Removed based on coverage analysis

            if (base_item) {
                // Use a very small prebuffer size to force reallocation.
                int prebuffer_size = fdp.ConsumeIntegralInRange<int>(0, 5); // Small buffer
                cJSON_bool format = fdp.ConsumeBool();
                std::unique_ptr<char, CJSONFreeDeleter> printed_string(
                    cJSON_PrintBuffered(base_item.get(), prebuffer_size, format)
                );
            }
            // base_item and printed_string are automatically freed.
            break;
        }
        case 6: {
            // Fuzz cJSON_Duplicate with empty object/array and recurse=true.
            // Based on coverage report for cJSON_Duplicate/copy_helper, duplicating empty items with recurse=true is missed.
            std::unique_ptr<cJSON, CJSONDeleter> empty_item = nullptr;
            if (fdp.ConsumeBool()) {
                empty_item.reset(cJSON_CreateObject());
            } else {
                empty_item.reset(cJSON_CreateArray());
            }

            if (empty_item) {
                // Duplicate an empty item with recurse set to true.
                cJSON_bool recurse = cJSON_True; // Specifically test recurse=true
                std::unique_ptr<cJSON, CJSONDeleter> duplicated_item(
                    cJSON_Duplicate(empty_item.get(), recurse)
                );
            }
            // empty_item and duplicated_item are automatically freed.
            break;
        }
        case 7: {
            // Fuzz cJSON_SetValuestring edge cases.
            // Based on coverage report for cJSON_SetValuestring, NULL item, non-string item, and setting NULL on NULL valuestring are missed.

            // Test with NULL item
            cJSON_SetValuestring(nullptr, "test"); // Should hit NULL item check

            // Test with non-string items
            std::vector<std::string> temp_strings; // For CreateRandomCJSONItem
            std::unique_ptr<cJSON, CJSONDeleter> non_string_item = CreateRandomCJSONItem(fdp, temp_strings);
            // Ensure it's not a string item for this test
            // Add a safety break to prevent infinite loops if fuzzer only provides data for strings
            int attempts = 0;
            while(non_string_item && (non_string_item->type & 0xFF) == cJSON_String && attempts < 10) {
                 non_string_item = CreateRandomCJSONItem(fdp, temp_strings);
                 attempts++;
            }
            if (non_string_item && (non_string_item->type & 0xFF) != cJSON_String) {
                 cJSON_SetValuestring(non_string_item.get(), "test"); // Should hit non-string type check
            }

            // Test setting NULL on a string item that already has NULL valuestring
            // Based on coverage, cJSON_CreateString(nullptr) returns NULL.
            // Manually create a string item and set its valuestring to NULL to hit the target branch.
            std::unique_ptr<cJSON, CJSONDeleter> null_valuestring_item(cJSON_CreateString("initial"));
            if (null_valuestring_item) {
                cJSON_free(null_valuestring_item->valuestring); // Free the initial string
                null_valuestring_item->valuestring = nullptr; // Manually set valuestring to NULL
                cJSON_SetValuestring(null_valuestring_item.get(), nullptr); // Should hit NULL value on NULL valuestring branch
            }

            // non_string_item and null_string_item are automatically freed.
            break;
        }
        case 8: {
            // Fuzz cJSON_Compare edge cases.
            // Based on coverage report for cJSON_Compare, NULL inputs, different types, and comparing the same item are missed.

            cJSON_bool case_sensitive = fdp.ConsumeBool();

            // Test with NULL inputs
            cJSON_Compare(nullptr, nullptr, case_sensitive); // Should hit (a == NULL) || (b == NULL)
            std::vector<std::string> temp_strings1;
            std::unique_ptr<cJSON, CJSONDeleter> item1 = CreateRandomCJSONItem(fdp, temp_strings1);
            if (item1) {
                cJSON_Compare(item1.get(), nullptr, case_sensitive); // Should hit (a == NULL) || (b == NULL)
                cJSON_Compare(nullptr, item1.get(), case_sensitive); // Should hit (a == NULL) || (b == NULL)
            }

            // Test with different types
            std::vector<std::string> temp_strings2;
            std::unique_ptr<cJSON, CJSONDeleter> item2 = CreateRandomCJSONItem(fdp, temp_strings2);
             // Ensure item1 and item2 are different types for this test
            int attempts = 0;
            while(item1 && item2 && (item1->type & 0xFF) == (item2->type & 0xFF) && attempts < 10) {
                 item2 = CreateRandomCJSONItem(fdp, temp_strings2);
                 attempts++;
            }
            if (item1 && item2 && (item1->type & 0xFF) != (item2->type & 0xFF)) {
                 cJSON_Compare(item1.get(), item2.get(), case_sensitive); // Should hit type mismatch check
            }

            // Test with the same item
            if (item1) {
                 cJSON_Compare(item1.get(), item1.get(), case_sensitive); // Should hit a == b check
            }

            // Test with same type, different values/structures (covered by existing base_item creation and random values)
            // No specific action needed here beyond ensuring base_item is created and varied.

            // item1 and item2 are automatically freed.
            break;
        }
        case 9: {
            // Fuzz cJSON_InsertItemInArray edge cases.
            // Based on coverage report for cJSON_InsertItemInArray, invalid/edge indices are missed.

            std::unique_ptr<cJSON, CJSONDeleter> array_item(cJSON_CreateArray());
            if (!array_item) break;

            // Populate the array with some items first
            std::vector<std::string> temp_strings;
            int initial_count = fdp.ConsumeIntegralInRange<int>(0, 10);
            for (int i = 0; i < initial_count; ++i) {
                std::unique_ptr<cJSON, CJSONDeleter> element = CreateRandomCJSONItem(fdp, temp_strings);
                if (element) {
                    cJSON_AddItemToArray(array_item.get(), element.release()); // AddItem takes ownership
                }
            }

            std::unique_ptr<cJSON, CJSONDeleter> item_to_insert = CreateRandomCJSONItem(fdp, temp_strings);
            if (!item_to_insert) break;

            int array_size = cJSON_GetArraySize(array_item.get());

            // Choose an index strategy
            const int index_choice = fdp.ConsumeIntegralInRange<int>(0, 4);
            int index_to_use;

            switch (index_choice) {
                case 0: index_to_use = fdp.ConsumeIntegralInRange<int>(-10, -1); break; // Negative index
                case 1: index_to_use = fdp.ConsumeIntegralInRange<int>(array_size + 1, array_size + 10); break; // Index > count
                case 2: index_to_use = 0; break; // Index == 0 (beginning)
                case 3: index_to_use = array_size; break; // Index == count (end)
                case 4: index_to_use = fdp.ConsumeIntegralInRange<int>(1, std::max(1, array_size - 1)); break; // 0 < index < count (middle)
            }

            // cJSON_InsertItemInArray takes ownership of item_to_insert on success.
            // If it fails, we need to manually delete item_to_insert.
            cJSON* inserted_item_ptr = item_to_insert.release(); // Release ownership from unique_ptr
            cJSON_bool success = cJSON_InsertItemInArray(array_item.get(), index_to_use, inserted_item_ptr);

            // If insertion failed, delete the item that was not inserted.
            if (!success) {
                cJSON_Delete(inserted_item_ptr);
            }

            // array_item is automatically freed.
            break;
        }
        case 10: {
            // Fuzz cJSON_Create*Array with NULL data and negative count.
            // Based on coverage report for cJSON_CreateIntArray/FloatArray/DoubleArray,
            // the NULL data and negative count checks are missed.
            int count = fdp.ConsumeIntegralInRange<int>(-10, 0); // Negative or zero count
            std::unique_ptr<cJSON, CJSONDeleter> int_array_item(cJSON_CreateIntArray(nullptr, count)); // Test NULL data and negative count
            std::unique_ptr<cJSON, CJSONDeleter> float_array_item(cJSON_CreateFloatArray(nullptr, count)); // Test NULL data and negative count
            std::unique_ptr<cJSON, CJSONDeleter> double_array_item(cJSON_CreateDoubleArray(nullptr, count)); // Test NULL data and negative count

            // Also test with valid data but negative count
            std::vector<int> int_data = {1, 2, 3};
            std::unique_ptr<cJSON, CJSONDeleter> int_array_item2(cJSON_CreateIntArray(int_data.data(), -1)); // Test negative count with valid data

            // Items are automatically freed by unique_ptr.
            break;
        }
        case 11: {
            // Fuzz cJSON_Duplicate edge cases related to NULL strings.
            // Based on coverage report for copy_helper, duplicating items with NULL keys or NULL valuestrings is missed.

            // Test duplicating an object with a NULL key
            std::unique_ptr<cJSON, CJSONDeleter> object_with_null_key(cJSON_CreateObject());
            if (object_with_null_key) {
                std::unique_ptr<cJSON, CJSONDeleter> child_item(cJSON_CreateNumber(123));
                if (child_item) {
                    // Manually set the string (key) to NULL
                    child_item->string = nullptr;
                    // Add the item to the object. AddItemToObjectCS handles NULL key.
                    cJSON_AddItemToObjectCS(object_with_null_key.get(), child_item->string, child_item.release()); // AddItem takes ownership
                }
                // Duplicate the object with the NULL key
                std::unique_ptr<cJSON, CJSONDeleter> duplicated_object(cJSON_Duplicate(object_with_null_key.get(), cJSON_True));
            }

            // Test duplicating a string item with a NULL valuestring
            std::unique_ptr<cJSON, CJSONDeleter> string_with_null_value(cJSON_CreateString("initial"));
            if (string_with_null_value) {
                cJSON_free(string_with_null_value->valuestring); // Free the initial string
                string_with_null_value->valuestring = nullptr; // Manually set valuestring to NULL
                // Duplicate the string item with NULL valuestring
                std::unique_ptr<cJSON, CJSONDeleter> duplicated_string(cJSON_Duplicate(string_with_null_value.get(), cJSON_False)); // recurse doesn't matter for string
            }

            // Items are automatically freed by unique_ptr.
            break;
        }
        case 12: {
            // Fuzz cJSON_Compare with non-equal arrays/objects and raw items with NULL valuestrings.
            // Based on coverage report for cJSON_Compare, comparing non-equal arrays/objects and raw items with NULL valuestrings is missed.

            cJSON_bool case_sensitive = fdp.ConsumeBool();
            std::vector<std::string> temp_strings;

            // Test comparing arrays with different sizes
            std::unique_ptr<cJSON, CJSONDeleter> array1(cJSON_CreateArray());
            std::unique_ptr<cJSON, CJSONDeleter> array2(cJSON_CreateArray());
            if (array1 && array2) {
                cJSON_AddItemToArray(array1.get(), cJSON_CreateNumber(1));
                cJSON_Compare(array1.get(), array2.get(), case_sensitive); // Different sizes
            }

            // Test comparing arrays with same size but different elements
            std::unique_ptr<cJSON, CJSONDeleter> array3(cJSON_CreateArray());
            std::unique_ptr<cJSON, CJSONDeleter> array4(cJSON_CreateArray());
            if (array3 && array4) {
                cJSON_AddItemToArray(array3.get(), cJSON_CreateNumber(1));
                cJSON_AddItemToArray(array4.get(), cJSON_CreateNumber(2));
                cJSON_Compare(array3.get(), array4.get(), case_sensitive); // Same size, different elements
            }

            // Test comparing objects with different sizes
            std::unique_ptr<cJSON, CJSONDeleter> object1(cJSON_CreateObject());
            std::unique_ptr<cJSON, CJSONDeleter> object2(cJSON_CreateObject());
            if (object1 && object2) {
                cJSON_AddItemToObject(object1.get(), "a", cJSON_CreateNumber(1));
                cJSON_Compare(object1.get(), object2.get(), case_sensitive); // Different sizes
            }

            // Test comparing objects with same size but different keys/values
            std::unique_ptr<cJSON, CJSONDeleter> object3(cJSON_CreateObject());
            std::unique_ptr<cJSON, CJSONDeleter> object4(cJSON_CreateObject());
            if (object3 && object4) {
                cJSON_AddItemToObject(object3.get(), "a", cJSON_CreateNumber(1));
                cJSON_AddItemToObject(object4.get(), "b", cJSON_CreateNumber(1)); // Different key
                cJSON_Compare(object3.get(), object4.get(), case_sensitive);

                cJSON_Delete(object3.release()); // Free previous object3
                cJSON_Delete(object4.release()); // Free previous object4

                object3.reset(cJSON_CreateObject());
                object4.reset(cJSON_CreateObject());
                 if (object3 && object4) {
                    cJSON_AddItemToObject(object3.get(), "a", cJSON_CreateNumber(1));
                    cJSON_AddItemToObject(object4.get(), "a", cJSON_CreateNumber(2)); // Different value
                    cJSON_Compare(object3.get(), object4.get(), case_sensitive);
                 }
            }

            // Test comparing Raw items with NULL valuestrings
            std::unique_ptr<cJSON, CJSONDeleter> raw1(cJSON_CreateRaw("initial"));
            std::unique_ptr<cJSON, CJSONDeleter> raw2(cJSON_CreateRaw("initial"));
            if (raw1 && raw2) {
                cJSON_free(raw1->valuestring);
                raw1->valuestring = nullptr;
                cJSON_free(raw2->valuestring);
                raw2->valuestring = nullptr;
                cJSON_Compare(raw1.get(), raw2.get(), case_sensitive); // Both NULL valuestring
            }
             std::unique_ptr<cJSON, CJSONDeleter> raw3(cJSON_CreateRaw("initial"));
             std::unique_ptr<cJSON, CJSONDeleter> raw4(cJSON_CreateRaw("initial"));
             if (raw3 && raw4) {
                cJSON_free(raw3->valuestring);
                raw3->valuestring = nullptr;
                cJSON_Compare(raw3.get(), raw4.get(), case_sensitive); // One NULL, one non-NULL
             }


            // Items are automatically freed by unique_ptr.
            break;
        }
    }

    // All allocated cJSON items and printed strings are managed by unique_ptr
    // and will be freed automatically when they go out of scope at the end of the function.
    // object_keys and array_strings vectors also go out of scope here,
    // deallocating the string data they hold.

    return 0;
}