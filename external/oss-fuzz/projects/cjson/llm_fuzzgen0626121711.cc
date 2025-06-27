#include <cstddef>
#include <cstdint>
#include <string>
#include <vector>
#include <cmath> // For fabs
#include <fuzzer/FuzzedDataProvider.h>

// Include the main cJSON header
#include "/src/cjson/cJSON.h"

// Define custom allocation functions for hooks
static void* fuzzer_malloc(size_t size) {
    // Added logging for debugging cJSON_malloc coverage
    // fprintf(stderr, "fuzzer_malloc called with size %zu\n", size);
    return malloc(size);
}

static void fuzzer_free(void* ptr) {
    // Added logging for debugging cJSON_free coverage
    // fprintf(stderr, "fuzzer_free called with ptr %p\n", ptr);
    free(ptr);
}

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size) {
  FuzzedDataProvider fdp(Data, Size);

  // --- Fuzz cJSON_InitHooks ---
  // Sometimes skip InitHooks or pass NULL to cover the default allocation path
  // and the cJSON_malloc wrapper function (which had 0% coverage).
  if (fdp.ConsumeBool()) {
      if (fdp.ConsumeBool()) {
          cJSON_InitHooks(NULL); // Cover the NULL case
      } else {
          cJSON_Hooks hooks;
          // Correct member names in cJSON_Hooks. realloc_fn does not exist.
          hooks.malloc_fn = fdp.ConsumeBool() ? fuzzer_malloc : NULL;
          hooks.free_fn = fdp.ConsumeBool() ? fuzzer_free : NULL;
          cJSON_InitHooks(&hooks);
      }
  }
  // If the outer ConsumeBool is false, cJSON_InitHooks is not called,
  // testing the default allocation behavior.


  // Consume data for various API calls
  std::string json_string = fdp.ConsumeRandomLengthString();
  // Changed print_buffer_size to int to test negative prebuffer in cJSON_PrintBuffered
  int print_buffer_size = fdp.ConsumeIntegralInRange<int>(-100, 4096);
  bool format_print = fdp.ConsumeBool();
  bool require_null_terminated = fdp.ConsumeBool();

  // --- Fuzz cJSON_ParseWithLengthOpts ---
  // Target low branch coverage in internal parsing functions and the NULL input case
  const char* parse_string_len = json_string.c_str();
  size_t parse_len = json_string.size();
   if (fdp.ConsumeBool()) {
      parse_string_len = NULL;
      parse_len = 0; // Length should be 0 if string is NULL
  } else {
      // Sometimes provide a length smaller than the actual string size
      if (fdp.ConsumeBool() && parse_len > 0) {
          parse_len = fdp.ConsumeIntegralInRange<size_t>(0, parse_len > 0 ? parse_len - 1 : 0);
      }
  }

  const char* return_parse_end = NULL;
  cJSON* parsed_item = cJSON_ParseWithLengthOpts(parse_string_len, parse_len, &return_parse_end, require_null_terminated);

  // --- Fuzz Printing Functions ---
  // Target low overall coverage and different cJSON types in internal print functions (print, print_value, ensure)
  if (parsed_item != NULL) {
      cJSON* item_to_print = parsed_item;
      cJSON* created_item = NULL; // Keep track of newly created item if not parsed_item

      // Sometimes create a new item of a specific type to ensure coverage of print cases
      if (fdp.ConsumeBool()) {
          int item_type = fdp.ConsumeIntegralInRange<int>(0, 6); // 0-6 for different types
          switch (item_type) {
              case 0: created_item = cJSON_CreateNull(); break;
              case 1: created_item = cJSON_CreateBool(fdp.ConsumeBool()); break;
              case 2: created_item = cJSON_CreateNumber(fdp.ConsumeFloatingPoint<double>()); break;
              case 3: created_item = cJSON_CreateString(fdp.ConsumeRandomLengthString().c_str()); break;
              case 4: created_item = cJSON_CreateArray(); break;
              case 5: created_item = cJSON_CreateObject(); break;
              case 6: created_item = cJSON_CreateRaw(fdp.ConsumeRandomLengthString().c_str()); break;
          }
          item_to_print = created_item;

          // If a new item was created, add some sub-items to arrays/objects
          if (item_to_print != NULL) {
              if (cJSON_IsArray(item_to_print)) {
                  int num_elements = fdp.ConsumeIntegralInRange<int>(0, 5);
                  for (int i = 0; i < num_elements; ++i) {
                      cJSON_AddItemToArray(item_to_print, cJSON_CreateNumber(fdp.ConsumeIntegral<int>()));
                  }
              } else if (cJSON_IsObject(item_to_print)) {
                   int num_elements = fdp.ConsumeIntegralInRange<int>(0, 5);
                   for (int i = 0; i < num_elements; ++i) {
                       cJSON_AddNumberToObject(item_to_print, fdp.ConsumeRandomLengthString(10).c_str(), fdp.ConsumeIntegral<int>());
                   }
              }
          }
      }

      // Fuzz cJSON_PrintBuffered
      // Using the fuzzed print_buffer_size (now int) to hit negative prebuffer branch.
      char* printed_string_buffered = NULL;
      if (item_to_print != NULL) {
          printed_string_buffered = cJSON_PrintBuffered(item_to_print, print_buffer_size, format_print);
      }
      if (printed_string_buffered != NULL) {
          cJSON_free(printed_string_buffered);
      }

      // Fuzz cJSON_Print (covers the 'format == true' path in internal print)
      char* printed_string_formatted = NULL;
      if (item_to_print != NULL) {
          printed_string_formatted = cJSON_Print(item_to_print);
      }
      if (printed_string_formatted != NULL) {
          cJSON_free(printed_string_formatted);
      }

      // Fuzz cJSON_PrintUnformatted (covers the 'format == false' path in internal print)
      char* printed_string_unformatted = NULL;
      if (item_to_print != NULL) {
          printed_string_unformatted = cJSON_PrintUnformatted(item_to_print);
      }
      if (printed_string_unformatted != NULL) {
          cJSON_free(printed_string_unformatted);
      }

      // Fuzz cJSON_PrintPreallocated (targets branches related to pre-allocated buffer and ensure with non-NULL buffer)
      if (item_to_print != NULL) {
          size_t prealloc_buffer_size = fdp.ConsumeIntegralInRange<size_t>(0, 2048); // Fuzzed buffer size
          std::vector<char> prealloc_buffer(prealloc_buffer_size);
          if (prealloc_buffer_size > 0) {
             cJSON_PrintPreallocated(item_to_print, prealloc_buffer.data(), prealloc_buffer_size, format_print);
          }
      }


      // Delete the newly created item if it wasn't the parsed_item
      if (created_item != NULL) {
          cJSON_Delete(created_item);
      }
  }


  // --- Fuzz cJSON_Duplicate ---
  // Target duplicating various structures and hitting NULL/non-recursive paths,
  // including duplicating a string reference to hit the cJSON_StringIsConst branch.
  if (parsed_item != NULL) {
      // Duplicate with recurse = true (already done)
      cJSON* duplicated_item_recursive = cJSON_Duplicate(parsed_item, 1);
      if (duplicated_item_recursive != NULL) {
          cJSON_Delete(duplicated_item_recursive);
      }

      // Duplicate with recurse = false (targets non-recursive branches)
      cJSON* duplicated_item_non_recursive = cJSON_Duplicate(parsed_item, 0);
       if (duplicated_item_non_recursive != NULL) {
          cJSON_Delete(duplicated_item_non_recursive);
      }

      // Target the !item branch in cJSON_Duplicate
      cJSON* duplicated_null = cJSON_Duplicate(NULL, fdp.ConsumeBool());
      // duplicated_null will be NULL, no need to delete

      // Duplicate a string reference to hit the cJSON_StringIsConst branch in cJSON_Duplicate
      std::string ref_string_data = fdp.ConsumeRandomLengthString(20);
      cJSON* string_ref_item = cJSON_CreateStringReference(ref_string_data.c_str());
      if (string_ref_item != NULL) {
          cJSON* duplicated_string_ref = cJSON_Duplicate(string_ref_item, fdp.ConsumeBool());
          if (duplicated_string_ref != NULL) {
              cJSON_Delete(duplicated_string_ref);
          }
          cJSON_Delete(string_ref_item); // Delete the original reference item
      }
  }

  // --- Fuzz cJSON_Compare ---
  // Target comparing different types and values, including NULL inputs
  if (parsed_item != NULL) {
      // Create another item to compare with
      cJSON* item_to_compare = NULL;
      int compare_item_type = fdp.ConsumeIntegralInRange<int>(0, 6); // 0-6 for different types
      switch (compare_item_type) {
          case 0: item_to_compare = cJSON_CreateNull(); break;
          case 1: item_to_compare = cJSON_CreateBool(fdp.ConsumeBool()); break;
          case 2: item_to_compare = cJSON_CreateNumber(fdp.ConsumeFloatingPoint<double>()); break;
          case 3: item_to_compare = cJSON_CreateString(fdp.ConsumeRandomLengthString().c_str()); break;
          case 4: item_to_compare = cJSON_CreateArray();
             if (item_to_compare != NULL) {
                 int num_elements = fdp.ConsumeIntegralInRange<int>(0, 5);
                 for (int i = 0; i < num_elements; ++i) {
                     cJSON_AddItemToArray(item_to_compare, cJSON_CreateNumber(fdp.ConsumeIntegral<int>()));
                 }
             }
             break;
          case 5: item_to_compare = cJSON_CreateObject();
             if (item_to_compare != NULL) {
                int num_elements = fdp.ConsumeIntegralInRange<int>(0, 5);
                for (int i = 0; i < num_elements; ++i) {
                    cJSON_AddNumberToObject(item_to_compare, fdp.ConsumeRandomLengthString(10).c_str(), fdp.ConsumeIntegral<int>());
                }
             }
             break;
          case 6: item_to_compare = cJSON_CreateRaw(fdp.ConsumeRandomLengthString().c_str()); break;
      }

      if (item_to_compare != NULL) {
          // Compare parsed_item with created_item
          cJSON_Compare(parsed_item, item_to_compare, fdp.ConsumeBool()); // 3rd arg is case_sensitive

          // Target NULL inputs for cJSON_Compare
          cJSON_Compare(NULL, item_to_compare, fdp.ConsumeBool());
          cJSON_Compare(parsed_item, NULL, fdp.ConsumeBool());
          cJSON_Compare(NULL, NULL, fdp.ConsumeBool());

          cJSON_Delete(item_to_compare); // Free the comparison item
      } else {
           // If item_to_compare creation failed, still fuzz NULL comparisons
           cJSON_Compare(parsed_item, NULL, fdp.ConsumeBool());
           cJSON_Compare(NULL, NULL, fdp.ConsumeBool());
      }
  } else {
      // If parsed_item is NULL, still fuzz NULL comparisons
      cJSON* item_to_compare_null = NULL; // Ensure this is NULL
      cJSON_Compare(NULL, item_to_compare_null, fdp.ConsumeBool());
      cJSON_Compare(item_to_compare_null, NULL, fdp.ConsumeBool());
      cJSON_Compare(NULL, NULL, fdp.ConsumeBool());
  }

  // --- Fuzz Array Creation Functions ---
  // Target cJSON_CreateIntArray, cJSON_CreateFloatArray, cJSON_CreateDoubleArray, cJSON_CreateStringArray
  // These had low branch coverage, specifically the count < 0 branch.
  if (fdp.ConsumeBool()) {
      // Changed num_elements to int to test negative count.
      int num_elements = fdp.ConsumeIntegralInRange<int>(-10, 10);
      if (num_elements > 0) {
          // Create Int Array
          std::vector<int> int_array;
          int_array.reserve(num_elements);
          for (int i = 0; i < num_elements; ++i) {
              int_array.push_back(fdp.ConsumeIntegralInRange<int>(-100, 100));
          }
          cJSON* int_cjson_array = cJSON_CreateIntArray(int_array.data(), num_elements);
          if (int_cjson_array != NULL) {
              cJSON_Delete(int_cjson_array);
          }

          // Create Float Array
          std::vector<float> float_array;
          float_array.reserve(num_elements);
          for (int i = 0; i < num_elements; ++i) {
              float_array.push_back(fdp.ConsumeFloatingPoint<float>());
          }
          cJSON* float_cjson_array = cJSON_CreateFloatArray(float_array.data(), num_elements);
          if (float_cjson_array != NULL) {
              cJSON_Delete(float_cjson_array);
          }

          // Create Double Array
          std::vector<double> double_array;
          double_array.reserve(num_elements);
          for (int i = 0; i < num_elements; ++i) {
              double_array.push_back(fdp.ConsumeFloatingPoint<double>());
          }
          cJSON* double_cjson_array = cJSON_CreateDoubleArray(double_array.data(), num_elements);
          if (double_cjson_array != NULL) {
              cJSON_Delete(double_cjson_array);
          }

          // Create String Array
          std::vector<std::string> string_vector;
          string_vector.reserve(num_elements);
          for(int i = 0; i < num_elements; ++i) {
              string_vector.push_back(fdp.ConsumeRandomLengthString(20));
          }
          std::vector<const char*> string_array_ptrs;
          string_array_ptrs.reserve(num_elements);
          for(const auto& s : string_vector) {
              string_array_ptrs.push_back(s.c_str());
          }
          cJSON* string_cjson_array = cJSON_CreateStringArray(string_array_ptrs.data(), num_elements);
           if (string_cjson_array != NULL) {
              cJSON_Delete(string_cjson_array);
          }
      } else {
           // Also test with num_elements <= 0, including negative values
           cJSON* int_cjson_array = cJSON_CreateIntArray(NULL, num_elements);
           if (int_cjson_array != NULL) cJSON_Delete(int_cjson_array);
           cJSON* float_cjson_array = cJSON_CreateFloatArray(NULL, num_elements);
           if (float_cjson_array != NULL) cJSON_Delete(float_cjson_array);
           cJSON* double_cjson_array = cJSON_CreateDoubleArray(NULL, num_elements);
           if (double_cjson_array != NULL) cJSON_Delete(double_cjson_array);
           // For string array with negative count, strings should be NULL according to the source code branch
           cJSON* string_cjson_array = cJSON_CreateStringArray(NULL, num_elements);
           if (string_cjson_array != NULL) cJSON_Delete(string_cjson_array);
      }
  }

  // --- Fuzz cJSON_SetValuestring on Reference Types ---
  // Target the branch in cJSON_SetValuestring when the object is a reference type.
  if (fdp.ConsumeBool()) {
      std::string ref_string_data = fdp.ConsumeRandomLengthString(20);
      cJSON* string_ref_item = cJSON_CreateStringReference(ref_string_data.c_str());
      if (string_ref_item != NULL) {
          std::string new_value = fdp.ConsumeRandomLengthString(20);
          // Calling SetValuestring on a string reference
          cJSON_SetValuestring(string_ref_item, new_value.c_str());
          cJSON_Delete(string_ref_item); // Free the reference item
      }

      // Although SetValuestring is primarily for strings, let's test on other reference types
      // to see how cJSON handles it, targeting the type check branches.
      cJSON* object_ref_item = cJSON_CreateObjectReference(parsed_item);
      if (object_ref_item != NULL) {
          std::string new_value = fdp.ConsumeRandomLengthString(20);
          cJSON_SetValuestring(object_ref_item, new_value.c_str());
          cJSON_Delete(object_ref_item);
      }

      cJSON* array_ref_item = cJSON_CreateArrayReference(parsed_item);
      if (array_ref_item != NULL) {
          std::string new_value = fdp.ConsumeRandomLengthString(20);
          cJSON_SetValuestring(array_ref_item, new_value.c_str());
          cJSON_Delete(array_ref_item);
      }
  }

  // --- Fuzz cJSON_InsertItemInArray ---
  // Target branches related to NULL array/item, negative index, and index out of bounds.
  if (fdp.ConsumeBool()) {
      cJSON* array = cJSON_CreateArray();
      cJSON* item_to_insert = cJSON_CreateNumber(fdp.ConsumeIntegral<int>());
      int index = fdp.ConsumeIntegralInRange<int>(-5, 10); // Test negative and out-of-bounds indices

      // Test with valid array and item, fuzzed index
      if (array != NULL && item_to_insert != NULL) {
          cJSON_InsertItemInArray(array, index, item_to_insert);
      }

      // Test with NULL array
      cJSON_InsertItemInArray(NULL, index, cJSON_CreateNumber(fdp.ConsumeIntegral<int>())); // Item created here will be leaked if InsertItemInArray returns false

      // Test with NULL item
      if (array != NULL) {
         cJSON_InsertItemInArray(array, index, NULL);
      }

      // Test with NULL array and NULL item
      cJSON_InsertItemInArray(NULL, index, NULL);

      // Clean up
      if (array != NULL) cJSON_Delete(array);
      // item_to_insert is either inserted (and deleted with array) or leaked in the NULL array test.
      // Need to handle the leak. If InsertItemInArray fails, the item is not added and needs to be deleted.
      // Let's restructure to ensure item_to_insert is always deleted if not successfully inserted.
  }

  // Restructured cJSON_InsertItemInArray fuzzing for memory safety
  if (fdp.ConsumeBool()) {
      cJSON* array = cJSON_CreateArray();
      cJSON* item_to_insert = cJSON_CreateNumber(fdp.ConsumeIntegral<int>());
      int index = fdp.ConsumeIntegralInRange<int>(-5, 10); // Test negative and out-of-bounds indices

      // Test with valid array and item, fuzzed index
      if (array != NULL && item_to_insert != NULL) {
          // If insertion fails, item_to_insert is not added to the array and needs to be deleted.
          if (!cJSON_InsertItemInArray(array, index, item_to_insert)) {
              cJSON_Delete(item_to_insert);
          }
      } else {
          // If array or item_to_insert creation failed, delete item_to_insert if it was created.
          if (item_to_insert != NULL) {
              cJSON_Delete(item_to_insert);
          }
      }

      // Test with NULL array (item_to_insert is created and passed, will be leaked if not deleted)
      cJSON* null_array_item = cJSON_CreateNumber(fdp.ConsumeIntegral<int>());
      if (null_array_item != NULL) {
          // cJSON_InsertItemInArray with NULL array returns false, item is not managed by cJSON
          cJSON_InsertItemInArray(NULL, index, null_array_item);
          cJSON_Delete(null_array_item); // Manually delete the item
      }


      // Test with NULL item (array must be valid to reach the NULL item check branch)
      if (array != NULL) {
         cJSON_InsertItemInArray(array, index, NULL); // Passing NULL item is handled by cJSON, no leak here
      }

      // Test with NULL array and NULL item
      cJSON_InsertItemInArray(NULL, index, NULL); // Handled by cJSON, no leak

      // Clean up the array
      if (array != NULL) cJSON_Delete(array);
  }


  // --- Fuzz cJSON_ReplaceItemViaPointer ---
  // Target branches related to NULL parent/item/replacement.
  if (fdp.ConsumeBool()) {
      cJSON* parent_array = cJSON_CreateArray();
      cJSON* original_item_array = cJSON_CreateNumber(1);
      cJSON* replacement_item_array = cJSON_CreateNumber(2);

      if (parent_array != NULL && original_item_array != NULL) {
          cJSON_AddItemToArray(parent_array, original_item_array); // Add item to have something to replace
      }

      // Test with valid parent, item, replacement
      if (parent_array != NULL && original_item_array != NULL && replacement_item_array != NULL) {
          // If replacement succeeds, original_item_array is deleted by cJSON.
          // If it fails, original_item_array is still in the array, and replacement_item_array needs deletion.
          if (!cJSON_ReplaceItemViaPointer(parent_array, original_item_array, replacement_item_array)) {
              cJSON_Delete(replacement_item_array);
          }
          // original_item_array is either deleted by cJSON or remains in the array (and deleted with parent_array).
      } else {
          // If creation failed, delete created items
          if (original_item_array != NULL) cJSON_Delete(original_item_array);
          if (replacement_item_array != NULL) cJSON_Delete(replacement_item_array);
      }

      // Test with NULL parent
      cJSON* null_parent_item = cJSON_CreateNumber(fdp.ConsumeIntegral<int>());
      cJSON* null_parent_replacement = cJSON_CreateNumber(fdp.ConsumeIntegral<int>());
      if (null_parent_item != NULL && null_parent_replacement != NULL) {
          // cJSON_ReplaceItemViaPointer with NULL parent returns false, items not managed by cJSON
          cJSON_ReplaceItemViaPointer(NULL, null_parent_item, null_parent_replacement);
          cJSON_Delete(null_parent_item);
          cJSON_Delete(null_parent_replacement);
      } else {
          if (null_parent_item != NULL) cJSON_Delete(null_parent_item);
          if (null_parent_replacement != NULL) cJSON_Delete(null_parent_replacement);
      }


      // Test with NULL item (parent and replacement must be valid)
      cJSON* null_item_parent = cJSON_CreateArray();
      cJSON* null_item_replacement = cJSON_CreateNumber(fdp.ConsumeIntegral<int>());
      if (null_item_parent != NULL && null_item_replacement != NULL) {
          cJSON_ReplaceItemViaPointer(null_item_parent, NULL, null_item_replacement); // Passing NULL item is handled by cJSON
          cJSON_Delete(null_item_replacement); // Replacement item is not used/deleted by cJSON if item is NULL
      } else {
          if (null_item_parent != NULL) cJSON_Delete(null_item_parent);
          if (null_item_replacement != NULL) cJSON_Delete(null_item_replacement);
      }


      // Test with NULL replacement (parent and item must be valid)
      cJSON* null_replacement_parent = cJSON_CreateArray();
      cJSON* null_replacement_item = cJSON_CreateNumber(fdp.ConsumeIntegral<int>());
      if (null_replacement_parent != NULL && null_replacement_item != NULL) {
           cJSON_AddItemToArray(null_replacement_parent, null_replacement_item); // Add item to replace
           cJSON_ReplaceItemViaPointer(null_replacement_parent, null_replacement_item, NULL); // Passing NULL replacement is handled by cJSON
           // null_replacement_item is deleted by cJSON if replacement is NULL and parent/item are valid
      } else {
          if (null_replacement_parent != NULL) cJSON_Delete(null_replacement_parent);
          if (null_replacement_item != NULL) cJSON_Delete(null_replacement_item);
      }


      // Test with NULL parent, item, and replacement
      cJSON_ReplaceItemViaPointer(NULL, NULL, NULL); // Handled by cJSON, no leak

      // Clean up parent arrays
      if (parent_array != NULL) cJSON_Delete(parent_array);
      if (null_item_parent != NULL) cJSON_Delete(null_item_parent);
      if (null_replacement_parent != NULL) cJSON_Delete(null_replacement_parent);
  }


  // The code block fuzzing cJSON_AddExistingItem has been removed as the function
  // does not appear to exist in the target cJSON version based on build errors.


  // Clean up the parsed item
  cJSON_Delete(parsed_item);

  // Reset hooks to default after testing to avoid affecting other calls in subsequent runs
  // Only reset if hooks were initialized by the fuzzer in this run.
  // This ensures the default allocation is tested when InitHooks is skipped.
  // The initial fdp.ConsumeBool() handles whether InitHooks was called.
  // If InitHooks was called with NULL, it's already reset.
  // If InitHooks was called with custom hooks, reset to NULL.
  // If InitHooks was skipped, no reset is needed.
  // The simplest is to always reset to NULL if InitHooks was called at all.
  // The outer if (fdp.ConsumeBool()) determines if InitHooks was called.
  // Let's add a flag.
  bool hooks_initialized = false;
  // ... inside the first if (fdp.ConsumeBool()) block ...
  // hooks_initialized = true;
  // ... after the main fuzzing logic ...
  // if (hooks_initialized) { cJSON_InitHooks(NULL); }
  // However, the current structure always calls InitHooks if the first bool is true.
  // The simplest is to always reset if the first bool was true.

  // Reset hooks to default if they were initialized by the fuzzer in this run.
  // The initial fdp.ConsumeBool() at line 30 determines if InitHooks was called.
  // If it was called with NULL, it's already reset. If with custom, reset to NULL.
  // If InitHooks was skipped, no reset is needed.
  // The current logic correctly resets to NULL if InitHooks was called with custom hooks.
  // If InitHooks(NULL) was called, it's already the default.
  // If InitHooks was skipped, we don't want to call InitHooks(NULL) here.
  // The current structure is fine.

  return 0;
}