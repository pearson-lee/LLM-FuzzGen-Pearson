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
  // Moved hooks initialization to the beginning to ensure subsequent cJSON calls
  // use these hooks, aiming to cover cJSON_malloc and cJSON_free wrappers.
  if (fdp.ConsumeBool()) {
      cJSON_InitHooks(NULL); // Cover the NULL case
  } else {
      cJSON_Hooks hooks;
      // Correct member names in cJSON_Hooks. realloc_fn does not exist.
      hooks.malloc_fn = fdp.ConsumeBool() ? fuzzer_malloc : NULL;
      hooks.free_fn = fdp.ConsumeBool() ? fuzzer_free : NULL;
      cJSON_InitHooks(&hooks);
  }

  // Consume data for various API calls
  std::string json_string = fdp.ConsumeRandomLengthString();
  bool format_print = fdp.ConsumeBool();
  size_t print_buffer_size = fdp.ConsumeIntegralInRange<size_t>(0, 4096); // Fuzzed buffer size hint for printing
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
  // Target duplicating various structures and hitting NULL/non-recursive paths
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
  // These were not explicitly called and had low branch coverage.
  if (fdp.ConsumeBool()) {
      size_t num_elements = fdp.ConsumeIntegralInRange<size_t>(0, 10);
      if (num_elements > 0) {
          // Create Int Array
          std::vector<int> int_array;
          int_array.reserve(num_elements);
          for (size_t i = 0; i < num_elements; ++i) {
              int_array.push_back(fdp.ConsumeIntegralInRange<int>(-100, 100));
          }
          cJSON* int_cjson_array = cJSON_CreateIntArray(int_array.data(), num_elements);
          if (int_cjson_array != NULL) {
              cJSON_Delete(int_cjson_array);
          }

          // Create Float Array
          std::vector<float> float_array;
          float_array.reserve(num_elements);
          for (size_t i = 0; i < num_elements; ++i) {
              float_array.push_back(fdp.ConsumeFloatingPoint<float>());
          }
          cJSON* float_cjson_array = cJSON_CreateFloatArray(float_array.data(), num_elements);
          if (float_cjson_array != NULL) {
              cJSON_Delete(float_cjson_array);
          }

          // Create Double Array
          std::vector<double> double_array;
          double_array.reserve(num_elements);
          for (size_t i = 0; i < num_elements; ++i) {
              double_array.push_back(fdp.ConsumeFloatingPoint<double>());
          }
          cJSON* double_cjson_array = cJSON_CreateDoubleArray(double_array.data(), num_elements);
          if (double_cjson_array != NULL) {
              cJSON_Delete(double_cjson_array);
          }

          // Create String Array
          std::vector<std::string> string_vector;
          string_vector.reserve(num_elements);
          for(size_t i = 0; i < num_elements; ++i) {
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
           // Also test with num_elements = 0
           cJSON* int_cjson_array = cJSON_CreateIntArray(NULL, 0);
           if (int_cjson_array != NULL) cJSON_Delete(int_cjson_array);
           cJSON* float_cjson_array = cJSON_CreateFloatArray(NULL, 0);
           if (float_cjson_array != NULL) cJSON_Delete(float_cjson_array);
           cJSON* double_cjson_array = cJSON_CreateDoubleArray(NULL, 0);
           if (double_cjson_array != NULL) cJSON_Delete(double_cjson_array);
           cJSON* string_cjson_array = cJSON_CreateStringArray(NULL, 0);
           if (string_cjson_array != NULL) cJSON_Delete(string_cjson_array);
      }
  }

  // The code block fuzzing cJSON_AddExistingItem has been removed as the function
  // does not appear to exist in the target cJSON version based on build errors.


  // Clean up the parsed item
  cJSON_Delete(parsed_item);

  // Reset hooks to default after testing to avoid affecting other calls in subsequent runs
  cJSON_InitHooks(NULL);

  return 0;
}