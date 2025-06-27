#include <cstddef>
#include <cstdint>
#include <string>
#include <vector>
#include <fuzzer/FuzzedDataProvider.h>

// Include the main cJSON header
#include "/src/cjson/cJSON.h"

// Define custom allocation functions for hooks
static void* fuzzer_malloc(size_t size) {
    return malloc(size);
}

static void fuzzer_free(void* ptr) {
    free(ptr);
}

// realloc hook might not be available in all cJSON versions or the struct definition
// static void* fuzzer_realloc(void* ptr, size_t size) {
//     return realloc(ptr, size);
// }


extern "C" int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size) {
  FuzzedDataProvider fdp(Data, Size);

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
          parse_len = fdp.ConsumeIntegralInRange<size_t>(0, parse_len - 1);
      }
  }

  // Fix: return_parse_end should be const char**
  const char* return_parse_end = NULL; // We don't need to process this in the fuzzer
  cJSON* parsed_item = cJSON_ParseWithLengthOpts(parse_string_len, parse_len, &return_parse_end, require_null_terminated);

  // --- 2. Fuzz cJSON_PrintBuffered ---
  // Target low overall coverage and different cJSON types in the internal print function
  if (parsed_item != NULL) {
      // We need a cJSON item to print. Use the parsed item or create a new one.
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
              case 4: created_item = cJSON_CreateArray(); /* Add some items? */ break;
              case 5: created_item = cJSON_CreateObject(); /* Add some items? */ break;
              case 6: created_item = cJSON_CreateRaw(fdp.ConsumeRandomLengthString().c_str()); break;
          }
          item_to_print = created_item;

          // If a new item was created, add some sub-items to arrays/objects
          if (item_to_print != NULL) {
              if (cJSON_IsArray(item_to_print)) {
                  int num_elements = fdp.ConsumeIntegralInRange<int>(0, 5);
                  for (int i = 0; i < num_elements; ++i) {
                      // Add a simple item, like a number
                      cJSON_AddItemToArray(item_to_print, cJSON_CreateNumber(fdp.ConsumeIntegral<int>()));
                  }
              } else if (cJSON_IsObject(item_to_print)) {
                   int num_elements = fdp.ConsumeIntegralInRange<int>(0, 5);
                   for (int i = 0; i < num_elements; ++i) {
                       // Add a simple key-value pair, like string key and number value
                       cJSON_AddNumberToObject(item_to_print, fdp.ConsumeRandomLengthString(10).c_str(), fdp.ConsumeIntegral<int>());
                   }
              }
          }
      }

      // Fix: Correct usage of cJSON_PrintBuffered. It returns an allocated string.
      // The second argument is prebuffer size hint, third is format flag.
      // The returned string must be freed using cJSON_free.
      char* printed_string = NULL;
      if (item_to_print != NULL) {
          printed_string = cJSON_PrintBuffered(item_to_print, print_buffer_size, format_print);
      }

      // Free the allocated string returned by cJSON_PrintBuffered
      if (printed_string != NULL) {
          cJSON_free(printed_string);
      }

      // Delete the newly created item if it wasn't the parsed_item
      if (created_item != NULL) { // Check created_item instead of item_to_print != parsed_item
          cJSON_Delete(created_item);
      }
  }


  // --- 3. Fuzz cJSON_InitHooks ---
  // Target the false branch (non-NULL hooks)
  if (fdp.ConsumeBool()) {
      cJSON_InitHooks(NULL); // Cover the NULL case (already covered, but good to include)
  } else {
      cJSON_Hooks hooks;
      // Fix: Correct member names in cJSON_Hooks. realloc_fn does not exist.
      hooks.malloc_fn = fdp.ConsumeBool() ? fuzzer_malloc : NULL;
      hooks.free_fn = fdp.ConsumeBool() ? fuzzer_free : NULL;
      // hooks.realloc_fn = fdp.ConsumeBool() ? fuzzer_realloc : NULL; // Removed as it's not a member
      cJSON_InitHooks(&hooks);
  }
    // Reset hooks to default after testing to avoid affecting other calls
    cJSON_InitHooks(NULL);


  // --- 4. Fuzz cJSON_Duplicate ---
  // Target duplicating various structures
  if (parsed_item != NULL) {
      cJSON* duplicated_item = cJSON_Duplicate(parsed_item, fdp.ConsumeBool()); // 2nd arg is recurse
      // Ensure duplicated_item is not NULL before deleting
      if (duplicated_item != NULL) {
          cJSON_Delete(duplicated_item); // Free the duplicated item
      }
  }

  // --- 5. Fuzz cJSON_Compare ---
  // Target comparing different types and values
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
          cJSON_Compare(parsed_item, item_to_compare, fdp.ConsumeBool()); // 3rd arg is case_sensitive
          cJSON_Delete(item_to_compare); // Free the comparison item
      }
  }


  // Clean up the parsed item
  cJSON_Delete(parsed_item);

  return 0;
}