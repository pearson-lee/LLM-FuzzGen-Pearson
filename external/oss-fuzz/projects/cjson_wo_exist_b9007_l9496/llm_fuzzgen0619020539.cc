#include <cstddef>
#include <cstdint>
#include <string>
#include <vector>
#include <fuzzer/FuzzedDataProvider.h>

// Include the project header
#include "/src/cjson/cJSON.h"

// Define the fuzzer entry point
extern "C" int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size) {
  FuzzedDataProvider fdp(Data, Size);

  // Consume data for the JSON string to be parsed
  std::string json_string = fdp.ConsumeRandomLengthString();

  // Consume boolean for require_null_terminated option
  cJSON_bool require_null_terminated = fdp.ConsumeBool();

  // return_parse_end is an output parameter for cJSON_ParseWithOpts
  const char* return_parse_end = nullptr;

  // --- Call cJSON_ParseWithOpts ---
  // Parses a JSON string with options. Targets parsing logic and error handling.
  cJSON* parsed_json = cJSON_ParseWithOpts(json_string.c_str(), &return_parse_end, require_null_terminated);

  // --- Call other functions if parsing was successful ---
  if (parsed_json != nullptr) {

    // Consume data for parameters of cJSON_PrintBuffered
    int offset = fdp.ConsumeIntegral<int>();
    cJSON_bool fmt_print_buffered = fdp.ConsumeBool();

    // --- Call cJSON_PrintBuffered ---
    // Prints a cJSON object to a pre-allocated buffer. Targets serialization logic.
    // The offset parameter can test buffer boundary conditions.
    // Fix: cJSON_PrintBuffered returns char*, not unsigned char*.
    char* printed_string_buffered = cJSON_PrintBuffered(parsed_json, offset, fmt_print_buffered);
    // cJSON_PrintBuffered allocates memory that needs to be freed with cJSON_free
    if (printed_string_buffered != nullptr) {
      cJSON_free(printed_string_buffered);
    }

    // Consume boolean for recurse option of cJSON_Duplicate
    cJSON_bool recurse_duplicate = fdp.ConsumeBool();

    // --- Call cJSON_Duplicate ---
    // Creates a duplicate of a cJSON object. Targets copying logic (shallow vs deep).
    cJSON* duplicated_json = cJSON_Duplicate(parsed_json, recurse_duplicate);
    // cJSON_Duplicate allocates memory that needs to be freed with cJSON_Delete
    if (duplicated_json != nullptr) {
      cJSON_Delete(duplicated_json);
    }

    // --- Call cJSON_ReplaceItemInObject ---
    // Replaces an item in a cJSON object. Targets object modification logic.
    // Need to create an object and a new item to replace with.
    cJSON* object_to_modify = cJSON_CreateObject();
    if (object_to_modify != nullptr) {
        // Consume data for the key and the new item type/content
        std::string key_replace = fdp.ConsumeRandomLengthString();

        cJSON* new_item = nullptr;
        // Determine the type of the new item using fuzzer data
        int item_type = fdp.ConsumeIntegralInRange<int>(0, 5); // 0: Null, 1: Bool, 2: Number, 3: String, 4: Array, 5: Object

        // Create the new item based on the determined type
        switch (item_type) {
            case 0: new_item = cJSON_CreateNull(); break;
            case 1: new_item = cJSON_CreateBool(fdp.ConsumeBool()); break;
            case 2: new_item = cJSON_CreateNumber(fdp.ConsumeFloatingPoint<double>()); break;
            case 3: new_item = cJSON_CreateString(fdp.ConsumeRandomLengthString().c_str()); break;
            case 4: new_item = cJSON_CreateArray(); break; // Create empty array for simplicity
            case 5: new_item = cJSON_CreateObject(); break; // Create empty object for simplicity
        }

        // If the new item was successfully created
        if (new_item != nullptr) {
            // cJSON_ReplaceItemInObject takes ownership of new_item on success.
            // If it fails, we are responsible for freeing new_item.
            cJSON_bool replace_success = cJSON_ReplaceItemInObject(object_to_modify, key_replace.c_str(), new_item);
            if (!replace_success) {
                // If replacement failed, free the new_item
                cJSON_Delete(new_item);
            }
        }
        // Free the object. This will also free the replaced item if replacement was successful.
        cJSON_Delete(object_to_modify);
    }

    // Free the original parsed object
    cJSON_Delete(parsed_json);
  }

  // --- Call cJSON_CreateArray ---
  // Creates an empty cJSON array. Targets array creation logic.
  cJSON* created_array = cJSON_CreateArray();
  // cJSON_CreateArray allocates memory that needs to be freed with cJSON_Delete
  if (created_array != nullptr) {
      cJSON_Delete(created_array);
  }

  return 0;
}