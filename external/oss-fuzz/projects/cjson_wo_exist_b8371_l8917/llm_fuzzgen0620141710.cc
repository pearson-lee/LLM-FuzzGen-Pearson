#include <cstddef>
#include <cstdint>
#include <string>
#include <fuzzer/FuzzedDataProvider.h>
#include "/src/cjson/cJSON.h"
#include <stdlib.h>

// Custom memory allocation functions for testing to trigger specific code paths.
// These are used to simulate memory allocation failures.
static void* custom_malloc(size_t size) {
    return malloc(size);
}

static void custom_free(void *ptr) {
    free(ptr);
}

// Fuzz target entry point.
extern "C" int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size) {
  FuzzedDataProvider fdp(Data, Size);

  // Create a cJSON object from the fuzzer input.
  std::string json_string = fdp.ConsumeRandomLengthString(1000);
  cJSON *json = cJSON_Parse(json_string.c_str());

  // If parsing fails, create a default object to continue fuzzing.
  if (json == NULL) {
    json = cJSON_CreateObject();
  }

  // Use custom hooks without realloc_fn to hit an uncovered branch in the internal print function.
  cJSON_Hooks hooks;
  hooks.malloc_fn = custom_malloc;
  hooks.free_fn = custom_free;
  cJSON_InitHooks(&hooks);

  // Target cJSON_Print and cJSON_PrintUnformatted to exercise printing logic.
  // The allocated strings are freed to prevent memory leaks.
  char *printed_json = cJSON_Print(json);
  if (printed_json != NULL) {
    free(printed_json);
  }

  char *printed_unformatted_json = cJSON_PrintUnformatted(json);
  if (printed_unformatted_json != NULL) {
    free(printed_unformatted_json);
  }
  
  // Restore default memory hooks.
  cJSON_InitHooks(NULL);

  // Target cJSON_ReplaceItemInObject and cJSON_ReplaceItemInObjectCaseSensitive.
  std::string key = fdp.ConsumeRandomLengthString(10);
  cJSON *new_item = cJSON_CreateString(fdp.ConsumeRandomLengthString(20).c_str());
  if (cJSON_IsObject(json)) {
      // We duplicate the item because cJSON_ReplaceItemInObject takes ownership.
      cJSON_ReplaceItemInObject(json, key.c_str(), cJSON_Duplicate(new_item, true));
      cJSON_ReplaceItemInObjectCaseSensitive(json, key.c_str(), cJSON_Duplicate(new_item, true));
  }
  cJSON_Delete(new_item);

  // Target a specific uncovered branch in the print_value function by creating a raw JSON with a NULL value.
  cJSON *raw_json = cJSON_CreateRaw(NULL);
  char *printed_raw = cJSON_Print(raw_json);
  if (printed_raw != NULL) {
      free(printed_raw);
  }
  cJSON_Delete(raw_json);

  // Call cJSON_Print with a NULL item to hit another uncovered branch in print_value.
  char *printed_null = cJSON_Print(NULL);
  if (printed_null != NULL) {
      free(printed_null);
  }

  // Clean up the main JSON object to prevent memory leaks.
  cJSON_Delete(json);

  return 0;
}