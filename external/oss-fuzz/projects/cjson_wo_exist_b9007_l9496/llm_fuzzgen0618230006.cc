#include <cstddef>
#include <cstdint>
#include <memory>
#include <string>
#include <fuzzer/FuzzedDataProvider.h>

#include "/src/cjson/cJSON.h"

// Custom deleter for cJSON objects to be used with std::unique_ptr for robust memory management.
struct CJSONDeleter {
  void operator()(cJSON* ptr) const {
    cJSON_Delete(ptr);
  }
};

// Custom deleter for memory allocated by cJSON_print, which uses cJSON_free.
struct CJSONPrintDeleter {
    void operator()(unsigned char* ptr) const {
        cJSON_free(ptr);
    }
};

// Target APIs:
// 1. cJSON_ParseWithOpts: Parses a JSON string with options.
// 2. cJSON_Duplicate: Creates a deep copy of a cJSON object.
// 3. cJSON_Compare: Compares two cJSON objects.
// 4. cJSON_ReplaceItemInObject: Replaces an item in a cJSON object.
// 5. cJSON_Print: Converts a cJSON object to a string.

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  FuzzedDataProvider fdp(data, size);

  // Create a JSON object by parsing a fuzzed string.
  const char *error_ptr = nullptr;
  std::unique_ptr<cJSON, CJSONDeleter> json(
      cJSON_ParseWithOpts(fdp.ConsumeRandomLengthString(1000).c_str(), &error_ptr, fdp.ConsumeBool()));

  if (json) {
    // Duplicate the parsed JSON object.
    std::unique_ptr<cJSON, CJSONDeleter> json_copy(cJSON_Duplicate(json.get(), fdp.ConsumeBool()));

    if (json_copy) {
      // Compare the original and the duplicated JSON objects.
      cJSON_Compare(json.get(), json_copy.get(), fdp.ConsumeBool());
    }

    // Replace an item in the original JSON object.
    std::string key = fdp.ConsumeRandomLengthString(10);
    std::unique_ptr<cJSON, CJSONDeleter> new_item(cJSON_CreateString(fdp.ConsumeRandomLengthString(20).c_str()));
    if (new_item) {
        // cJSON_ReplaceItemInObject takes ownership of new_item, so we release it from the unique_ptr.
        if (cJSON_IsObject(json.get())) {
            cJSON_ReplaceItemInObject(json.get(), key.c_str(), new_item.release());
        }
    }

    // Print the (potentially modified) JSON object to a string.
    std::unique_ptr<unsigned char, CJSONPrintDeleter> printed_json(
        reinterpret_cast<unsigned char*>(cJSON_Print(json.get())));
  }

  return 0;
}