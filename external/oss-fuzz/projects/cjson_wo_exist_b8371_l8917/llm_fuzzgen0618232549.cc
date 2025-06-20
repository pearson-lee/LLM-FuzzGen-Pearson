#include <cstddef>
#include <cstdint>
#include <memory>
#include <string>
#include <fuzzer/FuzzedDataProvider.h>
#include "/src/cjson/cJSON.h"

// Deleter for cJSON objects created by cJSON functions.
struct CJSONDeleter {
  void operator()(cJSON* ptr) const {
    cJSON_Delete(ptr);
  }
};

// Deleter for memory allocated by cJSON_malloc.
struct CJSONMallocDeleter {
  void operator()(void* ptr) const {
    cJSON_free(ptr);
  }
};

// Use unique_ptr with custom deleters for automatic memory management.
using cJSONUniquePtr = std::unique_ptr<cJSON, CJSONDeleter>;
using CJSONMallocUniquePtr = std::unique_ptr<char, CJSONMallocDeleter>;

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
  FuzzedDataProvider fdp(data, size);

  // Create a JSON string from the fuzzer input.
  std::string json_string = fdp.ConsumeRandomLengthString(1024);
  const char* json_c_str = json_string.c_str();

  // Parse the JSON string with options.
  const char* return_parse_end;
  cJSONUniquePtr json_object(cJSON_ParseWithOpts(json_c_str, &return_parse_end, fdp.ConsumeBool()));

  if (json_object) {
    // Duplicate the parsed JSON object.
    cJSONUniquePtr duplicated_object(cJSON_Duplicate(json_object.get(), fdp.ConsumeBool()));

    if (duplicated_object) {
      // Compare the original and duplicated objects.
      cJSON_Compare(json_object.get(), duplicated_object.get(), fdp.ConsumeBool());
    }

    // Create a new cJSON item to replace with.
    cJSONUniquePtr replacement_item(cJSON_CreateString(fdp.ConsumeRandomLengthString(128).c_str()));
    if (replacement_item) {
      // Replace an item in the original object.
      cJSON_ReplaceItemInObject(json_object.get(), fdp.ConsumeRandomLengthString(32).c_str(), replacement_item.release());
    }

    // Print the modified JSON object to a buffer.
    CJSONMallocUniquePtr printed_json((char*)cJSON_PrintBuffered(json_object.get(), fdp.ConsumeIntegralInRange<int>(1, 1024), fdp.ConsumeBool()));
  }

  return 0;
}