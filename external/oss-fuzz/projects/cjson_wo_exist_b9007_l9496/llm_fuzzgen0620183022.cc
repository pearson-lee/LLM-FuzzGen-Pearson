#include <cstddef>
#include <cstdint>
#include <string>
#include <fuzzer/FuzzedDataProvider.h>
#include "/src/cjson/cJSON.h"

// A flag to control whether the custom malloc should fail.
bool malloc_should_fail = false;

// A custom malloc function that can be made to fail.
static void *failing_malloc(size_t size) {
  if (malloc_should_fail) {
    return NULL;
  }
  return malloc(size);
}

// A custom free function.
static void custom_free(void *ptr) {
  free(ptr);
}

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size) {
  FuzzedDataProvider fdp(Data, Size);

  // Use fuzzer data to decide if malloc should fail.
  malloc_should_fail = fdp.ConsumeBool();

  // Initialize cJSON with custom allocation functions.
  cJSON_Hooks hooks;
  hooks.malloc_fn = failing_malloc;
  hooks.free_fn = custom_free;
  cJSON_InitHooks(&hooks);

  // Create a cJSON object from fuzzer data.
  std::string json_str = fdp.ConsumeRemainingBytesAsString();
  cJSON *json = cJSON_Parse(json_str.c_str());

  if (json != NULL) {
    // Test cJSON_PrintPreallocated with a small buffer to trigger reallocations.
    size_t buffer_size = fdp.ConsumeIntegralInRange<size_t>(0, 1024);
    char *buffer = (char *)malloc(buffer_size);
    if (buffer != NULL) {
      cJSON_PrintPreallocated(json, buffer, (int)buffer_size, fdp.ConsumeBool());
      free(buffer);
    }

    // Test cJSON_Print.
    char *printed_json = cJSON_Print(json);
    if (printed_json != NULL) {
      free(printed_json);
    }

    // Test cJSON_Minify.
    char *minified_json = cJSON_PrintUnformatted(json);
    if (minified_json != NULL) {
        cJSON_Minify(minified_json);
        free(minified_json);
    }

    // Clean up the cJSON object.
    cJSON_Delete(json);
  }

  // Reset hooks to default to avoid affecting other fuzzers.
  cJSON_InitHooks(NULL);

  return 0;
}