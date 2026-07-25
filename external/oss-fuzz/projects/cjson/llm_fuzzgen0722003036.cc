#include "/src/cjson/cJSON.h"
#include <fuzzer/FuzzedDataProvider.h>
#include <string>
#include <vector>
#include <climits>

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  FuzzedDataProvider fdp(data, size);
  static int depth = 0;
  bool cycle_created = false;

  cJSON *root = cJSON_CreateObject();
  if (!root) {
    return 0;
  }

  std::string ref_string = fdp.ConsumeRandomLengthString(100);
  cJSON *ref_array = cJSON_CreateArray();
  if (ref_array) {
      cJSON_AddItemToObject(root, "referenced_array_original", ref_array);
  }

  int num_items = fdp.ConsumeIntegralInRange<int>(1, 20);
  for (int i = 0; i < num_items; ++i) {
    std::string key = fdp.ConsumeRandomLengthString(20);

    switch (fdp.ConsumeIntegralInRange<int>(0, 5)) {
    case 0: {
      cJSON *string_item = cJSON_CreateString("short");
      if (string_item) {
        std::string long_string = fdp.ConsumeRandomLengthString(100);
        cJSON_SetValuestring(string_item, long_string.c_str());
        cJSON_AddItemToObject(root, key.c_str(), string_item);
      }
      break;
    }
    case 1: {
      cJSON *string_ref = cJSON_CreateStringReference(ref_string.c_str());
      if (string_ref) {
        cJSON_AddItemToObject(root, key.c_str(), string_ref);
      }
      break;
    }
    case 2: {
      if (ref_array && depth < 10) {
          cJSON *array_ref = cJSON_CreateArrayReference(ref_array);
          if (array_ref) {
              cJSON_AddItemToArray(ref_array, array_ref);
              cycle_created = true;
          }
      }
      break;
    }
    case 3: {
      cJSON *number_item = cJSON_CreateNumber(fdp.ConsumeFloatingPoint<double>());
      if (number_item) {
        cJSON_AddItemToObject(root, key.c_str(), number_item);
      }
      break;
    }
    case 4: {
      cJSON *bool_item = cJSON_CreateBool(fdp.ConsumeBool());
      if (bool_item) {
        cJSON_AddItemToObject(root, key.c_str(), bool_item);
      }
      break;
    }
    case 5: {
      depth++;
      cJSON *nested_object = cJSON_CreateObject();
      if (nested_object) {
        std::string nested_key = fdp.ConsumeRandomLengthString(10);
        std::string nested_val = fdp.ConsumeRandomLengthString(10);
        cJSON_AddStringToObject(nested_object, nested_key.c_str(), nested_val.c_str());
        cJSON_AddItemToObject(root, key.c_str(), nested_object);
      }
      depth--;
      break;
    }
    }
  }

  cJSON *duplicated_root = cJSON_Duplicate(root, fdp.ConsumeBool());
  if (duplicated_root) {
      cJSON_Delete(duplicated_root);
  }

  if (!cycle_created) {
    int prebuffer_size = fdp.ConsumeIntegralInRange<int>(-100, 4096);
    bool format = fdp.ConsumeBool();
    char *printed_json = cJSON_PrintBuffered(root, prebuffer_size, format);
    if (printed_json) {
      free(printed_json);
    }
  }

  cJSON_Delete(root);

  return 0;
}