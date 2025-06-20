#include <cstddef>
#include <cstdint>
#include <string>
#include <memory>
#include <fuzzer/FuzzedDataProvider.h>
#include "/src/cjson/cJSON.h"

// RAII wrapper for cJSON objects to ensure proper memory management.
struct cJSON_Deleter {
    void operator()(cJSON* ptr) const {
        cJSON_Delete(ptr);
    }
};
using cJSON_ptr = std::unique_ptr<cJSON, cJSON_Deleter>;

// Fuzz target entry point.
extern "C" int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size) {
    FuzzedDataProvider fdp(Data, Size);

    // Consume data for various operations.
    std::string str1 = fdp.ConsumeRandomLengthString(1000);
    std::string str2 = fdp.ConsumeRandomLengthString(100);
    std::string key = fdp.ConsumeRandomLengthString(20);
    bool case_sensitive = fdp.ConsumeBool();
    bool recurse = fdp.ConsumeBool();

    // --- Target: cJSON_ParseWithOpts ---
    // Investigate low coverage in cJSON_ParseWithOpts by sometimes passing NULL.
    cJSON_ptr json1 = nullptr;
    if (fdp.ConsumeIntegralInRange(0, 9) == 0) {
        // 10% chance to test the uncovered NULL path.
        json1.reset(cJSON_ParseWithOpts(NULL, NULL, fdp.ConsumeBool()));
    } else {
        json1.reset(cJSON_ParseWithOpts(str1.c_str(), NULL, fdp.ConsumeBool()));
    }

    // --- Target: cJSON_AddRawToObject ---
    // Investigate low coverage in cJSON_AddRawToObject.
    // The error path is taken if the target object is not a cJSON_Object.
    cJSON_ptr not_an_object = cJSON_ptr(cJSON_CreateNumber(fdp.ConsumeFloatingPoint<double>()));
    // This call is expected to fail and return NULL, exercising the error handling path.
    cJSON_AddRawToObject(not_an_object.get(), key.c_str(), str2.c_str());


    // --- Target: cJSON_SetValuestring ---
    // Investigate low coverage in cJSON_SetValuestring on a reference object.
    cJSON_ptr str_ref(cJSON_CreateStringReference(str2.c_str()));
    // This should not crash and will hit the branch checking for cJSON_IsReference.
    cJSON_SetValuestring(str_ref.get(), "new_value");


    // --- Target: cJSON_Duplicate ---
    // Investigate low coverage in cJSON_Duplicate with a const string key.
    cJSON_ptr obj_to_dup(cJSON_CreateObject());
    if (obj_to_dup) {
        cJSON_AddItemToObjectCS(obj_to_dup.get(), "const_key", cJSON_CreateString("value"));
        cJSON_ptr duplicated_obj(cJSON_Duplicate(obj_to_dup.get(), recurse));
    }

    // --- Target: cJSON_Compare ---
    // Investigate uncovered branches in cJSON_Compare.
    if (json1) {
        cJSON_ptr json2(cJSON_Duplicate(json1.get(), true));

        // Test comparison with a manually introduced invalid type to hit the default case.
        if (fdp.ConsumeBool() && json2) {
            json2->type = cJSON_Invalid | 200; // Corrupt type to an invalid value.
        }
        cJSON_Compare(json1.get(), json2.get(), case_sensitive);

        // Test comparison where one of the valuestrings is NULL.
        cJSON_ptr s1(cJSON_CreateString("a"));
        cJSON_ptr s2(cJSON_CreateString("b"));
        if (s1 && s2 && fdp.ConsumeBool()) {
            // This is an unsafe operation to reach a specific uncovered branch.
            // We save the original pointer to prevent memory issues.
            char* original_valuestring = s1->valuestring;
            s1->valuestring = NULL;
            cJSON_Compare(s1.get(), s2.get(), case_sensitive);
            s1->valuestring = original_valuestring; // Restore pointer to prevent memory leak.
        }
    }

    return 0;
}