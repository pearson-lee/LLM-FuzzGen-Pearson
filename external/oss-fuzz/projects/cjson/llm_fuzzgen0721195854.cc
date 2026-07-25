#include <cstddef>
#include <cstdint>
#include <string>
#include <fuzzer/FuzzedDataProvider.h>
#include "/src/cjson/cJSON.h"

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size) {
    FuzzedDataProvider fdp(Data, Size);

    // Create a cJSON object to be used in the tests
    cJSON *json = cJSON_CreateObject();
    if (json == NULL) {
        return 0;
    }

    // Add some data to the object
    cJSON_AddStringToObject(json, "name", fdp.ConsumeRandomLengthString(10).c_str());
    cJSON_AddNumberToObject(json, "age", fdp.ConsumeIntegral<int>());

    /*
     * ANALYSIS: The function-level coverage report showed cJSON_PrintBuffered had a branch
     *           with zero hits. The line-level report confirmed this was at line 1295,
     *           in the `if (!p.buffer)` check. This check fails if memory allocation returns NULL.
     * IMPLEMENTATION: The following code block sometimes passes a very large prebuffer size
     *                 to cJSON_PrintBuffered to increase the likelihood of a failed memory
     *                 allocation, thus exercising this uncovered error-handling path.
     */
    if (fdp.ConsumeBool()) {
        // Pass a large value to prebuffer to try and trigger allocation failure
        char *out = cJSON_PrintBuffered(json, fdp.ConsumeIntegralInRange<int>(1, 1000000), fdp.ConsumeBool());
        if (out) {
            cJSON_free(out);
        }
    }

    /*
     * ANALYSIS: The function-level coverage report showed cJSON_Compare had a branch
     *           with zero hits. The line-level report confirmed this was at line 3077,
     *           in the `if ((a->valuestring == NULL) || (b->valuestring == NULL))` check.
     * IMPLEMENTATION: The following code block creates two cJSON string objects and sets their
     *                 `valuestring` to NULL to specifically exercise this uncovered
     *                 error-handling path.
     */
    if (fdp.ConsumeBool()) {
        cJSON *a = cJSON_CreateString(fdp.ConsumeRandomLengthString(10).c_str());
        cJSON *b = cJSON_CreateString(fdp.ConsumeRandomLengthString(10).c_str());
        if (a != NULL && b != NULL) {
            char *original_valuestring = NULL;
            bool a_was_nulled = false;
            if (fdp.ConsumeBool()) {
                original_valuestring = a->valuestring;
                a->valuestring = NULL;
                a_was_nulled = true;
            } else {
                original_valuestring = b->valuestring;
                b->valuestring = NULL;
            }
            cJSON_Compare(a, b, fdp.ConsumeBool());
            // Restore the original pointer to prevent a memory leak
            if (a_was_nulled) {
                a->valuestring = original_valuestring;
            } else {
                b->valuestring = original_valuestring;
            }
        }
        cJSON_Delete(a);
        cJSON_Delete(b);
    }
    
    /*
     * ANALYSIS: The function-level coverage report showed cJSON_CreateObjectReference,
     *           which calls the internal `create_reference` function, had a branch with
     *           zero hits. The line-level report for `create_reference` confirmed this was
     *           at line 1967 in the `if (item == NULL)` check.
     * IMPLEMENTATION: The following code block sometimes calls cJSON_CreateObjectReference
     *                 with a NULL item to specifically exercise this uncovered error-handling path.
     */
    if (fdp.ConsumeBool()) {
        cJSON *ref = cJSON_CreateObjectReference(NULL);
        if (ref) {
            cJSON_Delete(ref);
        }
    }

    cJSON_Delete(json);

    return 0;
}