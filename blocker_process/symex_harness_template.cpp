#include <cstddef>
#include <cstdint>
#include <cstdlib>
#include <cstring>

// Replace this include with the project API needed to reach the blocker.
// Example:
// #include "/src/tinyxml2/tinyxml2.h"

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
    char* buffer = static_cast<char*>(malloc(size + 1));
    if (!buffer) {
        return 0;
    }

    memcpy(buffer, data, size);
    buffer[size] = '\0';

    // TODO:
    // 1. Create only the minimal objects needed by the project API.
    // 2. Call the shortest reasonable API path that can still reach the blocker.
    // 3. Avoid STL wrappers and FuzzedDataProvider in the input path.

    free(buffer);
    return 0;
}
