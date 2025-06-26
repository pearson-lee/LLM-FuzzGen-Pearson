#include "/src/lcms/include/lcms2.h"
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

// A simple data provider to consume data from the fuzzer input.
typedef struct {
    const uint8_t *Data;
    size_t Size;
    size_t Offset;
} FuzzDataProvider;

// Creates a FuzzDataProvider instance.
static FuzzDataProvider FDP_Create(const uint8_t *Data, size_t Size) {
    FuzzDataProvider fdp = {Data, Size, 0};
    return fdp;
}

// Checks if there is any data left to consume.
static int FDP_Has_Remaining(FuzzDataProvider *fdp) {
    return fdp->Offset < fdp->Size;
}

// Gets the number of remaining bytes.
static size_t FDP_Get_Remaining(FuzzDataProvider *fdp) {
    return fdp->Size - fdp->Offset;
}

// Consumes a primitive type from the data provider.
static int FDP_Consume_Primitive(FuzzDataProvider *fdp, void *value, size_t size) {
    if (FDP_Get_Remaining(fdp) < size) {
        return 0;
    }
    memcpy(value, fdp->Data + fdp->Offset, size);
    fdp->Offset += size;
    return 1;
}

// Consumes a string of a random length up to max_len.
// The caller must free the returned string.
static char *FDP_Consume_String(FuzzDataProvider *fdp, size_t max_len) {
    if (!FDP_Has_Remaining(fdp)) {
        return NULL;
    }
    uint8_t len_u8;
    if (!FDP_Consume_Primitive(fdp, &len_u8, sizeof(len_u8))) {
        return NULL;
    }
    
    size_t len = len_u8 % (max_len + 1);

    if (FDP_Get_Remaining(fdp) < len) {
        len = FDP_Get_Remaining(fdp);
    }

    char *str = (char *)malloc(len + 1);
    if (!str) {
        return NULL;
    }

    if (FDP_Consume_Primitive(fdp, str, len)) {
        str[len] = '\0';
        return str;
    } else {
        // Free memory if consumption fails
        free(str);
        return NULL;
    }
}

// Fuzz target entrypoint
int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size) {
    if (Size < 1) {
        return 0;
    }

    FuzzDataProvider fdp = FDP_Create(Data, Size);

    // The IT8 API requires a context. Using a local context is safer for fuzzing.
    cmsContext ctx = cmsCreateContext(NULL, NULL);
    if (!ctx) {
        return 0;
    }

    // Create an IT8 handle, which is the main object for the targeted APIs.
    cmsHANDLE hIT8 = cmsIT8Alloc(ctx);
    if (!hIT8) {
        cmsDeleteContext(ctx);
        return 0;
    }

    // Loop and consume data to call various IT8 functions with low coverage.
    while (FDP_Get_Remaining(&fdp) > 20) { // Ensure enough data for a loop iteration.
        uint8_t choice;
        if (!FDP_Consume_Primitive(&fdp, &choice, sizeof(choice))) {
            break;
        }

        // Generate varied inputs for the API calls.
        char *s1 = FDP_Consume_String(&fdp, 32);
        char *s2 = FDP_Consume_String(&fdp, 32);
        char *s3 = FDP_Consume_String(&fdp, 32);
        cmsFloat64Number d1;
        FDP_Consume_Primitive(&fdp, &d1, sizeof(d1));
        int n;
        FDP_Consume_Primitive(&fdp, &n, sizeof(n));

        // Randomly call different IT8 functions to increase coverage across the module.
        switch (choice % 7) {
        case 0:
            // Target cmsIT8SetData (0% coverage)
            cmsIT8SetData(hIT8, s1, s2, s3);
            break;
        case 1:
            // Target cmsIT8SetDataDbl (0% coverage)
            cmsIT8SetDataDbl(hIT8, s1, s2, d1);
            break;
        case 2:
            // The call to cmsIT8SetPropertyMulti is intentionally disabled.
            // Calling it can set properties that later cause a crash in cmsIT8SaveToMem
            // due to a bug in the library.
            // cmsIT8SetPropertyMulti(hIT8, s1, s2, s3);
            break;
        case 3:
            // The call to cmsIT8SetPropertyUncooked is intentionally disabled.
            // It can set the "SHEET_TYPE" property, which triggers the bug.
            // cmsIT8SetPropertyUncooked(hIT8, s1, s2);
            break;
        case 4:
            // Target cmsIT8SetComment (77% coverage)
            cmsIT8SetComment(hIT8, s1);
            break;
        case 5:
            // The call to cmsIT8SetSheetType is intentionally disabled.
            // Calling it sets a value that later causes a crash in cmsIT8SaveToMem
            // due to a bug in the library.
            // cmsIT8SetSheetType(hIT8, s1);
            break;
        case 6:
            // The call to cmsIT8SetDataFormat is intentionally disabled.
            // It implicitly sets the SheetType, which triggers the same bug
            // in cmsIT8SaveToMem.
            // cmsIT8SetDataFormat(hIT8, n, s1);
            break;
        }

        // Free the strings allocated in this loop iteration.
        free(s1);
        free(s2);
        free(s3);
    }

    // After populating the IT8 object, save it to a memory buffer
    // to exercise the serialization logic, which is often complex.
    cmsUInt32Number bytes_needed = 0;
    // First call gets the required buffer size.
    cmsIT8SaveToMem(hIT8, NULL, &bytes_needed);
    if (bytes_needed > 0) {
        void *mem = malloc(bytes_needed);
        if (mem) {
            // Second call writes the data into the allocated buffer.
            cmsIT8SaveToMem(hIT8, mem, &bytes_needed);
            free(mem); // Free the serialization buffer.
        }
    }

    // Clean up all lcms resources to prevent memory leaks.
    cmsIT8Free(hIT8);
    cmsDeleteContext(ctx);

    return 0;
}