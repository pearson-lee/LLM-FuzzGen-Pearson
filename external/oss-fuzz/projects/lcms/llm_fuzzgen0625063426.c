#include <stdint.h>
#include <stddef.h>
#include <string.h> // For memcpy
#include <stdlib.h> // For malloc, free
#include <math.h>   // For fabs, fmod

// Include necessary lcms headers
// These headers provide the declarations for the lcms API functions and types.
#include "/src/lcms/include/lcms2.h"
#include "/src/lcms/include/lcms2_plugin.h"

// Custom IO handler data structure for cmsOpenProfileFromIOhandler2THR.
// This struct holds the fuzzer's input data and current offset, allowing
// the custom IO functions to read from the fuzzer's buffer as if it were a file.
typedef struct {
    const uint8_t *Data;
    size_t Size;
    size_t Offset;
} FuzzerIOData;

// Custom Read function for cmsIOHANDLER.
// Reads 'Count' items of 'Size' bytes into 'Buffer' from the fuzzer's data.
static cmsUInt32Number ReadFn(cmsIOHANDLER* io, void* Buffer, cmsUInt32Number Size, cmsUInt32Number Count) {
    // Fix: Retrieve FuzzerIOData from io->stream, not io->ContextID.
    // io->ContextID holds the lcmsContext, while io->stream is intended for custom stream data.
    FuzzerIOData* fuzzerData = (FuzzerIOData*)io->stream;
    size_t bytesToRead = Size * Count;
    if (fuzzerData->Offset + bytesToRead > fuzzerData->Size) {
        bytesToRead = fuzzerData->Size - fuzzerData->Offset;
    }
    memcpy(Buffer, fuzzerData->Data + fuzzerData->Offset, bytesToRead);
    fuzzerData->Offset += bytesToRead;
    return (cmsUInt32Number)(bytesToRead / Size);
}

// Custom Seek function for cmsIOHANDLER.
// Sets the current offset within the fuzzer's data.
static cmsBool SeekFn(cmsIOHANDLER* io, cmsUInt32Number Offset) {
    // Fix: Retrieve FuzzerIOData from io->stream.
    FuzzerIOData* fuzzerData = (FuzzerIOData*)io->stream;
    if (Offset > fuzzerData->Size) {
        return FALSE;
    }
    fuzzerData->Offset = Offset;
    return TRUE;
}

// Custom Tell function for cmsIOHANDLER.
// Returns the current offset within the fuzzer's data.
static cmsUInt32Number TellFn(cmsIOHANDLER* io) {
    // Fix: Retrieve FuzzerIOData from io->stream.
    FuzzerIOData* fuzzerData = (FuzzerIOData*)io->stream;
    return (cmsUInt32Number)fuzzerData->Offset;
}

// Custom Close function for cmsIOHANDLER.
// No dynamic memory is allocated for the FuzzerIOData itself, so nothing to free here.
static cmsBool CloseFn(cmsIOHANDLER* io) {
    return TRUE;
}

// Helper function to safely consume bytes from the fuzzer's input buffer.
// This prevents out-of-bounds reads and unaligned access issues.
// Returns 1 on success (enough data consumed), 0 on failure.
static int consume_bytes(const uint8_t *data_buf, size_t data_size, size_t *offset, void *dest, size_t num_bytes) {
    if (*offset + num_bytes > data_size) {
        return 0; // Not enough data in the buffer
    }
    memcpy(dest, data_buf + *offset, num_bytes);
    *offset += num_bytes;
    return 1;
}

// LLVMFuzzerTestOneInput is the main entry point for the fuzzer.
// It takes a pointer to the fuzzer-generated data and its size.
int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size) {
    // Create a new lcms context for each fuzzer run.
    // This ensures isolation between runs and proper memory management.
    cmsContext ContextID = cmsCreateContext(NULL, NULL);
    if (ContextID == NULL) {
        return 0; // Failed to create context, nothing to do.
    }

    size_t current_offset = 0; // Tracks the current position in the fuzzer's input data.

    // 1. Fuzz cmsCreateInkLimitingDeviceLink
    // This function creates a device link profile with ink limiting.
    // We specifically target low-coverage branches identified in cmsCreateInkLimitingDeviceLinkTHR.
    cmsColorSpaceSignature ColorSpace;
    cmsFloat64Number Limit;
    uint8_t choice_byte;

    // Ensure enough data is available for the parameters.
    if (consume_bytes(Data, Size, &current_offset, &choice_byte, sizeof(uint8_t)) &&
        consume_bytes(Data, Size, &current_offset, &Limit, sizeof(cmsFloat64Number))) {

        // Target branch (402:9): [True: 4.98k, False: 13] for `ColorSpace != cmsSigCmykData`
        // We want to hit the `false` branch more often by providing `cmsSigCmykData`.
        if (choice_byte % 2 == 0) {
            ColorSpace = cmsSigCmykData; // This should hit the 'false' branch (CMYK)
        } else {
            ColorSpace = cmsSigRgbData; // This should hit the 'true' branch (non-CMYK, triggering error)
        }

        // Target branches (407:9) and (407:24) for `Limit < 0.0 || Limit > 400`
        // We manipulate `Limit` to fall outside and inside the expected range.
        if (choice_byte % 3 == 0) {
            Limit = -fabs(Limit); // Ensure negative to hit `Limit < 0.0`
        } else if (choice_byte % 3 == 1) {
            Limit = 400.0 + fabs(Limit); // Ensure > 400 to hit `Limit > 400`
        } else {
            Limit = fmod(fabs(Limit), 400.0); // Ensure within [0, 400)
        }

        cmsHPROFILE hProfile = cmsCreateInkLimitingDeviceLink(ColorSpace, Limit);
        if (hProfile) {
            cmsCloseProfile(hProfile); // Free the created profile to prevent memory leaks.
        }
    }

    // 2. Fuzz cmsIT8SetDataRowCol
    // This function sets data in an IT8 table at a specific row and column.
    // It requires a valid cmsHANDLE (IT8 table), row/column indices, and string data.
    int Row, Col;
    uint8_t str_len_byte;

    // Ensure enough data for row, column, and string length indicator.
    if (consume_bytes(Data, Size, &current_offset, &Row, sizeof(int)) &&
        consume_bytes(Data, Size, &current_offset, &Col, sizeof(int)) &&
        consume_bytes(Data, Size, &current_offset, &str_len_byte, sizeof(uint8_t))) {

        cmsHANDLE hIT8 = cmsIT8Alloc(ContextID); // Allocate an IT8 handle.
        if (hIT8) {
            size_t str_len = str_len_byte % 64; // Limit string length to prevent excessive memory allocation.
            char* str_data = NULL;

            if (str_len > 0) {
                str_data = (char*)malloc(str_len + 1); // Allocate memory for the string.
                if (str_data) {
                    // Consume bytes for the string content.
                    if (!consume_bytes(Data, Size, &current_offset, str_data, str_len)) {
                        free(str_data);
                        str_data = NULL; // Not enough data for the full string.
                    } else {
                        str_data[str_len] = '\0'; // Null-terminate the string.
                    }
                }
            } else {
                str_data = (char*)malloc(1); // For an empty string.
                if (str_data) str_data[0] = '\0';
            }

            if (str_data) {
                cmsIT8SetDataRowCol(hIT8, Row, Col, str_data);
                free(str_data); // Free the allocated string data.
            }
            cmsIT8Free(hIT8); // Free the IT8 handle to prevent memory leaks.
        }
    }

    // 3. Fuzz cmsOpenProfileFromIOhandler2THR
    // This function opens an ICC profile from a custom IO handler.
    // We use our custom `FuzzerIOData` and functions to simulate reading from a file.
    if (Size > current_offset) {
        FuzzerIOData fuzzerIO = { Data + current_offset, Size - current_offset, 0 };
        cmsIOHANDLER ioHandler;
        // Initialize the custom IO handler structure.
        ioHandler.ContextID = ContextID; // This is correct, it's the lcms context.
        ioHandler.stream = &fuzzerIO;    // Fix: Store FuzzerIOData pointer in 'stream' member.
        ioHandler.Read = ReadFn;
        ioHandler.Seek = SeekFn;
        ioHandler.Tell = TellFn;
        ioHandler.Close = CloseFn;
        ioHandler.UsedSpace = 0; // Not used by our simple handler.

        // Fuzz the `is_profile_v2` flag to test both code paths.
        cmsBool is_profile_v2 = FALSE;
        if (Size - current_offset >= 1) {
            is_profile_v2 = (Data[current_offset] % 2 == 0) ? TRUE : FALSE;
            current_offset++;
        }

        cmsHPROFILE hProfile = cmsOpenProfileFromIOhandler2THR(ContextID, &ioHandler, is_profile_v2);
        if (hProfile) {
            cmsCloseProfile(hProfile); // Free the opened profile to prevent memory leaks.
        }
    }

    // Delete the lcms context to clean up all resources allocated within it.
    cmsDeleteContext(ContextID);
    return 0;
}