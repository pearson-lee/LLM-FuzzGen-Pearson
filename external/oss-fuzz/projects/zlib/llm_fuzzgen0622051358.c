// Please note that in C, you do not need to use `extern "C"` to declare the `LLVMFuzzerTestOneInput` function, as it is a C function, not a C++ function.
// Additionally, in C, you cannot use FuzzedDataProvider.
#include <stdint.h>
#include <stddef.h>
#include <stdlib.h> // For malloc, free, calloc
#include <string.h> // For memcpy, memset

// Include zlib headers
#include "/src/zlib/zlib.h"
#include "/src/zlib/gzguts.h"   // Required for gz_statep, GZ_WRITE, Z_OK
#undef COPY // Undefine COPY macro to avoid conflict with inflate.h enum
#include "/src/zlib/inftrees.h" // Required for 'code' type and 'ENOUGH' macro
#include "/src/zlib/inflate.h"  // Required for inflate_state, HEAD, SYNC, STORED

// Custom allocation function for zcalloc to hit the 'opaque' branch
voidpf custom_zalloc(voidpf opaque, uInt items, uInt size) {
    (void)opaque; // Unused, but required by signature
    // Ensure items * size does not overflow before calling calloc
    if (items > 0 && size > 0 && items > (SIZE_MAX / size)) {
        return NULL; // Indicate allocation failure due to potential overflow
    }
    return calloc(items, size);
}

// Custom free function for zcalloc
void custom_zfree(voidpf opaque, voidpf address) {
    (void)opaque; // Unused, but required by signature
    free(address);
}

// Helper to consume a single byte from fuzzer input
uint8_t consume_uint8(const uint8_t *data, size_t *current_offset, size_t max_size) {
    if (*current_offset < max_size) {
        return data[(*current_offset)++];
    }
    return 0; // Return 0 if no more data
}

// Helper to consume a size_t from fuzzer input
size_t consume_size_t(const uint8_t *data, size_t *current_offset, size_t max_size) {
    size_t val = 0;
    for (int i = 0; i < sizeof(size_t); ++i) {
        val = (val << 8) | consume_uint8(data, current_offset, max_size);
    }
    return val;
}

// Helper to consume an int from fuzzer input
int consume_int(const uint8_t *data, size_t *current_offset, size_t max_size) {
    int val = 0;
    for (int i = 0; i < sizeof(int); ++i) {
        val = (val << 8) | consume_uint8(data, current_offset, max_size);
    }
    return val;
}

// Helper to consume a uLongf from fuzzer input
uLongf consume_uLongf(const uint8_t *data, size_t *current_offset, size_t max_size) {
    uLongf val = 0;
    for (int i = 0; i < sizeof(uLongf); ++i) {
        val = (val << 8) | consume_uint8(data, current_offset, max_size);
    }
    return val;
}

// Helper to consume a uInt from fuzzer input
uInt consume_uInt(const uint8_t *data, size_t *current_offset, size_t max_size) {
    uInt val = 0;
    for (int i = 0; i < sizeof(uInt); ++i) {
        val = (val << 8) | consume_uint8(data, current_offset, max_size);
    }
    return val;
}


// Fuzzer entry point
int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size) {
    // Offset to keep track of consumed fuzzer data
    size_t offset = 0;

    // --- Fuzzing zutil.c:zcalloc ---
    // Objective: Cover the 'opaque' branch in zcalloc.
    {
        uInt items = consume_uInt(Data, &offset, Size);
        uInt size = consume_uInt(Data, &offset, Size);

        // Limit items and size to prevent excessive memory allocation and potential integer overflow
        if (items > 1024) items = 1024;
        if (size > 1024) size = 1024;

        // Test the path where zlib uses custom allocators via a z_stream
        z_stream strm_custom;
        memset(&strm_custom, 0, sizeof(z_stream));
        strm_custom.zalloc = custom_zalloc;
        strm_custom.zfree = custom_zfree;
        strm_custom.opaque = (voidpf)1; // A non-NULL value for opaque

        // Initialize deflate stream, which will use custom_zalloc
        int ret_custom = deflateInit(&strm_custom, Z_DEFAULT_COMPRESSION);
        if (ret_custom == Z_OK) {
            deflateEnd(&strm_custom); // Clean up
        }

        // Test the NULL opaque path, which uses standard calloc/free (zlib's internal defaults)
        z_stream strm_null_opaque;
        memset(&strm_null_opaque, 0, sizeof(z_stream));
        strm_null_opaque.zalloc = Z_NULL; // Use default allocators
        strm_null_opaque.zfree = Z_NULL;
        strm_null_opaque.opaque = Z_NULL;

        // Initialize deflate stream, which will use zlib's default allocators
        int ret_null = deflateInit(&strm_null_opaque, Z_DEFAULT_COMPRESSION);
        if (ret_null == Z_OK) {
            deflateEnd(&strm_null_opaque); // Clean up
        }
    }

    // --- Fuzzing inflate.c:inflateSyncPoint ---
    // Objective: Trigger `inflateStateCheck` to return an error and hit `state->mode == STORED && state->bits == 0`.
    {
        z_stream strm;
        memset(&strm, 0, sizeof(strm)); // Initialize stream structure to zero

        // Attempt to make inflateStateCheck return Z_STREAM_ERROR
        // by setting zalloc/zfree to NULL or manipulating the internal state.
        if (consume_uint8(Data, &offset, Size) % 2 == 0) {
            strm.zalloc = Z_NULL; // Trigger Z_STREAM_ERROR path
        } else {
            strm.zalloc = custom_zalloc;
        }
        if (consume_uint8(Data, &offset, Size) % 2 == 0) {
            strm.zfree = Z_NULL; // Trigger Z_STREAM_ERROR path
        } else {
            strm.zfree = custom_zfree;
        }

        // Allocate and initialize inflate_state to control its members
        struct inflate_state *state = (struct inflate_state *)malloc(sizeof(struct inflate_state));
        if (state) {
            memset(state, 0, sizeof(struct inflate_state));
            strm.state = (voidpf)state; // Assign the allocated state to the stream

            // Manipulate state->strm to trigger `state->strm != strm` branch
            if (consume_uint8(Data, &offset, Size) % 2 == 0) {
                state->strm = Z_NULL; // Make it different from &strm
            } else {
                state->strm = &strm; // Make it point to the current stream
            }

            // Attempt to set state->mode to STORED and state->bits to 0
            // This is an internal state that is usually reached through specific inflate operations.
            // Manually setting it here helps to directly target the branch.
            if (consume_uint8(Data, &offset, Size) % 2 == 0) {
                state->mode = STORED;
                state->bits = 0;
            } else {
                // Use fuzzer input to set a random mode within valid range
                state->mode = consume_int(Data, &offset, Size) % (SYNC + 1);
                state->bits = consume_int(Data, &offset, Size);
            }

            inflateSyncPoint(&strm); // Call the target function
            free(state); // Free the allocated state
        } else {
            // If malloc fails, call inflateSyncPoint with potentially invalid strm.state
            inflateSyncPoint(&strm);
        }
    }

    // --- Fuzzing gzwrite.c:gzfwrite ---
    // Objective: Cover various error paths and edge cases.
    {
        // Case 1: file == NULL
        gzfwrite(NULL, 1, 1, NULL);

        // Allocate a dummy gz_state structure to simulate a gzFile
        gzFile file = (gzFile)malloc(sizeof(gz_state));
        if (file) {
            gz_statep state = (gz_statep)file;
            memset(state, 0, sizeof(gz_state)); // Initialize to zero

            // Case 2: state->mode != GZ_WRITE
            state->mode = GZ_READ; // Set mode to something other than GZ_WRITE
            gzfwrite(file, 1, 1, file);

            // Case 3: state->err != Z_OK
            state->mode = GZ_WRITE; // Set mode to GZ_WRITE
            state->err = Z_STREAM_ERROR; // Set error to something other than Z_OK
            gzfwrite(file, 1, 1, file);

            // Case 4: size && len / size != nitems (integer overflow scenario)
            // This is difficult to reliably trigger with fuzzer input alone due to SIZE_MAX.
            // We provide large values and rely on the fuzzer to find an overflow if possible.
            size_t nitems_val = consume_size_t(Data, &offset, Size);
            size_t size_val = consume_size_t(Data, &offset, Size);

            // Limit values to prevent excessive memory allocation if they were used for actual buffers
            if (nitems_val > 1024) nitems_val = 1024;
            if (size_val > 1024) size_val = 1024;

            // Attempt to trigger the overflow check
            if (size_val > 0 && nitems_val > (SIZE_MAX / size_val)) {
                gzfwrite(file, nitems_val, size_val, file);
            } else {
                gzfwrite(file, nitems_val, size_val, file);
            }

            // Case 5: len == 0 (nitems = 0 or size = 0)
            gzfwrite(file, 0, 1, file); // nitems = 0
            gzfwrite(file, 1, 0, file); // size = 0

            free(file); // Free the allocated gz_state
        }
    }

    // --- Fuzzing compress.c:compress2 ---
    // Objective: Test various compression parameters and trigger error conditions.
    {
        Bytef *dest = NULL;
        Bytef *source = NULL;
        uLongf destLen = 0;
        uLong sourceLen = 0;
        int level = Z_DEFAULT_COMPRESSION;

        // Consume fuzzer input for sourceLen and compression level
        sourceLen = consume_uLongf(Data, &offset, Size);
        // Ensure level is within valid range [Z_NO_COMPRESSION, Z_BEST_COMPRESSION]
        level = consume_int(Data, &offset, Size) % (Z_BEST_COMPRESSION + 1);

        // Limit sourceLen to prevent excessive memory allocation
        if (sourceLen > 1024 * 1024) sourceLen = 1024 * 1024; // Max 1MB input data

        source = (Bytef *)malloc(sourceLen);
        if (source) {
            // Fill source buffer with fuzzer data
            size_t bytes_to_copy = (Size - offset < sourceLen) ? (Size - offset) : sourceLen;
            memcpy(source, Data + offset, bytes_to_copy);
            offset += bytes_to_copy;

            // Calculate a reasonable destination buffer size
            destLen = compressBound(sourceLen);
            dest = (Bytef *)malloc(destLen);

            if (dest) {
                // Call compress2 with the fuzzer-provided parameters
                compress2(dest, &destLen, source, sourceLen, level);
                free(dest); // Free destination buffer
            }
            free(source); // Free source buffer
        }
    }

    // --- Fuzzing deflate.c:deflateParams ---
    // Objective: Test various compression levels and strategies, and invalid stream states.
    {
        z_stream strm;
        memset(&strm, 0, sizeof(strm)); // Initialize stream structure

        // Initialize the deflate stream
        int ret = deflateInit(&strm, Z_DEFAULT_COMPRESSION);
        if (ret == Z_OK) {
            // Consume fuzzer input for level and strategy
            int level = consume_int(Data, &offset, Size) % (Z_BEST_COMPRESSION + 1);
            int strategy = consume_int(Data, &offset, Size) % (Z_FIXED + 1); // Z_DEFAULT_STRATEGY to Z_FIXED

            // Call deflateParams with valid stream state
            deflateParams(&strm, level, strategy);

            // Clean up the stream
            deflateEnd(&strm);

            // Test deflateParams with an invalid stream state (after deflateEnd)
            // This should typically return Z_STREAM_ERROR
            deflateParams(&strm, level, strategy);
        }
    }

    return 0;
}