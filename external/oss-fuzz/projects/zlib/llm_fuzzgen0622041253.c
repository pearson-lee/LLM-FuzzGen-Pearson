#include <stdint.h>
#include <stddef.h>
#include <stdlib.h> // For malloc and free
#include <string.h> // For memcpy
#include <limits.h> // For ULONG_MAX

// Include zlib headers
#include "/src/zlib/zlib.h"
#include "/src/zlib/zutil.h" // For zcalloc and zcfree

// Define a custom allocation function for z_stream
static voidpf custom_alloc(voidpf opaque, uInt items, uInt size) {
    (void)opaque; // Unused
    return calloc(items, size);
}

// Define a custom free function for z_stream
static void custom_free(voidpf opaque, voidpf address) {
    (void)opaque; // Unused
    free(address);
}

// FuzzedDataProvider equivalent for C
typedef struct {
    const uint8_t *data;
    size_t size;
    size_t offset;
} FuzzedData;

void FuzzedData_init(FuzzedData *fd, const uint8_t *Data, size_t Size) {
    fd->data = Data;
    fd->size = Size;
    fd->offset = 0;
}

// Consume a byte
uint8_t FuzzedData_ConsumeUint8(FuzzedData *fd) {
    if (fd->offset < fd->size) {
        return fd->data[fd->offset++];
    }
    return 0; // Default value if no more data
}

// Consume a size_t in a range
size_t FuzzedData_ConsumeIntegralInRange_size_t(FuzzedData *fd, size_t min, size_t max) {
    if (fd->offset + sizeof(size_t) <= fd->size) {
        size_t val;
        memcpy(&val, fd->data + fd->offset, sizeof(size_t));
        fd->offset += sizeof(size_t);
        return min + (val % (max - min + 1));
    }
    return min; // Default value if no more data
}

// Consume uLong
uLong FuzzedData_ConsumeIntegral_uLong(FuzzedData *fd) {
    if (fd->offset + sizeof(uLong) <= fd->size) {
        uLong val;
        memcpy(&val, fd->data + fd->offset, sizeof(uLong));
        fd->offset += sizeof(uLong);
        return val;
    }
    return 0; // Default value if no more data
}

// Consume bytes
const uint8_t *FuzzedData_ConsumeBytes(FuzzedData *fd, size_t num_bytes, size_t *out_len) {
    if (fd->offset + num_bytes <= fd->size) {
        *out_len = num_bytes;
        const uint8_t *ptr = fd->data + fd->offset;
        fd->offset += num_bytes;
        return ptr;
    }
    *out_len = 0;
    return NULL;
}

// Remaining bytes
size_t FuzzedData_remaining_bytes(FuzzedData *fd) {
    return fd->size - fd->offset;
}

// Custom input function for inflateBack
static unsigned int custom_in(voidpf in_desc, unsigned char FAR *buf, unsigned int len) {
    FuzzedData *fd = (FuzzedData *)in_desc;
    size_t bytes_to_read = len;
    size_t actual_read_len;
    const uint8_t *data = FuzzedData_ConsumeBytes(fd, bytes_to_read, &actual_read_len);
    if (data) {
        memcpy(buf, data, actual_read_len);
        return (unsigned int)actual_read_len;
    }
    return 0;
}

// Custom output function for inflateBack
static int custom_out(voidpf out_desc, unsigned char FAR *buf, unsigned int len) {
    // In a fuzzer, we typically just consume the output or discard it.
    // For now, we'll just return 0 (success).
    (void)out_desc; // Unused
    (void)buf;      // Unused
    (void)len;      // Unused
    return 0; // Indicate success
}


int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size) {
    FuzzedData fd;
    FuzzedData_init(&fd, Data, Size);

    // Call zlibCompileFlags - no input needed
    // This function has low branch coverage due to compile-time checks,
    // but calling it ensures its execution path is covered.
    (void)zlibCompileFlags();

    z_stream strm;
    unsigned char *window = NULL;
    int ret;

    // Initialize strm for all tests to ensure consistent state
    strm.zalloc = custom_alloc;
    strm.zfree = custom_free;
    strm.opaque = Z_NULL;
    strm.state = Z_NULL; // Ensure state is NULL initially for inflateBack error tests

    // Scenario 1: Test error conditions for inflateBackInit_ to hit missed branches

    // Test version == Z_NULL (targets Branch 30:9 True)
    ret = inflateBackInit_(&strm, 10, NULL, Z_NULL, sizeof(z_stream));

    // Test version[0] != ZLIB_VERSION[0] (targets Branch 30:30 True)
    char wrong_version[2] = "X";
    ret = inflateBackInit_(&strm, 10, NULL, wrong_version, sizeof(z_stream));

    // Test stream_size != (int)(sizeof(z_stream)) (targets Branch 31:9 True)
    ret = inflateBackInit_(&strm, 10, NULL, ZLIB_VERSION, sizeof(z_stream) + 1);

    // Test strm == Z_NULL (targets Branch 33:9 True)
    // Passing Z_NULL directly to trigger the check before dereferencing strm.
    ret = inflateBackInit_(Z_NULL, 10, NULL, ZLIB_VERSION, sizeof(z_stream));

    // Test window == Z_NULL (targets Branch 33:27 True)
    ret = inflateBackInit_(&strm, 10, NULL, ZLIB_VERSION, sizeof(z_stream));

    // Test windowBits < 8 (targets Branch 34:9 True)
    ret = inflateBackInit_(&strm, 7, NULL, ZLIB_VERSION, sizeof(z_stream));

    // Test windowBits > 15 (targets Branch 34:27 True)
    ret = inflateBackInit_(&strm, 16, NULL, ZLIB_VERSION, sizeof(z_stream));

    // Test Z_MEM_ERROR (targets Branch 53:9 True)
    // Temporarily set zalloc to return NULL to simulate memory allocation failure.
    strm.zalloc = (alloc_func)0;
    strm.zfree = (free_func)0;
    ret = inflateBackInit_(&strm, 10, NULL, ZLIB_VERSION, sizeof(z_stream));
    // Reset zalloc/zfree for subsequent calls to allow normal operation.
    strm.zalloc = custom_alloc;
    strm.zfree = custom_free;


    // Scenario 2: Valid calls to inflateBackInit_ for normal execution paths
    // Fuzz windowBits between 8 and 15 to cover valid ranges.
    int windowBits = (int)FuzzedData_ConsumeIntegralInRange_size_t(&fd, 8, 15);
    size_t window_size = 1U << windowBits;
    window = (unsigned char *)malloc(window_size);
    if (window == NULL) {
        return 0; // Out of memory, exit early.
    }

    ret = inflateBackInit_(&strm, windowBits, window, ZLIB_VERSION, sizeof(z_stream));
    if (ret == Z_OK) {
        // If initialization is successful, end the stream to clean up resources.
        inflateBackEnd(&strm);
    }
    // Free the window buffer allocated for inflateBackInit_.
    free(window);
    window = NULL; // Set to NULL after freeing to prevent use-after-free


    // Scenario 3: Fuzz inflateBack with actual data and hit error conditions
    // Added calls to hit Branch (260:9) and (260:27) True in inflateBack (strm == Z_NULL || strm->state == Z_NULL)
    // These calls are made before any successful inflateBackInit_ to ensure strm->state is Z_NULL.
    inflateBack(Z_NULL, custom_in, &fd, custom_out, NULL); // strm == Z_NULL
    strm.state = Z_NULL; // Ensure strm->state is NULL for the next test
    inflateBack(&strm, custom_in, &fd, custom_out, NULL); // strm->state == Z_NULL

    // Re-initialize strm for inflateBack fuzzing
    strm.zalloc = custom_alloc;
    strm.zfree = custom_free;
    strm.opaque = Z_NULL;
    strm.state = Z_NULL; // Reset state for proper initialization

    // Allocate a window for inflateBackInit_
    windowBits = (int)FuzzedData_ConsumeIntegralInRange_size_t(&fd, 8, 15);
    window_size = 1U << windowBits;
    window = (unsigned char *)malloc(window_size);
    if (window == NULL) {
        // Memory allocation failed, return early.
        return 0;
    }

    ret = inflateBackInit_(&strm, windowBits, window, ZLIB_VERSION, sizeof(z_stream));
    if (ret == Z_OK) {
        // Prepare FuzzedData for inflateBack
        FuzzedData inflate_fd;
        // Use remaining data for inflateBack input
        FuzzedData_init(&inflate_fd, Data + fd.offset, FuzzedData_remaining_bytes(&fd));

        // Added call to hit Branch (270:12) True in inflateBack (next != Z_NULL is false)
        // This test requires a valid strm->state, but with next_in and avail_in set to 0.
        strm.next_in = Z_NULL;
        strm.avail_in = 0;
        inflateBack(&strm, custom_in, &inflate_fd, custom_out, NULL);

        // Re-initialize inflate_fd for the main inflateBack fuzzing to ensure it starts from the correct offset
        FuzzedData_init(&inflate_fd, Data + fd.offset, FuzzedData_remaining_bytes(&fd));
        // Call inflateBack with fuzzed data
        ret = inflateBack(&strm, custom_in, &inflate_fd, custom_out, NULL);
        // Clean up
        inflateBackEnd(&strm);
    }
    // Free the window buffer allocated for inflateBack.
    free(window);
    window = NULL; // Set to NULL after freeing to prevent use-after-free


    // Fuzz crc32_z
    // This function indirectly exercises byte_swap, which had 0% coverage.
    uLong crc = FuzzedData_ConsumeIntegral_uLong(&fd); // Consume a uLong for the initial CRC value.
    size_t data_len;
    // Consume remaining data for the input buffer.
    const uint8_t *input_data = FuzzedData_ConsumeBytes(&fd, FuzzedData_remaining_bytes(&fd), &data_len);

    if (input_data != NULL) {
        (void)crc32_z(crc, input_data, data_len);
    }

    return 0;
}