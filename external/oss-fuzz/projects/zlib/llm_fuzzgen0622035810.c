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


int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size) {
    FuzzedData fd;
    FuzzedData_init(&fd, Data, Size);

    // Call zlibCompileFlags - no input needed
    // This function has low branch coverage due to compile-time checks,
    // but calling it ensures its execution path is covered.
    (void)zlibCompileFlags();

    // Fuzz inflateBackInit_
    z_stream strm;
    unsigned char *window = NULL;
    int ret;

    // Initialize strm for all tests to ensure consistent state
    strm.zalloc = custom_alloc;
    strm.zfree = custom_free;
    strm.opaque = Z_NULL;

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