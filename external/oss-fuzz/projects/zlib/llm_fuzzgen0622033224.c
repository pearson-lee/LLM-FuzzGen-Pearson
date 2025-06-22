// Please note that in C, you do not need to use `extern "C"` to declare the `LLVMFuzzerTestOneInput` function, as it is a C function, not a C++ function.
// Additionally, in C, you cannot use FuzzedDataProvider directly, so a custom implementation is provided.
#include <stdint.h>
#include <stddef.h>
#include <stdlib.h> // For calloc, malloc, free
#include <string.h> // For memcpy

// Include zlib headers
#include "/src/zlib/zlib.h"
#include "/src/zlib/zutil.h" // For z_word_t, zcalloc, zcfree
#include "/src/zlib/deflate.h" // For internal_state definition
#include "/src/zlib/gzguts.h" // For gz_header

// Basic FuzzedDataProvider implementation for C
typedef struct {
    const uint8_t *data;
    size_t size;
    size_t offset;
} FuzzedDataProvider;

void FuzzedDataProvider_init(FuzzedDataProvider *fdp, const uint8_t *data, size_t size) {
    fdp->data = data;
    fdp->size = size;
    fdp->offset = 0;
}

size_t FuzzedDataProvider_remaining_bytes(FuzzedDataProvider *fdp) {
    return fdp->size - fdp->offset;
}

uint8_t FuzzedDataProvider_ConsumeUint8(FuzzedDataProvider *fdp) {
    if (FuzzedDataProvider_remaining_bytes(fdp) < sizeof(uint8_t)) {
        return 0; // Not enough data, return default
    }
    uint8_t value = fdp->data[fdp->offset];
    fdp->offset += sizeof(uint8_t);
    return value;
}

int FuzzedDataProvider_ConsumeIntegralInRange_int(FuzzedDataProvider *fdp, int min, int max) {
    if (FuzzedDataProvider_remaining_bytes(fdp) < sizeof(uint8_t)) { // Use uint8_t for range calculation
        return min; // Not enough data, return min
    }
    // Simple way to get a value in range, not perfectly uniform
    int value = min + (FuzzedDataProvider_ConsumeUint8(fdp) % (max - min + 1));
    return value;
}

uLong FuzzedDataProvider_ConsumeIntegral_uLong(FuzzedDataProvider *fdp) {
    if (FuzzedDataProvider_remaining_bytes(fdp) < sizeof(uLong)) {
        return 0; // Not enough data, return default
    }
    uLong value = 0;
    // Consume bytes for uLong
    for (size_t i = 0; i < sizeof(uLong); ++i) {
        value = (value << 8) | FuzzedDataProvider_ConsumeUint8(fdp);
    }
    return value;
}

const uint8_t *FuzzedDataProvider_ConsumeBytes(FuzzedDataProvider *fdp, size_t num_bytes, size_t *out_len) {
    size_t bytes_to_consume = num_bytes;
    if (FuzzedDataProvider_remaining_bytes(fdp) < bytes_to_consume) {
        bytes_to_consume = FuzzedDataProvider_remaining_bytes(fdp);
    }
    const uint8_t *ptr = fdp->data + fdp->offset;
    fdp->offset += bytes_to_consume;
    *out_len = bytes_to_consume;
    return ptr;
}

// Custom allocation functions to track memory and ensure no leaks
static voidpf custom_alloc(voidpf opaque, uInt items, uInt size) {
    (void)opaque; // Unused
    return calloc(items, size);
}

static void custom_free(voidpf opaque, voidpf address) {
    (void)opaque; // Unused
    free(address);
}

// Fuzz target
int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size) {
    FuzzedDataProvider fdp;
    FuzzedDataProvider_init(&fdp, Data, Size);

    // Added to cover deflateStateCheck(strm) when strm is Z_NULL.
    // This will hit the 'strm == Z_NULL' branch in deflateStateCheck.
    deflateSetHeader(Z_NULL, Z_NULL);

    // 1. Fuzz zlibCompileFlags
    // This function takes no arguments and provides information about zlib's compilation flags.
    // Calling it helps exercise its internal logic, including switch statements based on sizeof types.
    zlibCompileFlags();

    // 2. Fuzz deflateInit2_ and deflateBound
    // These functions are critical for zlib's compression functionality.
    // We aim to cover various initialization paths and the gzip header handling in deflateBound.
    z_stream strm;
    // Set custom allocation functions to ensure memory safety and track allocations.
    strm.zalloc = custom_alloc;
    strm.zfree = custom_free;
    strm.opaque = Z_NULL; // Opaque pointer for custom allocators, not used here.

    // Consume fuzzed inputs for deflateInit2_ parameters.
    // 'level' can range from -1 (Z_DEFAULT_COMPRESSION) to 9.
    int level = FuzzedDataProvider_ConsumeIntegralInRange_int(&fdp, -1, 9);
    // 'method' is typically Z_DEFLATED for standard compression.
    int method = Z_DEFLATED;
    // 'windowBits' controls the window size and wrapper type (zlib, gzip, or raw).
    // Values 8-15 are for zlib, >15 (e.g., 16-31) for gzip.
    int windowBits = FuzzedDataProvider_ConsumeIntegralInRange_int(&fdp, 8, 31);
    // 'memLevel' controls memory usage for internal compression state.
    int memLevel = FuzzedDataProvider_ConsumeIntegralInRange_int(&fdp, 1, MAX_MEM_LEVEL);
    // 'strategy' influences the compression algorithm.
    int strategy = FuzzedDataProvider_ConsumeIntegralInRange_int(&fdp, Z_DEFAULT_STRATEGY, Z_FIXED);

    // To specifically target the gzip wrapper branch in deflateBound,
    // we can force windowBits to be in the gzip range (16-31) with some probability.
    if (FuzzedDataProvider_ConsumeUint8(&fdp) % 2 == 0) {
        windowBits = FuzzedDataProvider_ConsumeIntegralInRange_int(&fdp, 16, 31);
    }

    // 'version' and 'stream_size' are fixed for compatibility checks.
    const char *version = ZLIB_VERSION;
    int stream_size = sizeof(z_stream);

    // Initialize the deflation stream.
    int ret = deflateInit2_(&strm, level, method, windowBits, memLevel, strategy, version, stream_size);

    if (ret == Z_OK) {
        // Store the internal state pointer before deflateEnd clears it.
        // This is crucial for manually freeing gzhead later, as deflateEnd sets strm.state to Z_NULL.
        struct internal_state FAR *internal_state_ptr = (struct internal_state FAR *)strm.state;

        // Added to improve coverage of deflateReset based on function-level coverage report.
        // Resets the stream to its initial state, allowing for different fuzzing paths.
        deflateReset(&strm);

        // Added to improve coverage of deflateParams based on function-level coverage report.
        // Fuzzing parameters mid-stream can exercise different compression strategies.
        int new_level = FuzzedDataProvider_ConsumeIntegralInRange_int(&fdp, -1, 9);
        int new_strategy = FuzzedDataProvider_ConsumeIntegralInRange_int(&fdp, Z_DEFAULT_STRATEGY, Z_FIXED);
        deflateParams(&strm, new_level, new_strategy);

        // Added to improve coverage of deflateCopy based on function-level coverage report.
        // This tests the stream state copying mechanism.
        z_stream strm_copy;
        strm_copy.zalloc = custom_alloc;
        strm_copy.zfree = custom_free;
        strm_copy.opaque = Z_NULL;
        int copy_ret = deflateCopy(&strm_copy, &strm);

        // If initialization is successful, fuzz deflateBound.
        // 'sourceLen' represents the input data length for compression.
        uLong sourceLen = FuzzedDataProvider_ConsumeIntegral_uLong(&fdp);
        deflateBound(&strm, sourceLen);

        // Added to cover deflateSetHeader when strm->state->wrap is not 2.
        // Pass Z_NULL for gz_headerp to cover that path.
        if (internal_state_ptr != Z_NULL && internal_state_ptr->wrap != 2) {
            deflateSetHeader(&strm, Z_NULL);
        }

        // To cover gzhead-related branches in deflateBound, if gzip wrapper is enabled.
        // We need to cast strm.state to internal_state* to access its internal members.
        if (internal_state_ptr != Z_NULL && internal_state_ptr->wrap == 2) {
            gz_header *gzhead = (gz_header *)calloc(1, sizeof(gz_header));
            if (gzhead != Z_NULL) {
                internal_state_ptr->gzhead = gzhead;

                // Fuzz gzhead fields to cover more branches.
                // extra field
                if (FuzzedDataProvider_ConsumeUint8(&fdp) % 2 == 0) {
                    size_t extra_len;
                    // Consume up to 100 bytes for extra data.
                    const uint8_t *extra_data = FuzzedDataProvider_ConsumeBytes(&fdp, 100, &extra_len);
                    if (extra_len > 0) {
                        gzhead->extra = (Bytef *)malloc(extra_len);
                        if (gzhead->extra != Z_NULL) {
                            memcpy(gzhead->extra, extra_data, extra_len);
                            gzhead->extra_len = (uInt)extra_len;
                            gzhead->extra_max = (uInt)extra_len; // Set max to current length for simplicity
                        }
                    }
                }

                // name field
                if (FuzzedDataProvider_ConsumeUint8(&fdp) % 2 == 0) {
                    size_t name_len;
                    // Consume up to 99 bytes for the name, plus one for null terminator.
                    const uint8_t *name_data = FuzzedDataProvider_ConsumeBytes(&fdp, 99, &name_len);
                    if (name_len > 0) {
                        gzhead->name = (Bytef *)malloc(name_len + 1);
                        if (gzhead->name != Z_NULL) {
                            memcpy(gzhead->name, name_data, name_len);
                            gzhead->name[name_len] = '\0'; // Null-terminate the string
                        }
                    }
                }

                // comment field
                if (FuzzedDataProvider_ConsumeUint8(&fdp) % 2 == 0) {
                    size_t comment_len;
                    // Consume up to 99 bytes for the comment, plus one for null terminator.
                    const uint8_t *comment_data = FuzzedDataProvider_ConsumeBytes(&fdp, 99, &comment_len);
                    if (comment_len > 0) {
                        gzhead->comment = (Bytef *)malloc(comment_len + 1);
                        if (gzhead->comment != Z_NULL) {
                            memcpy(gzhead->comment, comment_data, comment_len);
                            gzhead->comment[comment_len] = '\0'; // Null-terminate the string
                        }
                    }
                }

                // hcrc field
                if (FuzzedDataProvider_ConsumeUint8(&fdp) % 2 == 0) {
                    gzhead->hcrc = 1;
                }
            }
        }

        // Added to improve coverage of deflateSetDictionary based on function-level coverage report.
        size_t dict_len;
        const uint8_t *dictionary_data = FuzzedDataProvider_ConsumeBytes(&fdp, FuzzedDataProvider_remaining_bytes(&fdp) / 2, &dict_len);
        if (dict_len > 0) {
            deflateSetDictionary(&strm, (const Bytef *)dictionary_data, (uInt)dict_len);
        }

        // Added to improve coverage of the core deflate function based on function-level coverage report.
        size_t in_len;
        const uint8_t *in_data = FuzzedDataProvider_ConsumeBytes(&fdp, FuzzedDataProvider_remaining_bytes(&fdp), &in_len);
        
        if (in_len > 0) {
            strm.avail_in = (uInt)in_len;
            strm.next_in = (Bytef *)in_data;

            // Allocate output buffer, using deflateBound for a safe upper estimate.
            uLong out_buf_size = deflateBound(&strm, in_len);
            if (out_buf_size == 0) out_buf_size = in_len * 2; // Fallback for small inputs or edge cases

            Bytef *out_buf = (Bytef *)malloc(out_buf_size);
            if (out_buf != Z_NULL) {
                strm.avail_out = (uInt)out_buf_size;
                strm.next_out = out_buf;

                // Fuzz 'flush' parameter for deflate
                int flush = FuzzedDataProvider_ConsumeIntegralInRange_int(&fdp, Z_NO_FLUSH, Z_FINISH);

                deflate(&strm, flush);

                // Added to cover deflateResetKeep with s->wrap < 0.
                // This ensures deflateReset is called after deflate with Z_FINISH,
                // allowing the 's->wrap < 0' branch in deflateResetKeep to be hit.
                if (flush == Z_FINISH) {
                    deflateReset(&strm);
                }

                // Added to improve coverage of deflateGetDictionary based on function-level coverage report.
                // Retrieve the dictionary from the stream after deflation.
                // Allocate a buffer large enough for the maximum possible dictionary size (1 << MAX_WBITS).
                Bytef *retrieved_dict = (Bytef *)malloc(1 << MAX_WBITS); 
                uInt retrieved_dict_len = 0;
                if (retrieved_dict != Z_NULL) {
                    deflateGetDictionary(&strm, retrieved_dict, &retrieved_dict_len);
                    free(retrieved_dict); // Free the retrieved dictionary buffer to prevent memory leaks.
                }

                free(out_buf); // Free output buffer to prevent memory leaks.
            }
        }

        // Manually free gzhead and its members if they were allocated.
        // This is crucial for memory safety as deflateEnd sets strm.state to Z_NULL.
        // The internal_state_ptr was captured before deflateEnd for this purpose.
        if (internal_state_ptr != Z_NULL && internal_state_ptr->gzhead != Z_NULL) {
            gz_header *header_to_free = internal_state_ptr->gzhead;
            if (header_to_free->extra != Z_NULL) {
                free(header_to_free->extra);
            }
            if (header_to_free->name != Z_NULL) {
                free(header_to_free->name);
            }
            if (header_to_free->comment != Z_NULL) {
                free(header_to_free->comment);
            }
            free(header_to_free);
            internal_state_ptr->gzhead = Z_NULL; // Clear the pointer after freeing
        }

        // Clean up the original deflation stream.
        deflateEnd(&strm);

        // Clean up the copied deflation stream if it was successfully created.
        // deflateCopy allocates internal structures that must be freed by deflateEnd.
        if (copy_ret == Z_OK) {
            deflateEnd(&strm_copy);
        }
    } else {
        // Added to cover deflateCopy returning non-Z_OK when stream is not initialized.
        // This will hit the 'strm->state == Z_NULL' branch in deflateStateCheck within deflateCopy.
        z_stream strm_copy_fail;
        strm_copy_fail.zalloc = custom_alloc;
        strm_copy_fail.zfree = custom_free;
        strm_copy_fail.opaque = Z_NULL;
        deflateCopy(&strm_copy_fail, &strm); // strm is not Z_OK here, so deflateCopy should fail.
        // No need to deflateEnd strm_copy_fail as it won't be initialized by deflateCopy.
    }

    // 3. Fuzz crc32_z
    // This function calculates the CRC-32 checksum of a data buffer.
    // It is chosen to indirectly exercise the static byte_swap and crc_word_big functions
    // which are internal to crc32.c and not directly callable.
    if (FuzzedDataProvider_remaining_bytes(&fdp) >= 4) { // Ensure enough bytes for initial CRC and some data
        uLong crc = FuzzedDataProvider_ConsumeIntegral_uLong(&fdp); // Initial CRC value
        size_t data_len;
        // Consume remaining bytes as input data for CRC calculation.
        const Bytef *data_ptr = FuzzedDataProvider_ConsumeBytes(&fdp, FuzzedDataProvider_remaining_bytes(&fdp), &data_len);
        if (data_len > 0) {
            crc32_z(crc, data_ptr, (uInt)data_len);
        }
    }

    return 0;
}