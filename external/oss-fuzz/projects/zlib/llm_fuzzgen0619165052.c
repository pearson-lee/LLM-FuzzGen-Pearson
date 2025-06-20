#define _LARGEFILE64_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <stddef.h>
#include "/src/zlib/zlib.h"
#include "/src/zlib/gzguts.h"

// Helper structure and callbacks for inflateBack.
// This allows us to stream data from a memory buffer to the decompressor.
struct fuzzer_stream_state {
    const uint8_t *in_data;
    size_t in_size;
    size_t in_off;
    uint8_t *out_data;
    size_t out_size;
    size_t out_off;
};

// Input callback for inflateBack. Provides compressed data to zlib.
static unsigned fuzzer_in_func(void *in_desc, unsigned char **buf) {
    struct fuzzer_stream_state *state = (struct fuzzer_stream_state *)in_desc;
    if (state->in_off >= state->in_size) {
        return 0;
    }
    *buf = (unsigned char *)state->in_data + state->in_off;
    size_t read_size = state->in_size - state->in_off;
    state->in_off += read_size;
    return read_size;
}

// Output callback for inflateBack. Receives decompressed data from zlib.
static int fuzzer_out_func(void *out_desc, unsigned char *buf, unsigned len) {
    struct fuzzer_stream_state *state = (struct fuzzer_stream_state *)out_desc;
    if (state->out_off + len > state->out_size) {
        return 1; // Indicates an error (output buffer too small).
    }
    memcpy(state->out_data + state->out_off, buf, len);
    state->out_off += len;
    return 0;
}


// The fuzzer entry point.
// It takes a buffer of data and its size as input.
int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    if (size < 1) {
        return 0;
    }

    // Create a temporary file to be used with gzdopen.
    FILE *tmp = tmpfile();
    if (!tmp) {
        return 0;
    }
    int fd = fileno(tmp);

    // The mode for gzdopen is determined by the first byte of the input data.
    const char *mode = (data[0] % 2 == 0) ? "rb" : "wb";
    data++;
    size--;

    // Open the temporary file as a gzFile.
    gzFile file = gzdopen(fd, mode);
    if (file == NULL) {
        fclose(tmp);
        return 0;
    }

    // Consume the fuzzer data to exercise the target APIs.
    if (size > 0) {
        // Use one byte to decide which API to call.
        uint8_t api_selector = data[0];
        data++;
        size--;

        switch (api_selector % 23) { // Increased modulo to call more uncovered APIs.
        case 0:
            // Call gzputc with the remaining data.
            for (size_t i = 0; i < size; ++i) {
                gzputc(file, data[i]);
            }
            break;
        case 1:
            // Call gzputs with the remaining data as a string.
            // The data is not null-terminated, so we create a null-terminated string.
            if (size > 0) {
                char *str = (char *)malloc(size + 1);
                if (str) {
                    memcpy(str, data, size);
                    str[size] = '\0';
                    gzputs(file, str);
                    free(str);
                }
            }
            break;
        case 2:
            // Call gzgets to read a line from the file.
            // First, write the data to the file.
            if (size > 0) {
                gzwrite(file, data, size);
                gzrewind(file);
                char *buf = (char *)malloc(size);
                if (buf) {
                    gzgets(file, buf, size);
                    free(buf);
                }
            }
            break;
        case 3:
            // Call gzseek to move the file pointer.
            if (size >= 2) { // Fixed potential out-of-bounds read from original fuzzer.
                off_t offset = (off_t)data[0];
                off64_t offset64 = (off64_t)data[0];
                int whence = (data[1] % 2 == 0) ? SEEK_SET : SEEK_CUR;
                gzseek(file, offset, whence);
                // Added calls to uncovered 64-bit and offset functions based on coverage report.
                gzseek64(file, offset64, whence);
                gztell64(file);
                gzoffset(file);
                gzoffset64(file);
            }
            break;
        case 4:
            // Added call to uncovered function gzprintf() based on coverage report.
            if (size > 0) {
                char *str = (char *)malloc(size + 1);
                if (str) {
                    memcpy(str, data, size);
                    str[size] = '\0';
                    // Memory safety: str is freed after use.
                    gzprintf(file, "fuzz: %s", str);
                    free(str);
                }
            }
            break;
        case 5:
            // Added calls to uncovered functions gzgetc() and gzungetc() based on coverage report.
            if (size > 0) {
                gzwrite(file, data, size);
                gzrewind(file);
                int c = gzgetc(file);
                if (c != -1) {
                    gzungetc(c, file);
                }
            }
            break;
        case 6:
            // Added calls to uncovered functions gztell(), gzeof(), and gzdirect() based on coverage report.
            gztell(file);
            gzeof(file);
            gzdirect(file);
            break;
        case 7:
            // Added calls to uncovered functions gzerror() and gzclearerr() based on coverage report.
            gzerror(file, NULL);
            gzclearerr(file);
            break;
        case 8:
            // Added call to uncovered function gzbuffer() based on coverage report.
            if (size > 0) {
                gzbuffer(file, (unsigned int)data[0]);
            }
            break;
        case 9:
            // Added call to uncovered function gzfread() based on coverage report.
            if (size > 0) {
                gzwrite(file, data, size);
                gzrewind(file);
                char *buf = (char *)malloc(size);
                if (buf) {
                    // Memory safety: buf is freed after use.
                    gzfread(buf, 1, size, file);
                    free(buf);
                }
            }
            break;
        case 10:
            // Added calls to uncovered functions gzsetparams() and gzflush() based on coverage report.
            if (strcmp(mode, "wb") == 0 && size > 2) {
                int level = data[0] % 10;
                int strategy = data[1] % 5;
                gzsetparams(file, level, strategy);

                gzwrite(file, data + 2, size - 2);
                int flush_mode = data[2] % 4;
                switch(flush_mode) {
                    case 0: gzflush(file, Z_NO_FLUSH); break;
                    case 1: gzflush(file, Z_SYNC_FLUSH); break;
                    case 2: gzflush(file, Z_FULL_FLUSH); break;
                    case 3: gzflush(file, Z_FINISH); break;
                }
            }
            break;
        case 11:
            // Added calls to uncovered functions zlibVersion(), zlibCompileFlags(), and zError() based on coverage report.
            zlibVersion();
            zlibCompileFlags();
            get_crc_table(); // Added call to uncovered function get_crc_table()
            if (size > 0) {
                zError(data[0] % 9 - 6);
            } else {
                zError(0);
            }
            break;
        case 12:
            // Added calls to uncovered functions compress(), uncompress(), and compressBound() based on coverage report.
            if (size > 0) {
                uLongf destLen = compressBound(size);
                Bytef *dest = (Bytef *)malloc(destLen);
                if (dest) {
                    // Memory safety: dest is freed after use.
                    if (compress(dest, &destLen, data, size) == Z_OK) {
                        uLongf uncompLen = size;
                        Bytef *uncomp = (Bytef *)malloc(uncompLen);
                        if (uncomp) {
                            // Memory safety: uncomp is freed after use.
                            uncompress(uncomp, &uncompLen, dest, destLen);
                            free(uncomp);
                        }
                    }
                    free(dest);
                }
            }
            break;
        case 13:
            // Added calls to uncovered functions inflateBack, inflateBackInit, and inflateBackEnd.
            if (size > 1) {
                uLongf comp_size = compressBound(size);
                Bytef *comp_buf = (Bytef *)malloc(comp_size);
                if (!comp_buf) break;

                // Memory safety: comp_buf is freed below.
                if (compress(comp_buf, &comp_size, data, size) == Z_OK) {
                    z_stream strm;
                    memset(&strm, 0, sizeof(z_stream));
                    strm.zalloc = Z_NULL;
                    strm.zfree = Z_NULL;
                    strm.opaque = Z_NULL;

                    unsigned char *window = (unsigned char *)malloc(1 << 15);
                    if (window) {
                        // Memory safety: window is freed below.
                        if (inflateBackInit(&strm, 15, window) == Z_OK) {
                            struct fuzzer_stream_state s;
                            s.in_data = comp_buf;
                            s.in_size = comp_size;
                            s.in_off = 0;
                            s.out_size = size;
                            s.out_data = (uint8_t *)malloc(s.out_size);
                            s.out_off = 0;
                            if (s.out_data) {
                                // Memory safety: s.out_data is freed below.
                                inflateBack(&strm, fuzzer_in_func, &s, fuzzer_out_func, &s);
                                free(s.out_data);
                            }
                            inflateBackEnd(&strm);
                        }
                        free(window);
                    }
                }
                free(comp_buf);
            }
            break;
        case 14:
            // Added calls to uncovered dictionary functions deflateSetDictionary and inflateSetDictionary.
            if (size > 128) {
                size_t dict_size = 100;
                const Bytef *dict = data;
                const Bytef *source = data + dict_size;
                size_t source_size = size - dict_size;

                z_stream def_strm;
                memset(&def_strm, 0, sizeof(z_stream));
                def_strm.zalloc = Z_NULL;
                def_strm.zfree = Z_NULL;
                def_strm.opaque = Z_NULL;

                if (deflateInit(&def_strm, Z_DEFAULT_COMPRESSION) == Z_OK) {
                    deflateSetDictionary(&def_strm, dict, dict_size);
                    uLongf comp_size = compressBound(source_size);
                    Bytef *comp_buf = (Bytef *)malloc(comp_size);
                    if (comp_buf) {
                        // Memory safety: comp_buf is freed below.
                        def_strm.next_in = (Bytef *)source;
                        def_strm.avail_in = source_size;
                        def_strm.next_out = comp_buf;
                        def_strm.avail_out = comp_size;
                        deflate(&def_strm, Z_FINISH);
                        uLongf final_comp_size = def_strm.total_out;

                        z_stream inf_strm;
                        memset(&inf_strm, 0, sizeof(z_stream));
                        inf_strm.zalloc = Z_NULL;
                        inf_strm.zfree = Z_NULL;
                        inf_strm.opaque = Z_NULL;
                        if (inflateInit(&inf_strm) == Z_OK) {
                            Bytef *uncomp_buf = (Bytef *)malloc(source_size);
                            if (uncomp_buf) {
                                // Memory safety: uncomp_buf is freed below.
                                inf_strm.next_in = comp_buf;
                                inf_strm.avail_in = final_comp_size;
                                inf_strm.next_out = uncomp_buf;
                                inf_strm.avail_out = source_size;
                                if (inflate(&inf_strm, Z_NO_FLUSH) == Z_NEED_DICT) {
                                    inflateSetDictionary(&inf_strm, dict, dict_size);
                                    inflate(&inf_strm, Z_FINISH);
                                }
                                free(uncomp_buf);
                            }
                            inflateEnd(&inf_strm);
                        }
                        free(comp_buf);
                    }
                    deflateEnd(&def_strm);
                }
            }
            break;
        case 15:
            // Added calls to uncovered header functions deflateSetHeader and inflateGetHeader.
            if (size > 20) {
                gz_header header;
                memset(&header, 0, sizeof(header));
                header.text = 1;
                header.os = data[0];
                header.extra = (Bytef*)(data + 1);
                header.extra_len = 5;

                char name_str[6];
                memcpy(name_str, data + 6, 5);
                name_str[5] = '\0';
                header.name = (Bytef*)name_str;

                char comm_str[6];
                memcpy(comm_str, data + 11, 5);
                comm_str[5] = '\0';
                header.comment = (Bytef*)comm_str;

                z_stream def_strm;
                memset(&def_strm, 0, sizeof(z_stream));
                def_strm.zalloc = Z_NULL;
                def_strm.zfree = Z_NULL;
                def_strm.opaque = Z_NULL;

                if (deflateInit2(&def_strm, Z_DEFAULT_COMPRESSION, Z_DEFLATED, 15 + 16, 8, Z_DEFAULT_STRATEGY) == Z_OK) {
                    deflateSetHeader(&def_strm, &header);
                    
                    const Bytef *source = data + 20;
                    size_t source_size = size - 20;
                    uLongf comp_size = compressBound(source_size);
                    Bytef *comp_buf = (Bytef *)malloc(comp_size);
                    if (comp_buf) {
                        // Memory safety: comp_buf is freed after use.
                        def_strm.next_in = (Bytef *)source;
                        def_strm.avail_in = source_size;
                        def_strm.next_out = comp_buf;
                        def_strm.avail_out = comp_size;
                        deflate(&def_strm, Z_FINISH);
                        uLongf final_comp_size = def_strm.total_out;

                        z_stream inf_strm;
                        memset(&inf_strm, 0, sizeof(z_stream));
                        inf_strm.zalloc = Z_NULL;
                        inf_strm.zfree = Z_NULL;
                        inf_strm.opaque = Z_NULL;
                        // Use 15 + 16 to enable gzip header parsing for inflateGetHeader
                        if (inflateInit2(&inf_strm, 15 + 16) == Z_OK) {
                            gz_header get_header;
                            memset(&get_header, 0, sizeof(gz_header));
                            // Added call to uncovered function inflateGetHeader()
                            inflateGetHeader(&inf_strm, &get_header);

                            Bytef *uncomp_buf = (Bytef *)malloc(source_size);
                            if (uncomp_buf) {
                                // Memory safety: uncomp_buf is freed after use.
                                inf_strm.next_in = comp_buf;
                                inf_strm.avail_in = final_comp_size;
                                inf_strm.next_out = uncomp_buf;
                                inf_strm.avail_out = source_size;
                                inflate(&inf_strm, Z_FINISH);
                                free(uncomp_buf);
                            }
                            inflateEnd(&inf_strm);
                        }
                        free(comp_buf);
                    }
                    deflateEnd(&def_strm);
                }
            }
            break;
        case 16:
            // Added calls to uncovered functions gzopen64, and combine functions.
            if (size > 1) {
                char *filename = (char *)malloc(size);
                if (filename) {
                    // Memory safety: filename is freed below.
                    memcpy(filename, data, size - 1);
                    filename[size - 1] = '\0';
                    gzFile file64 = gzopen64(filename, "wb");
                    if (file64) {
                        gzclose(file64);
                    }
                    free(filename);
                }
            }
            if (size >= 32) {
                uLong val1, val2;
                off_t len2;
                off64_t len2_64;
                memcpy(&val1, data, sizeof(uLong));
                memcpy(&val2, data + sizeof(uLong), sizeof(uLong));
                memcpy(&len2, data + 2 * sizeof(uLong), sizeof(off_t));
                memcpy(&len2_64, data + 2 * sizeof(uLong), sizeof(off64_t));

                len2 = (len2 < 0) ? -len2 : len2;
                len2 %= 8192;
                len2_64 = (len2_64 < 0) ? -len2_64 : len2_64;
                len2_64 %= 8192;

                adler32_combine(val1, val2, len2);
                crc32_combine(val1, val2, len2);
                adler32_combine64(val1, val2, len2_64);
                crc32_combine64(val1, val2, len2_64);
            }
            break;
        case 17:
            // Added calls to uncovered functions deflateCopy and inflateCopy.
            if (size > 1) {
                z_stream def_strm, def_strm_copy;
                memset(&def_strm, 0, sizeof(z_stream));
                def_strm.zalloc = Z_NULL;
                def_strm.zfree = Z_NULL;
                def_strm.opaque = Z_NULL;

                if (deflateInit(&def_strm, Z_DEFAULT_COMPRESSION) == Z_OK) {
                    if (deflateCopy(&def_strm_copy, &def_strm) == Z_OK) {
                        deflateEnd(&def_strm_copy);
                    }
                    deflateEnd(&def_strm);
                }

                uLongf comp_size = compressBound(size);
                Bytef *comp_buf = (Bytef *)malloc(comp_size);
                if (!comp_buf) break;
                // Memory safety: comp_buf is freed below.
                if (compress(comp_buf, &comp_size, data, size) == Z_OK) {
                    z_stream inf_strm, inf_strm_copy;
                    memset(&inf_strm, 0, sizeof(z_stream));
                    inf_strm.zalloc = Z_NULL;
                    inf_strm.zfree = Z_NULL;
                    inf_strm.opaque = Z_NULL;
                    if (inflateInit(&inf_strm) == Z_OK) {
                        if (inflateCopy(&inf_strm_copy, &inf_strm) == Z_OK) {
                            inflateEnd(&inf_strm_copy);
                        }
                        inflateEnd(&inf_strm);
                    }
                }
                free(comp_buf);
            }
            break;
        case 18:
            // Added calls to uncovered functions deflateParams and deflateTune.
            if (size > 5) {
                z_stream def_strm;
                memset(&def_strm, 0, sizeof(z_stream));
                def_strm.zalloc = Z_NULL;
                def_strm.zfree = Z_NULL;
                def_strm.opaque = Z_NULL;

                if (deflateInit(&def_strm, Z_DEFAULT_COMPRESSION) == Z_OK) {
                    deflateParams(&def_strm, data[0] % 10, data[1] % 5);
                    deflateTune(&def_strm, data[2], data[3], data[4], data[5]);
                    deflateBound(&def_strm, size);
                    deflateEnd(&def_strm);
                }
            }
            break;
        case 19:
            // Added call to uncovered function inflateSync.
            if (size > 10) {
                uLongf comp_size = compressBound(size);
                Bytef *comp_buf = (Bytef *)malloc(comp_size);
                if (!comp_buf) break;
                // Memory safety: comp_buf is freed below.
                if (compress(comp_buf, &comp_size, data, size) == Z_OK) {
                    if (comp_size > 5) {
                        comp_buf[5] ^= 0xff; // Corrupt data to trigger error
                    }
                    z_stream inf_strm;
                    memset(&inf_strm, 0, sizeof(z_stream));
                    inf_strm.zalloc = Z_NULL;
                    inf_strm.zfree = Z_NULL;
                    inf_strm.opaque = Z_NULL;
                    if (inflateInit(&inf_strm) == Z_OK) {
                        Bytef *uncomp_buf = (Bytef*)malloc(size * 2);
                        if (uncomp_buf) {
                            // Memory safety: uncomp_buf is freed below.
                            inf_strm.next_in = comp_buf;
                            inf_strm.avail_in = comp_size;
                            inf_strm.next_out = uncomp_buf;
                            inf_strm.avail_out = size * 2;
                            int ret = inflate(&inf_strm, Z_NO_FLUSH);
                            if (ret != Z_OK && ret != Z_STREAM_END) {
                                inflateSync(&inf_strm);
                                inflate(&inf_strm, Z_FINISH);
                            }
                            free(uncomp_buf);
                        }
                        inflateEnd(&inf_strm);
                    }
                }
                free(comp_buf);
            }
            break;
        case 20:
            // Added call to uncovered function gzfwrite().
            if (size > 0 && strcmp(mode, "wb") == 0) {
                gzfwrite(data, 1, size, file);
            }
            break;
        case 21:
            // Added calls to uncovered functions deflatePrime and inflatePrime.
            if (size > 2) {
                z_stream strm;
                memset(&strm, 0, sizeof(z_stream));
                strm.zalloc = Z_NULL;
                strm.zfree = Z_NULL;
                strm.opaque = Z_NULL;
                if (deflateInit(&strm, Z_DEFAULT_COMPRESSION) == Z_OK) {
                    deflatePrime(&strm, data[0] % 16, data[1]);
                    deflateEnd(&strm);
                }
                if (inflateInit(&strm) == Z_OK) {
                    inflatePrime(&strm, data[0] % 16, data[1]);
                    inflateEnd(&strm);
                }
            }
            break;
        case 22:
            // Added calls to uncovered functions inflateMark, inflateCodesUsed, inflateGetDictionary, inflateValidate, inflateUndermine.
            if (size > 128) {
                size_t dict_size = 100;
                const Bytef *dict = data;
                const Bytef *source = data + dict_size;
                size_t source_size = size - dict_size;

                z_stream def_strm;
                memset(&def_strm, 0, sizeof(def_strm));
                if (deflateInit(&def_strm, Z_DEFAULT_COMPRESSION) == Z_OK) {
                    deflateSetDictionary(&def_strm, dict, dict_size);
                    uLongf comp_size = compressBound(source_size);
                    Bytef *comp_buf = (Bytef *)malloc(comp_size);
                    if (comp_buf) {
                        // Memory safety: comp_buf is freed below.
                        def_strm.next_in = (Bytef *)source;
                        def_strm.avail_in = source_size;
                        def_strm.next_out = comp_buf;
                        def_strm.avail_out = comp_size;
                        deflate(&def_strm, Z_FINISH);
                        uLongf final_comp_size = def_strm.total_out;

                        z_stream inf_strm;
                        memset(&inf_strm, 0, sizeof(inf_strm));
                        if (inflateInit(&inf_strm) == Z_OK) {
                            Bytef *uncomp_buf = (Bytef *)malloc(source_size);
                            if (uncomp_buf) {
                                // Memory safety: uncomp_buf is freed below.
                                inf_strm.next_in = comp_buf;
                                inf_strm.avail_in = final_comp_size;
                                inf_strm.next_out = uncomp_buf;
                                inf_strm.avail_out = source_size;
                                if (inflate(&inf_strm, Z_NO_FLUSH) == Z_NEED_DICT) {
                                    inflateSetDictionary(&inf_strm, dict, dict_size);
                                    inflate(&inf_strm, Z_FINISH);
                                }
                                inflateMark(&inf_strm);
                                inflateCodesUsed(&inf_strm);
                                inflateValidate(&inf_strm, 1);
                                inflateUndermine(&inf_strm, 1);
                                free(uncomp_buf);
                            }
                            inflateEnd(&inf_strm);
                        }
                        free(comp_buf);
                    }
                    deflateEnd(&def_strm);
                }
            }
            break;
        }
    }

    // Close the gzFile. This also closes the underlying file descriptor.
    gzclose(file);

    return 0;
}