#include "/src/zlib/zlib.h"
#include <string.h>
#include <stdlib.h>
#include <stdint.h>
#include <stdio.h>
#include <unistd.h>

#define CHUNK_SIZE 16384

#ifndef _FUZZ_TARGET_NAME
#define _FUZZ_TARGET_NAME "llm_fuzzgen0713211827"
#endif

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    if (size > 100) {
        uLongf compressed_size = compressBound(size);
        unsigned char *compressed_data = (unsigned char *)malloc(compressed_size);
        if (!compressed_data) {
            return 0;
        }

        z_stream def_strm;
        memset(&def_strm, 0, sizeof(def_strm));

        if (deflateInit(&def_strm, Z_DEFAULT_COMPRESSION) == Z_OK) {
            if (size > 10) {
                gz_header header;
                memset(&header, 0, sizeof(header));
                header.comment = (Bytef *)"fuzz-comment";
                deflateSetHeader(&def_strm, &header);
            }
            deflateTune(&def_strm, 258, 1024, 258, 1024);
            if (size > 2) {
               deflatePrime(&def_strm, data[0] % 16, data[1]);
            }

            if (size > 2) {
                deflateParams(&def_strm, data[0], data[1]);
            }

            const size_t dict_size = size > 1000 ? 1000 : size;
            const uint8_t *dict_data = data;
            const size_t plain_size = size > dict_size ? size - dict_size : 0;
            const uint8_t *plain_data = plain_size > 0 ? data + dict_size : data;
            deflateSetDictionary(&def_strm, dict_data, dict_size);
            uInt dict_len;
            deflateGetDictionary(&def_strm, NULL, &dict_len);
            def_strm.avail_in = plain_size;
            def_strm.next_in = (Bytef *)plain_data;
            def_strm.avail_out = compressed_size;
            def_strm.next_out = compressed_data;
            
            deflate(&def_strm, Z_PARTIAL_FLUSH);

            deflate(&def_strm, Z_FINISH);
            
            unsigned int pending;
            int bits;
            deflatePending(&def_strm, &pending, &bits);

            deflateUsed(&def_strm, &bits);

            z_stream inf_strm;
            memset(&inf_strm, 0, sizeof(inf_strm));
            if (inflateInit(&inf_strm) == Z_OK) {
                if (size > 1) {
                    gz_header header;
                    memset(&header, 0, sizeof(header));
                    inflateGetHeader(&inf_strm, &header);
                    inflateReset2(&inf_strm, data[0]);
                    if (size > 2) {
                        inflatePrime(&inf_strm, data[1] % 16, data[2]);
                    }
                    inflateMark(&inf_strm);
                    inflateSyncPoint(&inf_strm);
                    inflateUndermine(&inf_strm, 1);
                    inflateValidate(&inf_strm, 1);
                    inflateCodesUsed(&inf_strm);
                }

                unsigned char out_buffer[CHUNK_SIZE];
                inf_strm.avail_in = def_strm.total_out;
                inf_strm.next_in = compressed_data;
                inf_strm.avail_out = CHUNK_SIZE;
                inf_strm.next_out = out_buffer;
                int ret = inflate(&inf_strm, Z_NO_FLUSH);
                if (ret == Z_NEED_DICT) {
                    inflateSetDictionary(&inf_strm, dict_data, dict_size);
                    uInt dict_len_inf;
                    inflateGetDictionary(&inf_strm, NULL, &dict_len_inf);
                    inflate(&inf_strm, Z_FINISH);
                }
                inflateEnd(&inf_strm);
            }
            deflateEnd(&def_strm);
        }
        free(compressed_data);
        
        if (size >= 8) {
            uLong adler1 = adler32(0L, Z_NULL, 0);
            uLong adler2 = adler32(adler1, data, size/2);
            adler32_combine(adler1, adler2, size - (size/2));
            adler32_combine64(adler1, adler2, size - (size/2));

            uLong crc1 = crc32(0L, Z_NULL, 0);
            uLong crc2 = crc32(crc1, data, size/2);
            crc32_combine(crc1, crc2, size - (size/2));
            crc32_combine64(crc1, crc2, size - (size/2));
            get_crc_table();
        }

        if (size > 10) {
            z_stream source_def, dest_def;
            memset(&source_def, 0, sizeof(z_stream));
            memset(&dest_def, 0, sizeof(z_stream));

            if (deflateInit(&source_def, Z_DEFAULT_COMPRESSION) == Z_OK) {
                if (deflateCopy(&dest_def, &source_def) == Z_OK) {
                    deflateEnd(&dest_def);
                }
                deflateEnd(&source_def);
            }

            z_stream source_inf, dest_inf;
            memset(&source_inf, 0, sizeof(z_stream));
            memset(&dest_inf, 0, sizeof(z_stream));
            if (inflateInit(&source_inf) == Z_OK) {
                if (inflateCopy(&dest_inf, &source_inf) == Z_OK) {
                    inflateEnd(&dest_inf);
                }
                inflateEnd(&source_inf);
            }
        }
        
        char path[256];
        snprintf(path, sizeof(path), "/tmp/%s.tmp", _FUZZ_TARGET_NAME);

        FILE *fp = fopen(path, "wb");
        if (fp) {
            fwrite(data, 1, size, fp);
            fclose(fp);

            FILE *r_fp = fopen(path, "rb");
            if (r_fp) {
                gzFile r_file = gzdopen(fileno(r_fp), "rb");
                if (r_file) {
                    char buffer[256];
                    gzgets(r_file, buffer, sizeof(buffer));
                    gzread(r_file, buffer, sizeof(buffer));
                    gzseek(r_file, 10, SEEK_CUR);
                    gzclose(r_file);
                }
                fclose(r_fp);
            }

            FILE *w_fp = fopen(path, "ab");
            if (w_fp) {
                gzFile w_file = gzdopen(fileno(w_fp), "ab");
                if (w_file) {
                    if (size > 1) {
                        gzsetparams(w_file, data[0], data[1]);
                    }
                    for (size_t i = 0; i < 10 && i < size; ++i) {
                        gzputc(w_file, data[i]);
                    }

                    gzputs(w_file, "fuzz data");
                    gzwrite(w_file, data, size);
                    gzprintf(w_file, "fuzz printf %d", 123);
                    gzseek64(w_file, 1024, SEEK_CUR);
                    gzclose(w_file);
                }
                fclose(w_fp);
            }
        }
        unlink(path);


    } else {
        zlibVersion();
        zlibCompileFlags();
        zError(0);
        zError(1);
        zError(-1);

        if (size > 0) {
            z_stream strm;
            memset(&strm, 0, sizeof(strm));
            if (deflateInit(&strm, Z_DEFAULT_COMPRESSION) == Z_OK) {
                deflateBound(&strm, size);
                deflateEnd(&strm);
            }

            uLongf compressed_size_2 = compressBound(size);
            unsigned char *compressed_data_2 = (unsigned char *)malloc(compressed_size_2);
            if (compressed_data_2) {
                if (compress(compressed_data_2, &compressed_size_2, data, size) == Z_OK) {
                    unsigned char *uncompressed_data = (unsigned char *)malloc(size);
                    if (uncompressed_data) {
                        uLongf uncompressed_size = size;
                        uncompress2(uncompressed_data, &uncompressed_size, compressed_data_2, &compressed_size_2);
                        free(uncompressed_data);
                    }
                }
                free(compressed_data_2);
            }
        }
    }

    return 0;
}