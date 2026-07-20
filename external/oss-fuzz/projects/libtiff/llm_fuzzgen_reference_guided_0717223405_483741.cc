/* BLOCKER_STRATEGY_CONTRACT
required_state: The TIFF handle `tif` must be configured with `PLANARCONFIG_SEPARATE`, and the `strip` argument to `TIFFWriteEncodedStrip` must be greater than or equal to the number of strips in the image (`td->td_nstrips`).
state_constructor: `TIFFSetField` is used to set `TIFFTAG_PLANARCONFIG` to `PLANARCONFIG_SEPARATE`. The value is derived from the LSB of the `width` variable to avoid altering the fuzzing data consumption order. The `strip_index` is generated using `FuzzedDataProvider::ConsumeIntegralInRange` with an upper bound of `num_strips` (inclusive), allowing it to be equal to `num_strips` and thus satisfy the `strip >= td->td_nstrips` condition.
trigger_api: `TIFFWriteEncodedStrip(tif, strip_index, strip_buf.data(), strip_size)` is called within the "Strip image" logic path.
preserved_invariants: The original FuzzedDataProvider consumption sequence is strictly maintained to ensure existing seeds remain valid. The overall structure of the fuzz target, including image setup and tiled vs. strip logic, is preserved.
END_BLOCKER_STRATEGY_CONTRACT */

#include <cstdint>
#include <cstddef>
#include <string>
#include <vector>
#include <fuzzer/FuzzedDataProvider.h>

#include "tiffio.h"
#include <stdio.h>
#include <unistd.h>

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    if (size == 0) {
        return 0;
    }
    FuzzedDataProvider fdp(data, size);

    char filename[256];
    snprintf(filename, sizeof(filename), "/tmp/%s.tif", _FUZZ_TARGET_NAME);

    TIFF* tif = TIFFOpen(filename, "w");
    if (!tif) {
        return 0;
    }

    uint32_t width = fdp.ConsumeIntegralInRange<uint32_t>(1, 512);
    uint32_t height = fdp.ConsumeIntegralInRange<uint32_t>(1, 512);
    uint16_t samples_per_pixel = fdp.ConsumeIntegralInRange<uint16_t>(1, 4);
    uint16_t bits_per_sample = fdp.PickValueInArray<uint16_t>({8, 16});
    /*
     * ANALYSIS: The function-level coverage report showed that many functions
     *           related to OJPEG compression, such as OJPEGReadSecondarySos, were
     *           completely uncovered.
     * IMPLEMENTATION: Added COMPRESSION_OJPEG to the possible compression
     *                 types to enable fuzzing of the OJPEG codec paths.
     */
    uint16_t compression = fdp.PickValueInArray<uint16_t>({
        COMPRESSION_NONE, COMPRESSION_LZW, COMPRESSION_PACKBITS,
        COMPRESSION_JPEG, COMPRESSION_DEFLATE, COMPRESSION_ADOBE_DEFLATE,
        COMPRESSION_OJPEG
    });
    uint16_t photometric = fdp.PickValueInArray<uint16_t>({
        PHOTOMETRIC_MINISBLACK, PHOTOMETRIC_RGB, PHOTOMETRIC_PALETTE,
        PHOTOMETRIC_YCBCR
    });

    TIFFSetField(tif, TIFFTAG_IMAGEWIDTH, width);
    TIFFSetField(tif, TIFFTAG_IMAGELENGTH, height);
    TIFFSetField(tif, TIFFTAG_SAMPLESPERPIXEL, samples_per_pixel);
    TIFFSetField(tif, TIFFTAG_BITSPERSAMPLE, bits_per_sample);
    TIFFSetField(tif, TIFFTAG_COMPRESSION, compression);
    TIFFSetField(tif, TIFFTAG_PHOTOMETRIC, photometric);
    
    /*
     * BLOCKER-SPECIFIC CHANGE: To satisfy the `td->td_planarconfig == PLANARCONFIG_SEPARATE`
     * condition in the blocker, the planar configuration is now chosen based on a
     * previously consumed value. This avoids altering the input consumption contract
     * while enabling the required state.
     */
    uint16_t planar_config = (width & 1) ? PLANARCONFIG_SEPARATE : PLANARCONFIG_CONTIG;
    TIFFSetField(tif, TIFFTAG_PLANARCONFIG, planar_config);

    bool is_tiled = fdp.ConsumeBool();
    if (is_tiled) { // Tiled image
        uint32_t tile_width = fdp.ConsumeIntegralInRange<uint32_t>(16, 256);
        uint32_t tile_height = fdp.ConsumeIntegralInRange<uint32_t>(16, 256);
        if (tile_width > 0 && tile_height > 0) {
            TIFFSetField(tif, TIFFTAG_TILEWIDTH, tile_width);
            TIFFSetField(tif, TIFFTAG_TILELENGTH, tile_height);

            tsize_t tile_size = TIFFTileSize(tif);
            if (tile_size > 0 && tile_size < 1024 * 1024) {
                /*
                 * ANALYSIS: The detailed coverage report for the fuzz target showed that the
                 *           branch at line 56 `if (fdp.ConsumeData(tile_buf, tile_size) == tile_size)`
                 *           was never true. This prevented calls to TIFFWriteRawTile and
                 *           TIFFWriteEncodedTile, leaving them uncovered.
                 * IMPLEMENTATION: Replaced `ConsumeData` with `ConsumeBytes` and a size check
                 *                 on the returned vector. This ensures that when enough fuzzing
                 *                 data is available, the tile writing functions are called.
                 */
                std::vector<uint8_t> tile_buf = fdp.ConsumeBytes<uint8_t>(tile_size);
                if (tile_buf.size() == tile_size) {
                    tmsize_t num_tiles = TIFFNumberOfTiles(tif);
                    if (num_tiles > 0) {
                        ttile_t tile_index = fdp.ConsumeIntegralInRange<ttile_t>(0, num_tiles - 1);
                        if (compression == COMPRESSION_NONE && fdp.ConsumeBool()) {
                            TIFFWriteRawTile(tif, tile_index, tile_buf.data(), tile_size);
                        } else {
                            TIFFWriteEncodedTile(tif, tile_index, tile_buf.data(), tile_size);
                        }
                    }
                }
            }
        }
    } else { // Strip image
        uint32_t rows_per_strip = fdp.ConsumeIntegralInRange<uint32_t>(1, height);
        TIFFSetField(tif, TIFFTAG_ROWSPERSTRIP, rows_per_strip);

        tsize_t strip_size = TIFFStripSize(tif);
        if (strip_size > 0 && strip_size < 1024 * 1024) {
             /*
             * ANALYSIS: The detailed coverage report for the fuzz target showed that the
             *           branch at line 77 `if (fdp.ConsumeData(strip_buf, strip_size) == strip_size)`
             *           sometimes failed.
             * IMPLEMENTATION: Replaced `ConsumeData` with `ConsumeBytes` and a size check
             *                 on the returned vector. This makes the strip writing logic more
             *                 robust and likely to succeed when sufficient data is available.
             */
            std::vector<uint8_t> strip_buf = fdp.ConsumeBytes<uint8_t>(strip_size);
            if (strip_buf.size() == strip_size) {
                tstrip_t num_strips = TIFFNumberOfStrips(tif);
                if (num_strips > 0) {
                    /*
                     * BLOCKER-SPECIFIC CHANGE: To satisfy the `strip >= td->td_nstrips`
                     * condition in the blocker, the range for `strip_index` is extended
                     * to include `num_strips`. This allows the fuzzer to generate an
                     * index that triggers the desired path in TIFFWriteEncodedStrip.
                     */
                    tstrip_t strip_index = fdp.ConsumeIntegralInRange<tstrip_t>(0, num_strips);
                    if (compression == COMPRESSION_NONE && fdp.ConsumeBool()) {
                        TIFFWriteRawStrip(tif, strip_index, strip_buf.data(), strip_size);
                    } else {
                        TIFFWriteEncodedStrip(tif, strip_index, strip_buf.data(), strip_size);
                    }
                }
            }
        }
    }

    TIFFCheckpointDirectory(tif);
    tdir_t main_dir_index = TIFFCurrentDirectory(tif);

    if (fdp.ConsumeBool()) {
        if (TIFFWriteDirectory(tif)) {
            TIFFCheckpointDirectory(tif);
            uint64_t sub_dir_offset = 0;
            /*
             * ANALYSIS: The function-level coverage report showed that
             *           TIFFWriteCustomDirectory was completely uncovered (0% coverage).
             * IMPLEMENTATION: Added a call to TIFFWriteCustomDirectory to exercise
             *                 this function and improve its coverage.
             */
            if (fdp.ConsumeBool()) {
                TIFFWriteCustomDirectory(tif, &sub_dir_offset);
            }
            if (sub_dir_offset == 0) {
                sub_dir_offset = TIFFCurrentDirOffset(tif);
            }

            if (sub_dir_offset > 0) {
                TIFFSetDirectory(tif, main_dir_index);
                TIFFSetField(tif, TIFFTAG_SUBIFD, 1, &sub_dir_offset);
                TIFFCheckpointDirectory(tif);
                TIFFSetSubDirectory(tif, sub_dir_offset);
            }
        }
    }

    FILE* null_fp = fopen("/dev/null", "w");
    if (null_fp) {
        TIFFPrintDirectory(tif, null_fp, 0);
        fclose(null_fp);
    }
    
    TIFFClose(tif);

    tif = TIFFOpen(filename, "r");
    if (tif) {
        /*
         * ANALYSIS: The function-level coverage report showed that TIFFReadRawStrip
         *           and TIFFReadRawTile were completely uncovered (0% coverage). The
         *           existing fuzzer wrote raw strips/tiles but never read them.
         * IMPLEMENTATION: Added logic to read back raw strip or tile data when
         *                 the compression is COMPRESSION_NONE. This directly targets
         *                 the uncovered TIFFReadRawStrip and TIFFReadRawTile functions.
         */
        if (compression == COMPRESSION_NONE) {
            if (is_tiled) {
                tsize_t tile_size = TIFFTileSize(tif);
                if (tile_size > 0 && tile_size < 1024 * 1024) {
                    uint8_t* buf = new uint8_t[tile_size];
                    tmsize_t num_tiles = TIFFNumberOfTiles(tif);
                    if (num_tiles > 0) {
                        TIFFReadRawTile(tif, fdp.ConsumeIntegralInRange<ttile_t>(0, num_tiles - 1), buf, tile_size);
                    }
                    delete[] buf;
                }
            } else {
                tsize_t strip_size = TIFFStripSize(tif);
                if (strip_size > 0 && strip_size < 1024 * 1024) {
                    uint8_t* buf = new uint8_t[strip_size];
                    tstrip_t num_strips = TIFFNumberOfStrips(tif);
                     if (num_strips > 0) {
                        TIFFReadRawStrip(tif, fdp.ConsumeIntegralInRange<tstrip_t>(0, num_strips - 1), buf, strip_size);
                    }
                    delete[] buf;
                }
            }
        }

        TIFFRGBAImage img;
        char emsg[1024];
        if (TIFFRGBAImageBegin(&img, tif, 0, emsg)) {
            uint32_t* raster = (uint32_t*) _TIFFmalloc(width * height * sizeof(uint32_t));
            if (raster) {
                TIFFRGBAImageGet(&img, raster, width, height);
                _TIFFfree(raster);
            }
            TIFFRGBAImageEnd(&img);
        }
        TIFFClose(tif);
    }
    
    tif = TIFFOpen(filename, "a");
    if (tif) {
        tdir_t num_dirs = TIFFNumberOfDirectories(tif);
        if (num_dirs > 0 && fdp.ConsumeBool()) {
            tdir_t dir_to_unlink = fdp.PickValueInArray<tdir_t>({(tdir_t)0, (tdir_t)1, (tdir_t)(num_dirs + 1)});
            TIFFUnlinkDirectory(tif, dir_to_unlink);
        }
        TIFFClose(tif);
    }
    
    unlink(filename);

    return 0;
}
