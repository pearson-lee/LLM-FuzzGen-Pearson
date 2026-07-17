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
     * ANALYSIS: The function-level coverage report showed that functions in
     *           tif_pixarlog.c and tif_luv.c had zero or very low coverage.
     * IMPLEMENTATION: Added COMPRESSION_PIXARLOG, COMPRESSION_SGILOG, and
     *                 COMPRESSION_SGILOG24 to the possible compression types
     *                 to exercise these uncovered codecs.
     */
    uint16_t compression = fdp.PickValueInArray<uint16_t>({
        COMPRESSION_NONE, COMPRESSION_LZW, COMPRESSION_PACKBITS,
        COMPRESSION_JPEG, COMPRESSION_DEFLATE, COMPRESSION_ADOBE_DEFLATE,
        COMPRESSION_OJPEG, COMPRESSION_PIXARLOG, COMPRESSION_SGILOG,
        COMPRESSION_SGILOG24
    });
    /*
     * ANALYSIS: To properly exercise the SGILOG codecs, the correct
     *           photometric interpretation must be set. The function-level
     *           coverage report for tif_luv.c indicated these paths were not taken.
     * IMPLEMENTATION: Added PHOTOMETRIC_LOGL and PHOTOMETRIC_LOGLUV to the
     *                 list of possible photometric interpretations to enable
     *                 fuzzing of the SGILOG color space logic.
     */
    uint16_t photometric = fdp.PickValueInArray<uint16_t>({
        PHOTOMETRIC_MINISBLACK, PHOTOMETRIC_RGB, PHOTOMETRIC_PALETTE,
        PHOTOMETRIC_YCBCR, PHOTOMETRIC_LOGL, PHOTOMETRIC_LOGLUV
    });

    TIFFSetField(tif, TIFFTAG_IMAGEWIDTH, width);
    TIFFSetField(tif, TIFFTAG_IMAGELENGTH, height);
    TIFFSetField(tif, TIFFTAG_SAMPLESPERPIXEL, samples_per_pixel);
    TIFFSetField(tif, TIFFTAG_BITSPERSAMPLE, bits_per_sample);
    TIFFSetField(tif, TIFFTAG_COMPRESSION, compression);
    TIFFSetField(tif, TIFFTAG_PHOTOMETRIC, photometric);
    TIFFSetField(tif, TIFFTAG_PLANARCONFIG, PLANARCONFIG_CONTIG);

    /*
     * ANALYSIS: The function-level coverage report showed that
     *           tif_dirwrite.c:TIFFWriteDirectoryTagSampleformatArray was uncovered (0% coverage).
     *           This function is called when setting the TIFFTAG_SAMPLEFORMAT for multiple samples.
     * IMPLEMENTATION: When samples_per_pixel > 1, create an array of sample
     *                 formats and use TIFFSetField with TIFFTAG_SAMPLEFORMAT to
     *                 specifically target this uncovered function. The allocated
     *                 memory is immediately freed to prevent leaks.
     */
    if (samples_per_pixel > 1 && fdp.ConsumeBool()) {
        uint16_t* sample_formats = new uint16_t[samples_per_pixel];
        for (uint16_t i = 0; i < samples_per_pixel; ++i) {
            sample_formats[i] = fdp.PickValueInArray<uint16_t>({
                SAMPLEFORMAT_UINT, SAMPLEFORMAT_INT, SAMPLEFORMAT_IEEEFP,
                SAMPLEFORMAT_VOID, SAMPLEFORMAT_COMPLEXINT, SAMPLEFORMAT_COMPLEXIEEEFP
            });
        }
        TIFFSetField(tif, TIFFTAG_SAMPLEFORMAT, sample_formats);
        delete[] sample_formats;
    }

    bool is_tiled = fdp.ConsumeBool();
    if (is_tiled) { // Tiled image
        /*
         * ANALYSIS: The detailed fuzz target coverage report showed that the branch
         *           condition at line 74 (`if (tile_buf.size() == tile_size)`) was
         *           never true. This prevented tile writing functions from ever being
         *           called because the requested tile_size was too large for the
         *           remaining fuzzer data.
         * IMPLEMENTATION: Reduced the maximum tile width and height from 256 to 64.
         *                 This results in a smaller tile_size, increasing the
         *                 probability that the FuzzedDataProvider has enough data to
         *                 create a full tile buffer, thus entering the branch.
         */
        uint32_t tile_width = fdp.ConsumeIntegralInRange<uint32_t>(16, 64);
        uint32_t tile_height = fdp.ConsumeIntegralInRange<uint32_t>(16, 64);
        if (tile_width > 0 && tile_height > 0) {
            TIFFSetField(tif, TIFFTAG_TILEWIDTH, tile_width);
            TIFFSetField(tif, TIFFTAG_TILELENGTH, tile_height);

            tsize_t tile_size = TIFFTileSize(tif);
            if (tile_size > 0 && tile_size < 1024 * 1024) {
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
            std::vector<uint8_t> strip_buf = fdp.ConsumeBytes<uint8_t>(strip_size);
            if (strip_buf.size() == strip_size) {
                tstrip_t num_strips = TIFFNumberOfStrips(tif);
                if (num_strips > 0) {
                    tstrip_t strip_index = fdp.ConsumeIntegralInRange<tstrip_t>(0, num_strips - 1);
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
        /*
         * ANALYSIS: The function-level coverage report for tif_print.c showed
         *           that TIFFPrintDirectory had low coverage (36.73%). The function's
         *           behavior is controlled by a flags argument.
         * IMPLEMENTATION: Used FuzzedDataProvider to combine various TIFFPRINT_*
         *                 flags. This exercises the conditional logic within
         *                 TIFFPrintDirectory that handles the printing of different
         *                 directory components, thus increasing its coverage.
         */
        long flags = 0;
        if (fdp.ConsumeBool()) flags |= TIFFPRINT_STRIPS;
        if (fdp.ConsumeBool()) flags |= TIFFPRINT_COLORMAP;
        if (fdp.ConsumeBool()) flags |= TIFFPRINT_JPEGQTABLES;
        if (fdp.ConsumeBool()) flags |= TIFFPRINT_JPEGACTABLES;
        if (fdp.ConsumeBool()) flags |= TIFFPRINT_JPEGDCTABLES;
        TIFFPrintDirectory(tif, null_fp, flags);
        fclose(null_fp);
    }
    
    TIFFClose(tif);

    tif = TIFFOpen(filename, "r");
    if (tif) {
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