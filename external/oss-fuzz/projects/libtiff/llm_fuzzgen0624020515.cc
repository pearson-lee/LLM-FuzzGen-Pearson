#include <cstddef>
#include <cstdint>
#include <string>
#include <vector>
#include <algorithm>
#include <fuzzer/FuzzedDataProvider.h>
#include "/src/libtiff/libtiff/tiffio.h"

// Error handler to prevent exit() on error
static void silent_error_handler(const char* module, const char* fmt, va_list ap) {
    // Do nothing
}

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    FuzzedDataProvider fdp(data, size);

    // Create a temporary file to work with
    char temp_filename[] = "/tmp/fuzz.tif";

    // Create a TIFF file for writing
    TIFF* tif_write = TIFFOpen(temp_filename, "w");
    if (!tif_write) {
        return 0;
    }

    // Set a variety of TIFF tags to improve coverage in tif_dirwrite.c
    do {
        // Set TIFF fields
        uint32_t image_width = fdp.ConsumeIntegralInRange<uint32_t>(1, 512);
        uint32_t image_length = fdp.ConsumeIntegralInRange<uint32_t>(1, 512);
        uint16_t bits_per_sample = fdp.PickValueInArray<uint16_t>({1, 2, 4, 8, 16, 32});
        uint16_t samples_per_pixel = fdp.ConsumeIntegralInRange<uint16_t>(1, 4);
        uint16_t photometric = fdp.PickValueInArray<uint16_t>({
            PHOTOMETRIC_MINISWHITE,
            PHOTOMETRIC_MINISBLACK,
            PHOTOMETRIC_RGB,
            PHOTOMETRIC_PALETTE,
            PHOTOMETRIC_MASK,
            PHOTOMETRIC_SEPARATED,
            PHOTOMETRIC_YCBCR,
            PHOTOMETRIC_CIELAB,
            PHOTOMETRIC_LOGL,
            PHOTOMETRIC_LOGLUV
        });

        TIFFSetField(tif_write, TIFFTAG_IMAGEWIDTH, image_width);
        TIFFSetField(tif_write, TIFFTAG_IMAGELENGTH, image_length);
        TIFFSetField(tif_write, TIFFTAG_BITSPERSAMPLE, bits_per_sample);
        TIFFSetField(tif_write, TIFFTAG_SAMPLESPERPIXEL, samples_per_pixel);
        TIFFSetField(tif_write, TIFFTAG_PHOTOMETRIC, photometric);
        TIFFSetField(tif_write, TIFFTAG_PLANARCONFIG, fdp.PickValueInArray<uint16_t>({PLANARCONFIG_CONTIG, PLANARCONFIG_SEPARATE}));

        // Set a rational-type tag to improve coverage for rational handling functions.
        if (fdp.ConsumeBool()) {
            TIFFSetField(tif_write, EXIFTAG_SUBJECTDISTANCE, fdp.ConsumeFloatingPoint<float>());
        }

        // When creating a palette image, set the colormap to cover TIFFWriteDirectoryTagColormap.
        if (photometric == PHOTOMETRIC_PALETTE && bits_per_sample <= 8) {
            uint16_t n_colors = 1 << bits_per_sample;
            std::vector<uint16_t> r(n_colors), g(n_colors), b(n_colors);
            for(uint16_t i = 0; i < n_colors; i++) {
                r[i] = fdp.ConsumeIntegral<uint16_t>();
                g[i] = fdp.ConsumeIntegral<uint16_t>();
                b[i] = fdp.ConsumeIntegral<uint16_t>();
            }
            TIFFSetField(tif_write, TIFFTAG_COLORMAP, r.data(), g.data(), b.data());
        }

        uint16_t compression;
        // Force specific compression and parameters for LogLuv to improve tif_luv.c coverage.
        if (photometric == PHOTOMETRIC_LOGLUV) {
            compression = fdp.PickValueInArray<uint16_t>({COMPRESSION_SGILOG, COMPRESSION_SGILOG24});
            bits_per_sample = fdp.PickValueInArray<uint16_t>({8, 16});
            samples_per_pixel = fdp.ConsumeIntegralInRange<uint16_t>(3, 4);
            TIFFSetField(tif_write, TIFFTAG_BITSPERSAMPLE, bits_per_sample);
            TIFFSetField(tif_write, TIFFTAG_SAMPLESPERPIXEL, samples_per_pixel);
        } else {
            compression = fdp.PickValueInArray<uint16_t>({
                COMPRESSION_NONE,
                COMPRESSION_LZW,
                COMPRESSION_PACKBITS,
                COMPRESSION_DEFLATE,
                COMPRESSION_ADOBE_DEFLATE,
                COMPRESSION_JPEG,
                COMPRESSION_OJPEG,
                COMPRESSION_SGILOG,
                COMPRESSION_SGILOG24,
            });
        }
        TIFFSetField(tif_write, TIFFTAG_COMPRESSION, compression);

        // Set predictor for relevant compression types to improve coverage in tif_predict.c
        if (compression == COMPRESSION_LZW || compression == COMPRESSION_DEFLATE) {
            TIFFSetField(tif_write, TIFFTAG_PREDICTOR, fdp.ConsumeIntegralInRange<uint16_t>(1, 3));
        }

        // Added call to TIFFUnsetField to cover this function.
        if (fdp.ConsumeBool()) {
            TIFFUnsetField(tif_write, TIFFTAG_PREDICTOR);
        }

        // Added a switch between tiled and striped images to improve coverage.
        bool use_tiles = fdp.ConsumeBool();
        if (use_tiles) {
            // Tiled image path
            uint32_t tile_width = fdp.ConsumeIntegralInRange<uint32_t>(16, 256);
            uint32_t tile_length = fdp.ConsumeIntegralInRange<uint32_t>(16, 256);
            TIFFSetField(tif_write, TIFFTAG_TILEWIDTH, tile_width);
            TIFFSetField(tif_write, TIFFTAG_TILELENGTH, tile_length);

            tmsize_t tile_size = TIFFTileSize(tif_write);
            if (tile_size > 0) {
                std::vector<uint8_t> tile_buf(tile_size);
                size_t bytes_to_consume = std::min((size_t)tile_size, fdp.remaining_bytes());
                fdp.ConsumeData(tile_buf.data(), bytes_to_consume);
                TIFFWriteTile(tif_write, tile_buf.data(), 0, 0, 0, 0);
            }
        } else {
            // Striped image path
            uint32_t rows_per_strip = fdp.ConsumeIntegralInRange<uint32_t>(1, image_length);
            TIFFSetField(tif_write, TIFFTAG_ROWSPERSTRIP, rows_per_strip);

            tmsize_t scanline_size = TIFFScanlineSize(tif_write);
            if (scanline_size > 0) {
                std::vector<uint8_t> scanline_buf(scanline_size);
                size_t bytes_to_consume = std::min((size_t)scanline_size, fdp.remaining_bytes());
                fdp.ConsumeData(scanline_buf.data(), bytes_to_consume);
                TIFFWriteScanline(tif_write, scanline_buf.data(), 0, 0);
            }
        }

        // Write multiple directories to improve coverage in tif_dir.c and tif_dirwrite.c
    } while (fdp.ConsumeBool() && TIFFWriteDirectory(tif_write));

    // Added call to TIFFWriteCustomDirectory to improve coverage.
    if (fdp.ConsumeBool()) {
        uint64_t dir_offset = 0;
        TIFFWriteCustomDirectory(tif_write, &dir_offset);
    }

    TIFFClose(tif_write);

    // Open the TIFF file for reading
    TIFF* tif_read = TIFFOpen(temp_filename, "r");
    if (!tif_read) {
        remove(temp_filename);
        return 0;
    }

    TIFFSetErrorHandler(silent_error_handler);
    TIFFSetWarningHandler(silent_error_handler);

    // Read all directories to improve coverage in tif_dirread.c
    do {
        // Read back data based on whether it was tiled or striped
        if (TIFFIsTiled(tif_read)) {
            tmsize_t tile_size = TIFFTileSize(tif_read);
            if (tile_size > 0) {
                std::vector<uint8_t> read_buf(tile_size);
                TIFFReadTile(tif_read, read_buf.data(), 0, 0, 0, 0);
            }
        } else {
            tmsize_t scanline_size = TIFFScanlineSize(tif_read);
            if (scanline_size > 0) {
                std::vector<uint8_t> read_buf(scanline_size);
                TIFFReadScanline(tif_read, read_buf.data(), 0, 0);
            }
        }
        // Added calls to read EXIF and GPS directories to improve coverage.
        if (fdp.ConsumeBool()) {
            uint64_t dir_offset = 0;
            if (TIFFGetField(tif_read, TIFFTAG_EXIFIFD, &dir_offset)) {
                TIFFReadEXIFDirectory(tif_read, dir_offset);
            }
        }
        if (fdp.ConsumeBool()) {
            uint64_t dir_offset = 0;
            if (TIFFGetField(tif_read, TIFFTAG_GPSIFD, &dir_offset)) {
                TIFFReadGPSDirectory(tif_read, dir_offset);
            }
        }
        // Added call to TIFFReadCustomDirectory to improve coverage.
        if (fdp.ConsumeBool()) {
            uint64_t dir_offset = 0;
            if (TIFFGetField(tif_read, TIFFTAG_SUBIFD, &dir_offset)) {
                TIFFReadCustomDirectory(tif_read, dir_offset, nullptr);
            }
        }
    } while (TIFFReadDirectory(tif_read));

    TIFFClose(tif_read);
    remove(temp_filename);

    return 0;
}