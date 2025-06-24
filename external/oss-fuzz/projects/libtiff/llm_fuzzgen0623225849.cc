#include <cstddef>
#include <cstdint>
#include <string>
#include <vector>
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

    // Set TIFF fields
    uint32_t image_width = fdp.ConsumeIntegralInRange<uint32_t>(1, 512);
    uint32_t image_length = fdp.ConsumeIntegralInRange<uint32_t>(1, 512);
    uint16_t bits_per_sample = 8;
    uint16_t samples_per_pixel = 3;
    uint16_t photometric = PHOTOMETRIC_RGB;

    TIFFSetField(tif_write, TIFFTAG_IMAGEWIDTH, image_width);
    TIFFSetField(tif_write, TIFFTAG_IMAGELENGTH, image_length);
    TIFFSetField(tif_write, TIFFTAG_BITSPERSAMPLE, bits_per_sample);
    TIFFSetField(tif_write, TIFFTAG_SAMPLESPERPIXEL, samples_per_pixel);
    TIFFSetField(tif_write, TIFFTAG_PHOTOMETRIC, photometric);
    TIFFSetField(tif_write, TIFFTAG_PLANARCONFIG, PLANARCONFIG_CONTIG);

    // Added compression selection to improve coverage in compression-related files.
    uint16_t compression = fdp.PickValueInArray<uint16_t>({
        COMPRESSION_NONE,
        COMPRESSION_LZW,
        COMPRESSION_PACKBITS,
        COMPRESSION_DEFLATE,
    });
    TIFFSetField(tif_write, TIFFTAG_COMPRESSION, compression);

    // Set predictor for relevant compression types to improve coverage in tif_predict.c
    if (compression == COMPRESSION_LZW || compression == COMPRESSION_DEFLATE) {
        TIFFSetField(tif_write, TIFFTAG_PREDICTOR, fdp.ConsumeIntegralInRange<uint16_t>(1, 2));
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
        if (tile_size <= 0 || fdp.remaining_bytes() < tile_size) {
            TIFFClose(tif_write);
            return 0;
        }
        std::vector<uint8_t> tile_buf(tile_size);
        fdp.ConsumeData(tile_buf.data(), tile_size);
        TIFFWriteTile(tif_write, tile_buf.data(), 0, 0, 0, 0);
    } else {
        // Striped image path (original logic)
        uint32_t rows_per_strip = fdp.ConsumeIntegralInRange<uint32_t>(1, image_length);
        TIFFSetField(tif_write, TIFFTAG_ROWSPERSTRIP, rows_per_strip);

        tmsize_t scanline_size = TIFFScanlineSize(tif_write);
        if (scanline_size <= 0 || fdp.remaining_bytes() < scanline_size) {
            TIFFClose(tif_write);
            return 0;
        }
        std::vector<uint8_t> scanline_buf(scanline_size);
        fdp.ConsumeData(scanline_buf.data(), scanline_size);
        TIFFWriteScanline(tif_write, scanline_buf.data(), 0, 0);
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
    TIFFSetDirectory(tif_read, 0);

    // Read back data based on whether it was tiled or striped
    if (use_tiles) {
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

    TIFFClose(tif_read);
    remove(temp_filename);

    return 0;
}