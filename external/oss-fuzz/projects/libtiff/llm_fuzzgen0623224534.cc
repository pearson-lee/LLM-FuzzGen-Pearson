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
    uint32_t rows_per_strip = 1;
    uint16_t planar_config = PLANARCONFIG_CONTIG;
    uint16_t photometric = PHOTOMETRIC_RGB;

    TIFFSetField(tif_write, TIFFTAG_IMAGEWIDTH, image_width);
    TIFFSetField(tif_write, TIFFTAG_IMAGELENGTH, image_length);
    TIFFSetField(tif_write, TIFFTAG_BITSPERSAMPLE, bits_per_sample);
    TIFFSetField(tif_write, TIFFTAG_SAMPLESPERPIXEL, samples_per_pixel);
    TIFFSetField(tif_write, TIFFTAG_ROWSPERSTRIP, rows_per_strip);
    TIFFSetField(tif_write, TIFFTAG_PLANARCONFIG, planar_config);
    TIFFSetField(tif_write, TIFFTAG_PHOTOMETRIC, photometric);

    // Allocate buffer for one scanline
    tmsize_t scanline_size = TIFFScanlineSize(tif_write);
    if (scanline_size <= 0) {
        TIFFClose(tif_write);
        return 0;
    }
    std::vector<uint8_t> scanline_buf(scanline_size);

    // Fill the scanline with fuzz data
    if (fdp.remaining_bytes() < scanline_size) {
        TIFFClose(tif_write);
        return 0;
    }
    fdp.ConsumeData(scanline_buf.data(), scanline_size);

    // Write the scanline to the TIFF file
    TIFFWriteScanline(tif_write, scanline_buf.data(), 0, 0);

    // Close the TIFF file
    TIFFClose(tif_write);

    // Open the TIFF file for reading
    TIFF* tif_read = TIFFOpen(temp_filename, "r");
    if (!tif_read) {
        return 0;
    }

    // Set a silent error handler to avoid crashes on invalid TIFFs
    TIFFSetErrorHandler(silent_error_handler);
    TIFFSetWarningHandler(silent_error_handler);

    // Set the directory
    TIFFSetDirectory(tif_read, 0);

    // Allocate buffer for reading a scanline
    std::vector<uint8_t> read_buf(scanline_size);

    // Read a scanline from the TIFF file
    TIFFReadScanline(tif_read, read_buf.data(), 0, 0);

    // Close the TIFF file
    TIFFClose(tif_read);

    // Clean up the temporary file
    remove(temp_filename);

    return 0;
}