#include <cstddef>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <cstdarg>

#include <tiffio.h>

// A dummy error handler to prevent libtiff from exiting on non-fatal errors.
static void dummyErrorHandler(const char* module, const char* fmt, va_list ap) {
    // Do nothing.
}

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
    if (size < 2) {
        return 0;
    }

    const char* filename = "/tmp/symcc_libtiff.tif";

    // Set dummy error handlers to prevent exit().
    TIFFSetErrorHandler(dummyErrorHandler);
    TIFFSetWarningHandler(dummyErrorHandler);

    // Create a TIFF file for writing.
    TIFF *tif = TIFFOpen(filename, "w");
    if (!tif) {
        return 0;
    }

    // Set mandatory fields for a valid TIFF directory.
    TIFFSetField(tif, TIFFTAG_IMAGEWIDTH, 1);
    TIFFSetField(tif, TIFFTAG_IMAGELENGTH, 1);
    TIFFSetField(tif, TIFFTAG_SAMPLESPERPIXEL, 1);
    TIFFSetField(tif, TIFFTAG_PLANARCONFIG, PLANARCONFIG_CONTIG);
    TIFFSetField(tif, TIFFTAG_PHOTOMETRIC, PHOTOMETRIC_MINISBLACK);

    // Set fields to trigger the blocker path in TIFFWriteDirectoryTagSampleformatArray.
    // The required state is td_sampleformat == SAMPLEFORMAT_UINT and
    // 8 < td_bitspersample <= 16.
    TIFFSetField(tif, TIFFTAG_BITSPERSAMPLE, 16);
    TIFFSetField(tif, TIFFTAG_SAMPLEFORMAT, SAMPLEFORMAT_UINT);

    // Setting SMINSAMPLEVALUE triggers the call to the target function.
    // The value is taken from the raw input buffer.
    int16_t smin_val;
    memcpy(&smin_val, data, sizeof(smin_val));
    TIFFSetField(tif, TIFFTAG_SMINSAMPLEVALUE, (double)smin_val);

    // Write the directory, which calls the target function path.
    TIFFWriteDirectory(tif);

    TIFFClose(tif);

    return 0;
}