/* BLOCKER_STRATEGY_CONTRACT
required_state: tif->tif_flags & TIFF_SWAB is true, and a TIFF_RATIONAL tag is present in the directory.
state_constructor: TIFFOpen(filename, mode) is called with a mode that specifies a non-native byte order (e.g., "wb" on a little-endian machine), and TIFFSetField() is used to add a TIFFTAG_XRESOLUTION tag.
trigger_api: TIFFWriteDirectory(tif)
preserved_invariants: The TIFF file is opened with a specific, non-native byte order. At least one tag of type TIFF_RATIONAL is set before the directory is written.
END_BLOCKER_STRATEGY_CONTRACT */

#include <fuzzer/FuzzedDataProvider.h>
#include "/work/include/tiffio.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <stdarg.h>

// A dummy error handler to prevent libtiff from exiting.
static void dummyErrorHandler(const char* module, const char* fmt, va_list ap) {
    // Do nothing.
}

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    FuzzedDataProvider fdp(data, size);

    // Create a unique temporary filename.
    char filename[256];
    snprintf(filename, sizeof(filename), "/tmp/fuzz_target.tif");

    // Set a dummy error handler.
    TIFFSetErrorHandler(dummyErrorHandler);
    TIFFSetWarningHandler(dummyErrorHandler);

    // Open the TIFF file with a non-native byte order to set the TIFF_SWAB flag.
    // On a little-endian machine, "wb" (write big-endian) will set the flag.
    // On a big-endian machine, "wl" (write little-endian) will set the flag.
    const char* mode = fdp.ConsumeBool() ? "wb" : "wl";
    TIFF *tif = TIFFOpen(filename, mode);
    if (!tif) {
        unlink(filename);
        return 0;
    }

    // Set the necessary tags for a valid TIFF directory.
    TIFFSetField(tif, TIFFTAG_IMAGEWIDTH, fdp.ConsumeIntegralInRange<uint32_t>(1, 512));
    TIFFSetField(tif, TIFFTAG_IMAGELENGTH, fdp.ConsumeIntegralInRange<uint32_t>(1, 512));
    TIFFSetField(tif, TIFFTAG_BITSPERSAMPLE, 8);
    TIFFSetField(tif, TIFFTAG_SAMPLESPERPIXEL, 1);
    TIFFSetField(tif, TIFFTAG_PLANARCONFIG, PLANARCONFIG_CONTIG);
    TIFFSetField(tif, TIFFTAG_PHOTOMETRIC, PHOTOMETRIC_MINISBLACK);
    
    // Set a tag of type TIFF_RATIONAL to trigger the blocker function.
    // TIFFTAG_XRESOLUTION is a suitable tag.
    TIFFSetField(tif, TIFFTAG_XRESOLUTION, fdp.ConsumeFloatingPoint<float>());

    // Calling TIFFWriteDirectory will process the tags and call
    // TIFFWriteDirectoryTagCheckedRational for the rational tag.
    // Because TIFF_SWAB is set, this will hit the target branch.
    TIFFWriteDirectory(tif);

    TIFFClose(tif);
    unlink(filename);

    return 0;
}
