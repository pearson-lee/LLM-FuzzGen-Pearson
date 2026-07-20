#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <unistd.h>
#include <cstdarg>

#include <tiffio.h>

// Suppress libtiff errors/warnings to avoid polluting fuzzer output.
void SuppressErrorHandler(const char*, const char*, va_list) {}

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
    // This harness is designed to be minimal and deterministic to reach a specific
    // blocker path for SymCC analysis. It does not use the fuzzer input data.
    // The goal is to trigger the condition `tif->tif_flags & TIFF_SWAB` in
    // TIFFWriteDirectoryTagCheckedIfd8Array, which depends on file creation flags.

    char filename[256];
    sprintf(filename, "/tmp/symcc_libtiff_harness.tif");

    TIFFSetErrorHandler(SuppressErrorHandler);
    TIFFSetWarningHandler(SuppressErrorHandler);

    // Open a BigTIFF file ("8") in write mode ("w") with big-endian byte order ("b").
    // On a little-endian machine (like x86), this will set both the TIFF_BIGTIFF
    // and TIFF_SWAB flags in the TIFF handle, which is required to hit the blocker.
    TIFF* tif = TIFFOpen(filename, "w8b");
    if (!tif) {
        unlink(filename);
        return 0;
    }

    // Set minimal required fields for a valid directory.
    TIFFSetField(tif, TIFFTAG_IMAGEWIDTH, (uint32_t)1);
    TIFFSetField(tif, TIFFTAG_IMAGELENGTH, (uint32_t)1);
    TIFFSetField(tif, TIFFTAG_BITSPERSAMPLE, (uint16_t)8);
    TIFFSetField(tif, TIFFTAG_SAMPLESPERPIXEL, (uint16_t)1);
    TIFFSetField(tif, TIFFTAG_PLANARCONFIG, (uint16_t)PLANARCONFIG_CONTIG);
    TIFFSetField(tif, TIFFTAG_PHOTOMETRIC, (uint16_t)PHOTOMETRIC_MINISBLACK);

    // The blocker is in a code path related to writing SubIFD tags. We must
    // create a second directory and link it from the first one using
    // TIFFTAG_SUBIFD to trigger this path.
    tdir_t main_dir_index = 0; // The first directory in a new TIFF is at index 0.

    // Create and move to a new directory.
    if (TIFFWriteDirectory(tif)) {
        // Flush the new directory to disk to get a valid offset.
        TIFFCheckpointDirectory(tif);
        uint64_t sub_dir_offset = TIFFCurrentDirOffset(tif);

        if (sub_dir_offset > 0) {
            // Go back to the main directory.
            TIFFSetDirectory(tif, main_dir_index);

            // Set the SUBIFD tag to point to the new directory.
            TIFFSetField(tif, TIFFTAG_SUBIFD, 1, &sub_dir_offset);

            // Write the change to the main directory. This call will trigger
            // the call chain leading to TIFFWriteDirectoryTagCheckedIfd8Array.
            TIFFCheckpointDirectory(tif);
        }
    }

    TIFFClose(tif);
    unlink(filename);

    return 0;
}