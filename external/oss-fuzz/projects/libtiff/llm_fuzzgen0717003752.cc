#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <string>
#include <vector>
#include <unistd.h>

#include "/src/libtiff/libtiff/tiffio.h"
#include "/src/libtiff/libtiff/tif_hash_set.h"
#include <fuzzer/FuzzedDataProvider.h>

// Define a dummy hash function for the hash set
static unsigned long
hash_ptr(const void *p)
{
    return (unsigned long)(uintptr_t)p;
}

// Define a dummy equality function for the hash set
static bool
equal_ptr(const void *p1, const void *p2)
{
    return p1 == p2;
}


extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    FuzzedDataProvider fdp(data, size);

    // --- Part 1: Fuzz TIFFHashSet ---
    /*
     * ANALYSIS: The coverage report for TIFFHashSetInsert shows that branches for
     *           handling element collisions and rehashing are never taken.
     * IMPLEMENTATION: This block creates a TIFFHashSet and inserts multiple
     *                 elements. It inserts a duplicate pointer to test the collision
     *                 handling path. It also inserts a variable number of elements
     *                 to increase the probability of triggering a rehash.
     */
    if (fdp.ConsumeBool()) {
        TIFFHashSet *hash_set = TIFFHashSetNew(hash_ptr, equal_ptr, nullptr);
        if (hash_set) {
            const int num_insertions = fdp.ConsumeIntegralInRange<int>(5, 50);
            std::vector<void*> pointers;
            for (int i = 0; i < num_insertions; ++i) {
                // Use integer values as pointers for deterministic fuzzing
                void* p = reinterpret_cast<void*>(fdp.ConsumeIntegral<uintptr_t>());
                pointers.push_back(p);
                TIFFHashSetInsert(hash_set, p);
            }
            // Insert a duplicate to test collision handling
            if (!pointers.empty()) {
                TIFFHashSetInsert(hash_set, pointers[0]);
            }
            TIFFHashSetDestroy(hash_set);
        }
    }

    // --- Part 2: Fuzz TIFF Directory and Tag Writing ---
    std::string base_name = "fuzz_";
    // Use a compile-time macro to ensure unique filenames in parallel fuzzing
    #ifdef _FUZZ_TARGET_NAME
        base_name += _FUZZ_TARGET_NAME;
    #endif
    std::string filename = "/tmp/" + base_name + ".tif";

    TIFF *tif = TIFFOpen(filename.c_str(), "w");
    if (!tif) {
        return 0;
    }

    // Set mandatory fields
    TIFFSetField(tif, TIFFTAG_IMAGEWIDTH, fdp.ConsumeIntegralInRange<uint32_t>(1, 512));
    TIFFSetField(tif, TIFFTAG_IMAGELENGTH, fdp.ConsumeIntegralInRange<uint32_t>(1, 512));
    TIFFSetField(tif, TIFFTAG_BITSPERSAMPLE, 8);
    TIFFSetField(tif, TIFFTAG_SAMPLESPERPIXEL, 3);
    TIFFSetField(tif, TIFFTAG_PLANARCONFIG, PLANARCONFIG_CONTIG);
    TIFFSetField(tif, TIFFTAG_PHOTOMETRIC, PHOTOMETRIC_RGB);

    // --- Coverage-guided fuzzing for specific compression codecs ---
    if (fdp.ConsumeBool()) {
        /*
         * ANALYSIS: The line-coverage report for LogLuvVSetField shows that the
         *           branches for TIFFTAG_SGILOGDATAFMT and TIFFTAG_SGILOGENCODE
         *           are never executed.
         * IMPLEMENTATION: Set the compression to COMPRESSION_SGILOG and then
         *                 call TIFFSetField with the uncovered tags and fuzzed values
         *                 to exercise these specific code paths.
         */
        TIFFSetField(tif, TIFFTAG_COMPRESSION, COMPRESSION_SGILOG);
        TIFFSetField(tif, TIFFTAG_SGILOGDATAFMT, fdp.ConsumeIntegralInRange<int>(0, 4));
        TIFFSetField(tif, TIFFTAG_SGILOGENCODE, fdp.ConsumeIntegralInRange<int>(0, 2));

    } else if (fdp.ConsumeBool()) {
        /*
         * ANALYSIS: The line-coverage report for PixarLogVSetField shows that the
         *           branches for TIFFTAG_PIXARLOGQUALITY and TIFFTAG_PIXARLOGDATAFMT
         *           are never executed.
         * IMPLEMENTATION: Set the compression to COMPRESSION_PIXARLOG and then
         *                 call TIFFSetField with the uncovered tags and fuzzed values
         *                 to exercise these specific code paths.
         */
        TIFFSetField(tif, TIFFTAG_COMPRESSION, COMPRESSION_PIXARLOG);
        TIFFSetField(tif, TIFFTAG_PIXARLOGQUALITY, fdp.ConsumeIntegralInRange<int>(-128, 127));
        TIFFSetField(tif, TIFFTAG_PIXARLOGDATAFMT, fdp.ConsumeIntegralInRange<int>(0, 6));
    }

    // Write dummy scanline to make the image valid for directory writing
    std::vector<uint8_t> scanline(TIFFScanlineSize(tif), 0);
    if (TIFFScanlineSize(tif) > 0) {
        // Ensure the buffer is fully populated to avoid using uninitialized data
        size_t consumed_bytes = fdp.ConsumeData(scanline.data(), scanline.size());
        if (consumed_bytes == scanline.size()) {
            TIFFWriteScanline(tif, scanline.data(), 0, 0);
        }
    }

    /*
     * ANALYSIS: The function TIFFWriteDirectory and its underlying implementation
     *           TIFFWriteDirectorySec are completely uncovered (0% coverage).
     * IMPLEMENTATION: Call TIFFWriteDirectory() after setting various fields.
     *                 This single call will exercise the extensive, uncovered logic
     *                 for writing IFD (Image File Directory) entries to the file.
     */
    TIFFWriteDirectory(tif);

    // Close the TIFF file to flush all writes and release resources.
    TIFFClose(tif);

    // Clean up the temporary file.
    unlink(filename.c_str());

    return 0;
}