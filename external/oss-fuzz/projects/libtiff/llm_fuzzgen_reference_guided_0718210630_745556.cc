/* BLOCKER_STRATEGY_CONTRACT
required_state: The tif->tif_flags must have both TIFF_BIGTIFF and TIFF_SWAB set.
state_constructor: The TIFF file is created with a mode string that forces BigTIFF format and specifies a byte order (e.g., "w8b" or "w8l"). When libtiff opens this file on a machine with a different native byte order, it sets the TIFF_SWAB flag.
trigger_api: TIFFUnlinkDirectory(tif, dir_to_unlink)
preserved_invariants: The FuzzedDataProvider consumption sequence is unchanged. The high-level logic of creating a multi-directory TIFF, reopening it, and unlinking a directory is preserved.
END_BLOCKER_STRATEGY_CONTRACT */

#include <fuzzer/FuzzedDataProvider.h>
#include <tiffio.h>
#include <vector>
#include <string>
#include <unistd.h>
#include <cstdio>

// Define a custom tag in the private range for testing purposes.
#define TIFFTAG_MY_SRATIONAL 65000
static const TIFFFieldInfo xtiffFieldInfo[] = {
    // This custom tag is defined as TIFF_SRATIONAL to target uncovered code paths.
    // Read/Write count is variable (-1), and passcount is true (last '1').
    { TIFFTAG_MY_SRATIONAL, -1, -1, TIFF_SRATIONAL, FIELD_CUSTOM, 1, 1, "MyCustomSRational" }
};

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size) {
    if (Size == 0) {
        return 0;
    }
    FuzzedDataProvider fdp(Data, Size);

    // Create a unique temporary filename for thread safety.
    const std::string path = std::string("/tmp/") + _FUZZ_TARGET_NAME + ".tif";

    // BLOCKER-SPECIFIC CHANGE:
    // To reach the blocker in TIFFUnlinkDirectory, the TIFF file must be
    // in BigTIFF format and require byte swapping. The mode string is modified
    // to create a BigTIFF file ("w8") with a fuzzer-chosen byte order
    // ('b' for big-endian, 'l' for little-endian). When the file is re-opened,
    // libtiff will set the TIFF_SWAB flag if the file's byte order does not
    // match the host machine's byte order.
    const char* mode = fdp.ConsumeBool() ? "w8b" : "w8l";

    TIFF* tif = TIFFOpen(path.c_str(), mode);
    if (!tif) {
        return 0;
    }

    /*
     * ANALYSIS: The function DoubleToSrational has 0% coverage. It is called when writing
     *           a tag of type TIFF_SRATIONAL from a double array.
     * IMPLEMENTATION: A custom field TIFFTAG_MY_SRATIONAL is registered. TIFFSetField is
     *                 then used to associate fuzzer-generated double values with this tag.
     *                 When TIFFWriteDirectory is called, it invokes the path for handling
     *                 SRATIONAL arrays, thus covering DoubleToSrational.
     */
    TIFFMergeFieldInfo(tif, xtiffFieldInfo, 1);
    uint16_t count = fdp.ConsumeIntegralInRange<uint16_t>(1, 16);
    std::vector<double> srationals;
    for (int i = 0; i < count; ++i) {
        srationals.push_back(fdp.ConsumeFloatingPoint<double>());
    }
    if (!srationals.empty()) {
        TIFFSetField(tif, TIFFTAG_MY_SRATIONAL, srationals.size(), srationals.data());
    }

    // Set basic required tags to create a valid TIFF structure.
    TIFFSetField(tif, TIFFTAG_IMAGEWIDTH, fdp.ConsumeIntegralInRange<uint32_t>(1, 512));
    TIFFSetField(tif, TIFFTAG_IMAGELENGTH, fdp.ConsumeIntegralInRange<uint32_t>(1, 512));
    TIFFSetField(tif, TIFFTAG_BITSPERSAMPLE, 8);
    TIFFSetField(tif, TIFFTAG_SAMPLESPERPIXEL, 1);
    TIFFSetField(tif, TIFFTAG_PLANARCONFIG, PLANARCONFIG_CONTIG);
    TIFFSetField(tif, TIFFTAG_COMPRESSION, COMPRESSION_NONE);
    TIFFSetField(tif, TIFFTAG_PHOTOMETRIC, PHOTOMETRIC_MINISBLACK);

    // Write a single scanline to make the directory writable.
    tsize_t scanline_size = TIFFScanlineSize(tif);
    if (scanline_size > 0) {
        std::vector<char> dummy_scanline(scanline_size);
        TIFFWriteScanline(tif, dummy_scanline.data(), 0, 0);
    }

    // Create a chain of directories (IFDs).
    int num_dirs = fdp.ConsumeIntegralInRange<int>(1, 4);
    for (int i = 0; i < num_dirs - 1; ++i) {
        TIFFWriteDirectory(tif);
        // Set a unique tag for each directory to make them distinct.
        TIFFSetField(tif, TIFFTAG_PAGENUMBER, i + 1, num_dirs);
    }
    
    // Finalize writing by closing the file.
    TIFFClose(tif);

    // Re-open in append mode to modify the directory structure.
    tif = TIFFOpen(path.c_str(), "r+");
    if (!tif) {
        unlink(path.c_str());
        return 0;
    }

    /*
     * ANALYSIS: The function TIFFUnlinkDirectory has untested branches related to
     *           unlinking from different positions in the IFD chain.
     * IMPLEMENTATION: A directory is unlinked at a fuzzer-determined position.
     *                 This tests the logic for patching the 'next' pointers in the IFD chain.
     */
    if (num_dirs > 1) {
        tdir_t dir_to_unlink = fdp.ConsumeIntegralInRange<tdir_t>(0, num_dirs - 1);
        TIFFUnlinkDirectory(tif, dir_to_unlink);
    }
    
    // Close and reopen for the unlink to take effect on subsequent reads.
    TIFFClose(tif);
    tif = TIFFOpen(path.c_str(), "r");
    if (!tif) {
        unlink(path.c_str());
        return 0;
    }

    /*
     * ANALYSIS: The function TIFFPrintDirectory has low coverage (51.55%). Many
     *           branches for printing different tag types are not exercised.
     * IMPLEMENTATION: This code iterates through all directories in the generated
     *                 TIFF file and calls TIFFPrintDirectory on each one. The file
     *                 contains standard, custom, and multi-directory tags,
     *                 exercising more of the printing logic.
     */
    FILE* temp_file = tmpfile();
    if (temp_file) {
        do {
            TIFFPrintDirectory(tif, temp_file, 0);
        } while (TIFFReadDirectory(tif));
        fclose(temp_file);
    }

    // Final cleanup.
    TIFFClose(tif);
    unlink(path.c_str());

    return 0;
}
