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
    if (Size < 20) {
        // Require a minimum size to avoid trivial inputs.
        return 0;
    }
    FuzzedDataProvider fdp(Data, Size);

    // Create a unique temporary filename for thread safety.
    const std::string path = std::string("/tmp/") + _FUZZ_TARGET_NAME + ".tif";

    // Randomly choose between classic TIFF and BigTIFF format.
    const char* mode = fdp.ConsumeBool() ? "w" : "w8";

    TIFF* tif = TIFFOpen(path.c_str(), mode);
    if (!tif) {
        return 0;
    }

    // Set basic required tags to create a valid TIFF structure.
    TIFFSetField(tif, TIFFTAG_IMAGEWIDTH, fdp.ConsumeIntegralInRange<uint32_t>(1, 512));
    TIFFSetField(tif, TIFFTAG_IMAGELENGTH, fdp.ConsumeIntegralInRange<uint32_t>(1, 512));
    TIFFSetField(tif, TIFFTAG_BITSPERSAMPLE, 8);
    TIFFSetField(tif, TIFFTAG_SAMPLESPERPIXEL, 1);
    TIFFSetField(tif, TIFFTAG_PLANARCONFIG, PLANARCONFIG_CONTIG);
    TIFFSetField(tif, TIFFTAG_PHOTOMETRIC, PHOTOMETRIC_MINISBLACK);

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

    /*
     * ANALYSIS: TIFFReadCustomDirectory, TIFFCreateEXIFDirectory, and
     *           TIFFWriteCustomDirectory have 0% coverage.
     * IMPLEMENTATION: Create and write an EXIF directory, then link it to the
     *                 main IFD using the TIFFTAG_EXIFIFD tag. This exercises
     *                 the creation, writing, and subsequent reading of custom
     *                 directory types.
     */
    if (fdp.ConsumeBool()) {
        uint64_t exif_dir_offset = 0;
        TIFFCreateEXIFDirectory(tif);
        TIFFSetField(tif, TIFFTAG_IMAGEWIDTH, fdp.ConsumeIntegralInRange<uint32_t>(1, 64));
        TIFFSetField(tif, TIFFTAG_IMAGELENGTH, fdp.ConsumeIntegralInRange<uint32_t>(1, 64));
        TIFFWriteCustomDirectory(tif, &exif_dir_offset);
        TIFFSetDirectory(tif, 0); // Switch back to the main directory
        TIFFSetField(tif, TIFFTAG_EXIFIFD, exif_dir_offset);
    }

    /*
     * ANALYSIS: Coverage for various compression codecs (LZW, Packbits, Deflate)
     *           is low or zero.
     * IMPLEMENTATION: Randomly select a compression scheme to use for the image.
     *                 This exercises the encoding logic for different compressors.
     */
    const uint16_t compression_schemes[] = {
        COMPRESSION_NONE, COMPRESSION_LZW, COMPRESSION_PACKBITS, COMPRESSION_DEFLATE
    };
    uint16_t compression = fdp.PickValueInArray(compression_schemes);
    TIFFSetField(tif, TIFFTAG_COMPRESSION, compression);

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

    // Re-open for reading.
    tif = TIFFOpen(path.c_str(), "r");
    if (!tif) {
        unlink(path.c_str());
        return 0;
    }

    /*
     * ANALYSIS: Functions in tif_getimage.c (e.g., TIFFReadRGBAImage) and
     *           various decompression codecs have low coverage.
     * IMPLEMENTATION: TIFFReadRGBAImage is called to force the library to
     *                 decompress and process the image data, exercising the
     *                 full read path and the randomly selected compression
     *                 codec. Memory for the raster buffer is managed via
     *                 _TIFFmalloc/_TIFFfree to ensure safety.
     */
    uint32_t width = 0, height = 0;
    TIFFGetField(tif, TIFFTAG_IMAGEWIDTH, &width);
    TIFFGetField(tif, TIFFTAG_IMAGELENGTH, &height);
    if (width > 0 && height > 0 && width < 4096 && height < 4096) {
        uint32_t* raster = (uint32_t*)_TIFFmalloc(width * height * sizeof(uint32_t));
        if (raster) {
            TIFFReadRGBAImage(tif, width, height, raster, 0);
            _TIFFfree(raster);
        }
    }
    TIFFSetDirectory(tif, 0); // Reset to the first directory for printing.

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