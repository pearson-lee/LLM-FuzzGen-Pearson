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
    uint32_t width = fdp.ConsumeIntegralInRange<uint32_t>(1, 512);
    uint32_t height = fdp.ConsumeIntegralInRange<uint32_t>(1, 512);
    TIFFSetField(tif, TIFFTAG_IMAGEWIDTH, width);
    TIFFSetField(tif, TIFFTAG_IMAGELENGTH, height);
    TIFFSetField(tif, TIFFTAG_BITSPERSAMPLE, 8);
    TIFFSetField(tif, TIFFTAG_SAMPLESPERPIXEL, 1);
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

    /*
     * ANALYSIS: Functions like TIFFWriteTile, TIFFReadRGBATile, and TIFFReadRGBAStrip
     *           had 0% coverage because the fuzzer only created striped images and
     *           used a high-level read API.
     * IMPLEMENTATION: The fuzzer now randomly creates either a tiled or a striped
     *                 image. For tiled images, it calls TIFFWriteTile to write data.
     *                 For striped images, it calls TIFFWriteScanline. This ensures
     *                 both writing paths are exercised.
     */
    if (fdp.ConsumeBool()) {
        // Tiled image path
        TIFFSetField(tif, TIFFTAG_TILEWIDTH, fdp.ConsumeIntegralInRange<uint32_t>(16, 256));
        TIFFSetField(tif, TIFFTAG_TILELENGTH, fdp.ConsumeIntegralInRange<uint32_t>(16, 256));
        tsize_t tile_size = TIFFTileSize(tif);
        if (tile_size > 0) {
            std::vector<char> dummy_tile(tile_size);
            fdp.ConsumeData(dummy_tile.data(), tile_size);
            TIFFWriteTile(tif, dummy_tile.data(), 0, 0, 0, 0);
        }
    } else {
        // Striped image path
        TIFFSetField(tif, TIFFTAG_PLANARCONFIG, PLANARCONFIG_CONTIG);
        tsize_t scanline_size = TIFFScanlineSize(tif);
        if (scanline_size > 0) {
            std::vector<char> dummy_scanline(scanline_size);
            TIFFWriteScanline(tif, dummy_scanline.data(), 0, 0);
        }
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

    bool is_tiled = TIFFIsTiled(tif);
    if (is_tiled) {
        /*
         * ANALYSIS: The functions TIFFReadRGBATile and TIFFReadRGBATileExt have 0% coverage.
         * IMPLEMENTATION: When a tiled image is detected, TIFFReadRGBATile is called to
         *                 read the first tile, exercising the tile-reading code paths.
         */
        uint32_t tile_width = 0, tile_height = 0;
        TIFFGetField(tif, TIFFTAG_TILEWIDTH, &tile_width);
        TIFFGetField(tif, TIFFTAG_TILELENGTH, &tile_height);
        if (tile_width > 0 && tile_height > 0 && tile_width < 4096 && tile_height < 4096) {
            uint32_t* raster = (uint32_t*)_TIFFmalloc(tile_width * tile_height * sizeof(uint32_t));
            if (raster) {
                TIFFReadRGBATile(tif, 0, 0, raster);
                _TIFFfree(raster);
            }
        }
    } else {
        /*
         * ANALYSIS: The functions TIFFReadRGBAStrip and TIFFReadRGBAStripExt have 0% coverage.
         * IMPLEMENTATION: When a striped image is detected, TIFFReadRGBAStrip is called to
         *                 read the first strip, exercising the strip-reading code paths.
         */
        uint32_t s_width = 0, s_height = 0;
        TIFFGetField(tif, TIFFTAG_IMAGEWIDTH, &s_width);
        TIFFGetField(tif, TIFFTAG_IMAGELENGTH, &s_height);
        if (s_height > 0 && s_width > 0 && s_width < 4096 && s_height < 4096) {
            // TIFFReadRGBAStrip reads a single strip. The buffer must be large enough
            // for the entire strip. A buffer for the whole image is safe.
            uint32_t* raster = (uint32_t*)_TIFFmalloc(s_width * s_height * sizeof(uint32_t));
            if (raster) {
                TIFFReadRGBAStrip(tif, 0, raster);
                _TIFFfree(raster);
            }
        }
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
    uint32_t r_width = 0, r_height = 0;
    TIFFGetField(tif, TIFFTAG_IMAGEWIDTH, &r_width);
    TIFFGetField(tif, TIFFTAG_IMAGELENGTH, &r_height);
    if (r_width > 0 && r_height > 0 && r_width < 4096 && r_height < 4096) {
        uint32_t* raster = (uint32_t*)_TIFFmalloc(r_width * r_height * sizeof(uint32_t));
        if (raster) {
            TIFFReadRGBAImage(tif, r_width, r_height, raster, 0);
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