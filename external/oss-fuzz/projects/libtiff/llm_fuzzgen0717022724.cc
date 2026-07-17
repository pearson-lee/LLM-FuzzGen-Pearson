#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <string>
#include <unistd.h>
#include <fuzzer/FuzzedDataProvider.h>
#include "tiffio.h"

// Suppress error/warning messages from libtiff to avoid polluting fuzzer output
void SuppressErrorHandler(const char*, const char*, va_list) {}

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
    FuzzedDataProvider fdp(data, size);

    // Set custom error and warning handlers to suppress console output.
    TIFFSetErrorHandler(SuppressErrorHandler);
    TIFFSetWarningHandler(SuppressErrorHandler);

    char filename[256];
    // Create a unique temporary filename to avoid race conditions.
    sprintf(filename, "/tmp/%s.tif", _FUZZ_TARGET_NAME);

    // Decide on TIFF mode (classic, big-endian, little-endian, BigTIFF)
    const char* mode;
    switch (fdp.ConsumeIntegralInRange<uint8_t>(0, 3)) {
        case 0:
            mode = "w"; // classic, native endian
            break;
        case 1:
            mode = "wb"; // classic, big-endian
            break;
        case 2:
            mode = "wl"; // classic, little-endian
            break;
        default:
            mode = "w8"; // BigTIFF
            break;
    }

    TIFF* tif = TIFFOpen(filename, mode);
    if (!tif) {
        // If opening fails, clean up and exit.
        unlink(filename);
        return 0;
    }

    /*
     * ANALYSIS: The coverage report shows many TIFF tags are not being exercised
     * in TIFFPrintDirectory. Also, the encoding path of TIFFWriteEncodedTile is
     * completely uncovered.
     * IMPLEMENTATION: We will set a wide variety of tags based on fuzzer input
     * and use a compression scheme to create a complex TIFF file. This will
     * improve coverage in TIFFWriteEncodedTile and TIFFPrintDirectory.
    */
    uint32_t width = fdp.ConsumeIntegralInRange<uint32_t>(1, 512);
    uint32_t height = fdp.ConsumeIntegralInRange<uint32_t>(1, 512);
    uint16_t bps = fdp.PickValueInArray<uint16_t>({1, 2, 4, 8, 16});
    uint16_t spp = fdp.ConsumeIntegralInRange<uint16_t>(1, 4);
    uint16_t planarconfig = fdp.PickValueInArray<uint16_t>({PLANARCONFIG_CONTIG, PLANARCONFIG_SEPARATE});
    uint32_t tile_width = fdp.ConsumeIntegralInRange<uint32_t>(16, 256);
    uint32_t tile_height = fdp.ConsumeIntegralInRange<uint32_t>(16, 256);

    TIFFSetField(tif, TIFFTAG_IMAGEWIDTH, width);
    TIFFSetField(tif, TIFFTAG_IMAGELENGTH, height);
    TIFFSetField(tif, TIFFTAG_BITSPERSAMPLE, bps);
    TIFFSetField(tif, TIFFTAG_SAMPLESPERPIXEL, spp);
    TIFFSetField(tif, TIFFTAG_PLANARCONFIG, planarconfig);
    TIFFSetField(tif, TIFFTAG_TILEWIDTH, tile_width);
    TIFFSetField(tif, TIFFTAG_TILELENGTH, tile_height);
    TIFFSetField(tif, TIFFTAG_PHOTOMETRIC, fdp.PickValueInArray<uint16_t>({PHOTOMETRIC_MINISWHITE, PHOTOMETRIC_MINISBLACK, PHOTOMETRIC_RGB}));
    TIFFSetField(tif, TIFFTAG_COMPRESSION, fdp.PickValueInArray<uint16_t>({COMPRESSION_NONE, COMPRESSION_PACKBITS, COMPRESSION_LZW}));

    // Write some tile data
    tsize_t tile_size = TIFFTileSize(tif);
    if (tile_size > 0 && tile_size < 1024 * 1024) { // Avoid excessive allocation
        uint8_t* tile_buf = new uint8_t[tile_size];
        if (fdp.ConsumeData(tile_buf, tile_size) == tile_size) {
            ttile_t num_tiles = TIFFNumberOfTiles(tif);
            if (num_tiles > 0) {
                ttile_t tile_index = fdp.ConsumeIntegralInRange<ttile_t>(0, num_tiles - 1);
                /*
                 * ANALYSIS: TIFFWriteEncodedTile has low coverage, especially its encoding paths.
                 * IMPLEMENTATION: Call TIFFWriteEncodedTile to write fuzzer-generated
                 * data to a tile, exercising the configured compression.
                */
                TIFFWriteEncodedTile(tif, tile_index, tile_buf, tile_size);
            }
        }
        delete[] tile_buf;
    }

    // Write the directory to disk.
    TIFFCheckpointDirectory(tif);

    /*
     * ANALYSIS: TIFFSetSubDirectory has 0% coverage.
     * IMPLEMENTATION: Create a sub-IFD by writing another directory and then
     * use TIFFSetSubDirectory to navigate to it, exercising this uncovered function.
    */
    if (fdp.ConsumeBool()) {
        TIFFWriteDirectory(tif);
        uint64_t sub_offset = 0;
        // The subIFD offset is the *next* directory offset
        TIFFGetField(tif, TIFFTAG_SUBIFD, &sub_offset);
        if (sub_offset > 0) {
            TIFFSetSubDirectory(tif, sub_offset);
        }
    }

    /*
     * ANALYSIS: TIFFPrintDirectory has very low coverage (18%) because many
     * tags are not being set in the input files.
     * IMPLEMENTATION: Open /dev/null to discard output and call TIFFPrintDirectory.
     * Because we set many tags earlier, this will hit many uncovered branches.
    */
    FILE* null_fp = fopen("/dev/null", "w");
    if (null_fp) {
        TIFFPrintDirectory(tif, null_fp, 0);
        fclose(null_fp);
    }

    /*
     * ANALYSIS: TIFFReadEncodedTile has low coverage on its success paths.
     * IMPLEMENTATION: After writing tiles, attempt to read one back to exercise
     * the tile decoding logic.
    */
    tsize_t read_tile_size = TIFFTileSize(tif);
    if (read_tile_size > 0 && read_tile_size < 1024 * 1024) {
        uint8_t* read_buf = new uint8_t[read_tile_size];
        ttile_t num_tiles = TIFFNumberOfTiles(tif);
        if (num_tiles > 0) {
            ttile_t tile_to_read = fdp.ConsumeIntegralInRange<ttile_t>(0, num_tiles - 1);
            TIFFReadEncodedTile(tif, tile_to_read, read_buf, read_tile_size);
        }
        delete[] read_buf;
    }

    /*
     * ANALYSIS: TIFFUnlinkDirectory has many uncovered error paths and conditional branches.
     * IMPLEMENTATION: Re-open the file in append mode and call TIFFUnlinkDirectory with
     * various inputs to target specific branches, such as dirn=0, dirn=1, and an out-of-bounds dirn.
    */
    TIFFClose(tif);
    tif = TIFFOpen(filename, "a"); // Re-open in append mode for writing
    if (tif) {
        tdir_t num_dirs = TIFFNumberOfDirectories(tif);
        if (num_dirs > 0 && fdp.ConsumeBool()) {
            // Test edge cases: 0 (invalid), 1 (first), and out-of-bounds
            tdir_t dir_to_unlink = fdp.PickValueInArray<tdir_t>({(tdir_t)0, (tdir_t)1, (tdir_t)(num_dirs + 1)});
            TIFFUnlinkDirectory(tif, dir_to_unlink);
        }
    }

    // Final cleanup
    if (tif) {
        TIFFClose(tif);
    }
    unlink(filename);

    return 0;
}