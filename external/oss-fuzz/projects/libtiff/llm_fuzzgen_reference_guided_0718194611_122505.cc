/* BLOCKER_STRATEGY_CONTRACT
required_state: The predicate `!isFillOrder(tif, td->td_fillorder)` at tif_read.c:970 must evaluate to true. This requires the TIFF directory's fillorder tag to be different from the machine's native fill order. Additionally, `td->td_compression` must be `COMPRESSION_NONE` to enter the relevant code path.
state_constructor: Explicitly set `TIFFTAG_COMPRESSION` to `COMPRESSION_NONE` and `TIFFTAG_FILLORDER` to `FILLORDER_LSB2MSB`. The latter is typically different from the default machine fill order (`FILLORDER_MSB2LSB`), satisfying the predicate.
trigger_api: `TIFFReadEncodedTile` is called after writing tile data to the TIFF file, which then hits the blocker.
preserved_invariants: The fuzz target's input consumption contract is preserved. The core logic of creating a TIFF file, writing data, and then reading it back remains intact. No `FuzzedDataProvider` calls are reordered or removed.
END_BLOCKER_STRATEGY_CONTRACT */

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
    sprintf(filename, "/tmp/%s.tif", "llm_fuzzgen0717022724");

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
    
    // BLOCKER-SPECIFIC CHANGE: Set compression to NONE and fill order to LSB2MSB
    // to satisfy the conditions at tif_read.c:970 and trigger TIFFReverseBits.
    TIFFSetField(tif, TIFFTAG_COMPRESSION, COMPRESSION_NONE);
    TIFFSetField(tif, TIFFTAG_FILLORDER, FILLORDER_LSB2MSB);

    // Write some tile data
    tsize_t tile_size = TIFFTileSize(tif);
    if (tile_size > 0 && tile_size < 1024 * 1024) { // Avoid excessive allocation
        uint8_t* tile_buf = new uint8_t[tile_size];
        if (fdp.ConsumeData(tile_buf, tile_size) == tile_size) {
            ttile_t num_tiles = TIFFNumberOfTiles(tif);
            if (num_tiles > 0) {
                ttile_t tile_index = fdp.ConsumeIntegralInRange<ttile_t>(0, num_tiles - 1);
                TIFFWriteEncodedTile(tif, tile_index, tile_buf, tile_size);
            }
        }
        delete[] tile_buf;
    }

    // Write the directory to disk.
    TIFFCheckpointDirectory(tif);

    if (fdp.ConsumeBool()) {
        TIFFWriteDirectory(tif);
        uint64_t sub_offset = 0;
        // The subIFD offset is the *next* directory offset
        TIFFGetField(tif, TIFFTAG_SUBIFD, &sub_offset);
        if (sub_offset > 0) {
            TIFFSetSubDirectory(tif, sub_offset);
        }
    }

    FILE* null_fp = fopen("/dev/null", "w");
    if (null_fp) {
        TIFFPrintDirectory(tif, null_fp, 0);
        fclose(null_fp);
    }

    tsize_t read_tile_size = TIFFTileSize(tif);
    if (read_tile_size > 0 && read_tile_size < 1024 * 1024) {
        uint8_t* read_buf = new uint8_t[read_tile_size];
        ttile_t num_tiles = TIFFNumberOfTiles(tif);
        if (num_tiles > 0) {
            ttile_t tile_to_read = fdp.ConsumeIntegralInRange<ttile_t>(0, num_tiles - 1);
            // TRIGGER: This call hits the blocker. The state set above should now allow it to pass.
            TIFFReadEncodedTile(tif, tile_to_read, read_buf, read_tile_size);
        }
        delete[] read_buf;
    }

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
