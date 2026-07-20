/* BLOCKER_STRATEGY_CONTRACT
required_state: (tif->tif_flags & TIFF_DIRTYSTRIP) && !(tif->tif_flags & TIFF_DIRTYDIRECT) && (tif->tif_mode == O_RDWR)
state_constructor: First, a complete TIFF file is created and written to disk using TIFFOpen with "w" mode. This file is then closed. Second, the same file is re-opened using TIFFOpen with "r+" mode, which sets tif_mode to O_RDWR. Then, TIFFWriteScanline is called to modify image data, which sets the TIFF_DIRTYSTRIP flag without setting the TIFF_DIRTYDIRECT flag.
trigger_api: TIFFFlush(tif)
preserved_invariants: The file must be opened in "r+" mode for the second stage. TIFFSetField must not be called in the second stage before TIFFFlush.
END_BLOCKER_STRATEGY_CONTRACT */

#include <cstdint>
#include <string>
#include <vector>
#include <unistd.h>
#include <fuzzer/FuzzedDataProvider.h>

#include "tiffio.h"

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    FuzzedDataProvider fdp(data, size);
    std::string filename = "/tmp/fuzz_tiff_flush.tif";

    // Part 1: Create a valid baseline TIFF file on disk.
    TIFF *tif_write = TIFFOpen(filename.c_str(), "w");
    if (!tif_write) {
        return 0;
    }

    uint32_t width = fdp.ConsumeIntegralInRange<uint32_t>(1, 512);
    uint32_t height = fdp.ConsumeIntegralInRange<uint32_t>(1, 512);

    TIFFSetField(tif_write, TIFFTAG_IMAGEWIDTH, width);
    TIFFSetField(tif_write, TIFFTAG_IMAGELENGTH, height);
    TIFFSetField(tif_write, TIFFTAG_BITSPERSAMPLE, 8);
    TIFFSetField(tif_write, TIFFTAG_SAMPLESPERPIXEL, 1);
    TIFFSetField(tif_write, TIFFTAG_PLANARCONFIG, PLANARCONFIG_CONTIG);
    TIFFSetField(tif_write, TIFFTAG_PHOTOMETRIC, PHOTOMETRIC_MINISBLACK);
    TIFFSetField(tif_write, TIFFTAG_ROWSPERSTRIP, height);

    tmsize_t scanline_size = TIFFScanlineSize(tif_write);
    if (scanline_size > 0 && (height * scanline_size) < 1000000) {
        std::vector<uint8_t> scanline(scanline_size, 0);
        for (uint32_t row = 0; row < height; ++row) {
            if (TIFFWriteScanline(tif_write, scanline.data(), row, 0) < 0) {
                TIFFClose(tif_write);
                unlink(filename.c_str());
                return 0;
            }
        }
    } else {
        TIFFClose(tif_write);
        unlink(filename.c_str());
        return 0;
    }

    TIFFWriteDirectory(tif_write);
    TIFFClose(tif_write);

    // Part 2: Re-open the file in update mode ("r+") to get O_RDWR.
    TIFF *tif_update = TIFFOpen(filename.c_str(), "r+");
    if (!tif_update) {
        unlink(filename.c_str());
        return 0;
    }

    // Part 3: Dirty a strip to set TIFF_DIRTYSTRIP, without dirtying the directory.
    scanline_size = TIFFScanlineSize(tif_update);
    if (scanline_size > 0 && fdp.remaining_bytes() >= scanline_size) {
        std::vector<uint8_t> fuzz_scanline = fdp.ConsumeBytes<uint8_t>(scanline_size);
        uint32_t row_to_write = fdp.ConsumeIntegralInRange<uint32_t>(0, height - 1);
        // This write should set the TIFF_DIRTYSTRIP flag.
        TIFFWriteScanline(tif_update, fuzz_scanline.data(), row_to_write, 0);
    }

    // Part 4: Trigger the blocker.
    // At this point, tif_mode is O_RDWR, TIFF_DIRTYSTRIP is set,
    // and TIFF_DIRTYDIRECT is not set.
    TIFFFlush(tif_update);

    // Cleanup
    TIFFClose(tif_update);
    unlink(filename.c_str());

    return 0;
}
