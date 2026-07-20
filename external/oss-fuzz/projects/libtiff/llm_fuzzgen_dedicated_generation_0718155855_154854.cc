/* BLOCKER_STRATEGY_CONTRACT
required_state: The `tif->tif_flags` field of the `TIFF` structure must have the `TIFF_SWAB` flag set. This is achieved when the byte order of the TIFF file is opposite to the native byte order of the machine processing it. The file must also be memory-mapped to enter the correct branch in TIFFAdvanceDirectory.
state_constructor: A TIFF file is created with a non-native byte order by calling `TIFFOpen` with the mode "wb" (write, big-endian). This file is written with at least two directories. After closing, the file is re-opened with `TIFFOpen` in read mode ("r"). Libtiff detects the endianness mismatch from the file's header and sets the `TIFF_SWAB` flag. Opening in read mode also enables memory mapping by default.
trigger_api: `TIFFNumberOfDirectories()` is called. This function internally loops through all directories using `TIFFAdvanceDirectory`, which contains the blocker.
preserved_invariants: A valid, multi-directory TIFF file is created and then read. The core logic of creating, writing, closing, and re-opening a TIFF file is preserved.
END_BLOCKER_STRATEGY_CONTRACT */

#include <fuzzer/FuzzedDataProvider.h>
#include <tiffio.h>
#include <tiff.h>
#include <unistd.h>
#include <string>
#include <vector>

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size) {
    if (Size < 20) {
        return 0;
    }
    FuzzedDataProvider fdp(Data, Size);
    const std::string path = "/tmp/fuzz_tiff_swab.tif";

    // Part 1: Create a big-endian TIFF file with two directories.
    // Using "wb" forces big-endian (Motorola) byte order. On a typical
    // little-endian fuzzer host, this will trigger the byte-swapping logic.
    TIFF* tif_w = TIFFOpen(path.c_str(), "wb");
    if (!tif_w) {
        return 0;
    }

    // --- Directory 1 ---
    TIFFSetField(tif_w, TIFFTAG_IMAGEWIDTH, fdp.ConsumeIntegralInRange<uint32_t>(1, 256));
    TIFFSetField(tif_w, TIFFTAG_IMAGELENGTH, fdp.ConsumeIntegralInRange<uint32_t>(1, 256));
    TIFFSetField(tif_w, TIFFTAG_BITSPERSAMPLE, (uint16_t)8);
    TIFFSetField(tif_w, TIFFTAG_SAMPLESPERPIXEL, (uint16_t)1);
    TIFFSetField(tif_w, TIFFTAG_PHOTOMETRIC, PHOTOMETRIC_MINISBLACK);
    TIFFSetField(tif_w, TIFFTAG_PLANARCONFIG, PLANARCONFIG_CONTIG);
    TIFFSetField(tif_w, TIFFTAG_COMPRESSION, COMPRESSION_NONE);
    TIFFSetField(tif_w, TIFFTAG_ROWSPERSTRIP, fdp.ConsumeIntegralInRange<uint32_t>(1, 256));

    tsize_t scanline_size = TIFFScanlineSize(tif_w);
    if (scanline_size > 0) {
        std::vector<char> dummy_scanline(scanline_size);
        fdp.ConsumeData(dummy_scanline.data(), scanline_size);
        TIFFWriteScanline(tif_w, dummy_scanline.data(), 0, 0);
    }

    // Write the first directory and prepare for the second.
    if (!TIFFWriteDirectory(tif_w)) {
        TIFFClose(tif_w);
        unlink(path.c_str());
        return 0;
    }

    // --- Directory 2 ---
    TIFFSetField(tif_w, TIFFTAG_IMAGEWIDTH, fdp.ConsumeIntegralInRange<uint32_t>(1, 256));
    TIFFSetField(tif_w, TIFFTAG_IMAGELENGTH, fdp.ConsumeIntegralInRange<uint32_t>(1, 256));
    TIFFSetField(tif_w, TIFFTAG_BITSPERSAMPLE, (uint16_t)8);
    TIFFSetField(tif_w, TIFFTAG_SAMPLESPERPIXEL, (uint16_t)1);
    TIFFSetField(tif_w, TIFFTAG_PHOTOMETRIC, PHOTOMETRIC_MINISBLACK);
    TIFFSetField(tif_w, TIFFTAG_PLANARCONFIG, PLANARCONFIG_CONTIG);
    TIFFSetField(tif_w, TIFFTAG_COMPRESSION, COMPRESSION_NONE);
    TIFFSetField(tif_w, TIFFTAG_ROWSPERSTRIP, fdp.ConsumeIntegralInRange<uint32_t>(1, 256));
    TIFFSetField(tif_w, TIFFTAG_SUBFILETYPE, FILETYPE_PAGE);
    TIFFSetField(tif_w, TIFFTAG_PAGENUMBER, (uint16_t)1, (uint16_t)2);

    scanline_size = TIFFScanlineSize(tif_w);
    if (scanline_size > 0) {
        std::vector<char> dummy_scanline(scanline_size);
        fdp.ConsumeData(dummy_scanline.data(), scanline_size);
        TIFFWriteScanline(tif_w, dummy_scanline.data(), 0, 0);
    }

    TIFFClose(tif_w);

    // Part 2: Open the file for reading. This will set TIFF_SWAB if the
    // file's endianness is different from the host's, and will memory-map it.
    TIFF* tif_r = TIFFOpen(path.c_str(), "r");
    if (!tif_r) {
        unlink(path.c_str());
        return 0;
    }

    // Call TIFFNumberOfDirectories, which will loop through all directories
    // using TIFFAdvanceDirectory internally.
    TIFFNumberOfDirectories(tif_r);

    TIFFClose(tif_r);
    unlink(path.c_str());

    return 0;
}
