#include <cstddef>
#include <cstdint>
#include <vector>
#include <fuzzer/FuzzedDataProvider.h>

#include "/work/include/tiffio.h"

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size) {
    FuzzedDataProvider fdp(Data, Size);

    const char* filename = "/tmp/fuzz.tif";
    TIFF *write_tif = TIFFOpen(filename, "w");
    if (!write_tif) {
        return 0;
    }

    const int width = fdp.ConsumeIntegralInRange<int>(1, 512);
    const int height = fdp.ConsumeIntegralInRange<int>(1, 512);

    TIFFSetField(write_tif, TIFFTAG_IMAGEWIDTH, width);
    TIFFSetField(write_tif, TIFFTAG_IMAGELENGTH, height);
    TIFFSetField(write_tif, TIFFTAG_BITSPERSAMPLE, 8);
    TIFFSetField(write_tif, TIFFTAG_SAMPLESPERPIXEL, 1);
    TIFFSetField(write_tif, TIFFTAG_PLANARCONFIG, PLANARCONFIG_CONTIG);
    TIFFSetField(write_tif, TIFFTAG_PHOTOMETRIC, PHOTOMETRIC_MINISBLACK);
    TIFFSetField(write_tif, TIFFTAG_ROWSPERSTRIP, height);

    std::vector<uint8_t> scanline(width, 0);
    if (TIFFWriteScanline(write_tif, scanline.data(), 0, 0) < 0) {
        TIFFClose(write_tif);
        return 0;
    }

    TIFFWriteDirectory(write_tif);

    // Added to create a multi-directory TIFF, covering previously missed branches for reading them.
    if (fdp.ConsumeBool()) {
        TIFFSetField(write_tif, TIFFTAG_SUBFILETYPE, FILETYPE_REDUCEDIMAGE);
        const int new_width = width / 2 > 0 ? width / 2 : 1;
        const int new_height = height / 2 > 0 ? height / 2 : 1;
        TIFFSetField(write_tif, TIFFTAG_IMAGEWIDTH, new_width);
        TIFFSetField(write_tif, TIFFTAG_IMAGELENGTH, new_height);
        TIFFSetField(write_tif, TIFFTAG_BITSPERSAMPLE, 8);
        TIFFSetField(write_tif, TIFFTAG_SAMPLESPERPIXEL, 1);
        TIFFSetField(write_tif, TIFFTAG_PLANARCONFIG, PLANARCONFIG_CONTIG);
        TIFFSetField(write_tif, TIFFTAG_PHOTOMETRIC, PHOTOMETRIC_MINISBLACK);
        TIFFSetField(write_tif, TIFFTAG_ROWSPERSTRIP, new_height);
        TIFFWriteDirectory(write_tif);
    }

    TIFFClose(write_tif);

    TIFF *read_tif = TIFFOpen(filename, "r");
    if (read_tif) {
        do {
            uint32_t w, h;
            TIFFGetField(read_tif, TIFFTAG_IMAGEWIDTH, &w);
            TIFFGetField(read_tif, TIFFTAG_IMAGELENGTH, &h);
            tsize_t scanline_size = TIFFScanlineSize(read_tif);
            if (scanline_size > 0) {
                std::vector<uint8_t> buffer(scanline_size);
                for (uint32_t row = 0; row < h; ++row) {
                    TIFFReadScanline(read_tif, buffer.data(), row);
                }
            }
        } while (TIFFReadDirectory(read_tif));
        TIFFClose(read_tif);
    }

    return 0;
}