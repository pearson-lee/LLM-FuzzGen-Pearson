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
    uint16_t samplesperpixel = 1;
    uint16_t photometric = PHOTOMETRIC_MINISBLACK;
    uint16_t compression_tag = COMPRESSION_NONE;

    // Added different compression types to improve coverage in compression-related files.
    uint16_t compression_type = fdp.ConsumeIntegralInRange<uint16_t>(0, 3);
    if (compression_type == 1) {
        compression_tag = COMPRESSION_LZW;
    } else if (compression_type == 2) {
        compression_tag = COMPRESSION_ADOBE_DEFLATE;
    } else if (compression_type == 3) {
        compression_tag = COMPRESSION_JPEG;
        samplesperpixel = 3;
        photometric = PHOTOMETRIC_YCBCR;
    }

    TIFFSetField(write_tif, TIFFTAG_IMAGEWIDTH, width);
    TIFFSetField(write_tif, TIFFTAG_IMAGELENGTH, height);
    TIFFSetField(write_tif, TIFFTAG_BITSPERSAMPLE, 8);
    TIFFSetField(write_tif, TIFFTAG_SAMPLESPERPIXEL, samplesperpixel);
    TIFFSetField(write_tif, TIFFTAG_PLANARCONFIG, PLANARCONFIG_CONTIG);
    TIFFSetField(write_tif, TIFFTAG_PHOTOMETRIC, photometric);
    TIFFSetField(write_tif, TIFFTAG_COMPRESSION, compression_tag);

    // Added predictor to improve coverage in tif_predict.c for LZW and Deflate compressions.
    if (compression_tag == COMPRESSION_LZW || compression_tag == COMPRESSION_ADOBE_DEFLATE) {
        if (fdp.ConsumeBool()) {
            TIFFSetField(write_tif, TIFFTAG_PREDICTOR, PREDICTOR_HORIZONTAL);
        }
    }

    if (compression_tag == COMPRESSION_JPEG) {
        TIFFSetField(write_tif, TIFFTAG_JPEGQUALITY, fdp.ConsumeIntegralInRange<int>(1, 100));
        TIFFSetField(write_tif, TIFFTAG_JPEGCOLORMODE, JPEGCOLORMODE_RGB);
    }

    // Added tiling to improve coverage in tile-related functions (tif_tile.c, tif_getimage.c).
    if (fdp.ConsumeBool()) { // Tiled
        uint32_t tile_width = fdp.ConsumeIntegralInRange<uint32_t>(16, 256);
        uint32_t tile_height = fdp.ConsumeIntegralInRange<uint32_t>(16, 256);
        TIFFSetField(write_tif, TIFFTAG_TILEWIDTH, tile_width);
        TIFFSetField(write_tif, TIFFTAG_TILELENGTH, tile_height);

        tsize_t tile_size = TIFFTileSize(write_tif);
        if (tile_size > 0) {
            std::vector<uint8_t> tile_buffer(tile_size);
            for (uint32_t y = 0; y < height; y += tile_height) {
                for (uint32_t x = 0; x < width; x += tile_width) {
                    if (TIFFWriteEncodedTile(write_tif, TIFFComputeTile(write_tif, x, y, 0, 0), tile_buffer.data(), tile_size) < 0) {
                        TIFFClose(write_tif);
                        return 0;
                    }
                }
            }
        }
    } else { // Stripped
        TIFFSetField(write_tif, TIFFTAG_ROWSPERSTRIP, height);
        tsize_t scanline_size = TIFFScanlineSize(write_tif);
        if (scanline_size > 0) {
            std::vector<uint8_t> scanline(scanline_size);
            for (int row = 0; row < height; ++row) {
                if (TIFFWriteScanline(write_tif, scanline.data(), row, 0) < 0) {
                    TIFFClose(write_tif);
                    return 0;
                }
            }
        }
    }

    // Added call to TIFFRewriteDirectory to improve coverage in tif_dirwrite.c.
    if (fdp.ConsumeBool()) {
        TIFFRewriteDirectory(write_tif);
    } else {
        TIFFWriteDirectory(write_tif);
    }

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
            if (TIFFIsTiled(read_tif)) {
                tsize_t tile_size = TIFFTileSize(read_tif);
                if (tile_size > 0) {
                    std::vector<uint8_t> buffer(tile_size);
                    uint32_t w, h, tw, th;
                    TIFFGetField(read_tif, TIFFTAG_IMAGEWIDTH, &w);
                    TIFFGetField(read_tif, TIFFTAG_IMAGELENGTH, &h);
                    TIFFGetField(read_tif, TIFFTAG_TILEWIDTH, &tw);
                    TIFFGetField(read_tif, TIFFTAG_TILELENGTH, &th);
                    for (uint32_t y = 0; y < h; y += th) {
                        for (uint32_t x = 0; x < w; x += tw) {
                            TIFFReadEncodedTile(read_tif, TIFFComputeTile(read_tif, x, y, 0, 0), buffer.data(), -1);
                        }
                    }
                }
            } else {
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
            }
        } while (TIFFReadDirectory(read_tif));
        TIFFClose(read_tif);
    }

    return 0;
}