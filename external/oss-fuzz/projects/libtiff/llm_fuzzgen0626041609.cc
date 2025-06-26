#include <cstddef>
#include <cstdint>
#include <vector>
#include <fuzzer/FuzzedDataProvider.h>
#include "tiffio.h"

// Struct to hold data for in-memory I/O operations.
// This allows libtiff to read from and write to a std::vector in memory.
struct TiffFuzzData {
    FuzzedDataProvider* fdp;
    std::vector<uint8_t> buffer;
    tmsize_t buffer_offset;
};

// libtiff callback for reading data from the in-memory buffer.
static tmsize_t readProc(thandle_t handle, void* data, tmsize_t size) {
    TiffFuzzData* fuzz_data = reinterpret_cast<TiffFuzzData*>(handle);
    tmsize_t available = fuzz_data->buffer.size() - fuzz_data->buffer_offset;
    tmsize_t to_read = size < available ? size : available;
    if (to_read > 0) {
        memcpy(data, fuzz_data->buffer.data() + fuzz_data->buffer_offset, to_read);
        fuzz_data->buffer_offset += to_read;
    }
    return to_read;
}

// libtiff callback for writing data to the in-memory buffer.
static tmsize_t writeProc(thandle_t handle, void* data, tmsize_t size) {
    TiffFuzzData* fuzz_data = reinterpret_cast<TiffFuzzData*>(handle);
    size_t new_offset = fuzz_data->buffer_offset + size;
    if (new_offset > fuzz_data->buffer.size()) {
        fuzz_data->buffer.resize(new_offset);
    }
    memcpy(fuzz_data->buffer.data() + fuzz_data->buffer_offset, data, size);
    fuzz_data->buffer_offset += size;
    return size;
}

// libtiff callback for seeking within the in-memory buffer.
static toff_t seekProc(thandle_t handle, toff_t offset, int whence) {
    TiffFuzzData* fuzz_data = reinterpret_cast<TiffFuzzData*>(handle);
    toff_t new_offset;
    switch (whence) {
        case SEEK_SET:
            new_offset = offset;
            break;
        case SEEK_CUR:
            new_offset = fuzz_data->buffer_offset + offset;
            break;
        case SEEK_END:
            new_offset = fuzz_data->buffer.size() + offset;
            break;
        default:
            return -1;
    }
    if (new_offset < 0) {
        return -1;
    }
    fuzz_data->buffer_offset = static_cast<tmsize_t>(new_offset);
    return new_offset;
}

// libtiff callback for closing the stream (no-op for memory streams).
static int closeProc(thandle_t) {
    return 0;
}

// libtiff callback for getting the size of the in-memory buffer.
static toff_t sizeProc(thandle_t handle) {
    TiffFuzzData* fuzz_data = reinterpret_cast<TiffFuzzData*>(handle);
    return fuzz_data->buffer.size();
}

// Dummy map/unmap callbacks required by TIFFClientOpen.
static int mapProc(thandle_t, void**, toff_t*) {
    return 0;
}
static void unmapProc(thandle_t, void*, toff_t) {}

// Suppress error and warning messages from libtiff to avoid spamming the console.
static void fuzzErrorHandler(const char*, const char*, va_list) {}

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
    if (size < 100) {
        return 0;
    }

    FuzzedDataProvider fdp(data, size);
    TiffFuzzData fuzz_data;
    fuzz_data.fdp = &fdp;
    fuzz_data.buffer_offset = 0;

    // Suppress all error/warning output from libtiff.
    TIFFSetErrorHandler(fuzzErrorHandler);
    TIFFSetWarningHandler(fuzzErrorHandler);

    // --- Write Phase: Create a TIFF in memory ---
    TIFF* write_tif = TIFFClientOpen("fuzz_write", "w",
                                     reinterpret_cast<thandle_t>(&fuzz_data),
                                     readProc, writeProc, seekProc, closeProc,
                                     sizeProc, mapProc, unmapProc);
    if (!write_tif) {
        return 0;
    }

    // Create and write one directory.
    uint32_t width = fdp.ConsumeIntegralInRange<uint32_t>(1, 256);
    uint32_t height = fdp.ConsumeIntegralInRange<uint32_t>(1, 256);
    uint16_t bpp = fdp.PickValueInArray<uint16_t>({1, 2, 4, 8, 16});
    uint16_t spp = fdp.ConsumeIntegralInRange<uint16_t>(1, 4);

    uint16_t compression = fdp.PickValueInArray<uint16_t>({
        COMPRESSION_NONE, COMPRESSION_LZW, COMPRESSION_PACKBITS,
        COMPRESSION_DEFLATE, COMPRESSION_ADOBE_DEFLATE, COMPRESSION_NEXT,
        COMPRESSION_CCITTRLE, COMPRESSION_CCITTFAX3, COMPRESSION_CCITTFAX4,
        COMPRESSION_THUNDERSCAN, COMPRESSION_OJPEG, COMPRESSION_JBIG,
        COMPRESSION_LZMA, COMPRESSION_PIXARLOG
    });
    uint16_t photometric = fdp.PickValueInArray<uint16_t>({
        PHOTOMETRIC_MINISWHITE, PHOTOMETRIC_MINISBLACK, PHOTOMETRIC_RGB,
        PHOTOMETRIC_PALETTE, PHOTOMETRIC_SEPARATED, PHOTOMETRIC_YCBCR,
        PHOTOMETRIC_CIELAB, PHOTOMETRIC_LOGL, PHOTOMETRIC_LOGLUV
    });
    
    TIFFSetField(write_tif, TIFFTAG_IMAGEWIDTH, width);
    TIFFSetField(write_tif, TIFFTAG_IMAGELENGTH, height);
    TIFFSetField(write_tif, TIFFTAG_BITSPERSAMPLE, bpp);
    TIFFSetField(write_tif, TIFFTAG_SAMPLESPERPIXEL, spp);
    TIFFSetField(write_tif, TIFFTAG_COMPRESSION, compression);
    TIFFSetField(write_tif, TIFFTAG_PHOTOMETRIC, photometric);
    TIFFSetField(write_tif, TIFFTAG_PLANARCONFIG, fdp.PickValueInArray<uint16_t>({PLANARCONFIG_CONTIG, PLANARCONFIG_SEPARATE}));

    bool is_tiled = fdp.ConsumeBool();
    if (is_tiled) {
        uint32_t tile_width = fdp.ConsumeIntegralInRange<uint32_t>(1, 16) * 16;
        uint32_t tile_height = fdp.ConsumeIntegralInRange<uint32_t>(1, 16) * 16;
        TIFFSetField(write_tif, TIFFTAG_TILEWIDTH, tile_width);
        TIFFSetField(write_tif, TIFFTAG_TILELENGTH, tile_height);
    } else {
        uint32_t rows_per_strip = fdp.ConsumeIntegralInRange<uint32_t>(1, height);
        TIFFSetField(write_tif, TIFFTAG_ROWSPERSTRIP, rows_per_strip);
    }

    if (is_tiled) {
        tmsize_t tile_size = TIFFTileSize(write_tif);
        if (tile_size > 0 && tile_size < fdp.remaining_bytes()) {
            std::vector<uint8_t> tile_buf = fdp.ConsumeBytes<uint8_t>(tile_size);
            if (tile_buf.size() == tile_size) {
                for (uint32_t tile = 0; tile < TIFFNumberOfTiles(write_tif); ++tile) {
                    if (TIFFWriteEncodedTile(write_tif, tile, tile_buf.data(), tile_size) == -1) {
                        break;
                    }
                }
            }
        }
    } else {
        tmsize_t scanline_size = TIFFScanlineSize(write_tif);
        if (scanline_size > 0 && scanline_size < fdp.remaining_bytes()) {
            std::vector<uint8_t> scanline_buf = fdp.ConsumeBytes<uint8_t>(scanline_size);
            if (scanline_buf.size() == scanline_size) {
                 for (uint32_t row = 0; row < height; ++row) {
                    if (TIFFWriteScanline(write_tif, scanline_buf.data(), row, 0) == -1) {
                        break;
                    }
                }
            }
        }
    }
    
    TIFFWriteDirectory(write_tif);
    TIFFClose(write_tif);

    // --- Read Phase: Read the TIFF from memory ---
    if (fuzz_data.buffer.empty()) {
        return 0;
    }
    fuzz_data.buffer_offset = 0;

    TIFF* read_tif = TIFFClientOpen("fuzz_read", "r",
                                    reinterpret_cast<thandle_t>(&fuzz_data),
                                    readProc, writeProc, seekProc, closeProc,
                                    sizeProc, mapProc, unmapProc);

    if (!read_tif) {
        return 0;
    }
    
    if (TIFFIsTiled(read_tif)) {
        uint32_t num_tiles = TIFFNumberOfTiles(read_tif);
        if (num_tiles > 0) {
            uint32_t tile_to_read = fdp.ConsumeIntegralInRange<uint32_t>(0, num_tiles - 1);
            tmsize_t tile_size = TIFFTileSize(read_tif);
            if (tile_size > 0 && tile_size < 1000000) {
                uint64_t* tile_byte_counts = nullptr;
                TIFFGetField(read_tif, TIFFTAG_TILEBYTECOUNTS, &tile_byte_counts);
                bool skip_read = false;
                if (tile_byte_counts && tile_to_read < num_tiles && tile_byte_counts[tile_to_read] > (uint64_t)tile_size) {
                    skip_read = true;
                }
                if (!skip_read) {
                    void* tile_buf = _TIFFmalloc(tile_size);
                    if (tile_buf) {
                        TIFFReadEncodedTile(read_tif, tile_to_read, tile_buf, tile_size);
                        _TIFFfree(tile_buf);
                    }
                }
            }
        }
    } else {
        uint32_t num_strips = TIFFNumberOfStrips(read_tif);
        if (num_strips > 0) {
            uint32_t strip_to_read = fdp.ConsumeIntegralInRange<uint32_t>(0, num_strips - 1);
            tmsize_t strip_size = TIFFStripSize(read_tif);
            if (strip_size > 0 && strip_size < 1000000) {
                uint64_t* strip_byte_counts = nullptr;
                TIFFGetField(read_tif, TIFFTAG_STRIPBYTECOUNTS, &strip_byte_counts);
                bool skip_read = false;
                if (strip_byte_counts && strip_to_read < num_strips && strip_byte_counts[strip_to_read] > (uint64_t)strip_size) {
                    skip_read = true;
                }
                if (!skip_read) {
                    void* strip_buf = _TIFFmalloc(strip_size);
                    if (strip_buf) {
                        TIFFReadEncodedStrip(read_tif, strip_to_read, strip_buf, strip_size);
                        _TIFFfree(strip_buf);
                    }
                }
            }
        }
    }

    TIFFClose(read_tif);

    return 0;
}