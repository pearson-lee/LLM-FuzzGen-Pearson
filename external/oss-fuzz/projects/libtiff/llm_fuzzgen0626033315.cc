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

    // Create and write two directories to test multi-directory handling.
    for (int i = 0; i < 2; ++i) {
        uint32_t width = fdp.ConsumeIntegralInRange<uint32_t>(1, 256);
        uint32_t height = fdp.ConsumeIntegralInRange<uint32_t>(1, 256);
        uint16_t bpp = fdp.PickValueInArray<uint16_t>({1, 2, 4, 8, 16});
        uint16_t spp = fdp.ConsumeIntegralInRange<uint16_t>(1, 4);
        uint16_t compression = fdp.PickValueInArray<uint16_t>({
            COMPRESSION_NONE, COMPRESSION_LZW, COMPRESSION_PACKBITS,
            COMPRESSION_DEFLATE
        });
        uint16_t photometric = fdp.PickValueInArray<uint16_t>({
            PHOTOMETRIC_MINISWHITE, PHOTOMETRIC_MINISBLACK, PHOTOMETRIC_RGB,
            PHOTOMETRIC_PALETTE, PHOTOMETRIC_SEPARATED
        });
        
        TIFFSetField(write_tif, TIFFTAG_IMAGEWIDTH, width);
        TIFFSetField(write_tif, TIFFTAG_IMAGELENGTH, height);
        TIFFSetField(write_tif, TIFFTAG_BITSPERSAMPLE, bpp);
        TIFFSetField(write_tif, TIFFTAG_SAMPLESPERPIXEL, spp);
        TIFFSetField(write_tif, TIFFTAG_COMPRESSION, compression);
        TIFFSetField(write_tif, TIFFTAG_PHOTOMETRIC, photometric);
        TIFFSetField(write_tif, TIFFTAG_PLANARCONFIG, PLANARCONFIG_CONTIG);
        TIFFSetField(write_tif, TIFFTAG_ROWSPERSTRIP, height); // One strip per image

        tmsize_t scanline_size = TIFFScanlineSize(write_tif);
        if (scanline_size > 0 && scanline_size < fdp.remaining_bytes()) {
            std::vector<uint8_t> scanline_buf = fdp.ConsumeBytes<uint8_t>(scanline_size);
            if (scanline_buf.size() == scanline_size) {
                 for (uint32_t row = 0; row < height; ++row) {
                    TIFFWriteScanline(write_tif, scanline_buf.data(), row, 0);
                }
            }
        }
        
        // Finalize the current directory to allow for another one.
        TIFFWriteDirectory(write_tif);
    }

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

    // Target TIFFSetDirectory by selecting a valid directory to read.
    uint16_t num_dirs = TIFFNumberOfDirectories(read_tif);
    if (num_dirs > 0) {
        uint16_t dir_to_read = fdp.ConsumeIntegralInRange<uint16_t>(0, num_dirs - 1);
        TIFFSetDirectory(read_tif, dir_to_read);
    }

    // Target TIFFReadRGBAImage to cover tif_getimage.c functions.
    uint32_t read_width, read_height;
    TIFFGetField(read_tif, TIFFTAG_IMAGEWIDTH, &read_width);
    TIFFGetField(read_tif, TIFFTAG_IMAGELENGTH, &read_height);

    if (read_width > 0 && read_height > 0 && read_width < 4096 && read_height < 4096) {
        size_t raster_size = read_width * read_height;
        // Prevent enormous allocations.
        if (raster_size > 0 && raster_size < 1000000) {
            uint32_t* raster = (uint32_t*)_TIFFmalloc(raster_size * sizeof(uint32_t));
            if (raster) {
                // This high-level call targets many underlying functions like
                // TIFFReadRGBAStrip, TIFFReadRGBATile, and color converters.
                TIFFReadRGBAImage(read_tif, read_width, read_height, raster, 0);
                _TIFFfree(raster);
            }
        }
    }
    
    // Speculatively target TIFFReadFromUserBuffer.
    uint32_t num_strips = TIFFNumberOfStrips(read_tif);
    if (num_strips > 0) {
        uint32_t strip_to_read = fdp.ConsumeIntegralInRange<uint32_t>(0, num_strips - 1);
        tmsize_t strip_size = TIFFRawStripSize(read_tif, strip_to_read);
        if (strip_size > 0 && strip_size < fdp.remaining_bytes()) {
             std::vector<uint8_t> in_buf = fdp.ConsumeBytes<uint8_t>(strip_size);
             if (in_buf.size() == strip_size) {
                tmsize_t out_size = TIFFStripSize(read_tif);
                if (out_size > 0 && out_size < 1000000) { // Avoid large allocation
                    std::vector<uint8_t> out_buf(out_size);
                    TIFFReadFromUserBuffer(read_tif, strip_to_read, in_buf.data(), in_buf.size(), out_buf.data(), out_buf.size());
                }
             }
        }
    }

    // Clean up the TIFF handle.
    TIFFClose(read_tif);

    return 0;
}