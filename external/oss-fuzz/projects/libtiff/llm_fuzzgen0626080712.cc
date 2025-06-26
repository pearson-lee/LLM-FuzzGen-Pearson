#include <cstdint>
#include <cstddef>
#include <vector>
#include <sstream>
#include <fuzzer/FuzzedDataProvider.h>

#include "/src/libtiff/libtiff/tiffio.h"
#include "/src/libtiff/libtiff/tiff.h"

// Data structure to hold the stringstream for our callbacks
struct TiffStream {
    std::stringstream stream;
};

// Suppress error messages from libtiff
void TiffErrorHandler(const char*, const char*, va_list) {
    // Do nothing
}

// Callback functions for TIFFClientOpen
tsize_t read_proc(thandle_t handle, tdata_t buf, tsize_t size) {
    TiffStream* ts = reinterpret_cast<TiffStream*>(handle);
    ts->stream.read(static_cast<char*>(buf), size);
    return ts->stream.gcount();
}

tsize_t write_proc(thandle_t handle, tdata_t buf, tsize_t size) {
    TiffStream* ts = reinterpret_cast<TiffStream*>(handle);
    ts->stream.write(static_cast<const char*>(buf), size);
    return size;
}

toff_t seek_proc(thandle_t handle, toff_t offset, int whence) {
    TiffStream* ts = reinterpret_cast<TiffStream*>(handle);
    std::ios_base::seekdir dir;
    switch (whence) {
        case SEEK_SET:
            dir = std::ios_base::beg;
            break;
        case SEEK_CUR:
            dir = std::ios_base::cur;
            break;
        case SEEK_END:
            dir = std::ios_base::end;
            break;
        default:
            return static_cast<toff_t>(-1);
    }
    if (ts->stream.eof()) {
        ts->stream.clear();
    }
    ts->stream.seekg(offset, dir);
    ts->stream.seekp(offset, dir);
    return ts->stream.tellg();
}

int close_proc(thandle_t) {
    return 0;
}

toff_t size_proc(thandle_t handle) {
    TiffStream* ts = reinterpret_cast<TiffStream*>(handle);
    std::streampos original_pos = ts->stream.tellp();
    ts->stream.seekp(0, std::ios_base::end);
    toff_t size = ts->stream.tellp();
    ts->stream.seekp(original_pos);
    return size;
}

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size) {
    if (Size == 0) {
        return 0;
    }

    TIFFSetErrorHandler(TiffErrorHandler);
    TIFFSetWarningHandler(TiffErrorHandler);

    FuzzedDataProvider fdp(Data, Size);
    TiffStream tiff_stream_data;

    // Part 1: Write a TIFF image to the in-memory stream
    TIFF *tiff_write = TIFFClientOpen("fuzz_write.tif", "w", reinterpret_cast<thandle_t>(&tiff_stream_data), read_proc, write_proc, seek_proc, close_proc, size_proc, nullptr, nullptr);
    if (!tiff_write) {
        return 0;
    }

    uint32_t width = fdp.ConsumeIntegralInRange<uint32_t>(1, 512);
    uint32_t height = fdp.ConsumeIntegralInRange<uint32_t>(1, 512);
    uint16_t bps = fdp.PickValueInArray<uint16_t>({1, 2, 4, 8, 16});
    uint16_t spp = fdp.ConsumeIntegralInRange<uint16_t>(1, 4);
    uint16_t planarconfig = fdp.PickValueInArray<uint16_t>({PLANARCONFIG_CONTIG, PLANARCONFIG_SEPARATE});
    uint16_t compression = fdp.PickValueInArray<uint16_t>({
        COMPRESSION_NONE, 
        COMPRESSION_LZW, 
        COMPRESSION_PACKBITS, 
        COMPRESSION_ADOBE_DEFLATE,
        COMPRESSION_DEFLATE
    });
    uint16_t photometric;
    if (spp == 1) {
        photometric = PHOTOMETRIC_MINISBLACK;
    } else if (spp == 3) {
        photometric = PHOTOMETRIC_RGB;
    } else {
        photometric = PHOTOMETRIC_SEPARATED;
    }

    TIFFSetField(tiff_write, TIFFTAG_IMAGEWIDTH, width);
    TIFFSetField(tiff_write, TIFFTAG_IMAGELENGTH, height);
    TIFFSetField(tiff_write, TIFFTAG_BITSPERSAMPLE, bps);
    TIFFSetField(tiff_write, TIFFTAG_SAMPLESPERPIXEL, spp);
    TIFFSetField(tiff_write, TIFFTAG_ROWSPERSTRIP, height);
    TIFFSetField(tiff_write, TIFFTAG_PLANARCONFIG, planarconfig);
    TIFFSetField(tiff_write, TIFFTAG_COMPRESSION, compression);
    TIFFSetField(tiff_write, TIFFTAG_PHOTOMETRIC, photometric);
    
    if (compression == COMPRESSION_LZW || compression == COMPRESSION_DEFLATE || compression == COMPRESSION_ADOBE_DEFLATE) {
        TIFFSetField(tiff_write, TIFFTAG_PREDICTOR, fdp.ConsumeBool() ? PREDICTOR_HORIZONTAL : PREDICTOR_NONE);
    }

    tsize_t scanline_size = TIFFScanlineSize(tiff_write);
    if (scanline_size > 0 && fdp.remaining_bytes() >= scanline_size) {
        uint8_t* scanline_buf = new uint8_t[scanline_size];
        fdp.ConsumeData(scanline_buf, scanline_size);
        for (uint32_t row = 0; row < height; ++row) {
            if (TIFFWriteScanline(tiff_write, scanline_buf, row, 0) < 0) {
                break;
            }
        }
        delete[] scanline_buf;
    }

    TIFFClose(tiff_write);

    // Part 2: Read the TIFF image back from the stream
    TIFF *tiff_read = TIFFClientOpen("fuzz_read.tif", "r", reinterpret_cast<thandle_t>(&tiff_stream_data), read_proc, write_proc, seek_proc, close_proc, size_proc, nullptr, nullptr);
    if (!tiff_read) {
        return 0;
    }

    uint32_t read_width = 0, read_height = 0;
    TIFFGetField(tiff_read, TIFFTAG_IMAGEWIDTH, &read_width);
    TIFFGetField(tiff_read, TIFFTAG_IMAGELENGTH, &read_height);

    if (read_width > 0 && read_height > 0) {
        tsize_t read_scanline_size = TIFFScanlineSize(tiff_read);
        if (read_scanline_size > 0) {
            uint8_t* read_buf = new uint8_t[read_scanline_size];
            for (uint32_t row = 0; row < read_height; ++row) {
                if (TIFFReadScanline(tiff_read, read_buf, row, 0) < 0) {
                    break;
                }
            }
            delete[] read_buf;
        }
    }
    
    TIFFClose(tiff_read);

    return 0;
}