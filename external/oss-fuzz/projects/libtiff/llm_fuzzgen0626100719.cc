#include <cstdint>
#include <cstddef>
#include <vector>
#include <sstream>
#include <string>
#include <fuzzer/FuzzedDataProvider.h>

#include "/src/libtiff/libtiff/tiffio.h"
#include "/src/libtiff/libtiff/tiff.h"
#include "/src/libtiff/libtiff/tif_predict.h"
#include <stdio.h>

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
    if (Size < 10) { // Need some minimal data
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

    std::string client_name = fdp.ConsumeRandomLengthString(16);
    std::string client_data = fdp.ConsumeRandomLengthString(16);
    TIFFSetClientInfo(tiff_write, (void*)client_data.c_str(), client_name.c_str());
    TIFFGetClientInfo(tiff_write, client_name.c_str());

    uint32_t width = fdp.ConsumeIntegralInRange<uint32_t>(1, 512);
    uint32_t height = fdp.ConsumeIntegralInRange<uint32_t>(1, 512);
    uint16_t spp = fdp.ConsumeIntegralInRange<uint16_t>(1, 4);
    uint16_t planarconfig = fdp.PickValueInArray<uint16_t>({PLANARCONFIG_CONTIG, PLANARCONFIG_SEPARATE});
    
    uint16_t bps;
    uint16_t sampleformat;
    int format_choice = fdp.ConsumeIntegralInRange(0, 2);
    if (format_choice == 0) {
        sampleformat = SAMPLEFORMAT_IEEEFP;
        bps = fdp.PickValueInArray<uint16_t>({32, 64});
    } else if (format_choice == 1) {
        sampleformat = SAMPLEFORMAT_INT;
        bps = fdp.PickValueInArray<uint16_t>({8, 16, 32});
    } else {
        sampleformat = SAMPLEFORMAT_UINT;
        bps = fdp.PickValueInArray<uint16_t>({1, 2, 4, 8, 16});
    }
    
    uint16_t compression = fdp.PickValueInArray<uint16_t>({
        COMPRESSION_NONE, COMPRESSION_LZW, COMPRESSION_PACKBITS,
        COMPRESSION_ADOBE_DEFLATE, COMPRESSION_DEFLATE, COMPRESSION_JPEG,
        COMPRESSION_PIXARLOG, COMPRESSION_SGILOG, COMPRESSION_SGILOG24,
        COMPRESSION_LZMA, COMPRESSION_CCITTRLE
    });
    uint16_t photometric;

    bool use_palette = fdp.ConsumeBool() && compression != COMPRESSION_JPEG && compression != COMPRESSION_SGILOG && compression != COMPRESSION_SGILOG24 && compression != COMPRESSION_CCITTRLE;

    if (use_palette) {
        photometric = PHOTOMETRIC_PALETTE;
        spp = 1;
        bps = fdp.PickValueInArray<uint16_t>({1, 2, 4, 8});
        sampleformat = SAMPLEFORMAT_UINT; // Palette must be uint
    } else if (compression == COMPRESSION_SGILOG || compression == COMPRESSION_SGILOG24) {
        photometric = fdp.PickValueInArray<uint16_t>({PHOTOMETRIC_LOGL, PHOTOMETRIC_LOGLUV});
        if (photometric == PHOTOMETRIC_LOGLUV) spp = 3;
        else spp = 1;
    } else if (compression == COMPRESSION_JPEG) {
        photometric = PHOTOMETRIC_YCBCR;
        spp = 3;
    } else if (compression == COMPRESSION_CCITTRLE) {
        photometric = PHOTOMETRIC_MINISWHITE;
        spp = 1;
        bps = 1;
        sampleformat = SAMPLEFORMAT_UINT; // CCITT must be uint.
    } else {
        if (spp == 1) photometric = PHOTOMETRIC_MINISBLACK;
        else if (spp == 3) photometric = PHOTOMETRIC_RGB;
        else photometric = PHOTOMETRIC_SEPARATED;
    }

    TIFFSetField(tiff_write, TIFFTAG_IMAGEWIDTH, width);
    TIFFSetField(tiff_write, TIFFTAG_IMAGELENGTH, height);
    TIFFSetField(tiff_write, TIFFTAG_BITSPERSAMPLE, bps);
    TIFFSetField(tiff_write, TIFFTAG_SAMPLEFORMAT, sampleformat);
    TIFFSetField(tiff_write, TIFFTAG_SAMPLESPERPIXEL, spp);
    TIFFSetField(tiff_write, TIFFTAG_PLANARCONFIG, planarconfig);
    TIFFSetField(tiff_write, TIFFTAG_COMPRESSION, compression);
    TIFFSetField(tiff_write, TIFFTAG_PHOTOMETRIC, photometric);
    
    if (use_palette) {
        const int cmap_size = 1 << bps;
        std::vector<uint16_t> r(cmap_size), g(cmap_size), b(cmap_size);
        for (int i = 0; i < cmap_size; ++i) {
            r[i] = fdp.ConsumeIntegral<uint16_t>();
            g[i] = fdp.ConsumeIntegral<uint16_t>();
            b[i] = fdp.ConsumeIntegral<uint16_t>();
        }
        TIFFSetField(tiff_write, TIFFTAG_COLORMAP, r.data(), g.data(), b.data());
    }
    
    if (compression == COMPRESSION_JPEG) {
        TIFFSetField(tiff_write, TIFFTAG_JPEGCOLORMODE, JPEGCOLORMODE_RGB);
        TIFFSetField(tiff_write, TIFFTAG_JPEGTABLESMODE, JPEGTABLESMODE_QUANT | JPEGTABLESMODE_HUFF);
    } else if (compression == COMPRESSION_LZW || compression == COMPRESSION_DEFLATE || compression == COMPRESSION_ADOBE_DEFLATE) {
        TIFFSetField(tiff_write, TIFFTAG_PREDICTOR, fdp.ConsumeBool() ? PREDICTOR_HORIZONTAL : PREDICTOR_NONE);
    }

    if (fdp.ConsumeBool()) {
        toff_t exif_offset = 0;
        if (TIFFCreateEXIFDirectory(tiff_write) == 0) {
            char datetime[] = "2024:01:01 00:00:00";
            TIFFSetField(tiff_write, EXIFTAG_DATETIMEORIGINAL, datetime);
            if (TIFFWriteCustomDirectory(tiff_write, &exif_offset) && exif_offset != 0) {
                TIFFSetDirectory(tiff_write, 0);
                TIFFSetField(tiff_write, TIFFTAG_EXIFIFD, exif_offset);
            }
        }
    }

    if (fdp.ConsumeBool()) { // Tiled
        uint32_t tile_width = fdp.PickValueInArray<uint32_t>({16, 32, 64});
        uint32_t tile_height = fdp.PickValueInArray<uint32_t>({16, 32, 64});
        TIFFSetField(tiff_write, TIFFTAG_TILEWIDTH, tile_width);
        TIFFSetField(tiff_write, TIFFTAG_TILELENGTH, tile_height);
        tsize_t tile_size = TIFFTileSize(tiff_write);
        if (tile_size > 0 && fdp.remaining_bytes() >= tile_size) {
            std::vector<uint8_t> tile_buf(tile_size);
            fdp.ConsumeData(tile_buf.data(), tile_size);
            for (uint32_t y = 0; y < height; y += tile_height) {
                for (uint32_t x = 0; x < width; x += tile_width) {
                    if (TIFFWriteTile(tiff_write, tile_buf.data(), x, y, 0, 0) < 0) break;
                }
            }
        }
    } else { // Stripped
        TIFFSetField(tiff_write, TIFFTAG_ROWSPERSTRIP, height);
        tsize_t scanline_size = TIFFScanlineSize(tiff_write);
        if (scanline_size > 0 && fdp.remaining_bytes() >= scanline_size) {
            std::vector<uint8_t> scanline_buf(scanline_size);
            fdp.ConsumeData(scanline_buf.data(), scanline_size);
            for (uint32_t row = 0; row < height; ++row) {
                if (TIFFWriteScanline(tiff_write, scanline_buf.data(), row, 0) < 0) break;
            }
        }
    }

    if (fdp.ConsumeBool()) {
        TIFFForceStrileArrayWriting(tiff_write);
    }

    TIFFClose(tiff_write);

    // Part 2: Read the TIFF image back from the stream
    tiff_stream_data.stream.clear();
    tiff_stream_data.stream.seekg(0, std::ios::beg);

    TIFF *tiff_read = TIFFClientOpen("fuzz_read.tif", "r", reinterpret_cast<thandle_t>(&tiff_stream_data), read_proc, write_proc, seek_proc, close_proc, size_proc, nullptr, nullptr);
    if (!tiff_read) {
        return 0;
    }

    if (TIFFIsTiled(tiff_read)) {
        tsize_t tile_size = TIFFTileSize(tiff_read);
        if (tile_size > 0) {
            std::vector<uint8_t> tile_buf(tile_size);
            uint32_t read_width = 0, read_height = 0, tile_width = 0, tile_height = 0;
            TIFFGetField(tiff_read, TIFFTAG_IMAGEWIDTH, &read_width);
            TIFFGetField(tiff_read, TIFFTAG_IMAGELENGTH, &read_height);
            TIFFGetField(tiff_read, TIFFTAG_TILEWIDTH, &tile_width);
            TIFFGetField(tiff_read, TIFFTAG_TILELENGTH, &tile_height);
            if (tile_width > 0 && tile_height > 0) {
                for (uint32_t y = 0; y < read_height; y += tile_height) {
                    for (uint32_t x = 0; x < read_width; x += tile_width) {
                        if (TIFFReadTile(tiff_read, tile_buf.data(), x, y, 0, 0) < 0) break;
                    }
                }
            }
        }
    } else {
        uint32_t read_width = 0, read_height = 0;
        TIFFGetField(tiff_read, TIFFTAG_IMAGEWIDTH, &read_width);
        TIFFGetField(tiff_read, TIFFTAG_IMAGELENGTH, &read_height);
        if (read_width > 0 && read_height > 0) {
            tsize_t read_scanline_size = TIFFScanlineSize(tiff_read);
            if (read_scanline_size > 0) {
                std::vector<uint8_t> read_buf(read_scanline_size);
                for (uint32_t row = 0; row < read_height; ++row) {
                    if (TIFFReadScanline(tiff_read, read_buf.data(), row, 0) < 0) break;
                }
            }
        }
    }
    
    TIFFPrintDirectory(tiff_read, stdout, 0);

    uint64_t exif_offset = 0;
    if (TIFFGetField(tiff_read, TIFFTAG_EXIFIFD, &exif_offset) == 1 && exif_offset > 0) {
        TIFFReadEXIFDirectory(tiff_read, exif_offset);
    }

    TIFFClose(tiff_read);

    return 0;
}