#include <cstddef>
#include <cstdint>
#include <vector>
#include <string.h>
#include <fuzzer/FuzzedDataProvider.h>
#include "tiffio.h"

// Custom data structure to hold in-memory TIFF data.
// This is used with TIFFClientOpen to avoid file I/O.
struct TiffData {
    std::vector<uint8_t> data;
    toff_t pos;
};

// libtiff read callback for in-memory data.
static tmsize_t read_proc(thandle_t handle, void* buf, tmsize_t size) {
    TiffData* tiff_data = reinterpret_cast<TiffData*>(handle);
    tmsize_t to_read = size;
    if (tiff_data->pos + size > tiff_data->data.size()) {
        to_read = tiff_data->data.size() - tiff_data->pos;
    }
    if (to_read > 0) {
        memcpy(buf, tiff_data->data.data() + tiff_data->pos, to_read);
        tiff_data->pos += to_read;
    }
    return to_read;
}

// libtiff write callback for in-memory data.
static tmsize_t write_proc(thandle_t handle, void* buf, tmsize_t size) {
    TiffData* tiff_data = reinterpret_cast<TiffData*>(handle);
    if (tiff_data->pos + size > tiff_data->data.capacity()) {
        tiff_data->data.reserve(tiff_data->pos + size);
    }
    if (tiff_data->pos + size > tiff_data->data.size()) {
        tiff_data->data.resize(tiff_data->pos + size);
    }
    memcpy(tiff_data->data.data() + tiff_data->pos, buf, size);
    tiff_data->pos += size;
    return size;
}

// libtiff seek callback for in-memory data.
static toff_t seek_proc(thandle_t handle, toff_t offset, int whence) {
    TiffData* tiff_data = reinterpret_cast<TiffData*>(handle);
    toff_t new_pos = tiff_data->pos;
    if (whence == SEEK_SET) {
        new_pos = offset;
    } else if (whence == SEEK_CUR) {
        new_pos += offset;
    } else if (whence == SEEK_END) {
        new_pos = tiff_data->data.size() + offset;
    }
    if (new_pos > tiff_data->data.size()) {
        tiff_data->pos = tiff_data->data.size();
    } else {
        tiff_data->pos = new_pos;
    }
    return tiff_data->pos;
}

// libtiff close callback.
static int close_proc(thandle_t handle) {
    // Memory is managed by the TiffData struct, so nothing to do here.
    return 0;
}

// libtiff size callback.
static toff_t size_proc(thandle_t handle) {
    TiffData* tiff_data = reinterpret_cast<TiffData*>(handle);
    return tiff_data->data.size();
}

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    FuzzedDataProvider fdp(data, size);

    // Data for writing a new TIFF
    TiffData out_tiff_data;
    out_tiff_data.pos = 0;

    // Open a TIFF handle for writing to an in-memory buffer.
    TIFF* write_tif = TIFFClientOpen("fuzzer_write", "w", &out_tiff_data,
                                     read_proc, write_proc, seek_proc, close_proc, size_proc, nullptr, nullptr);

    if (write_tif) {
        // Fuzz TIFF fields
        uint32_t width = fdp.ConsumeIntegralInRange<uint32_t>(1, 512);
        uint32_t height = fdp.ConsumeIntegralInRange<uint32_t>(1, 512);
        uint16_t bps = fdp.PickValueInArray<uint16_t>({1, 2, 4, 8, 16, 32});
        uint16_t spp = fdp.ConsumeIntegralInRange<uint16_t>(1, 4);
        uint16_t photometric = fdp.PickValueInArray<uint16_t>({PHOTOMETRIC_MINISWHITE, PHOTOMETRIC_MINISBLACK, PHOTOMETRIC_RGB, PHOTOMETRIC_PALETTE, PHOTOMETRIC_MASK, PHOTOMETRIC_SEPARATED, PHOTOMETRIC_YCBCR, PHOTOMETRIC_CIELAB, PHOTOMETRIC_LOGL, PHOTOMETRIC_LOGLUV});
        uint16_t planarconfig = fdp.PickValueInArray<uint16_t>({PLANARCONFIG_CONTIG, PLANARCONFIG_SEPARATE});
        uint16_t compression = fdp.PickValueInArray<uint16_t>({COMPRESSION_NONE, COMPRESSION_LZW, COMPRESSION_PACKBITS, COMPRESSION_DEFLATE});

        // Set TIFF fields.
        TIFFSetField(write_tif, TIFFTAG_IMAGEWIDTH, width);
        TIFFSetField(write_tif, TIFFTAG_IMAGELENGTH, height);
        TIFFSetField(write_tif, TIFFTAG_BITSPERSAMPLE, bps);
        TIFFSetField(write_tif, TIFFTAG_SAMPLESPERPIXEL, spp);
        TIFFSetField(write_tif, TIFFTAG_PHOTOMETRIC, photometric);
        TIFFSetField(write_tif, TIFFTAG_PLANARCONFIG, planarconfig);
        TIFFSetField(write_tif, TIFFTAG_COMPRESSION, compression);
        TIFFSetField(write_tif, TIFFTAG_ROWSPERSTRIP, TIFFDefaultStripSize(write_tif, 0));

        // Handle palette-based images.
        if (photometric == PHOTOMETRIC_PALETTE) {
            if (bps <= 16) { // Valid bps for colormap are 1..16
                const uint32_t cmap_size = 1 << bps;
                std::vector<uint16_t> r(cmap_size);
                std::vector<uint16_t> g(cmap_size);
                std::vector<uint16_t> b(cmap_size);

                for (uint32_t i = 0; i < cmap_size; ++i) {
                    if (fdp.remaining_bytes() < sizeof(uint16_t) * 3) {
                        break;
                    }
                    r[i] = fdp.ConsumeIntegral<uint16_t>();
                    g[i] = fdp.ConsumeIntegral<uint16_t>();
                    b[i] = fdp.ConsumeIntegral<uint16_t>();
                }
                TIFFSetField(write_tif, TIFFTAG_COLORMAP, r.data(), g.data(), b.data());
            }
        }

        // Write scanline data.
        tsize_t scanline_size = TIFFScanlineSize(write_tif);
        if (scanline_size > 0 && scanline_size < size) {
            std::vector<uint8_t> scanline_buffer(scanline_size);
            if (fdp.remaining_bytes() >= scanline_size) {
                auto line_data = fdp.ConsumeBytes<uint8_t>(scanline_size);
                memcpy(scanline_buffer.data(), line_data.data(), line_data.size());
            }
            for (uint32_t row = 0; row < height; ++row) {
                TIFFWriteScanline(write_tif, scanline_buffer.data(), row, 0);
            }
        }

        // Write the directory.
        TIFFWriteDirectory(write_tif);

        // Added to exercise directory rewriting logic, which was previously uncovered.
        TIFFRewriteDirectory(write_tif);

        // Added to create a multi-directory TIFF, covering previously missed branches for reading them.
        if (fdp.ConsumeBool()) {
            TIFFSetField(write_tif, TIFFTAG_IMAGEWIDTH, width / 2);
            TIFFSetField(write_tif, TIFFTAG_IMAGELENGTH, height / 2);
            TIFFWriteDirectory(write_tif);
        }

        // Close the handle.
        TIFFClose(write_tif);
    }

    // Read from the TIFF data generated by the write part.
    out_tiff_data.pos = 0;
    TIFF* read_tif = TIFFClientOpen("fuzzer_read", "r", &out_tiff_data,
                                    read_proc, write_proc, seek_proc, close_proc, size_proc, nullptr, nullptr);

    if (read_tif) {
        // Exercise directory navigation.
        tdir_t dir_count = 0;
        do {
            dir_count++;
        } while (TIFFReadDirectory(read_tif));

        if (dir_count > 1) {
            TIFFSetDirectory(read_tif, fdp.ConsumeIntegralInRange<tdir_t>(0, dir_count - 1));
        }

        // Read image data.
        uint32_t width, height;
        TIFFGetField(read_tif, TIFFTAG_IMAGEWIDTH, &width);
        TIFFGetField(read_tif, TIFFTAG_IMAGELENGTH, &height);

        if (width > 0 && height > 0 && width < 4096 && height < 4096) {
            tsize_t scanline_size = TIFFScanlineSize(read_tif);
            tsize_t strip_size = TIFFStripSize(read_tif);
            if (scanline_size > 0 || strip_size > 0) {
                tsize_t buffer_size = scanline_size > strip_size ? scanline_size : strip_size;
                if (buffer_size > 0 && buffer_size < size) {
                    std::vector<uint8_t> read_buffer(buffer_size);
                    for (uint32_t row = 0; row < height; ++row) {
                        // Randomly choose between reading a scanline or a strip.
                        if (fdp.ConsumeBool()) {
                            TIFFReadScanline(read_tif, read_buffer.data(), row, 0);
                        } else {
                            uint32_t strip = TIFFComputeStrip(read_tif, row, 0);
                            TIFFReadEncodedStrip(read_tif, strip, read_buffer.data(), -1);
                        }
                    }
                }
            }
        }
        TIFFClose(read_tif);
    }

    return 0;
}