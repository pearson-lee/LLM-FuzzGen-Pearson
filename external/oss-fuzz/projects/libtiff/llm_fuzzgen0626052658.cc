#include <cstddef>
#include <cstdint>
#include <vector>
#include <cstdio> // For tmpfile
#include <fuzzer/FuzzedDataProvider.h>
#include "/src/libtiff/libtiff/tiffio.h"

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

    // Added to improve coverage of TIFFDeferStrileArrayWriting in tif_dirwrite.c
    if (fdp.ConsumeBool()) {
        TIFFDeferStrileArrayWriting(write_tif);
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
    
    // Added to improve coverage in tif_pixarlog.c by exercising different data formats.
    if (compression == COMPRESSION_PIXARLOG) {
        uint16_t pixarlog_data_fmt = fdp.PickValueInArray<uint16_t>({
            PIXARLOGDATAFMT_8BIT,
            PIXARLOGDATAFMT_12BITPICIO, PIXARLOGDATAFMT_16BIT
        });
        TIFFSetField(write_tif, TIFFTAG_PIXARLOGDATAFMT, pixarlog_data_fmt);
    }

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
        // Use TIFFWriteRawTile instead of TIFFWriteEncodedTile to let libtiff handle encoding.
        // This provides valid compressed data for the read phase to decode, improving
        // coverage in compression-specific files (tif_jbig.c, tif_thunder.c, etc.).
        tmsize_t tile_size = TIFFTileSize(write_tif);
        if (tile_size > 0 && tile_size < fdp.remaining_bytes()) {
            std::vector<uint8_t> tile_buf = fdp.ConsumeBytes<uint8_t>(tile_size);
            if (tile_buf.size() == tile_size) {
                for (uint32_t tile = 0; tile < TIFFNumberOfTiles(write_tif); ++tile) {
                    if (TIFFWriteRawTile(write_tif, tile, tile_buf.data(), tile_size) == -1) {
                        break;
                    }
                }
            }
        }
    } else {
        // Use TIFFWriteRawStrip instead of TIFFWriteScanline to let libtiff handle encoding.
        // This provides valid compressed data for the read phase to decode.
        tmsize_t strip_size = TIFFStripSize(write_tif);
        if (strip_size > 0 && strip_size < fdp.remaining_bytes()) {
            std::vector<uint8_t> strip_buf = fdp.ConsumeBytes<uint8_t>(strip_size);
            if (strip_buf.size() == strip_size) {
                 for (uint32_t strip = 0; strip < TIFFNumberOfStrips(write_tif); ++strip) {
                    if (TIFFWriteRawStrip(write_tif, strip, strip_buf.data(), strip_size) == -1) {
                        break;
                    }
                }
            }
        }
    }
    
    TIFFWriteDirectory(write_tif);

    // Add a second directory to improve coverage of multi-directory handling.
    if (width > 1 && height > 1) {
        TIFFSetField(write_tif, TIFFTAG_IMAGEWIDTH, width / 2);
        TIFFSetField(write_tif, TIFFTAG_IMAGELENGTH, height / 2);
        TIFFSetField(write_tif, TIFFTAG_SUBFILETYPE, FILETYPE_REDUCEDIMAGE);
        TIFFWriteDirectory(write_tif);

        // Added to improve coverage of TIFFUnlinkDirectory in tif_dir.c
        if (fdp.ConsumeBool()) {
            TIFFUnlinkDirectory(write_tif, 1);
        }
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

    // Added to improve coverage of TIFFDefaultTransferFunction in tif_aux.c
    uint16_t* tf_val[3];
    TIFFGetFieldDefaulted(read_tif, TIFFTAG_TRANSFERFUNCTION, &tf_val[0], &tf_val[1], &tf_val[2]);

    // Add call to TIFFPrintDirectory to improve coverage in tif_print.c
    FILE* dev_null = tmpfile();
    if (dev_null) {
        TIFFPrintDirectory(read_tif, dev_null, 0);
        fclose(dev_null);
    }
    
    // Add calls to the TIFFReadRGBAImage API to improve coverage in tif_getimage.c
    uint32_t img_width = 0, img_height = 0;
    TIFFGetField(read_tif, TIFFTAG_IMAGEWIDTH, &img_width);
    TIFFGetField(read_tif, TIFFTAG_IMAGELENGTH, &img_height);
    if (img_width > 0 && img_height > 0 && img_width < 5000 && img_height < 5000) {
        TIFFRGBAImage img;
        char emsg[1024] = {0};
        if (TIFFRGBAImageOK(read_tif, emsg)) {
            if (TIFFRGBAImageBegin(&img, read_tif, 0, emsg)) {
                size_t npixels = (size_t)img.width * img.height;
                if (npixels > 0 && npixels < 1000000) {
                    uint32_t* raster = (uint32_t*)_TIFFmalloc(npixels * sizeof(uint32_t));
                    if (raster) {
                        TIFFReadRGBAImageOriented(read_tif, img.width, img.height, raster, img.orientation, 0);
                        _TIFFfree(raster);
                    }
                }
                TIFFRGBAImageEnd(&img);
            }
        }
    }
    
    if (TIFFIsTiled(read_tif)) {
        uint32_t num_tiles = TIFFNumberOfTiles(read_tif);
        if (num_tiles > 0) {
            uint32_t tile_to_read = fdp.ConsumeIntegralInRange<uint32_t>(0, num_tiles - 1);
            tmsize_t tile_size = TIFFTileSize(read_tif);
            if (tile_size > 0 && tile_size < 1000000) {
                void* tile_buf = _TIFFmalloc(tile_size);
                if (tile_buf) {
                    TIFFReadEncodedTile(read_tif, tile_to_read, tile_buf, tile_size);
                    _TIFFfree(tile_buf);
                }
            }
        }
    } else {
        uint32_t num_strips = TIFFNumberOfStrips(read_tif);
        if (num_strips > 0) {
            uint32_t strip_to_read = fdp.ConsumeIntegralInRange<uint32_t>(0, num_strips - 1);
            tmsize_t strip_size = TIFFStripSize(read_tif);
            if (strip_size > 0 && strip_size < 1000000) {
                void* strip_buf = _TIFFmalloc(strip_size);
                if (strip_buf) {
                    TIFFReadEncodedStrip(read_tif, strip_to_read, strip_buf, strip_size);
                    _TIFFfree(strip_buf);
                }
            }
        }
    }

    TIFFClose(read_tif);

    return 0;
}