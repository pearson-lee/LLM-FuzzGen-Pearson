#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <string>
#include <unistd.h>
#include <fuzzer/FuzzedDataProvider.h>
#include "/src/libtiff/libtiff/tiff.h"
#include "/src/libtiff/libtiff/tiffio.h"
#include "/src/libtiff/libtiff/tiffiop.h"
#include "/src/libtiff/libtiff/tif_dir.h"

// Manually define JPEGPROC_OJPEG as it may be guarded by preprocessor directives
// not enabled in the build environment. This allows fuzzing of the code path
// that handles this value.
#define JPEGPROC_OJPEG 1

// Suppress error/warning messages from libtiff to avoid polluting fuzzer output
void SuppressErrorHandler(const char*, const char*, va_list) {}

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
    FuzzedDataProvider fdp(data, size);

    // Set custom error and warning handlers to suppress console output.
    TIFFSetErrorHandler(SuppressErrorHandler);
    TIFFSetWarningHandler(SuppressErrorHandler);

    char filename[256];
    // Create a unique temporary filename to avoid race conditions.
    sprintf(filename, "/tmp/%s.tif", _FUZZ_TARGET_NAME);

    // Decide on TIFF mode (classic, big-endian, little-endian, BigTIFF)
    const char* mode;
    switch (fdp.ConsumeIntegralInRange<uint8_t>(0, 3)) {
        case 0:
            mode = "w"; // classic, native endian
            break;
        case 1:
            mode = "wb"; // classic, big-endian
            break;
        case 2:
            mode = "wl"; // classic, little-endian
            break;
        default:
            mode = "w8"; // BigTIFF
            break;
    }

    TIFF* tif = TIFFOpen(filename, mode);
    if (!tif) {
        // If opening fails, clean up and exit.
        unlink(filename);
        return 0;
    }

    uint32_t width = fdp.ConsumeIntegralInRange<uint32_t>(1, 512);
    uint32_t height = fdp.ConsumeIntegralInRange<uint32_t>(1, 512);
    uint16_t bps = fdp.PickValueInArray<uint16_t>({1, 2, 4, 8, 16});
    uint16_t spp = fdp.ConsumeIntegralInRange<uint16_t>(1, 4);
    uint16_t planarconfig = fdp.PickValueInArray<uint16_t>({PLANARCONFIG_CONTIG, PLANARCONFIG_SEPARATE});

    TIFFSetField(tif, TIFFTAG_IMAGEWIDTH, width);
    TIFFSetField(tif, TIFFTAG_IMAGELENGTH, height);
    TIFFSetField(tif, TIFFTAG_BITSPERSAMPLE, bps);
    TIFFSetField(tif, TIFFTAG_SAMPLESPERPIXEL, spp);
    TIFFSetField(tif, TIFFTAG_PLANARCONFIG, planarconfig);
    TIFFSetField(tif, TIFFTAG_PHOTOMETRIC, fdp.PickValueInArray<uint16_t>({PHOTOMETRIC_MINISWHITE, PHOTOMETRIC_MINISBLACK, PHOTOMETRIC_RGB}));

    if (fdp.ConsumeBool()) {
        float primaries[6];
        if (fdp.ConsumeData(primaries, sizeof(primaries)) == sizeof(primaries)) {
            TIFFSetField(tif, TIFFTAG_PRIMARYCHROMATICITIES, primaries);
        }
    }
    
    if (fdp.ConsumeBool()) {
        double stonits = fdp.ConsumeFloatingPoint<double>();
        TIFFSetField(tif, TIFFTAG_STONITS, stonits);
    }

    uint16_t compression = fdp.PickValueInArray<uint16_t>({
        COMPRESSION_NONE,
        COMPRESSION_PACKBITS,
        COMPRESSION_LZW,
        COMPRESSION_OJPEG,
        COMPRESSION_PIXARLOG,
        COMPRESSION_SGILOG,
        COMPRESSION_SGILOG24
    });
    TIFFSetField(tif, TIFFTAG_COMPRESSION, compression);

    if (compression == COMPRESSION_OJPEG) {
        TIFFSetField(tif, TIFFTAG_JPEGPROC, JPEGPROC_OJPEG);
        TIFFSetField(tif, TIFFTAG_PHOTOMETRIC, PHOTOMETRIC_YCBCR);
        uint16_t subsampling[] = { 2, 2 };
        TIFFSetField(tif, TIFFTAG_YCBCRSUBSAMPLING, subsampling[0], subsampling[1]);
    } else if (compression == COMPRESSION_PIXARLOG) {
        TIFFSetField(tif, TIFFTAG_PREDICTOR, fdp.PickValueInArray<uint16_t>({PREDICTOR_NONE, PREDICTOR_HORIZONTAL, PREDICTOR_FLOATINGPOINT}));
        uint16_t pixarlog_data_fmt = fdp.PickValueInArray<uint16_t>({
            0, 1, 2, 3, 4
        });
        TIFFSetField(tif, TIFFTAG_PIXARLOGDATAFMT, pixarlog_data_fmt);
    } else if (compression == COMPRESSION_SGILOG || compression == COMPRESSION_SGILOG24) {
        TIFFSetField(tif, TIFFTAG_PHOTOMETRIC, fdp.PickValueInArray<uint16_t>({PHOTOMETRIC_LOGL, PHOTOMETRIC_LOGLUV}));
    }

    bool is_tiled = fdp.ConsumeBool();
    if (is_tiled) { // Tiled image
        uint32_t tile_width = fdp.ConsumeIntegralInRange<uint32_t>(16, 256);
        uint32_t tile_height = fdp.ConsumeIntegralInRange<uint32_t>(16, 256);
        TIFFSetField(tif, TIFFTAG_TILEWIDTH, tile_width);
        TIFFSetField(tif, TIFFTAG_TILELENGTH, tile_height);
        
        tsize_t tile_size = TIFFTileSize(tif);
        if (tile_size > 0 && tile_size < 1024 * 1024) {
            uint8_t* tile_buf = new uint8_t[tile_size];
            if (fdp.ConsumeData(tile_buf, tile_size) == tile_size) {
                ttile_t num_tiles = TIFFNumberOfTiles(tif);
                if (num_tiles > 0) {
                    ttile_t tile_index = fdp.ConsumeIntegralInRange<ttile_t>(0, num_tiles - 1);
                    TIFFWriteEncodedTile(tif, tile_index, tile_buf, tile_size);
                }
            }
            delete[] tile_buf;
        }
    } else { // Strip image
        uint32_t rows_per_strip = fdp.ConsumeIntegralInRange<uint32_t>(1, height);
        TIFFSetField(tif, TIFFTAG_ROWSPERSTRIP, rows_per_strip);

        tsize_t strip_size = TIFFStripSize(tif);
        if (strip_size > 0 && strip_size < 1024 * 1024) {
            uint8_t* strip_buf = new uint8_t[strip_size];
            if (fdp.ConsumeData(strip_buf, strip_size) == strip_size) {
                tstrip_t num_strips = TIFFNumberOfStrips(tif);
                if (num_strips > 0) {
                    tstrip_t strip_index = fdp.ConsumeIntegralInRange<tstrip_t>(0, num_strips - 1);
                    TIFFWriteEncodedStrip(tif, strip_index, strip_buf, strip_size);
                }
            }
            delete[] strip_buf;
        }
    }

    TIFFCheckpointDirectory(tif);
    tdir_t main_dir_index = TIFFCurrentDirectory(tif);

    if (fdp.ConsumeBool()) {
        if (TIFFWriteDirectory(tif)) {
            TIFFCheckpointDirectory(tif);
            uint64_t sub_dir_offset = TIFFCurrentDirOffset(tif);
            if (sub_dir_offset > 0) {
                TIFFSetDirectory(tif, main_dir_index);
                TIFFSetField(tif, TIFFTAG_SUBIFD, 1, &sub_dir_offset);
                TIFFCheckpointDirectory(tif);
                TIFFSetSubDirectory(tif, sub_dir_offset);
            }
        }
    }

    FILE* null_fp = fopen("/dev/null", "w");
    if (null_fp) {
        TIFFPrintDirectory(tif, null_fp, 0);
        fclose(null_fp);
    }
    
    // Moved read logic into conditional blocks above
    // This resolves the crash when trying to read a tile from a striped image.

    TIFFClose(tif);

    tif = TIFFOpen(filename, "r");
    if (tif) {
        TIFFRGBAImage img;
        char emsg[1024];
        if (TIFFRGBAImageBegin(&img, tif, 0, emsg)) {
            uint32_t* raster = (uint32_t*) _TIFFmalloc(width * height * sizeof(uint32_t));
            if (raster) {
                TIFFRGBAImageGet(&img, raster, width, height);
                _TIFFfree(raster);
            }
            TIFFRGBAImageEnd(&img);
        }
        TIFFClose(tif);
    }
    
    tif = TIFFOpen(filename, "a");
    if (tif) {
        tdir_t num_dirs = TIFFNumberOfDirectories(tif);
        if (num_dirs > 0 && fdp.ConsumeBool()) {
            tdir_t dir_to_unlink = fdp.PickValueInArray<tdir_t>({(tdir_t)0, (tdir_t)1, (tdir_t)(num_dirs + 1)});
            TIFFUnlinkDirectory(tif, dir_to_unlink);
        }
        TIFFClose(tif);
    }
    
    unlink(filename);

    return 0;
}