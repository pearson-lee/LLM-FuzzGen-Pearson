/* BLOCKER_STRATEGY_CONTRACT
required_state: td->td_nstrips in TIFFSetupStrips must be greater than or equal to 0x20000000 (for classic TIFF) or 0x10000000 (for BigTIFF). This is achieved by setting TIFFTAG_IMAGELENGTH to a large value (e.g., 0x20000000) and TIFFTAG_ROWSPERSTRIP to a small value (e.g., 1).
state_constructor: In the striped image path, call TIFFSetField() to set TIFFTAG_IMAGELENGTH to 0x20000000 and TIFFTAG_ROWSPERSTRIP to 1.
trigger_api: TIFFWriteScanline(), which leads to the call to TIFFSetupStrips().
preserved_invariants: The original input consumption sequence via FuzzedDataProvider is maintained. The core logic of creating, writing, closing, and re-opening a TIFF file is preserved. The modification is additive and confined to the striped-image code path.
END_BLOCKER_STRATEGY_CONTRACT */

#include <fuzzer/FuzzedDataProvider.h>
#include <tiffio.h>
#include <tiff.h>
#include <vector>
#include <string>
#include <unistd.h>
#include <cstdio>

// Define a custom tag in the private range for testing purposes.
#define TIFFTAG_MY_SRATIONAL 65000
static const TIFFFieldInfo xtiffFieldInfo[] = {
    // This custom tag is defined as TIFF_SRATIONAL to target uncovered code paths.
    // Read/Write count is variable (-1), and passcount is true (last '1').
    { TIFFTAG_MY_SRATIONAL, -1, -1, TIFF_SRATIONAL, FIELD_CUSTOM, 1, 1, "MyCustomSRational" }
};

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size) {
    if (Size < 20) {
        // Require a minimum size to avoid trivial inputs.
        return 0;
    }
    FuzzedDataProvider fdp(Data, Size);

    // Create a unique temporary filename for thread safety.
    const std::string path = std::string("/tmp/") + _FUZZ_TARGET_NAME + ".tif";

    // Randomly choose between classic TIFF and BigTIFF format.
    const char* mode = fdp.ConsumeBool() ? "w" : "w8";

    TIFF* tif = TIFFOpen(path.c_str(), mode);
    if (!tif) {
        return 0;
    }

    int num_dirs = fdp.ConsumeIntegralInRange<int>(1, 4);
    for (int i = 0; i < num_dirs; ++i) {
        // Set basic required tags to create a valid TIFF structure.
        uint32_t width = fdp.ConsumeIntegralInRange<uint32_t>(1, 512);
        uint32_t height = fdp.ConsumeIntegralInRange<uint32_t>(1, 512);
        TIFFSetField(tif, TIFFTAG_IMAGEWIDTH, width);
        TIFFSetField(tif, TIFFTAG_IMAGELENGTH, height);

        // Handle custom directory creation before setting compression to avoid state corruption.
        if (fdp.ConsumeBool()) {
            uint64_t exif_dir_offset = 0;
            TIFFCreateEXIFDirectory(tif);
            TIFFSetField(tif, TIFFTAG_IMAGEWIDTH, fdp.ConsumeIntegralInRange<uint32_t>(1, 64));
            TIFFSetField(tif, TIFFTAG_IMAGELENGTH, fdp.ConsumeIntegralInRange<uint32_t>(1, 64));
            TIFFWriteCustomDirectory(tif, &exif_dir_offset);
            TIFFSetField(tif, TIFFTAG_EXIFIFD, exif_dir_offset);
        }

        if (fdp.ConsumeBool()) {
            uint64_t gps_dir_offset = 0;
            TIFFCreateGPSDirectory(tif);
            TIFFSetField(tif, GPSTAG_VERSIONID, "\x02\x02\x00\x00");
            TIFFWriteCustomDirectory(tif, &gps_dir_offset);
            TIFFSetField(tif, TIFFTAG_GPSIFD, gps_dir_offset);
        }

        const uint16_t compression_schemes[] = {
            COMPRESSION_NONE, COMPRESSION_LZW, COMPRESSION_PACKBITS, COMPRESSION_DEFLATE,
            COMPRESSION_SGILOG
        };
        uint16_t compression = fdp.PickValueInArray(compression_schemes);
        TIFFSetField(tif, TIFFTAG_COMPRESSION, compression);

        if (compression == COMPRESSION_SGILOG) {
            TIFFSetField(tif, TIFFTAG_PHOTOMETRIC, PHOTOMETRIC_LOGLUV);
            TIFFSetField(tif, TIFFTAG_SAMPLESPERPIXEL, (uint16_t)3);
            TIFFSetField(tif, TIFFTAG_BITSPERSAMPLE, (uint16_t)8);
        } else {
            TIFFSetField(tif, TIFFTAG_PHOTOMETRIC, PHOTOMETRIC_MINISBLACK);
            TIFFSetField(tif, TIFFTAG_SAMPLESPERPIXEL, (uint16_t)1);
            TIFFSetField(tif, TIFFTAG_BITSPERSAMPLE, (uint16_t)8);
        }

        TIFFMergeFieldInfo(tif, xtiffFieldInfo, 1);
        uint16_t count = fdp.ConsumeIntegralInRange<uint16_t>(1, 16);
        std::vector<double> srationals;
        for (int j = 0; j < count; ++j) {
            srationals.push_back(fdp.ConsumeFloatingPoint<double>());
        }
        if (!srationals.empty()) {
            TIFFSetField(tif, TIFFTAG_MY_SRATIONAL, srationals.size(), srationals.data());
        }

        if (fdp.ConsumeBool()) {
            // Tiled image path
            TIFFSetField(tif, TIFFTAG_TILEWIDTH, fdp.ConsumeIntegralInRange<uint32_t>(16, 256));
            TIFFSetField(tif, TIFFTAG_TILELENGTH, fdp.ConsumeIntegralInRange<uint32_t>(16, 256));
            tsize_t tile_size = TIFFTileSize(tif);
            if (tile_size > 0) {
                std::vector<char> dummy_tile(tile_size);
                if (fdp.ConsumeData(dummy_tile.data(), tile_size) == (size_t)tile_size) {
                    TIFFWriteTile(tif, dummy_tile.data(), 0, 0, 0, 0);
                }
            }
        } else {
            // Striped image path
            
            // BLOCKER-SPECIFIC CODE
            // To trigger the vulnerability, a large number of strips is needed.
            // We can achieve this by setting a large ImageLength and a small
            // RowsPerStrip value. This will cause td->td_nstrips to exceed the
            // threshold inside TIFFSetupStrips, triggering the desired error path.
            const uint32_t large_imagelength = 0x20000000;
            TIFFSetField(tif, TIFFTAG_IMAGELENGTH, large_imagelength);
            TIFFSetField(tif, TIFFTAG_ROWSPERSTRIP, (uint32_t)1);

            TIFFSetField(tif, TIFFTAG_PLANARCONFIG, PLANARCONFIG_CONTIG);
            tsize_t scanline_size = TIFFScanlineSize(tif);
            if (scanline_size > 0) {
                std::vector<char> dummy_scanline(scanline_size);
                TIFFWriteScanline(tif, dummy_scanline.data(), 0, 0);
            }
        }

        TIFFSetField(tif, TIFFTAG_PAGENUMBER, (uint16_t)i, (uint16_t)num_dirs);

        if (i < num_dirs - 1) {
            if (!TIFFWriteDirectory(tif)) {
                TIFFClose(tif);
                unlink(path.c_str());
                return 0;
            }
        }
    }
    
    // Finalize writing by closing the file.
    TIFFClose(tif);

    // Re-open for reading.
    tif = TIFFOpen(path.c_str(), "r");
    if (!tif) {
        unlink(path.c_str());
        return 0;
    }

    FILE* temp_file = tmpfile();
    if (temp_file) {
        do {
            TIFFPrintDirectory(tif, temp_file, 0);
        } while (TIFFReadDirectory(tif));
        fclose(temp_file);
    }
    TIFFSetDirectory(tif, 0);

    // BLOCKER-SPECIFIC CODE
    // Call TIFFSetSubDirectory with a fuzzer-controlled offset. This is
    // intended to trigger the miss case in the hash lookup inside
    // _TIFFGetDirNumberFromOffset, allowing execution to reach
    // TIFFNumberOfDirectories.
    if (fdp.remaining_bytes() >= sizeof(uint64_t)) {
      uint64_t fake_offset = fdp.ConsumeIntegral<uint64_t>();
      TIFFSetSubDirectory(tif, fake_offset);
    }

    bool is_tiled = TIFFIsTiled(tif);
    if (is_tiled) {
        uint32_t tile_width = 0, tile_height = 0;
        TIFFGetField(tif, TIFFTAG_TILEWIDTH, &tile_width);
        TIFFGetField(tif, TIFFTAG_TILELENGTH, &tile_height);
        if (tile_width > 0 && tile_height > 0 && tile_width < 4096 && tile_height < 4096) {
            uint32_t* raster = (uint32_t*)_TIFFmalloc(tile_width * tile_height * sizeof(uint32_t));
            if (raster) {
                TIFFReadRGBATile(tif, 0, 0, raster);
                _TIFFfree(raster);
            }
        }
    } else {
        uint32_t s_width = 0, s_height = 0;
        TIFFGetField(tif, TIFFTAG_IMAGEWIDTH, &s_width);
        TIFFGetField(tif, TIFFTAG_IMAGELENGTH, &s_height);
        if (s_height > 0 && s_width > 0 && s_width < 4096 && s_height < 4096) {
            uint32_t* raster = (uint32_t*)_TIFFmalloc(s_width * s_height * sizeof(uint32_t));
            if (raster) {
                TIFFReadRGBAStrip(tif, 0, raster);
                _TIFFfree(raster);
            }
        }
    }

    uint32_t r_width = 0, r_height = 0;
    TIFFGetField(tif, TIFFTAG_IMAGEWIDTH, &r_width);
    TIFFGetField(tif, TIFFTAG_IMAGELENGTH, &r_height);
    if (r_width > 0 && r_height > 0 && r_width < 4096 && r_height < 4096) {
        uint32_t* raster = (uint32_t*)_TIFFmalloc(r_width * r_height * sizeof(uint32_t));
        if (raster) {
            TIFFReadRGBAImage(tif, r_width, r_height, raster, 0);
            _TIFFfree(raster);
        }
    }

    // Final cleanup.
    TIFFClose(tif);
    unlink(path.c_str());

    return 0;
}
