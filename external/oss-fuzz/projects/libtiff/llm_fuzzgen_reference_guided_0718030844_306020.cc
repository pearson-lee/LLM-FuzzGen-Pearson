/* BLOCKER_STRATEGY_CONTRACT
required_state: The `sp->state` field in the `ZIPState` struct must have the `ZSTATE_INIT_DECODE` flag set when `ZIPSetupEncode` is called.
state_constructor: A TIFF file with DEFLATE compression is created and saved. It is then re-opened in read-write mode ("r+"). A read operation (`TIFFReadScanline` or `TIFFReadEncodedTile`) is performed, which initializes the ZIP decoder and sets the `ZSTATE_INIT_DECODE` flag.
trigger_api: A subsequent write operation (`TIFFWriteScanline` or `TIFFWriteTile`) on the same `TIFF` handle invokes the encoding setup path, leading to `ZIPSetupEncode` being called with the required state to enter the desired branch.
preserved_invariants: The original input consumption sequence via `FuzzedDataProvider` is maintained. The core logic of creating, writing, closing, and re-opening a TIFF file is preserved. The change is additive, inserting a new API call sequence into the read phase without altering the existing logic.
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

    // Re-open for reading and writing to trigger state transition.
    const char* read_mode = fdp.ConsumeBool() ? "r+" : "r+8";
    tif = TIFFOpen(path.c_str(), read_mode);
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

    // BLOCKER-SPECIFIC CODE:
    // To hit the `sp->state & ZSTATE_INIT_DECODE` branch in `ZIPSetupEncode`,
    // we need to initialize the decoder, then call an encoder function.
    // 1. Re-open the TIFF in read-write ("r+") mode. (Done above)
    // 2. Perform a read operation to trigger `ZIPSetupDecode` and set the flag.
    // 3. Perform a write operation to trigger `ZIPSetupEncode`.
    uint16_t compression_type = 0;
    TIFFGetField(tif, TIFFTAG_COMPRESSION, &compression_type);

    if (compression_type == COMPRESSION_DEFLATE) {
        if (TIFFIsTiled(tif)) {
            tsize_t tile_size = TIFFTileSize(tif);
            if (tile_size > 0) {
                std::vector<char> buffer(tile_size, 0);
                // 2. Read a tile to set ZSTATE_INIT_DECODE
                if (TIFFReadEncodedTile(tif, 0, buffer.data(), tile_size) != -1) {
                    // 3. Write a tile to trigger ZIPSetupEncode
                    TIFFWriteTile(tif, buffer.data(), 0, 0, 0, 0);
                }
            }
        } else {
            tsize_t scanline_size = TIFFScanlineSize(tif);
            if (scanline_size > 0) {
                std::vector<char> buffer(scanline_size, 0);
                // 2. Read a scanline to set ZSTATE_INIT_DECODE
                if (TIFFReadScanline(tif, buffer.data(), 0, 0) != -1) {
                    // 3. Write a scanline to trigger ZIPSetupEncode
                    TIFFWriteScanline(tif, buffer.data(), 0, 0);
                }
            }
        }
    }

    // BLOCKER-SPECIFIC CODE (from original target)
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
