#include <cstddef>
#include <cstdint>
#include <string>
#include <vector>
#include <unistd.h>
#include <fuzzer/FuzzedDataProvider.h>

#include "/src/libtiff/libtiff/tiffio.h"
#include "/src/zlib/zlib.h"
#include "/src/libtiff/libtiff/tiffiop.h" // For FIELD_CUSTOM

// Fuzz target entry point
extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  FuzzedDataProvider fdp(data, size);

  // Target 1: deflateSetDictionary from zlib
  // Directly exercise the zlib API used by libtiff for ZIP compression.
  // This helps test the integration and handling of zlib features.
  if (fdp.ConsumeBool()) {
    z_stream strm;
    strm.zalloc = Z_NULL;
    strm.zfree = Z_NULL;
    strm.opaque = Z_NULL;
    // Use a fuzzed compression level
    if (deflateInit(&strm, fdp.ConsumeIntegralInRange(-1, Z_BEST_COMPRESSION)) == Z_OK) {
      // Use fuzzed data as the dictionary
      auto dict = fdp.ConsumeBytes<Bytef>(fdp.ConsumeIntegralInRange(0, 4096));
      if (!dict.empty()) {
        deflateSetDictionary(&strm, dict.data(), dict.size());
      }
      // Clean up the zlib stream
      deflateEnd(&strm);
    }
  }

  // Create a temporary file for TIFF writing and reading
  char filename[] = "/tmp/libtiff_fuzzer.XXXXXX";
  int fd = mkstemp(filename);
  if (fd < 0) {
    return 0;
  }
  close(fd);

  // Open the temporary file for writing a TIFF image
  TIFF* tif_w = TIFFOpen(filename, "w");
  if (!tif_w) {
    unlink(filename);
    return 0;
  }

  // Setup basic TIFF fields with fuzzed values
  TIFFSetField(tif_w, TIFFTAG_IMAGEWIDTH, fdp.ConsumeIntegralInRange<uint32_t>(1, 512));
  TIFFSetField(tif_w, TIFFTAG_IMAGELENGTH, fdp.ConsumeIntegralInRange<uint32_t>(1, 512));
  TIFFSetField(tif_w, TIFFTAG_BITSPERSAMPLE, 8);
  TIFFSetField(tif_w, TIFFTAG_SAMPLESPERPIXEL, 3);
  TIFFSetField(tif_w, TIFFTAG_PLANARCONFIG, PLANARCONFIG_CONTIG);

  // Added to cover floating-point sample format functions like TIFFClampDoubleToFloat.
  if (fdp.ConsumeBool()) {
    TIFFSetField(tif_w, TIFFTAG_SAMPLEFORMAT, SAMPLEFORMAT_IEEEFP);
    TIFFSetField(tif_w, TIFFTAG_BITSPERSAMPLE, 32);
  }

  // Target 2: _TIFFFindOrRegisterField and TIFFUnsetField
  // Register and set a custom tag to test the library's handling of non-standard fields,
  // then unset it to improve coverage of TIFFUnsetField.
  if (fdp.ConsumeBool()) {
    const TIFFFieldInfo my_field_info = {
        fdp.ConsumeIntegralInRange<uint32_t>(65536, 65537), // Custom tag range
        1, 1, TIFF_LONG, FIELD_CUSTOM,
        1, 0, (char*)"MyCustomTag"
    };
    TIFFMergeFieldInfo(tif_w, &my_field_info, 1);
    TIFFSetField(tif_w, my_field_info.field_tag, fdp.ConsumeIntegral<uint32_t>());
    // Added to cover TIFFUnsetField which was previously uncovered.
    TIFFUnsetField(tif_w, my_field_info.field_tag);
  }

  // Target 3: DoubleToRational
  // Set a rational field with a double to exercise the type conversion logic.
  if (fdp.ConsumeBool()) {
    // Improved input generation to better target uncovered branches in DoubleToRational.
    if (fdp.ConsumeBool()) {
        // Target the negative value check.
        TIFFSetField(tif_w, TIFFTAG_XPOSITION, -1.0 * fdp.ConsumeFloatingPoint<double>());
    } else if (fdp.ConsumeBool()) {
        // Target the very small value check.
        TIFFSetField(tif_w, TIFFTAG_XPOSITION, fdp.ConsumeFloatingPoint<double>() / 0xFFFFFFFFUL);
    } else {
        // Target the non-integer path by adding a fractional part.
        TIFFSetField(tif_w, TIFFTAG_XPOSITION, fdp.ConsumeFloatingPoint<double>() + 0.5);
    }
  }

  // Always set tile dimensions to increase coverage of tiled image functions.
  TIFFSetField(tif_w, TIFFTAG_TILEWIDTH, fdp.ConsumeIntegralInRange<uint32_t>(16, 256));
  TIFFSetField(tif_w, TIFFTAG_TILELENGTH, fdp.ConsumeIntegralInRange<uint32_t>(16, 256));

  // Target 4: LogLuvEncodeStrip/Tile
  // Configure the TIFF for LogLuv compression and write image data.
  if (fdp.ConsumeBool()) {
    TIFFSetField(tif_w, TIFFTAG_COMPRESSION, COMPRESSION_SGILOG);
    TIFFSetField(tif_w, TIFFTAG_PHOTOMETRIC, PHOTOMETRIC_LOGLUV);
    if (TIFFIsTiled(tif_w)) {
        tmsize_t tile_size = TIFFTileSize(tif_w);
        if (tile_size > 0 && tile_size < 100000) {
            auto tile_data = fdp.ConsumeBytes<uint8_t>(tile_size);
            if (tile_data.size() == tile_size) {
                TIFFWriteEncodedTile(tif_w, 0, tile_data.data(), tile_size);
            }
        }
    } else {
        tmsize_t strip_size = TIFFStripSize(tif_w);
        if (strip_size > 0 && strip_size < 100000) {
            auto strip_data = fdp.ConsumeBytes<uint8_t>(strip_size);
            if (strip_data.size() == strip_size) {
                TIFFWriteEncodedStrip(tif_w, 0, strip_data.data(), strip_size);
            }
        }
    }
  }

  // Close the TIFF file to ensure all data is written
  TIFFClose(tif_w);

  // Attempt to read the TIFF file we just created to test decoders
  TIFF* tif_r = TIFFOpen(filename, "r");
  if (tif_r) {
    uint32_t w, h;
    TIFFGetField(tif_r, TIFFTAG_IMAGEWIDTH, &w);
    TIFFGetField(tif_r, TIFFTAG_IMAGELENGTH, &h);
    if (w > 0 && h > 0) {
      if (TIFFIsTiled(tif_r)) {
        uint32_t tile_w, tile_h;
        TIFFGetField(tif_r, TIFFTAG_TILEWIDTH, &tile_w);
        TIFFGetField(tif_r, TIFFTAG_TILELENGTH, &tile_h);
        if (tile_w > 0 && tile_h > 0) {
          std::vector<uint32_t> buf(tile_w * tile_h);
          TIFFReadRGBATile(tif_r, 0, 0, buf.data());
        }
      } else {
        tmsize_t scanline_size = TIFFScanlineSize(tif_r);
        if (scanline_size > 0 && scanline_size < 100000) {
          std::vector<uint8_t> buf(scanline_size);
          for (uint32_t i = 0; i < h; ++i) {
            TIFFReadScanline(tif_r, buf.data(), i);
          }
        }
      }
    }
    // Clean up the TIFF reader object
    TIFFClose(tif_r);
  }

  // Clean up the temporary file
  unlink(filename);

  return 0;
}