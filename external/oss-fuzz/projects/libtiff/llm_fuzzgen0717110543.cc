#include "fuzzer/FuzzedDataProvider.h"
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <string>
#include <vector>
#include <unistd.h>

#include "tiffio.h"

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
  FuzzedDataProvider fdp(data, size);

  const std::string tiff_filename = std::string("/tmp/") + _FUZZ_TARGET_NAME + ".tif";

  // Create a TIFF file in memory
  TIFF* tif = TIFFOpen(tiff_filename.c_str(), "w");
  if (!tif) {
    return 0;
  }

  // Set basic TIFF fields
  TIFFSetField(tif, TIFFTAG_IMAGEWIDTH, fdp.ConsumeIntegralInRange<uint32_t>(1, 256));
  TIFFSetField(tif, TIFFTAG_IMAGELENGTH, fdp.ConsumeIntegralInRange<uint32_t>(1, 256));
  TIFFSetField(tif, TIFFTAG_BITSPERSAMPLE, 8);
  TIFFSetField(tif, TIFFTAG_SAMPLESPERPIXEL, 1);
  TIFFSetField(tif, TIFFTAG_PLANARCONFIG, PLANARCONFIG_CONTIG);

  /*
   * ANALYSIS: The function-level coverage report for tif_getimage.c shows that
   *           color conversion functions for YCbCr, LogLuv, etc., have low or
   *           zero coverage. The original fuzzer only used PHOTOMETRIC_MINISBLACK.
   * IMPLEMENTATION: The following code block uses FuzzedDataProvider to select
   *                 from a variety of photometric interpretations to exercise
   *                 these color conversion code paths.
   */
  const auto photometric = fdp.PickValueInArray<uint16_t>({
      PHOTOMETRIC_MINISBLACK,
      PHOTOMETRIC_YCBCR,
      PHOTOMETRIC_LOGLUV,
      PHOTOMETRIC_LOGL,
  });
  TIFFSetField(tif, TIFFTAG_PHOTOMETRIC, photometric);

  /*
   * ANALYSIS: The function-level coverage report shows many 0% coverage functions
   *           related to different compression schemes (e.g., in tif_luv.c,
   *           tif_pixarlog.c, tif_lzma.c). The fuzzer previously used a smaller set.
   * IMPLEMENTATION: The following code block uses FuzzedDataProvider to select from
   *                 an expanded variety of compression types, exercising the setup
   *                 and initialization logic for more codecs.
   */
  const auto compression = fdp.PickValueInArray<uint16_t>({
      COMPRESSION_NONE,
      COMPRESSION_LZW,
      COMPRESSION_PACKBITS,
      COMPRESSION_ADOBE_DEFLATE,
      COMPRESSION_JPEG,
      COMPRESSION_SGILOG,
      COMPRESSION_PIXARLOG,
      COMPRESSION_LZMA,
  });
  TIFFSetField(tif, TIFFTAG_COMPRESSION, compression);

  if (fdp.ConsumeBool()) {
    double value = fdp.ConsumeFloatingPoint<double>();
    TIFFSetField(tif, TIFFTAG_XRESOLUTION, value);
  }

  if (fdp.ConsumeBool()) {
    uint16_t h_sub = fdp.ConsumeIntegral<uint16_t>();
    uint16_t v_sub = fdp.ConsumeIntegral<uint16_t>();
    TIFFSetField(tif, TIFFTAG_YCBCRSUBSAMPLING, h_sub, v_sub);
  }

  if (fdp.ConsumeBool()) {
    uint16_t count = fdp.ConsumeIntegralInRange<uint16_t>(0, 10);
    std::vector<uint64_t> values;
    for (uint16_t i = 0; i < count; ++i) {
      values.push_back(fdp.ConsumeIntegral<uint64_t>());
    }
    if (!values.empty()) {
      TIFFSetField(tif, TIFFTAG_SUBIFD, count, values.data());
    }
  }

  if (fdp.ConsumeBool()) {
    float whitepoint[2];
    whitepoint[0] = fdp.ConsumeFloatingPoint<float>();
    whitepoint[1] = fdp.ConsumeFloatingPoint<float>();
    TIFFSetField(tif, TIFFTAG_WHITEPOINT, whitepoint);
  }

  /*
   * ANALYSIS: The function-level coverage report for tif_tile.c shows that
   *           tile-related functions like TIFFWriteTile, TIFFTileSize, etc.,
   *           have zero or very low coverage. The original fuzzer only ever
   *           wrote scanlines.
   * IMPLEMENTATION: The following code block introduces a fuzzer-controlled choice
   *                 to either write tiles or scanlines. When tiles are chosen, it
   *                 sets the tile dimensions and uses TIFFWriteTile to exercise the
   *                 previously uncovered tile-writing code paths.
   */
  bool use_tiles = fdp.ConsumeBool();
  if (use_tiles) {
    TIFFSetField(tif, TIFFTAG_TILEWIDTH, 16);
    TIFFSetField(tif, TIFFTAG_TILELENGTH, 16);
    tsize_t tile_size = TIFFTileSize(tif);
    if (tile_size > 0) {
      std::vector<uint8_t> tile_buf = fdp.ConsumeBytes<uint8_t>(tile_size);
      if (tile_buf.size() == static_cast<size_t>(tile_size)) {
        TIFFWriteTile(tif, tile_buf.data(), 0, 0, 0, 0);
      }
    }
  } else {
    tsize_t scanline_size = TIFFScanlineSize(tif);
    if (scanline_size > 0) {
      std::vector<uint8_t> scanline = fdp.ConsumeBytes<uint8_t>(scanline_size);
      if (scanline.size() == static_cast<size_t>(scanline_size)) {
        TIFFWriteScanline(tif, scanline.data(), 0, 0);
      }
    }
  }

  if (fdp.ConsumeBool()) {
    long print_flags = fdp.ConsumeIntegral<long>();
    TIFFPrintDirectory(tif, stdout, print_flags);
  }

  // Close the TIFF file
  TIFFClose(tif);

  /*
   * ANALYSIS: The function-level coverage reports for tif_read.c, tif_dirread.c,
   *           and tif_tile.c show that tile-reading logic was completely uncovered.
   * IMPLEMENTATION: The following code block re-opens the TIFF file and checks if
   *                 it is a tiled image using TIFFIsTiled(). If so, it calls
   *                 TIFFReadTile() to exercise the tile-reading code paths. Otherwise,
   *                 it falls back to the existing scanline reading logic.
   */
  TIFF* tif_read = TIFFOpen(tiff_filename.c_str(), "r");
  if (tif_read) {
    if (TIFFIsTiled(tif_read)) {
      tsize_t read_tile_size = TIFFTileSize(tif_read);
      if (read_tile_size > 0) {
        std::vector<uint8_t> buffer(read_tile_size);
        TIFFReadTile(tif_read, buffer.data(), 0, 0, 0, 0);
      }
    } else {
      tsize_t read_scanline_size = TIFFScanlineSize(tif_read);
      if (read_scanline_size > 0) {
        std::vector<uint8_t> buffer(read_scanline_size);
        TIFFReadScanline(tif_read, buffer.data(), 0, 0);
      }
    }
    TIFFClose(tif_read);
  }


  // Clean up the created file
  unlink(tiff_filename.c_str());

  return 0;
}