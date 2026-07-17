#include <cstdint>
#include <cstdlib>
#include <cstring>
#include <string>
#include <vector>
#include <unistd.h>
#include <stdio.h>

#include "tiffio.h"
#include <fuzzer/FuzzedDataProvider.h>

// Custom error and warning handlers to suppress output
static void errorHandler(const char *, const char *, va_list) {}
static void warningHandler(const char *, const char *, va_list) {}

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  FuzzedDataProvider fdp(data, size);

  // Suppress error and warning messages from libtiff
  TIFFSetErrorHandler(errorHandler);
  TIFFSetWarningHandler(warningHandler);

  // Create a unique temporary filename for the TIFF image
  const std::string filename = std::string("/tmp/") + _FUZZ_TARGET_NAME + ".tif";

  // Open the TIFF file for writing
  TIFF *tif = TIFFOpen(filename.c_str(), "w");
  if (!tif) {
    return 0;
  }

  // Set basic TIFF fields
  TIFFSetField(tif, TIFFTAG_IMAGEWIDTH, fdp.ConsumeIntegralInRange<uint32_t>(1, 256));
  TIFFSetField(tif, TIFFTAG_IMAGELENGTH, fdp.ConsumeIntegralInRange<uint32_t>(1, 256));
  TIFFSetField(tif, TIFFTAG_BITSPERSAMPLE, 8);
  TIFFSetField(tif, TIFFTAG_SAMPLESPERPIXEL, 1);
  TIFFSetField(tif, TIFFTAG_PLANARCONFIG, PLANARCONFIG_CONTIG);
  TIFFSetField(tif, TIFFTAG_COMPRESSION, COMPRESSION_NONE);
  TIFFSetField(tif, TIFFTAG_PHOTOMETRIC, PHOTOMETRIC_MINISBLACK);

  /*
   * ANALYSIS: The line coverage report for TIFFPrintDirectory shows many
   *           uncovered branches related to specific tags.
   * IMPLEMENTATION: Set more tags like RESOLUTIONUNIT and SAMPLEFORMAT to
   *                 exercise these branches when TIFFPrintDirectory is called.
   */
  if (fdp.ConsumeBool()) {
    TIFFSetField(tif, TIFFTAG_XRESOLUTION, fdp.ConsumeFloatingPoint<float>());
    TIFFSetField(tif, TIFFTAG_YRESOLUTION, fdp.ConsumeFloatingPoint<float>());
    TIFFSetField(tif, TIFFTAG_RESOLUTIONUNIT, fdp.ConsumeIntegralInRange<uint16_t>(1, 3));
  }
  if (fdp.ConsumeBool()) {
    TIFFSetField(tif, TIFFTAG_SAMPLEFORMAT, fdp.PickValueInArray({SAMPLEFORMAT_UINT, SAMPLEFORMAT_INT, SAMPLEFORMAT_IEEEFP}));
  }

  /*
   * ANALYSIS: The coverage report for tif_tile.c shows functions like
   *           TIFFCheckTile and TIFFWriteTile have low or no coverage.
   * IMPLEMENTATION: Add logic to sometimes create a tiled TIFF image instead
   *                 of a stripped one. This involves setting tile-specific
   *                 tags and using TIFFWriteTile.
   */
  if (fdp.ConsumeBool()) {
    // Write a dummy scanline for a stripped image
    std::vector<uint8_t> dummy_scanline(TIFFScanlineSize(tif), 0);
    TIFFWriteScanline(tif, dummy_scanline.data(), 0, 0);
  } else {
    // Write a dummy tile for a tiled image
    TIFFSetField(tif, TIFFTAG_TILEWIDTH, 16);
    TIFFSetField(tif, TIFFTAG_TILELENGTH, 16);
    tsize_t tile_size = TIFFTileSize(tif);
    if (tile_size > 0) {
        std::vector<uint8_t> dummy_tile(tile_size, 0);
        TIFFWriteTile(tif, dummy_tile.data(), 0, 0, 0, 0);
    }
  }

  /*
   * ANALYSIS: The function _TIFFRewriteField has low coverage (37.09%).
   * IMPLEMENTATION: By calling TIFFRewriteDirectory, we trigger the use of
   * _TIFFRewriteField, which will rewrite the directory information we've
   * previously set, thus improving its coverage.
   */
  TIFFRewriteDirectory(tif);

  // Close the TIFF file to ensure all data is written to disk
  TIFFClose(tif);

  // Re-open the TIFF file for reading to test read-related functions
  tif = TIFFOpen(filename.c_str(), "r");
  if (!tif) {
    unlink(filename.c_str());
    return 0;
  }

  // Read the directory to initialize the TIFF handle before further operations
  TIFFReadDirectory(tif);

  /*
   * ANALYSIS: The function-level coverage report shows TIFFPrintDirectory
   *           has only 60.62% coverage and is never called by the fuzzer.
   * IMPLEMENTATION: Add a call to TIFFPrintDirectory to exercise its logic.
   *                 Output is redirected to /dev/null to avoid polluting stdout and ensure
   *                 memory safety by properly handling the FILE object.
   */
  FILE* devnull = fopen("/dev/null", "w");
  if (devnull) {
    TIFFPrintDirectory(tif, devnull, 0);
    fclose(devnull);
  }

  /*
   * ANALYSIS: The function OJPEGReadSecondarySos has 0% coverage. This
   * function is part of the OJPEG codec.
   * IMPLEMENTATION: We set the compression to OJPEG and then attempt to read
   * a scanline. While this may not fully succeed without a valid OJPEG image,
   * it can trigger initial setup and error-handling paths within the OJPEG
   * decoding logic, including OJPEGReadSecondarySos.
   */
  if (fdp.ConsumeBool()) {
    TIFFSetField(tif, TIFFTAG_COMPRESSION, COMPRESSION_OJPEG);
    tsize_t scanlineSize = TIFFScanlineSize(tif);
    if (scanlineSize > 0) {
      std::vector<uint8_t> buffer(scanlineSize);
      TIFFReadScanline(tif, buffer.data(), fdp.ConsumeIntegral<uint32_t>());
    }
  }

  // Clean up resources
  TIFFClose(tif);
  unlink(filename.c_str());

  return 0;
}