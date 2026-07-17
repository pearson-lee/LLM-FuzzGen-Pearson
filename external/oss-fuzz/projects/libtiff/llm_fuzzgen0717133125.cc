#include <cstdint>
#include <cstdlib>
#include <cstring>
#include <string>
#include <vector>
#include <unistd.h>

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

  // Write a dummy scanline to finalize the directory
  std::vector<uint8_t> dummy_scanline(TIFFScanlineSize(tif), 0);
  TIFFWriteScanline(tif, dummy_scanline.data(), 0, 0);

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
   * ANALYSIS: The function OJPEGReadSecondarySos has 0% coverage. This
   * function is part of the OJPEG codec.
   * IMPLEMENTATION: We set the compression to OJPEG and then attempt to read
   * a scanline. While this may not fully succeed without a valid OJPEG image,
   * it can trigger initial setup and error-handling paths within the OJPEG
   * decoding logic, including OJPEGReadSecondarySos.
   */
  if (fdp.ConsumeBool()) {
    TIFFSetField(tif, TIFFTAG_COMPRESSION, COMPRESSION_OJPEG);
    std::vector<uint8_t> buffer(TIFFScanlineSize(tif), 0);
    TIFFReadScanline(tif, buffer.data(), fdp.ConsumeIntegral<uint32_t>());
  }

  // Clean up resources
  TIFFClose(tif);
  unlink(filename.c_str());

  return 0;
}