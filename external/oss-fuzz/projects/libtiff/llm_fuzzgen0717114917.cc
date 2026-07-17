#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <string>
#include <unistd.h>
#include <vector>
#include <array>

#include "fuzzer/FuzzedDataProvider.h"
#include "tiffio.h"
#include "tiff.h"

// _FUZZ_TARGET_NAME is a compile-time macro provided by the build system.
#ifndef _FUZZ_TARGET_NAME
#define _FUZZ_TARGET_NAME "fuzz_target"
#endif

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  if (size < 100) {
    return 0;
  }

  FuzzedDataProvider fdp(data, size);

  // Create a unique temporary filename to avoid race conditions.
  char filename[256];
  snprintf(filename, sizeof(filename), "/tmp/%s.tif", _FUZZ_TARGET_NAME);

  // Open the TIFF file for writing.
  TIFF *tif = TIFFOpen(filename, "w");
  if (!tif) {
    return 0;
  }

  // Set basic TIFF tags using fuzzed data.
  TIFFSetField(tif, TIFFTAG_IMAGEWIDTH, fdp.ConsumeIntegralInRange<uint32_t>(1, 512));
  TIFFSetField(tif, TIFFTAG_IMAGELENGTH, fdp.ConsumeIntegralInRange<uint32_t>(1, 512));
  const std::array<uint16_t, 5> bits_per_sample_options = {1, 2, 4, 8, 16};
  TIFFSetField(tif, TIFFTAG_BITSPERSAMPLE, fdp.PickValueInArray(bits_per_sample_options));
  TIFFSetField(tif, TIFFTAG_SAMPLESPERPIXEL, (uint16_t)1);
  TIFFSetField(tif, TIFFTAG_PLANARCONFIG, PLANARCONFIG_CONTIG);
  TIFFSetField(tif, TIFFTAG_PHOTOMETRIC, PHOTOMETRIC_MINISBLACK);

  /*
   * ANALYSIS: The function-level coverage report showed that ZIPVSetField in
   *           tif_zip.c has very low coverage (17.65%). This function is
   *           called when TIFFTAG_ZIPQUALITY is set for a ZIP-compressed image.
   * IMPLEMENTATION: The following block sets the compression to COMPRESSION_DEFLATE
   *                 (the internal implementation for ZIP) and then sets the
   *                 TIFFTAG_ZIPQUALITY to a fuzzed value. This directly
   *                 exercises the logic within ZIPVSetField.
   */
  if (fdp.ConsumeBool()) {
    TIFFSetField(tif, TIFFTAG_COMPRESSION, COMPRESSION_DEFLATE);
    TIFFSetField(tif, TIFFTAG_ZIPQUALITY, fdp.ConsumeIntegralInRange<int>(1, 9));
  }
  /*
   * ANALYSIS: The coverage report indicates that OJPEGReadSecondarySos and
   *           OJPEGVGetField in tif_ojpeg.c have 0% and 45% coverage,
   *           respectively. These are part of the Old-JPEG support.
   * IMPLEMENTATION: To target these functions, we set the compression to
   *                 COMPRESSION_OJPEG. We then attempt to get an OJPEG-specific
   *                 field (TIFFTAG_JPEGPROC) to trigger OJPEGVGetField.
   *                 Setting up an OJPEG context is the first step to potentially
   *                 reaching OJPEGReadSecondarySos during a read operation.
   */
  else {
    TIFFSetField(tif, TIFFTAG_COMPRESSION, COMPRESSION_OJPEG);
    int ojpeg_proc = 0;
    // This call will trigger OJPEGVGetField.
    TIFFGetField(tif, TIFFTAG_JPEGPROC, &ojpeg_proc);
  }

  /*
   * ANALYSIS: The function _TIFFRewriteField in tif_dirwrite.c has very low
   *           coverage (37.09%). This function is complex and handles rewriting
   *           existing tags in a TIFF directory.
   * IMPLEMENTATION: To exercise this path, we first write a tag (TIFFTAG_INKNAMES)
   *                 with some initial data. Then, we use TIFFSetField again on the
   *                 same tag with different data, which should trigger the rewrite
   *                 logic in _TIFFRewriteField.
   */
  const char *initial_ink_names = "InitialCyan\0Magenta\0Yellow\0Black";
  TIFFSetField(tif, TIFFTAG_INKNAMES, 4, initial_ink_names);
  std::string new_ink_names_str = fdp.ConsumeRandomLengthString(50);
  TIFFSetField(tif, TIFFTAG_INKNAMES, 1, new_ink_names_str.c_str());

  // Write a single scanline to make the TIFF file valid.
  std::vector<uint8_t> scanline_buf(TIFFScanlineSize(tif), 0);
  TIFFWriteScanline(tif, scanline_buf.data(), 0, 0);

  // Write the directory and close the file.
  TIFFWriteDirectory(tif);
  TIFFClose(tif);

  // Re-open the TIFF file for reading to test read-related functions.
  tif = TIFFOpen(filename, "r");
  if (!tif) {
    unlink(filename);
    return 0;
  }

  // Clean up resources.
  TIFFClose(tif);
  unlink(filename);

  return 0;
}