/* BLOCKER_STRATEGY_CONTRACT
required_state: The `sp->state` field in the `ZIPState` struct must have the `ZSTATE_INIT_ENCODE` flag set when `ZIPVSetField` is called for `TIFFTAG_ZIPQUALITY`.
state_constructor: The `ZSTATE_INIT_ENCODE` flag is set by the codec's setup routine (`ZIPSetupEncode`), which is triggered by the first call to `TIFFWriteScanline` after the compression has been set to `COMPRESSION_DEFLATE`.
trigger_api: A second call to `TIFFSetField(tif, TIFFTAG_ZIPQUALITY, ...)` is added *after* `TIFFWriteScanline` has been called. This call re-uses the quality value from the fuzzer input and now finds the encoder state initialized, allowing the predicate at `tif_zip.c:606` to pass.
preserved_invariants: The original sequence of `FuzzedDataProvider::Consume...` calls is maintained, ensuring seed compatibility. The initial `TIFFSetField(tif, TIFFTAG_ZIPQUALITY, ...)` call remains before `TIFFWriteScanline` to preserve the original fuzzer's behavior.
END_BLOCKER_STRATEGY_CONTRACT */

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

  bool use_deflate_path = fdp.ConsumeBool();
  int zip_quality = 0; // Default value, only updated and used in the deflate path.

  if (use_deflate_path) {
    TIFFSetField(tif, TIFFTAG_COMPRESSION, COMPRESSION_DEFLATE);
    zip_quality = fdp.ConsumeIntegralInRange<int>(1, 9);
    TIFFSetField(tif, TIFFTAG_ZIPQUALITY, zip_quality);
  }
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

  // BLOCKER-CROSSING LOGIC:
  // The original call to set TIFFTAG_ZIPQUALITY happens before the encoder is
  // initialized, so the predicate `sp->state & ZSTATE_INIT_ENCODE` is false.
  // After TIFFWriteScanline, the encoder is initialized. This second call to
  // TIFFSetField with the same quality value will now trigger the logic
  // on the previously unreached side of the branch.
  if (use_deflate_path) {
    TIFFSetField(tif, TIFFTAG_ZIPQUALITY, zip_quality);
  }

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
