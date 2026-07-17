#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <string>
#include <vector>
#include <unistd.h>

#include "fuzzer/FuzzedDataProvider.h"
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
   * ANALYSIS: The function-level coverage report shows many 0% coverage functions
   *           related to different compression schemes (e.g., in tif_lzw.c, tif_zip.c).
   *           The original fuzzer only used COMPRESSION_NONE.
   * IMPLEMENTATION: The following code block uses FuzzedDataProvider to select from
   *                 a variety of compression types, exercising the setup and
   *                 initialization logic for those codecs.
   */
  const auto compression = fdp.PickValueInArray<uint16_t>({
      COMPRESSION_NONE,
      COMPRESSION_LZW,
      COMPRESSION_PACKBITS,
      COMPRESSION_ADOBE_DEFLATE,
      COMPRESSION_JPEG,
  });
  TIFFSetField(tif, TIFFTAG_COMPRESSION, compression);

  TIFFSetField(tif, TIFFTAG_PHOTOMETRIC, PHOTOMETRIC_MINISBLACK);

  /*
   * Corrected to use the proper TIFFSetField signature for a single rational value.
   */
  if (fdp.ConsumeBool()) {
    double value = fdp.ConsumeFloatingPoint<double>();
    TIFFSetField(tif, TIFFTAG_XRESOLUTION, value);
  }

  /*
   * Corrected to use the proper TIFFSetField signature for YCbCrSubsampling,
   * which expects two separate uint16_t arguments.
   */
  if (fdp.ConsumeBool()) {
    uint16_t h_sub = fdp.ConsumeIntegral<uint16_t>();
    uint16_t v_sub = fdp.ConsumeIntegral<uint16_t>();
    TIFFSetField(tif, TIFFTAG_YCBCRSUBSAMPLING, h_sub, v_sub);
  }

  /*
   * Corrected to use the proper types for TIFFTAG_SUBIFD (uint16_t count, uint64_t* data),
   * which was the cause of the crash.
   */
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

  /*
   * Corrected to use the proper TIFFSetField signature for WhitePoint,
   * which expects a pointer to an array of 2 floats.
   */
  if (fdp.ConsumeBool()) {
    float whitepoint[2];
    whitepoint[0] = fdp.ConsumeFloatingPoint<float>();
    whitepoint[1] = fdp.ConsumeFloatingPoint<float>();
    TIFFSetField(tif, TIFFTAG_WHITEPOINT, whitepoint);
  }

  // Write a dummy scanline to be able to close the file
  tsize_t scanline_size = TIFFScanlineSize(tif);
  if (scanline_size > 0) {
    std::vector<uint8_t> scanline = fdp.ConsumeBytes<uint8_t>(scanline_size);
    if (scanline.size() == static_cast<size_t>(scanline_size)) {
      TIFFWriteScanline(tif, scanline.data(), 0, 0);
    }
  }

  /*
   * ANALYSIS: The function-level coverage report for tif_print.c shows that
   *           TIFFPrintDirectory has low coverage (53.32%) and other printing
   *           functions have 0% coverage.
   * IMPLEMENTATION: The following call to TIFFPrintDirectory exercises this
   *                 uncovered functionality by printing the directory structure
   *                 of the generated TIFF file to stdout. The flags are also
   *                 fuzzed to explore different print options.
   */
  if (fdp.ConsumeBool()) {
    long print_flags = fdp.ConsumeIntegral<long>();
    TIFFPrintDirectory(tif, stdout, print_flags);
  }

  // Close the TIFF file
  TIFFClose(tif);

  /*
   * ANALYSIS: The function-level coverage report shows large portions of tif_read.c
   *           and tif_dirread.c have 0% coverage (e.g., TIFFReadCustomDirectory,
   *           TIFFReadScanline, TIFFReadEncodedStrip). The original fuzzer only
   *           wrote a TIFF file, it never read one.
   * IMPLEMENTATION: The following code block re-opens the TIFF file just created
   *                 in read mode and attempts to read a scanline. This directly
   *                 targets the file reading and parsing logic that was previously
   *                 uncovered.
   */
  TIFF* tif_read = TIFFOpen(tiff_filename.c_str(), "r");
  if (tif_read) {
    tsize_t read_scanline_size = TIFFScanlineSize(tif_read);
    if (read_scanline_size > 0) {
      std::vector<uint8_t> buffer(read_scanline_size);
      TIFFReadScanline(tif_read, buffer.data(), 0, 0);
    }
    TIFFClose(tif_read);
  }


  // Clean up the created file
  unlink(tiff_filename.c_str());

  return 0;
}