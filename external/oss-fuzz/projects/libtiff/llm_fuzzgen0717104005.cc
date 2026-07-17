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
  TIFFSetField(tif, TIFFTAG_COMPRESSION, COMPRESSION_NONE);
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

  // Close the TIFF file
  TIFFClose(tif);

  // Clean up the created file
  unlink(tiff_filename.c_str());

  return 0;
}