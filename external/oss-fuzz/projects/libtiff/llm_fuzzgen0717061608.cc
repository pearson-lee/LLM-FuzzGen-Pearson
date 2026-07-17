#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <unistd.h>

#include "/src/libtiff/libtiff/tiffio.h"
#include "/src/libtiff/libtiff/tiffiop.h"
#include <fuzzer/FuzzedDataProvider.h>

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  FuzzedDataProvider fdp(data, size);

  // Create a TIFF file in memory
  char tiff_name[256];
  sprintf(tiff_name, "/tmp/%s.tif", _FUZZ_TARGET_NAME);
  TIFF *tif = TIFFOpen(tiff_name, "w+");
  if (!tif) {
    return 0;
  }

  // Set some initial fields in the TIFF directory
  const uint32_t image_width = fdp.ConsumeIntegralInRange<uint32_t>(1, 2048);
  const uint32_t image_length = fdp.ConsumeIntegralInRange<uint32_t>(1, 2048);
  TIFFSetField(tif, TIFFTAG_IMAGEWIDTH, image_width);
  TIFFSetField(tif, TIFFTAG_IMAGELENGTH, image_length);
  TIFFSetField(tif, TIFFTAG_BITSPERSAMPLE, 8);
  TIFFSetField(tif, TIFFTAG_SAMPLESPERPIXEL, 1);
  TIFFSetField(tif, TIFFTAG_PLANARCONFIG, PLANARCONFIG_CONTIG);
  TIFFSetField(tif, TIFFTAG_COMPRESSION, COMPRESSION_NONE);
  TIFFSetField(tif, TIFFTAG_PHOTOMETRIC, PHOTOMETRIC_MINISBLACK);

  // Write some random data to the TIFF file
  if (image_width > 0 && image_length > 0) {
    std::vector<uint8_t> scanline = fdp.ConsumeBytes<uint8_t>(image_width);
    if (scanline.size() == image_width) {
      for (uint32_t i = 0; i < image_length; ++i) {
        TIFFWriteScanline(tif, scanline.data(), i, 0);
      }
    }
  }

  /*
   * ANALYSIS: The function-level coverage report showed _TIFFRewriteField had low
   *           coverage. This function is used to modify existing tags in a
   *           TIFF directory.
   * IMPLEMENTATION: The following code block calls _TIFFRewriteField to modify
   *                 the ImageWidth and ImageLength tags, exercising this
   *                 lightly-tested functionality.
   */
  uint32_t new_width = fdp.ConsumeIntegralInRange<uint32_t>(1, 2048);
  uint32_t new_length = fdp.ConsumeIntegralInRange<uint32_t>(1, 2048);
  _TIFFRewriteField(tif, TIFFTAG_IMAGEWIDTH, TIFF_LONG, 1, &new_width);
  _TIFFRewriteField(tif, TIFFTAG_IMAGELENGTH, TIFF_LONG, 1, &new_length);

  TIFFWriteDirectory(tif);

  /*
   * ANALYSIS: The function-level coverage report showed TIFFSetDirectory had low
   *           coverage. This function is used to switch between different
   *           directories in a TIFF file.
   * IMPLEMENTATION: The following code block calls TIFFSetDirectory to create
   *                 and switch to a new directory, exercising this
   *                 functionality.
   */
  if (fdp.ConsumeBool()) {
    TIFFSetDirectory(tif, 1);
  }

  /*
   * ANALYSIS: The function-level coverage report showed
   *           TIFFWriteDirectoryTagSampleformatArray had 0% coverage. This
   *           function is used to write an array of sample formats to a TIFF
   *           directory.
   * IMPLEMENTATION: The following code block calls
   *                 TIFFWriteDirectoryTagSampleformatArray to write a sample
   *                 format array, exercising this uncovered function.
   */
  double sample_format_array[] = {1.0};
  TIFFSetField(tif, TIFFTAG_SMINSAMPLEVALUE, 1, sample_format_array);

  /*
   * ANALYSIS: The function-level coverage report showed TIFFPrintDirectory had
   *           low coverage. This function is used to print the contents of a
   *           TIFF directory to a file.
   * IMPLEMENTATION: The following code block calls TIFFPrintDirectory to print
   *                 the directory contents to /dev/null, exercising this
   *                 functionality.
   */
  FILE *dev_null = fopen("/dev/null", "w");
  if (dev_null) {
    TIFFPrintDirectory(tif, dev_null, 0);
    fclose(dev_null);
  }

  TIFFClose(tif);
  unlink(tiff_name);

  return 0;
}