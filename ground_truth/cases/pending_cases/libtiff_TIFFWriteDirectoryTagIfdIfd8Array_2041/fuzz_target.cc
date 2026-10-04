#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <string>
#include <vector>
#include <unistd.h>

#include "fuzzer/FuzzedDataProvider.h"
#include "tiffio.h"

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  if (size == 0) {
    return 0;
  }

  FuzzedDataProvider fdp(data, size);

  // Create a unique temporary filename for the TIFF file.
  char filename[256];
  snprintf(filename, sizeof(filename), "/tmp/%s.tiff", _FUZZ_TARGET_NAME);

  // Consume data from the fuzzer to create the TIFF file content.
  const std::vector<uint8_t> tiff_data =
      fdp.ConsumeRemainingBytes<uint8_t>();
  FILE *fp = fopen(filename, "wb");
  if (!fp) {
    return 0;
  }
  fwrite(tiff_data.data(), 1, tiff_data.size(), fp);
  fclose(fp);

  // Open the TIFF file for reading and writing.
  TIFF *tif = TIFFOpen(filename, "r+");
  if (!tif) {
    unlink(filename);
    return 0;
  }

  /*
   * ANALYSIS: The function TIFFSetDirectory has low coverage because the fuzzer
   *           never generates multi-directory TIFFs, causing the 'if (dir_count > 1)'
   *           check in the original fuzzer to always be false.
   * IMPLEMENTATION: Call TIFFWriteDirectory() to create a second directory in the
   *                 TIFF file. This ensures that TIFFNumberOfDirectories() will be
   *                 greater than 1, allowing the subsequent call to TIFFSetDirectory
   *                 to be exercised.
   */
  TIFFWriteDirectory(tif);
  int dir_count = TIFFNumberOfDirectories(tif);
  if (dir_count > 1) {
    tdir_t dir_to_set = fdp.ConsumeIntegralInRange<tdir_t>(0, dir_count - 1);
    TIFFSetDirectory(tif, dir_to_set);
  }

  /*
   * ANALYSIS: Functions in tif_getimage.c, such as TIFFReadRGBAImage,
   *           TIFFRGBAImageGet, gtTileContig, and gtStripContig have low or no
   *           coverage. These are critical for image reading.
   * IMPLEMENTATION: The following code calls TIFFReadRGBAImage to exercise the
   *                 core image reading and color space conversion logic. It reads
   *                 the image dimensions, allocates a sufficiently large buffer for
   *                 the raster, and then frees the buffer to prevent memory leaks.
   */
  uint32_t width, height;
  TIFFGetField(tif, TIFFTAG_IMAGEWIDTH, &width);
  TIFFGetField(tif, TIFFTAG_IMAGELENGTH, &height);
  // Cap dimensions to prevent excessive memory allocation.
  if (width > 0 && width <= 4096 && height > 0 && height <= 4096) {
    uint32_t* raster = (uint32_t*)_TIFFmalloc(width * height * sizeof(uint32_t));
    if (raster) {
        TIFFReadRGBAImage(tif, width, height, raster, 0);
        _TIFFfree(raster);
    }
  }

  /*
   * ANALYSIS: The function TIFFPrintDirectory has low coverage (39.60% line,
   *           43.48% branch), and Fax3PrintDir has 0% coverage.
   * IMPLEMENTATION: The following code calls TIFFPrintDirectory. While the
   *                 fuzzer-generated TIFF may not always have Fax3 compression,
   *                 this call exercises the general directory printing logic and
   *                 provides a chance to hit Fax3PrintDir if the input data happens
   *                 to specify that compression.
   */
  FILE *print_fp = fopen("/dev/null", "w");
  if (print_fp) {
    TIFFPrintDirectory(tif, print_fp, 0);
    fclose(print_fp);
  }

  // Clean up resources.
  TIFFClose(tif);
  unlink(filename);

  return 0;
}