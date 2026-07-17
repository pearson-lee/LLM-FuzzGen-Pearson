#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <string>
#include <unistd.h>
#include <vector>

#include "fuzzer/FuzzedDataProvider.h"
#include "/src/libtiff/libtiff/tiff.h"
#include "/src/libtiff/libtiff/tiffio.h"
#include "/src/libtiff/libtiff/tiffiop.h"
#include "/src/libtiff/libtiff/tif_dir.h"

// Forward declaration for the internal function if not exposed in headers.
extern "C" int _TIFFRewriteField(TIFF *, uint16_t, TIFFDataType, tmsize_t,
                                 void *);

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  FuzzedDataProvider fdp(data, size);

  // Create a unique temporary filename to avoid race conditions.
  char filename[256];
  snprintf(filename, sizeof(filename), "/tmp/%s.tif", _FUZZ_TARGET_NAME);

  // Open the TIFF file for writing.
  TIFF *tif = TIFFOpen(filename, "w");
  if (!tif) {
    return 0;
  }

  /*
   * ANALYSIS: The function-level coverage report showed that TIFFWriteDirectorySec
   *           has many untested branches related to writing specific TIFF tags.
   *           Fax3PrintDir also has 0% coverage.
   * IMPLEMENTATION: The following code sets a variety of TIFF tags, including
   *                 compression-specific ones for FAX3, to exercise these
   *                 uncovered paths.
   */
  uint32_t width = fdp.ConsumeIntegralInRange<uint32_t>(1, 512);
  uint32_t height = fdp.ConsumeIntegralInRange<uint32_t>(1, 512);
  uint16_t spp = fdp.PickValueInArray<uint16_t>({1, 3, 4});
  uint16_t bps = fdp.PickValueInArray<uint16_t>({8, 16});
  uint16_t planarconfig = fdp.PickValueInArray<uint16_t>(
      {PLANARCONFIG_CONTIG, PLANARCONFIG_SEPARATE});
  uint16_t compression = fdp.PickValueInArray<uint16_t>({COMPRESSION_NONE,
                                                         COMPRESSION_PACKBITS,
                                                         COMPRESSION_CCITTFAX3,
                                                         COMPRESSION_CCITTFAX4});
  uint16_t photometric =
      (spp == 1) ? fdp.PickValueInArray<uint16_t>({PHOTOMETRIC_MINISBLACK, PHOTOMETRIC_MINISWHITE}) : fdp.PickValueInArray<uint16_t>({PHOTOMETRIC_RGB, PHOTOMETRIC_SEPARATED});

  TIFFSetField(tif, TIFFTAG_IMAGEWIDTH, width);
  TIFFSetField(tif, TIFFTAG_IMAGELENGTH, height);
  TIFFSetField(tif, TIFFTAG_SAMPLESPERPIXEL, spp);
  TIFFSetField(tif, TIFFTAG_BITSPERSAMPLE, bps);
  TIFFSetField(tif, TIFFTAG_PLANARCONFIG, planarconfig);
  TIFFSetField(tif, TIFFTAG_COMPRESSION, compression);
  TIFFSetField(tif, TIFFTAG_PHOTOMETRIC, photometric);
  TIFFSetField(tif, TIFFTAG_ROWSPERSTRIP, height);

  if (compression == COMPRESSION_CCITTFAX3 ||
      compression == COMPRESSION_CCITTFAX4) {
    /*
     * ANALYSIS: The function-level coverage report showed that Fax3PrintDir has
     *           0% coverage. This is called by TIFFPrintDirectory when the
     *           compression is FAX3/4 and related tags are present.
     * IMPLEMENTATION: Set various FAX-related tags to trigger the logic inside
     *                 Fax3PrintDir during the TIFFPrintDirectory call below.
     */
    TIFFSetField(tif, TIFFTAG_GROUP3OPTIONS,
                 fdp.ConsumeIntegral<uint32_t>());
    TIFFSetField(tif, TIFFTAG_CLEANFAXDATA,
                 fdp.ConsumeIntegralInRange<uint16_t>(0, 2));
    TIFFSetField(tif, TIFFTAG_BADFAXLINES, fdp.ConsumeIntegral<uint32_t>());
  }

  if (photometric == PHOTOMETRIC_SEPARATED) {
    TIFFSetField(tif, TIFFTAG_INKSET, INKSET_CMYK);
  }

  // Write a single scanline of dummy data.
  if (TIFFScanlineSize(tif) > 0) {
    std::vector<uint8_t> scanline(TIFFScanlineSize(tif));
    if (TIFFWriteScanline(tif, scanline.data(), 0, 0) < 0) {
      TIFFClose(tif);
      unlink(filename);
      return 0;
    }
  }

  /*
   * ANALYSIS: The function-level coverage report showed that TIFFSetSubDirectory
   *           has low coverage.
   * IMPLEMENTATION: The following code creates a second directory and links it
   *                 as a sub-IFD to the first one. This allows testing the
   *                 logic for handling subdirectories.
   */
  TIFFWriteDirectory(tif);
  uint64_t subifd_offset = 0;
  TIFFSetField(tif, TIFFTAG_SUBIFD, 1, &subifd_offset);
  TIFFWriteDirectory(tif); // This writes the SubIFD

  TIFFClose(tif);

  // Re-open the TIFF for reading and print the directory.
  tif = TIFFOpen(filename, "r");
  if (tif) {
    /*
     * ANALYSIS: The function-level coverage report showed that TIFFPrintDirectory
     *           and Fax3PrintDir have low or zero coverage.
     * IMPLEMENTATION: The following code calls TIFFPrintDirectory to exercise
     *                 the printing logic for the generated TIFF file, which
     *                 now includes FAX3-specific tags.
     */
    FILE *devnull = fopen("/dev/null", "w");
    if (devnull) {
      TIFFPrintDirectory(tif, devnull, 0);
      fclose(devnull);
    }

    /*
     * ANALYSIS: The function-level coverage report showed low coverage for
     *           functions in tif_getimage.c, like TIFFRGBAImageBegin.
     * IMPLEMENTATION: The following code reads the image data using the
     *                 TIFFRGBAImage interface, exercising a wide range of image
     *                 parsing and color conversion logic.
     */
    uint32_t *raster = (uint32_t *)_TIFFmalloc(width * height * sizeof(uint32_t));
    if (raster) {
      TIFFRGBAImage img;
      char emsg[1024];
      if (TIFFRGBAImageBegin(&img, tif, 0, emsg)) {
        TIFFRGBAImageGet(&img, raster, width, height);
        TIFFRGBAImageEnd(&img);
      }
      _TIFFfree(raster);
    }
    TIFFClose(tif);
  }

  // Re-open the TIFF for updating to test _TIFFRewriteField.
  tif = TIFFOpen(filename, "r+");
  if (tif) {
    /*
     * ANALYSIS: The function-level coverage report showed that _TIFFRewriteField
     *           has 0% coverage.
     * IMPLEMENTATION: The following code calls the internal _TIFFRewriteField
     *                 function to modify a field in the existing TIFF file,
     *                 directly targeting this uncovered function.
     */
    uint32_t new_width = fdp.ConsumeIntegralInRange<uint32_t>(1, 512);
    _TIFFRewriteField(tif, TIFFTAG_IMAGEWIDTH, TIFF_LONG, 1, &new_width);
    TIFFClose(tif);
  }

  // Clean up the temporary file.
  unlink(filename);

  return 0;
}