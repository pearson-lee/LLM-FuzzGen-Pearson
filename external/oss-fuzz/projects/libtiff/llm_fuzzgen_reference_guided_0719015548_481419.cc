/* BLOCKER_STRATEGY_CONTRACT
required_state: When `_TIFFRewriteField` is called, the `tif->tif_flags` must have the `TIFF_SWAB` bit set, and the internal `datatype` variable must be a type where `TIFFDataWidth` returns 8.
state_constructor: The `TIFF_SWAB` flag is set by opening a file written with big-endian byte order ("wb") on a little-endian host. A `TIFF_DOUBLE` tag (`TIFFTAG_STONITS`) is added during the initial write phase, with its value derived from already-consumed fuzzer data to maintain the input contract.
trigger_api: `_TIFFRewriteField` is called with `TIFF_DOUBLE` as the data type on the `TIFFTAG_STONITS` tag. This ensures the internal `datatype` variable becomes `TIFF_DOUBLE`, for which `TIFFDataWidth` returns 8, satisfying the blocker condition.
preserved_invariants: The original fuzz target's input consumption contract via `FuzzedDataProvider` is fully preserved. The sequence of creating, writing, reading, and then updating the TIFF file remains intact, and the order of `Consume...` calls is unchanged.
END_BLOCKER_STRATEGY_CONTRACT */

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
  snprintf(filename, sizeof(filename), "/tmp/%s.tif", "llm_fuzzgen_reference_guided_0718193942_583890");

  // Open the TIFF file for writing.
  // BLOCKER_REMEDIATION: Use "wb" to write in big-endian format. This will
  // cause the TIFF_SWAB flag to be set when the file is re-opened on a
  // little-endian machine, satisfying the blocker condition.
  TIFF *tif = TIFFOpen(filename, "wb");
  if (!tif) {
    return 0;
  }

  uint32_t width = fdp.ConsumeIntegralInRange<uint32_t>(1, 512);
  uint32_t height = fdp.ConsumeIntegralInRange<uint32_t>(1, 512);
  uint16_t spp = fdp.PickValueInArray<uint16_t>({1, 3, 4});
  uint16_t bps = fdp.PickValueInArray<uint16_t>({8, 16});
  uint16_t planarconfig = fdp.PickValueInArray<uint16_t>(
      {PLANARCONFIG_CONTIG, PLANARCONFIG_SEPARATE});
  /*
   * ANALYSIS: The function-level coverage report showed that functions in
   *           tif_ojpeg.c, such as OJPEGEncode, have 0% coverage.
   * IMPLEMENTATION: Added COMPRESSION_OJPEG to the list of possible
   *                 compressions to enable testing of the Old JPEG codec.
   */
  uint16_t compression =
      fdp.PickValueInArray<uint16_t>({COMPRESSION_NONE, COMPRESSION_PACKBITS,
                                      COMPRESSION_CCITTFAX3,
                                      COMPRESSION_CCITTFAX4, COMPRESSION_OJPEG});
  uint16_t photometric =
      (spp == 1)
          ? fdp.PickValueInArray<uint16_t>(
                {PHOTOMETRIC_MINISBLACK, PHOTOMETRIC_MINISWHITE})
          : fdp.PickValueInArray<uint16_t>(
                {PHOTOMETRIC_RGB, PHOTOMETRIC_SEPARATED, PHOTOMETRIC_YCBCR});

  TIFFSetField(tif, TIFFTAG_IMAGEWIDTH, width);
  TIFFSetField(tif, TIFFTAG_IMAGELENGTH, height);
  TIFFSetField(tif, TIFFTAG_BITSPERSAMPLE, bps);
  TIFFSetField(tif, TIFFTAG_PLANARCONFIG, planarconfig);
  TIFFSetField(tif, TIFFTAG_COMPRESSION, compression);
  TIFFSetField(tif, TIFFTAG_ROWSPERSTRIP, height);

  /*
   * ANALYSIS: The function-level coverage report showed that
   *           TIFFWriteDirectoryTagSampleformatArray has 0% coverage. This
   *           function handles writing an array of sample formats, which is
   *           necessary when SamplesPerPixel > 1.
   * IMPLEMENTATION: When spp > 1, create an array of sample formats and
   *                 pass it to TIFFSetField to exercise the array-writing logic.
   */
  uint16_t sampleformat = fdp.PickValueInArray<uint16_t>(
      {SAMPLEFORMAT_UINT, SAMPLEFORMAT_INT, SAMPLEFORMAT_IEEEFP});
  if (spp > 1) {
    std::vector<uint16_t> sampleformats(spp, sampleformat);
    TIFFSetField(tif, TIFFTAG_SAMPLEFORMAT, sampleformats.data());
  } else {
    TIFFSetField(tif, TIFFTAG_SAMPLEFORMAT, sampleformat);
  }

  /*
   * ANALYSIS: The function-level coverage report showed that TIFFPrintDirectory
   *           has low coverage, and its helper functions like _TIFFprintAsciiTag
   *           have 0% coverage. This is because no ASCII tags were being set.
   * IMPLEMENTATION: Set the TIFFTAG_ARTIST tag with a fuzzed string. This
   *                 will be printed by TIFFPrintDirectory, exercising the
   *                 ASCII-printing code paths.
   */
  std::string artist = fdp.ConsumeRandomLengthString(100);
  TIFFSetField(tif, TIFFTAG_ARTIST, artist.c_str());

  if (compression == COMPRESSION_OJPEG) {
    /*
     * ANALYSIS: The OJPEG codec requires specific tags and photometric settings
     *           to function correctly. The OJPEG-related functions in
     *           tif_ojpeg.c had 0% coverage.
     * IMPLEMENTATION: When COMPRESSION_OJPEG is selected, force the required
     *                 settings (spp=3, photometric=YCBCR) and set OJPEG-specific
     *                 tags to trigger the encoding and writing logic for this codec.
     */
    spp = 3;
    photometric = PHOTOMETRIC_YCBCR;
    TIFFSetField(tif, TIFFTAG_JPEGPROC, JPEGPROC_BASELINE);
    TIFFSetField(tif, TIFFTAG_YCBCRSUBSAMPLING, (uint16_t)2, (uint16_t)2);
  }

  TIFFSetField(tif, TIFFTAG_SAMPLESPERPIXEL, spp);
  TIFFSetField(tif, TIFFTAG_PHOTOMETRIC, photometric);

  if (compression == COMPRESSION_CCITTFAX3 ||
      compression == COMPRESSION_CCITTFAX4) {
    TIFFSetField(tif, TIFFTAG_GROUP3OPTIONS,
                 fdp.ConsumeIntegral<uint32_t>());
    TIFFSetField(tif, TIFFTAG_CLEANFAXDATA,
                 fdp.ConsumeIntegralInRange<uint16_t>(0, 2));
    TIFFSetField(tif, TIFFTAG_BADFAXLINES, fdp.ConsumeIntegral<uint32_t>());
  }

  if (photometric == PHOTOMETRIC_SEPARATED) {
    TIFFSetField(tif, TIFFTAG_INKSET, INKSET_CMYK);
  }
  
  // BLOCKER-ORIENTED ADDITION:
  // Create and set an 8-byte tag (TIFF_DOUBLE) to prepare for the rewrite.
  // The value is derived from already-consumed data to preserve the input contract.
  double stonits_val = (double)width / (double)height;
  TIFFSetField(tif, TIFFTAG_STONITS, stonits_val);

  // Write a single scanline of dummy data.
  if (TIFFScanlineSize(tif) > 0) {
    std::vector<uint8_t> scanline(TIFFScanlineSize(tif));
    if (TIFFWriteScanline(tif, scanline.data(), 0, 0) < 0) {
      TIFFClose(tif);
      unlink(filename);
      return 0;
    }
  }

  TIFFWriteDirectory(tif);
  uint64_t subifd_offset = 0;
  TIFFSetField(tif, TIFFTAG_SUBIFD, 1, &subifd_offset);
  TIFFWriteDirectory(tif); // This writes the SubIFD

  TIFFClose(tif);

  // Re-open the TIFF for reading and print the directory.
  tif = TIFFOpen(filename, "r");
  if (tif) {
    FILE *devnull = fopen("/dev/null", "w");
    if (devnull) {
      TIFFPrintDirectory(tif, devnull, 0);
      fclose(devnull);
    }

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
    uint32_t new_width = fdp.ConsumeIntegralInRange<uint32_t>(1, 512);
    _TIFFRewriteField(tif, TIFFTAG_IMAGEWIDTH, TIFF_LONG, 1, &new_width);

    /*
     * ANALYSIS: The function _TIFFRewriteField has low coverage (30%). The
     *           existing fuzzer only rewrites the IMAGEWIDTH tag.
     * IMPLEMENTATION: Add a rewrite for an ASCII tag (TIFFTAG_ARTIST) to
     *                 exercise the string-handling code paths within
     *                 _TIFFRewriteField.
     */
    std::string new_artist = fdp.ConsumeRandomLengthString(100);
    if (!new_artist.empty()) {
      _TIFFRewriteField(tif, TIFFTAG_ARTIST, TIFF_ASCII,
                        new_artist.length() + 1, (void*)new_artist.c_str());
    }

    // BLOCKER-ORIENTED ADDITION:
    // Rewrite the 8-byte tag using a TIFF_DOUBLE data type. This will cause
    // TIFFDataWidth(datatype) to return 8, hitting the desired code path.
    // The value is derived from already-consumed data to preserve the input contract.
    double new_stonits_val = (double)new_width;
    _TIFFRewriteField(tif, TIFFTAG_STONITS, TIFF_DOUBLE, 1, &new_stonits_val);

    TIFFClose(tif);
  }

  // Clean up the temporary file.
  unlink(filename);

  return 0;
}
