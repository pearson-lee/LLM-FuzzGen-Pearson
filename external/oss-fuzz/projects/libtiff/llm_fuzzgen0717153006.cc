#include "tiffio.h"
#include <fuzzer/FuzzedDataProvider.h>
#include <string>
#include <vector>
#include <unistd.h>
#include <cstdint>

// Forward declaration for the non-public function we are targeting.
extern "C" int _TIFFRewriteField(TIFF *, uint16_t, TIFFDataType, uint64_t, void *);

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  if (size < 100) {
    return 0;
  }
  FuzzedDataProvider fdp(data, size);

  std::string filename = std::string("/tmp/") + _FUZZ_TARGET_NAME + ".tiff";
  
  // Randomly choose between classic and BigTIFF format.
  const char* mode = fdp.ConsumeBool() ? "w" : "w8";
  TIFF *tif = TIFFOpen(filename.c_str(), mode);
  if (!tif) {
    return 0;
  }

  /*
   * ANALYSIS: The function-level coverage report showed _TIFFVSetField has many
   *           uncovered branches. The line-level report confirmed this was due to
   *           many tags not being set, or set with very specific values.
   * IMPLEMENTATION: The following code block sets a wide variety of tags with
   *                 fuzzed data to exercise these uncovered paths.
   */
  uint32_t width = fdp.ConsumeIntegralInRange<uint32_t>(1, 512);
  uint32_t height = fdp.ConsumeIntegralInRange<uint32_t>(1, 512);
  TIFFSetField(tif, TIFFTAG_IMAGEWIDTH, width);
  TIFFSetField(tif, TIFFTAG_IMAGELENGTH, height);
  TIFFSetField(tif, TIFFTAG_BITSPERSAMPLE, fdp.PickValueInArray<uint16_t>({8, 16, 32}));
  TIFFSetField(tif, TIFFTAG_SAMPLESPERPIXEL, fdp.ConsumeIntegralInRange<uint16_t>(1, 4));
  TIFFSetField(tif, TIFFTAG_PLANARCONFIG, fdp.PickValueInArray<uint16_t>({PLANARCONFIG_CONTIG, PLANARCONFIG_SEPARATE}));
  TIFFSetField(tif, TIFFTAG_PHOTOMETRIC, fdp.ConsumeIntegralInRange<uint16_t>(0, 10));
  TIFFSetField(tif, TIFFTAG_COMPRESSION, fdp.ConsumeIntegralInRange<uint16_t>(1, 8)); // Avoid COMPRESSION_NONE to exercise codec paths
  TIFFSetField(tif, TIFFTAG_ORIENTATION, fdp.ConsumeIntegralInRange<uint16_t>(1, 8));
  TIFFSetField(tif, TIFFTAG_ROWSPERSTRIP, fdp.ConsumeIntegralInRange<uint32_t>(1, height));

  // Write dummy image data.
  tsize_t scanline_size = TIFFScanlineSize(tif);
  if (scanline_size > 0 && scanline_size < 1024*1024) {
    uint8_t* scanline = new uint8_t[scanline_size];
    if (fdp.ConsumeData(scanline, scanline_size) == scanline_size) {
        for (uint32_t i = 0; i < height; i++) {
            if (TIFFWriteScanline(tif, scanline, i, 0) < 0) {
                break;
            }
        }
    }
    delete[] scanline;
  }

  // This will call TIFFWriteDirectorySec.
  if (TIFFWriteDirectory(tif) != 1) {
      TIFFClose(tif);
      unlink(filename.c_str());
      return 0;
  }

  /*
   * ANALYSIS: The function-level coverage report showed _TIFFRewriteField has
   *           very low coverage (37.09%). The line-level report showed that most
   *           of the function's logic for handling different data types and counts
   *           was not being exercised.
   * IMPLEMENTATION: The following code block attempts to rewrite a field that
   *                 has already been written to disk. It uses fuzzed data to
   *                 select the tag, data type, and value to better explore the
   *                 different paths in _TIFFRewriteField.
   */
  uint16_t tag_to_rewrite = fdp.PickValueInArray<uint16_t>({
      TIFFTAG_IMAGEWIDTH, TIFFTAG_IMAGELENGTH, TIFFTAG_ORIENTATION,
      TIFFTAG_RESOLUTIONUNIT, TIFFTAG_XRESOLUTION, TIFFTAG_ARTIST
  });

  switch(tag_to_rewrite) {
    case TIFFTAG_IMAGEWIDTH:
    case TIFFTAG_IMAGELENGTH: {
      uint32_t val = fdp.ConsumeIntegral<uint32_t>();
      _TIFFRewriteField(tif, tag_to_rewrite, TIFF_LONG, 1, &val);
      break;
    }
    case TIFFTAG_ORIENTATION:
    case TIFFTAG_RESOLUTIONUNIT: {
      uint16_t val = fdp.ConsumeIntegral<uint16_t>();
      _TIFFRewriteField(tif, tag_to_rewrite, TIFF_SHORT, 1, &val);
      break;
    }
    case TIFFTAG_XRESOLUTION: {
      float val = fdp.ConsumeFloatingPoint<float>();
      _TIFFRewriteField(tif, tag_to_rewrite, TIFF_RATIONAL, 1, &val);
      break;
    }
    case TIFFTAG_ARTIST: {
      std::string s = fdp.ConsumeRandomLengthString(100);
      if (!s.empty()) {
        _TIFFRewriteField(tif, tag_to_rewrite, TIFF_ASCII, s.length() + 1, (void*)s.c_str());
      }
      break;
    }
  }

  // Create a second directory to further exercise directory writing logic.
  TIFFSetField(tif, TIFFTAG_IMAGEWIDTH, fdp.ConsumeIntegralInRange<uint32_t>(1, 512));
  TIFFSetField(tif, TIFFTAG_IMAGELENGTH, fdp.ConsumeIntegralInRange<uint32_t>(1, 512));
  TIFFSetField(tif, TIFFTAG_SUBFILETYPE, FILETYPE_PAGE);
  TIFFWriteDirectory(tif);


  TIFFClose(tif);
  unlink(filename.c_str());

  return 0;
}