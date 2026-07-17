#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <string>
#include <vector>
#include <unistd.h>
#include <cstring>

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
   * ANALYSIS: The original fuzz target often failed to create a valid directory
   *           structure from raw fuzzer data. This prevented TIFFWriteDirectory from
   *           succeeding, which in turn meant TIFFSetDirectory was never called. It also
   *           caused width/height to be invalid, preventing TIFFReadRGBAImage from being called.
   * IMPLEMENTATION: Set fundamental TIFF tags like width, height, samples, etc.,
   *                 using fuzzer-derived values. This creates a valid baseline
   *                 directory, ensuring that subsequent API calls that depend on a valid
   *                 directory structure can be properly exercised.
   */
  /*
   * ANALYSIS: The function Fax3PrintDir had 0% coverage. This is called by
   *           TIFFPrintDirectory for FAX compressions.
   * IMPLEMENTATION: Add COMPRESSION_CCITTFAX3 and COMPRESSION_CCITTFAX4 to the
   *                 list of possible compressions to enable coverage of
   *                 fax-specific code paths.
   */
  uint16_t compression = fdp.PickValueInArray({COMPRESSION_NONE, COMPRESSION_LZW, COMPRESSION_PACKBITS, COMPRESSION_DEFLATE, COMPRESSION_CCITTFAX3, COMPRESSION_CCITTFAX4});
  uint16_t samples = fdp.ConsumeIntegralInRange<uint16_t>(1, 5);
  uint32_t width = fdp.ConsumeIntegralInRange<uint32_t>(1, 512);
  uint32_t height = fdp.ConsumeIntegralInRange<uint32_t>(1, 512);
  TIFFSetField(tif, TIFFTAG_IMAGEWIDTH, width);
  TIFFSetField(tif, TIFFTAG_IMAGELENGTH, height);
  TIFFSetField(tif, TIFFTAG_BITSPERSAMPLE, 8);
  TIFFSetField(tif, TIFFTAG_SAMPLESPERPIXEL, samples);
  TIFFSetField(tif, TIFFTAG_PLANARCONFIG, PLANARCONFIG_CONTIG);
  TIFFSetField(tif, TIFFTAG_COMPRESSION, compression);
  if (samples > 2) {
      TIFFSetField(tif, TIFFTAG_PHOTOMETRIC, PHOTOMETRIC_RGB);
  } else {
      TIFFSetField(tif, TIFFTAG_PHOTOMETRIC, PHOTOMETRIC_MINISBLACK);
  }

  /*
   * ANALYSIS: Coverage for tif_write.c and tif_tile.c is low or zero,
   *           specifically for TIFFWriteTile (0%).
   * IMPLEMENTATION: Add a path to create tiled TIFFs by setting tile
   *                 dimensions. Then, write a tile or scanline to make the
   *                 directory valid, which also exercises TIFFWriteTile or
   *                 TIFFWriteScanline and enables subsequent calls to
   *                 TIFFWriteDirectory to succeed.
   */
  if (fdp.ConsumeBool()) {
    TIFFSetField(tif, TIFFTAG_TILEWIDTH, fdp.ConsumeIntegralInRange<uint32_t>(16, 256));
    TIFFSetField(tif, TIFFTAG_TILELENGTH, fdp.ConsumeIntegralInRange<uint32_t>(16, 256));
  }
  if (TIFFIsTiled(tif)) {
    tsize_t tile_size = TIFFTileSize(tif);
    if (tile_size > 0 && tile_size < 500000) {
      char* buf = (char*)_TIFFmalloc(tile_size);
      if (buf) {
        if (fdp.ConsumeData(buf, tile_size) == tile_size) {
          TIFFWriteTile(tif, buf, 0, 0, 0, 0);
        }
        _TIFFfree(buf);
      }
    }
  } else {
    tsize_t scanline_size = TIFFScanlineSize(tif);
    if (scanline_size > 0 && scanline_size < 500000) {
      char* buf = (char*)_TIFFmalloc(scanline_size);
      if (buf) {
        if (fdp.ConsumeData(buf, scanline_size) > 0) {
          TIFFWriteScanline(tif, buf, 0, 0);
        }
        _TIFFfree(buf);
      }
    }
  }

  /*
   * ANALYSIS: The function-level coverage report shows 0% coverage for
   *           TIFFReadCustomDirectory, TIFFReadEXIFDirectory, and TIFFReadGPSDirectory.
   * IMPLEMENTATION: Add direct calls to these functions with a fuzzer-provided
   *                 offset to ensure they are executed.
   */
  if (fdp.ConsumeBool()) {
    uint64_t offset = fdp.ConsumeIntegral<uint64_t>();
    TIFFReadCustomDirectory(tif, offset, nullptr);
    TIFFReadEXIFDirectory(tif, offset);
    TIFFReadGPSDirectory(tif, offset);
  }

  /*
   * ANALYSIS: The function TIFFSetDirectory had low coverage because TIFFWriteDirectory
   *           was failing on the malformed initial directory.
   * IMPLEMENTATION: After setting basic fields and writing a scanline/tile to create a
   *                 valid directory, call TIFFWriteDirectory() to create a second directory.
   *                 This ensures TIFFNumberOfDirectories() will be greater than 1, allowing
   *                 the subsequent call to TIFFSetDirectory to be exercised.
   */
  TIFFWriteDirectory(tif);
  int dir_count = TIFFNumberOfDirectories(tif);
  if (dir_count > 1) {
    tdir_t dir_to_set = fdp.ConsumeIntegralInRange<tdir_t>(0, dir_count - 1);
    TIFFSetDirectory(tif, dir_to_set);
  }

  /*
   * ANALYSIS: The call to TIFFReadRGBAImage was previously not being reached because
   *           the image dimensions read from the fuzzer-generated file were rarely
   *           within the valid range.
   * IMPLEMENTATION: By setting TIFFTAG_IMAGEWIDTH and TIFFTAG_IMAGELENGTH to sane
   *                 values earlier, we ensure the dimensions are valid. This allows the
   *                 existing logic to proceed, calling TIFFReadRGBAImage and exercising
   *                 the image reading paths in tif_getimage.c.
   */
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