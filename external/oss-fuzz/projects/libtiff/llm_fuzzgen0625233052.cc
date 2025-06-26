#include <cstddef>
#include <cstdint>
#include <string>
#include <vector>
#include <fuzzer/FuzzedDataProvider.h>
#include "tiffio.h"
#include <unistd.h>

// The fuzzer creates a temporary file for writing and reading.
// Using a fixed name is simple but not safe for parallel execution.
const char* kTempTiffFile = "/tmp/libtiff_fuzzer.tif";

// Fuzz target entry point.
extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  FuzzedDataProvider fdp(data, size);

  // Consume basic image parameters. Keep them small to avoid timeouts.
  const uint32_t width = fdp.ConsumeIntegralInRange<uint32_t>(1, 512);
  const uint32_t height = fdp.ConsumeIntegralInRange<uint32_t>(1, 512);
  const uint16_t bits_per_sample = fdp.PickValueInArray<uint16_t>({1, 2, 4, 8, 16});
  const uint16_t samples_per_pixel = fdp.PickValueInArray<uint16_t>({1, 3, 4});
  const uint16_t compression = fdp.PickValueInArray<uint16_t>({COMPRESSION_NONE, COMPRESSION_PACKBITS, COMPRESSION_LZW});

  // Open a TIFF file for writing.
  TIFF *tif_w = TIFFOpen(kTempTiffFile, "w");
  if (!tif_w) {
    return 0;
  }

  // Set mandatory TIFF fields.
  TIFFSetField(tif_w, TIFFTAG_IMAGEWIDTH, width);
  TIFFSetField(tif_w, TIFFTAG_IMAGELENGTH, height);
  TIFFSetField(tif_w, TIFFTAG_BITSPERSAMPLE, bits_per_sample);
  TIFFSetField(tif_w, TIFFTAG_SAMPLESPERPIXEL, samples_per_pixel);
  TIFFSetField(tif_w, TIFFTAG_PLANARCONFIG, PLANARCONFIG_CONTIG);
  TIFFSetField(tif_w, TIFFTAG_PHOTOMETRIC, PHOTOMETRIC_MINISBLACK);
  TIFFSetField(tif_w, TIFFTAG_COMPRESSION, compression);

  // Set optional fields to improve coverage in TIFFPrintDirectory.
  if (fdp.ConsumeBool()) {
    std::string desc = fdp.ConsumeRandomLengthString(100);
    TIFFSetField(tif_w, TIFFTAG_IMAGEDESCRIPTION, desc.c_str());
  }
  if (fdp.ConsumeBool()) {
    std::string artist = fdp.ConsumeRandomLengthString(100);
    TIFFSetField(tif_w, TIFFTAG_ARTIST, artist.c_str());
  }

  bool is_tiled = fdp.ConsumeBool();
  if (is_tiled) {
    // Configure for tiled image. Tile dimensions must be a multiple of 16.
    uint32_t tile_width = fdp.ConsumeIntegralInRange<uint32_t>(1, 32) * 16;
    uint32_t tile_height = fdp.ConsumeIntegralInRange<uint32_t>(1, 32) * 16;
    TIFFSetField(tif_w, TIFFTAG_TILEWIDTH, tile_width);
    TIFFSetField(tif_w, TIFFTAG_TILELENGTH, tile_height);

    // Write data to tiles to exercise TIFFWriteTile.
    tmsize_t tile_size = TIFFTileSize(tif_w);
    if (tile_size > 0) {
      std::vector<uint8_t> tile_buf = fdp.ConsumeBytes<uint8_t>(tile_size);
      if (tile_buf.size() == tile_size) {
        for (uint32_t y = 0; y < height; y += tile_height) {
          for (uint32_t x = 0; x < width; x += tile_width) {
            TIFFWriteTile(tif_w, tile_buf.data(), x, y, 0, 0);
          }
        }
      }
    }
  } else {
    // Configure for striped image.
    uint32_t rows_per_strip = fdp.ConsumeIntegralInRange<uint32_t>(1, height);
    TIFFSetField(tif_w, TIFFTAG_ROWSPERSTRIP, rows_per_strip);

    // Write data to scanlines to exercise TIFFWriteScanline.
    tmsize_t scanline_size = TIFFScanlineSize(tif_w);
    if (scanline_size > 0) {
      std::vector<uint8_t> scanline_buf = fdp.ConsumeBytes<uint8_t>(scanline_size);
      if (scanline_buf.size() == scanline_size) {
        for (uint32_t row = 0; row < height; ++row) {
          TIFFWriteScanline(tif_w, scanline_buf.data(), row, 0);
        }
      }
    }
  }

  // Finalize and close the written file.
  TIFFClose(tif_w);

  // Re-open the file for reading to test read-path functions.
  TIFF *tif_r = TIFFOpen(kTempTiffFile, "r");
  if (tif_r) {
    if (is_tiled) {
      // Target TIFFReadRawTile, which has 0% coverage.
      uint32_t num_tiles = TIFFNumberOfTiles(tif_r);
      if (num_tiles > 0) {
        uint32_t tile_to_read = fdp.ConsumeIntegralInRange<uint32_t>(0, num_tiles - 1);
        tmsize_t tile_size = TIFFTileSize(tif_r);
        if (tile_size > 0) {
          std::vector<uint8_t> tile_buf(tile_size);
          TIFFReadRawTile(tif_r, tile_to_read, tile_buf.data(), tile_size);
        }
      }
    } else {
      // Target TIFFReadRawStrip, which has 0% coverage.
      uint32_t num_strips = TIFFNumberOfStrips(tif_r);
      if (num_strips > 0) {
        uint32_t strip_to_read = fdp.ConsumeIntegralInRange<uint32_t>(0, num_strips - 1);
        tmsize_t strip_size = TIFFRawStripSize(tif_r, strip_to_read);
        if (strip_size > 0 && strip_size != (tmsize_t)-1) {
          std::vector<uint8_t> strip_buf(strip_size);
          TIFFReadRawStrip(tif_r, strip_to_read, strip_buf.data(), strip_size);
        }
      }
    }

    // Target TIFFPrintDirectory, which has low coverage.
    // Printing to stdout is acceptable as fuzzer output is discarded.
    TIFFPrintDirectory(tif_r, stdout, 0);

    TIFFClose(tif_r);
  }

  // Clean up the temporary file.
  unlink(kTempTiffFile);

  return 0;
}