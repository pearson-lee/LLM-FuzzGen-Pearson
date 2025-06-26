#include <cstddef>
#include <cstdint>
#include <string>
#include <vector>
#include <fuzzer/FuzzedDataProvider.h>
#include "/src/libtiff/libtiff/tiffio.h"
#include "/src/libtiff/libtiff/tiffiop.h" // For _TIFFmalloc and _TIFFfree
#include "/src/libtiff/libtiff/tif_dir.h" // For TIFFFieldInfo and FIELD_CUSTOM
#include <unistd.h>

// The fuzzer creates a temporary file for writing and reading.
// Using a fixed name is simple but not safe for parallel execution.
const char* kTempTiffFile = "/tmp/libtiff_fuzzer.tif";

// Define a custom tag and field array to test custom directory handling.
#define MY_CUSTOM_TAG 65535
static TIFFFieldInfo my_fields[] = {
    { MY_CUSTOM_TAG, 1, 1, TIFF_LONG, FIELD_CUSTOM, 1, 0, "MyCustomTag" },
};

// Tag extender callback to register our custom fields.
static void ExtenderCallback(TIFF* tif) {
    TIFFMergeFieldInfo(tif, my_fields, sizeof(my_fields) / sizeof(my_fields[0]));
}

// Fuzz target entry point.
extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  FuzzedDataProvider fdp(data, size);

  // Set the tag extender before any TIFF operations.
  TIFFSetTagExtender(ExtenderCallback);

  // Consume basic image parameters. Keep them small to avoid timeouts.
  const uint32_t width = fdp.ConsumeIntegralInRange<uint32_t>(1, 512);
  const uint32_t height = fdp.ConsumeIntegralInRange<uint32_t>(1, 512);
  const uint16_t bits_per_sample = fdp.PickValueInArray<uint16_t>({1, 2, 4, 8, 16});
  const uint16_t samples_per_pixel = fdp.PickValueInArray<uint16_t>({1, 3, 4});
  // Added more compression types to explore different codecs like ThunderScan, LogLuv, Fax, and NeXT.
  const uint16_t compression = fdp.PickValueInArray<uint16_t>({
      COMPRESSION_NONE, COMPRESSION_PACKBITS, COMPRESSION_LZW,
      COMPRESSION_THUNDERSCAN, COMPRESSION_SGILOG, COMPRESSION_CCITTFAX3,
      COMPRESSION_NEXT // Added to improve coverage in tif_next.c
  });
  // Allow different photometric interpretations needed by some compression schemes.
  const uint16_t photometric = fdp.PickValueInArray<uint16_t>({
      PHOTOMETRIC_MINISBLACK, PHOTOMETRIC_MINISWHITE, PHOTOMETRIC_RGB,
      PHOTOMETRIC_PALETTE, PHOTOMETRIC_LOGL, PHOTOMETRIC_LOGLUV
  });


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
  TIFFSetField(tif_w, TIFFTAG_PHOTOMETRIC, photometric);
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
  if (fdp.ConsumeBool()) {
      TIFFSetField(tif_w, TIFFTAG_XRESOLUTION, fdp.ConsumeFloatingPointInRange<float>(1.0, 600.0));
      TIFFSetField(tif_w, TIFFTAG_YRESOLUTION, fdp.ConsumeFloatingPointInRange<float>(1.0, 600.0));
      TIFFSetField(tif_w, TIFFTAG_RESOLUTIONUNIT, fdp.ConsumeIntegralInRange<uint16_t>(1, 3));
  }
  if (fdp.ConsumeBool()) {
      std::string software = fdp.ConsumeRandomLengthString(30);
      TIFFSetField(tif_w, TIFFTAG_SOFTWARE, software.c_str());
  }

  // Set and then unset a custom field to improve coverage in the custom field handling path of TIFFUnsetField.
  if (fdp.ConsumeBool()) {
    TIFFMergeFieldInfo(tif_w, my_fields, 1);
    uint32_t my_custom_data = fdp.ConsumeIntegral<uint32_t>();
    TIFFSetField(tif_w, MY_CUSTOM_TAG, my_custom_data);
    TIFFUnsetField(tif_w, MY_CUSTOM_TAG);
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

  // Write the main directory. A custom directory will be written after this.
  TIFFWriteDirectory(tif_w);

  // Write a custom directory to improve coverage in TIFFReadCustomDirectory, which is currently at 0%.
  uint64_t custom_dir_offset = 0;
  if (fdp.ConsumeBool()) {
      TIFFMergeFieldInfo(tif_w, my_fields, 1);
      uint32_t my_custom_data = fdp.ConsumeIntegral<uint32_t>();
      TIFFSetField(tif_w, MY_CUSTOM_TAG, my_custom_data);
      TIFFWriteCustomDirectory(tif_w, &custom_dir_offset);
  }

  // Finalize and close the written file.
  TIFFClose(tif_w);

  // Re-open the file for reading to test read-path functions.
  TIFF *tif_r = TIFFOpen(kTempTiffFile, "r");
  if (tif_r) {
    if (is_tiled) {
      // Target TIFFReadEncodedTile to exercise decoders, which are missed by TIFFReadRawTile.
      uint32_t num_tiles = TIFFNumberOfTiles(tif_r);
      if (num_tiles > 0) {
        uint32_t tile_to_read = fdp.ConsumeIntegralInRange<uint32_t>(0, num_tiles - 1);
        tmsize_t tile_buf_size = TIFFTileSize(tif_r);
        if (tile_buf_size > 0) {
          std::vector<uint8_t> tile_buf(tile_buf_size);
          TIFFReadEncodedTile(tif_r, tile_to_read, tile_buf.data(), -1);
        }
      }
    } else {
      // Target TIFFReadEncodedStrip to exercise decoders, which are missed by TIFFReadRawStrip.
      uint32_t num_strips = TIFFNumberOfStrips(tif_r);
      if (num_strips > 0) {
        uint32_t strip_to_read = fdp.ConsumeIntegralInRange<uint32_t>(0, num_strips - 1);
        tmsize_t strip_buf_size = TIFFStripSize(tif_r);
        if (strip_buf_size > 0 && strip_buf_size != (tmsize_t)-1) {
          std::vector<uint8_t> strip_buf(strip_buf_size);
          TIFFReadEncodedStrip(tif_r, strip_to_read, strip_buf.data(), -1);
        }
      }
    }
    
    // If a custom directory was written, try to read it to cover TIFFReadCustomDirectory.
    if (custom_dir_offset > 0) {
        TIFFSetSubDirectory(tif_r, custom_dir_offset);
    }

    // Target TIFFPrintDirectory, which has low coverage.
    // Printing to stdout is acceptable as fuzzer output is discarded.
    TIFFPrintDirectory(tif_r, stdout, 0);

    // Added calls to the TIFFRGBAImage interface to improve coverage in tif_getimage.c.
    uint32_t img_width, img_height;
    TIFFGetField(tif_r, TIFFTAG_IMAGEWIDTH, &img_width);
    TIFFGetField(tif_r, TIFFTAG_IMAGELENGTH, &img_height);
    
    TIFFRGBAImage img;
    char emsg[1024] = {0};
    if (TIFFRGBAImageOK(tif_r, emsg)) {
        if (TIFFRGBAImageBegin(&img, tif_r, 0, emsg)) {
            size_t npixels = img_width * img_height;
            if (npixels > 0) {
                // This allocation is memory-safe because raster is always freed by _TIFFfree.
                uint32_t* raster = (uint32_t*)_TIFFmalloc(npixels * sizeof(uint32_t));
                if (raster) {
                    TIFFReadRGBAImage(tif_r, img_width, img_height, raster, 0);
                    _TIFFfree(raster);
                }
            }
            TIFFRGBAImageEnd(&img);
        }
    }

    TIFFClose(tif_r);
  }

  // Clean up the temporary file.
  unlink(kTempTiffFile);

  return 0;
}