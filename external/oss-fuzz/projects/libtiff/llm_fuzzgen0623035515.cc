#include <cstddef>
#include <cstdint>
#include <string>
#include <vector>
#include <fcntl.h>
#include <unistd.h>

#include "fuzzer/FuzzedDataProvider.h"
#include "tiffio.h"

// The fuzzer is designed to create a TIFF file with fuzzed parameters,
// write data to it using various libtiff APIs, and then read it back.
// This approach aims to cover both writing and reading paths in the library.
extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  FuzzedDataProvider fdp(data, size);

  // Create a temporary file to write the TIFF data to.
  const char *filename = "/tmp/fuzz.tif";
  int fd = open(filename, O_RDWR | O_CREAT | O_TRUNC, 0644);
  if (fd < 0) {
    return 0;
  }

  // Open the TIFF file for writing using the file descriptor.
  // This exercises the TIFFFdOpen API.
  TIFF *tif_write = TIFFFdOpen(fd, filename, "w");
  if (!tif_write) {
    close(fd);
    return 0;
  }

  // Define image parameters with fuzzed values.
  uint32_t width = fdp.ConsumeIntegralInRange<uint32_t>(1, 512);
  uint32_t height = fdp.ConsumeIntegralInRange<uint32_t>(1, 512);
  uint16_t bps = fdp.PickValueInArray<uint16_t>({1, 2, 4, 8, 16});
  uint16_t spp = fdp.PickValueInArray<uint16_t>({1, 3, 4});
  uint16_t planarconfig = fdp.PickValueInArray<uint16_t>(
      {PLANARCONFIG_CONTIG, PLANARCONFIG_SEPARATE});
  uint16_t compression = fdp.PickValueInArray<uint16_t>({
      COMPRESSION_NONE,
      COMPRESSION_LZW,
      COMPRESSION_PACKBITS,
  });
  uint16_t photometric =
      (spp == 1) ? PHOTOMETRIC_MINISBLACK
                 : (spp == 3 ? PHOTOMETRIC_RGB : PHOTOMETRIC_SEPARATED);

  // Set TIFF fields.
  TIFFSetField(tif_write, TIFFTAG_IMAGEWIDTH, width);
  TIFFSetField(tif_write, TIFFTAG_IMAGELENGTH, height);
  TIFFSetField(tif_write, TIFFTAG_BITSPERSAMPLE, bps);
  TIFFSetField(tif_write, TIFFTAG_SAMPLESPERPIXEL, spp);
  TIFFSetField(tif_write, TIFFTAG_PLANARCONFIG, planarconfig);
  TIFFSetField(tif_write, TIFFTAG_COMPRESSION, compression);
  TIFFSetField(tif_write, TIFFTAG_PHOTOMETRIC, photometric);
  TIFFSetField(tif_write, TIFFTAG_ROWSPERSTRIP,
               fdp.ConsumeIntegralInRange<uint32_t>(1, height));

  // Write data using different APIs to maximize coverage.
  if (fdp.ConsumeBool()) {
    // Exercise TIFFWriteEncodedStrip
    tmsize_t strip_size = TIFFStripSize(tif_write);
    if (strip_size > 0 && fdp.remaining_bytes() >= (size_t)strip_size) {
      std::vector<uint8_t> strip_data = fdp.ConsumeBytes<uint8_t>(strip_size);
      tstrip_t strip = fdp.ConsumeIntegralInRange<tstrip_t>(
          0, TIFFNumberOfStrips(tif_write) - 1);
      TIFFWriteEncodedStrip(tif_write, strip, strip_data.data(),
                            strip_data.size());
    }
  } else if (fdp.ConsumeBool()) {
    // Exercise TIFFWriteRawStrip
    tmsize_t strip_size = TIFFStripSize(tif_write);
    if (strip_size > 0 && fdp.remaining_bytes() >= (size_t)strip_size) {
      std::vector<uint8_t> raw_strip_data = fdp.ConsumeBytes<uint8_t>(strip_size);
      tstrip_t strip = fdp.ConsumeIntegralInRange<tstrip_t>(
          0, TIFFNumberOfStrips(tif_write) - 1);
      TIFFWriteRawStrip(tif_write, strip, raw_strip_data.data(),
                        raw_strip_data.size());
    }
  } else {
    // Exercise TIFFWriteTile
    TIFFSetField(tif_write, TIFFTAG_TILEWIDTH, 16);
    TIFFSetField(tif_write, TIFFTAG_TILELENGTH, 16);
    tmsize_t tile_size = TIFFTileSize(tif_write);
    if (tile_size > 0 && fdp.remaining_bytes() >= (size_t)tile_size) {
      std::vector<uint8_t> tile_data = fdp.ConsumeBytes<uint8_t>(tile_size);
      uint32_t x = fdp.ConsumeIntegralInRange<uint32_t>(0, width - 1);
      uint32_t y = fdp.ConsumeIntegralInRange<uint32_t>(0, height - 1);
      TIFFWriteTile(tif_write, tile_data.data(), x, y, 0, 0);
    }
  }

  // Close the TIFF handle, which flushes all written data.
  TIFFClose(tif_write);

  // Re-open the file for reading.
  int read_fd = open(filename, O_RDONLY);
  if (read_fd < 0) {
    unlink(filename);
    return 0;
  }

  TIFF *tif_read = TIFFFdOpen(read_fd, filename, "r");
  if (tif_read) {
    // Exercise TIFFReadRGBAImage
    uint32_t read_width, read_height;
    TIFFGetField(tif_read, TIFFTAG_IMAGEWIDTH, &read_width);
    TIFFGetField(tif_read, TIFFTAG_IMAGELENGTH, &read_height);
    if (read_width > 0 && read_height > 0) {
      uint32_t npixels = read_width * read_height;
      // Avoid excessive memory allocation.
      if (npixels < 1000000) {
        uint32_t *raster =
            (uint32_t *)_TIFFmalloc(npixels * sizeof(uint32_t));
        if (raster) {
          TIFFReadRGBAImage(tif_read, read_width, read_height, raster, 0);
          _TIFFfree(raster);
        }
      }
    }
    TIFFClose(tif_read);
  } else {
    close(read_fd);
  }

  // Clean up the temporary file.
  unlink(filename);

  return 0;
}