#include <cstddef>
#include <cstdint>
#include <string>
#include <vector>
#include <cstdio>
#include <unistd.h>
#include <fuzzer/FuzzedDataProvider.h>
#include "tiffio.h"

// Custom error handler to suppress error messages
static void SuppressErrorHandler(const char* module, const char* fmt, va_list ap) {
  (void)module;
  (void)fmt;
  (void)ap;
}

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* Data, size_t Size) {
  FuzzedDataProvider fdp(Data, Size);

  // Suppress error messages from libtiff
  TIFFSetErrorHandler(SuppressErrorHandler);
  TIFFSetWarningHandler(SuppressErrorHandler);

  std::string filename = "/tmp/fuzz-" + std::to_string(getpid()) + ".tif";
  TIFF* tif = TIFFOpen(filename.c_str(), "w");
  if (!tif) {
    return 0;
  }

  // Set essential TIFF tags
  uint32_t width = fdp.ConsumeIntegralInRange<uint32_t>(1, 512);
  uint32_t height = fdp.ConsumeIntegralInRange<uint32_t>(1, 512);
  uint16_t bits_per_sample = fdp.PickValueInArray<uint16_t>({1, 2, 4, 8, 16});
  uint16_t samples_per_pixel = fdp.ConsumeIntegralInRange<uint16_t>(1, 4);
  uint16_t planar_config = fdp.PickValueInArray<uint16_t>({PLANARCONFIG_CONTIG, PLANARCONFIG_SEPARATE});

  TIFFSetField(tif, TIFFTAG_IMAGEWIDTH, width);
  TIFFSetField(tif, TIFFTAG_IMAGELENGTH, height);
  TIFFSetField(tif, TIFFTAG_BITSPERSAMPLE, bits_per_sample);
  TIFFSetField(tif, TIFFTAG_SAMPLESPERPIXEL, samples_per_pixel);
  TIFFSetField(tif, TIFFTAG_PLANARCONFIG, planar_config);
  TIFFSetField(tif, TIFFTAG_COMPRESSION, COMPRESSION_NONE);
  TIFFSetField(tif, TIFFTAG_PHOTOMETRIC, PHOTOMETRIC_MINISBLACK);
  TIFFSetField(tif, TIFFTAG_ROWSPERSTRIP, height); // Single strip for simplicity

  // Allocate buffer for one scanline
  tmsize_t scanline_size = TIFFScanlineSize(tif);
  if (scanline_size <= 0) {
    TIFFClose(tif);
    remove(filename.c_str());
    return 0;
  }
  std::vector<uint8_t> scanline_buf(scanline_size);

  // Write scanlines
  for (uint32_t i = 0; i < height; ++i) {
    if (fdp.remaining_bytes() < scanline_size) {
      break;
    }
    fdp.ConsumeData(scanline_buf.data(), scanline_size);
    // Write scanlines, sometimes randomly to trigger non-sequential writes
    uint32_t row_to_write = fdp.ConsumeBool() ? i : fdp.ConsumeIntegralInRange<uint32_t>(0, height - 1);
    TIFFWriteScanline(tif, scanline_buf.data(), row_to_write, 0);
  }

  // Write a second directory
  TIFFWriteDirectory(tif);

  // Set fields for the second directory
  uint32_t width2 = width / 2 > 0 ? width / 2 : 1;
  uint32_t height2 = height / 2 > 0 ? height / 2 : 1;
  TIFFSetField(tif, TIFFTAG_IMAGEWIDTH, width2);
  TIFFSetField(tif, TIFFTAG_IMAGELENGTH, height2);
  TIFFSetField(tif, TIFFTAG_BITSPERSAMPLE, bits_per_sample);
  TIFFSetField(tif, TIFFTAG_SAMPLESPERPIXEL, samples_per_pixel);
  TIFFSetField(tif, TIFFTAG_PLANARCONFIG, planar_config);
  TIFFSetField(tif, TIFFTAG_COMPRESSION, COMPRESSION_NONE);
  TIFFSetField(tif, TIFFTAG_PHOTOMETRIC, PHOTOMETRIC_MINISBLACK);
  TIFFSetField(tif, TIFFTAG_ROWSPERSTRIP, height2);

  // Write some more scanlines to the second directory
  scanline_size = TIFFScanlineSize(tif);
  if (scanline_size > 0) {
    std::vector<uint8_t> scanline_buf2(scanline_size);
    for (uint32_t i = 0; i < height2; ++i) {
      if (fdp.remaining_bytes() < scanline_size) {
        break;
      }
      fdp.ConsumeData(scanline_buf2.data(), scanline_size);
      TIFFWriteScanline(tif, scanline_buf2.data(), i, 0);
    }
  }

  // Close the TIFF file
  TIFFClose(tif);

  // Now try to read the created TIFF file to fuzz the reading part
  tif = TIFFOpen(filename.c_str(), "r");
  if (tif) {
    do {
      uint32_t w, h;
      TIFFGetField(tif, TIFFTAG_IMAGEWIDTH, &w);
      TIFFGetField(tif, TIFFTAG_IMAGELENGTH, &h);
      if (w > 0 && h > 0) {
        uint32_t npixels = w * h;
        // Check for potential overflow before allocating
        if (npixels / w == h && npixels <= 1000000) {
          uint32_t* raster = (uint32_t*)_TIFFmalloc(npixels * sizeof(uint32_t));
          if (raster) {
            TIFFReadRGBAImage(tif, w, h, raster, 0);
            _TIFFfree(raster);
          }
        }
      }
    } while (TIFFReadDirectory(tif));
    TIFFClose(tif);
  }

  remove(filename.c_str());

  return 0;
}