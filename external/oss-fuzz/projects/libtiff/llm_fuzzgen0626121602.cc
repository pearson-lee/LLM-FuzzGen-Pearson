#include <cstdint>
#include <cstdlib>
#include <iostream>
#include <memory>
#include <sstream>
#include <string>
#include <vector>

#include <fuzzer/FuzzedDataProvider.h>

#include "libtiff/libtiff/tiffio.h"
#include "libtiff/libtiff/tiffio.hxx"

struct TIFFCloser {
  void operator()(TIFF *tif) const {
    if (tif) {
      TIFFClose(tif);
    }
  }
};

using TiffUniquePtr = std::unique_ptr<TIFF, TIFFCloser>;

void SetRandomFields(TIFF *tif, FuzzedDataProvider &fdp) {
  TIFFSetField(tif, TIFFTAG_IMAGEWIDTH, fdp.ConsumeIntegralInRange<uint32_t>(1, 512));
  TIFFSetField(tif, TIFFTAG_IMAGELENGTH, fdp.ConsumeIntegralInRange<uint32_t>(1, 512));
  TIFFSetField(tif, TIFFTAG_BITSPERSAMPLE, fdp.PickValueInArray<uint16_t>({1, 2, 4, 8, 16}));
  TIFFSetField(tif, TIFFTAG_SAMPLESPERPIXEL, fdp.PickValueInArray<uint16_t>({1, 3, 4}));
  TIFFSetField(tif, TIFFTAG_PLANARCONFIG, fdp.PickValueInArray<uint16_t>({PLANARCONFIG_CONTIG, PLANARCONFIG_SEPARATE}));
  TIFFSetField(tif, TIFFTAG_COMPRESSION, COMPRESSION_NONE);
  TIFFSetField(tif, TIFFTAG_PHOTOMETRIC, PHOTOMETRIC_RGB);

  uint8_t field_choice = fdp.ConsumeIntegral<uint8_t>();

  switch (field_choice % 5) {
  case 0: {
    std::string artist = fdp.ConsumeRandomLengthString(100);
    TIFFSetField(tif, TIFFTAG_ARTIST, artist.c_str());
    break;
  }
  case 1:
    TIFFSetField(tif, TIFFTAG_SUBFILETYPE, fdp.ConsumeIntegral<uint32_t>());
    break;
  case 2:
    TIFFSetField(tif, TIFFTAG_INKSET, fdp.ConsumeIntegral<uint16_t>());
    break;
  case 3: {
    float xy[2];
    xy[0] = fdp.ConsumeFloatingPoint<float>();
    xy[1] = fdp.ConsumeFloatingPoint<float>();
    TIFFSetField(tif, TIFFTAG_XPOSITION, xy[0]);
    TIFFSetField(tif, TIFFTAG_YPOSITION, xy[1]);
    break;
  }
  case 4: {
    uint16_t bits_per_sample = 0;
    uint16_t samples_per_pixel = 0;
    TIFFGetField(tif, TIFFTAG_BITSPERSAMPLE, &bits_per_sample);
    TIFFGetField(tif, TIFFTAG_SAMPLESPERPIXEL, &samples_per_pixel);

    if (samples_per_pixel == 1) {
      if (bits_per_sample > 0 && bits_per_sample <= 12) {
        const size_t num_elements = 1 << bits_per_sample;
        std::vector<uint16_t> transfer_function;
        transfer_function.reserve(num_elements);
        for (size_t i = 0; i < num_elements; ++i) {
          if (fdp.remaining_bytes() < sizeof(uint16_t)) {
            transfer_function.clear();
            break;
          }
          transfer_function.push_back(fdp.ConsumeIntegral<uint16_t>());
        }

        if (!transfer_function.empty()) {
          TIFFSetField(tif, TIFFTAG_TRANSFERFUNCTION, transfer_function.data());
        }
      }
    }
    break;
  }
  }
}

void SilentErrorHandler(const char *, const char *, va_list) {}

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  if (size == 0) {
    return 0;
  }
  FuzzedDataProvider fdp(data, size);
  TIFFSetErrorHandler(SilentErrorHandler);

  std::stringstream tiff_stream;

  TiffUniquePtr tif(TIFFStreamOpen("fuzz_tiff", static_cast<std::ostream *>(&tiff_stream)));
  if (!tif) {
    return 0;
  }

  SetRandomFields(tif.get(), fdp);

  std::vector<uint8_t> scanline_buf;
  tmsize_t scanline_size = TIFFScanlineSize(tif.get());
  if (scanline_size > 0) {
    scanline_buf = fdp.ConsumeBytes<uint8_t>(scanline_size);
    if (scanline_buf.size() == scanline_size) {
      uint32_t image_length = 0;
      TIFFGetField(tif.get(), TIFFTAG_IMAGELENGTH, &image_length);
      for (uint32_t row = 0; row < image_length; ++row) {
        if (TIFFWriteScanline(tif.get(), scanline_buf.data(), row, 0) < 0) {
          break;
        }
      }
    }
  }

  if (TIFFWriteDirectory(tif.get()) != 1) {
  } else {
    SetRandomFields(tif.get(), fdp);
    TIFFWriteDirectory(tif.get());
  }

  tif.reset();

  tiff_stream.seekg(0);

  TiffUniquePtr tif_read(TIFFStreamOpen("fuzz_tiff_read", static_cast<std::istream *>(&tiff_stream)));
  if (!tif_read) {
    return 0;
  }

  do {
    uint32_t w = 0, h = 0;
    char emsg[1024] = {0};

    if (TIFFRGBAImageOK(tif_read.get(), emsg)) {
      TIFFGetField(tif_read.get(), TIFFTAG_IMAGEWIDTH, &w);
      TIFFGetField(tif_read.get(), TIFFTAG_IMAGELENGTH, &h);
      if (w > 0 && h > 0) {
        // Prevent excessive memory allocation from fuzzer-generated dimensions.
        if ((uint64_t)w * h > 4000000) { // Cap at ~16MB
          return 0;
        }
        // Allocate a buffer for the entire image. This is required for
        // TIFFReadRGBAImage.
        std::vector<uint32_t> raster((size_t)w * h);
        // Read the entire image using the high-level API. This is safer than
        // reading strip-by-strip as it handles buffer size calculation correctly.
        TIFFReadRGBAImage(tif_read.get(), w, h, raster.data(), 0);
      }
    }
  } while (TIFFReadDirectory(tif_read.get()));

  return 0;
}