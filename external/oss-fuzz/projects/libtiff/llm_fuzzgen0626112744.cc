#include <cstdint>
#include <cstdlib>
#include <iostream>
#include <memory>
#include <sstream>
#include <string>
#include <vector>

#include <fuzzer/FuzzedDataProvider.h>

// Include libtiff headers
#include "libtiff/libtiff/tiffio.h"
#include "libtiff/libtiff/tiffio.hxx"

// Custom deleter for the TIFF handle to ensure TIFFClose is always called.
struct TIFFCloser {
  void operator()(TIFF *tif) const {
    if (tif) {
      TIFFClose(tif);
    }
  }
};

using TiffUniquePtr = std::unique_ptr<TIFF, TIFFCloser>;

// A helper function to set a variety of TIFF fields based on fuzzer input.
// This is crucial for improving coverage in tif_dirwrite.c, which has many
// branches for handling different tag types.
void SetRandomFields(TIFF *tif, FuzzedDataProvider &fdp) {
  // Set mandatory fields for a baseline valid TIFF
  TIFFSetField(tif, TIFFTAG_IMAGEWIDTH, fdp.ConsumeIntegralInRange<uint32_t>(1, 512));
  TIFFSetField(tif, TIFFTAG_IMAGELENGTH, fdp.ConsumeIntegralInRange<uint32_t>(1, 512));
  TIFFSetField(tif, TIFFTAG_BITSPERSAMPLE, fdp.PickValueInArray<uint16_t>({1, 2, 4, 8, 16}));
  TIFFSetField(tif, TIFFTAG_SAMPLESPERPIXEL, fdp.PickValueInArray<uint16_t>({1, 3, 4}));
  TIFFSetField(tif, TIFFTAG_PLANARCONFIG, fdp.PickValueInArray<uint16_t>({PLANARCONFIG_CONTIG, PLANARCONFIG_SEPARATE}));
  TIFFSetField(tif, TIFFTAG_COMPRESSION, COMPRESSION_NONE);
  TIFFSetField(tif, TIFFTAG_PHOTOMETRIC, PHOTOMETRIC_RGB);

  // Consume a few bytes to pick optional fields to set
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

    // The TIFFTAG_TRANSFERFUNCTION API is tricky with multiple samples.
    // To avoid variadic argument mismatches, only test this tag when
    // samplesperpixel is 1.
    if (samples_per_pixel == 1) {
      // Cap bits_per_sample to prevent excessive memory allocation.
      if (bits_per_sample > 0 && bits_per_sample <= 12) {
        const size_t num_elements = 1 << bits_per_sample;
        std::vector<uint16_t> transfer_function;
        transfer_function.reserve(num_elements);
        for (size_t i = 0; i < num_elements; ++i) {
          if (fdp.remaining_bytes() < sizeof(uint16_t)) {
            transfer_function.clear(); // Not enough data.
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

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  if (size == 0) {
    return 0;
  }
  FuzzedDataProvider fdp(data, size);

  // Use a stringstream for in-memory fuzzing, avoiding file I/O.
  std::stringstream tiff_stream;

  // Open the TIFF stream for writing.
  // TiffUniquePtr ensures TIFFClose is called automatically.
  // The cast to std::ostream* is necessary to resolve the ambiguity between
  // TIFFStreamOpen(..., std::ostream*) and TIFFStreamOpen(..., std::istream*).
  TiffUniquePtr tif(TIFFStreamOpen("fuzz_tiff", static_cast<std::ostream *>(&tiff_stream)));
  if (!tif) {
    return 0;
  }

  // Set a variety of fields to exercise directory writing logic.
  SetRandomFields(tif.get(), fdp);

  // Write image data, which will exercise low-coverage functions in
  // tif_write.c like TIFFAppendToStrip and TIFFGrowStrips.
  tmsize_t scanline_size = TIFFScanlineSize(tif.get());
  if (scanline_size > 0) {
    std::vector<uint8_t> scanline_buf = fdp.ConsumeBytes<uint8_t>(scanline_size);
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

  // Write the first directory.
  if (TIFFWriteDirectory(tif.get()) != 1) {
    return 0;
  }

  // Set another field to make the directory "dirty".
  std::string software = fdp.ConsumeRandomLengthString(50);
  TIFFSetField(tif.get(), TIFFTAG_SOFTWARE, software.c_str());

  // Rewrite the directory. This is a key part of the fuzzer, as
  // TIFFRewriteDirectory and its helper _TIFFRewriteField have very low
  // coverage.
  if (TIFFRewriteDirectory(tif.get()) != 1) {
    // This may fail if the changes don't fit, which is a valid scenario.
  }

  // Create and switch to a new directory to test multi-directory handling.
  if (TIFFWriteDirectory(tif.get()) == 1) {
    // Switch back to the first directory to exercise TIFFSetDirectory
    TIFFSetDirectory(tif.get(), 0);
  }

  return 0;
}