#include <cstdint>
#include <sstream>
#include <vector>

#include "fuzzer/FuzzedDataProvider.h"
#include "tiffio.h"
#include "tiffio.hxx"

// Entry point for the fuzzer
extern "C" int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size) {
  FuzzedDataProvider fdp(Data, Size);

  // Use a stringstream for in-memory TIFF writing.
  std::stringstream ostream;

  // Open the TIFF handle using the C++ stream interface.
  TIFF *tif = TIFFStreamOpen("fuzzer.tif", static_cast<std::ostream *>(&ostream));
  if (!tif) {
    return 0;
  }

  // Define basic image parameters, driven by the fuzzer.
  const uint32_t width = fdp.ConsumeIntegralInRange<uint32_t>(1, 512);
  const uint32_t height = fdp.ConsumeIntegralInRange<uint32_t>(1, 512);

  TIFFSetField(tif, TIFFTAG_IMAGEWIDTH, width);
  TIFFSetField(tif, TIFFTAG_IMAGELENGTH, height);
  TIFFSetField(tif, TIFFTAG_PLANARCONFIG, PLANARCONFIG_CONTIG);

  // Conditionally test the LogLuv codec.
  if (fdp.ConsumeBool()) {
    TIFFSetField(tif, TIFFTAG_COMPRESSION, COMPRESSION_SGILOG);
    TIFFSetField(tif, TIFFTAG_PHOTOMETRIC, PHOTOMETRIC_LOGLUV);
    TIFFSetField(tif, TIFFTAG_BITSPERSAMPLE, 32);
    TIFFSetField(tif, TIFFTAG_SAMPLESPERPIXEL, 3);
    TIFFSetField(tif, TIFFTAG_SGILOGDATAFMT, SGILOGDATAFMT_FLOAT);
  } else {
    // Test other common configurations.
    TIFFSetField(tif, TIFFTAG_COMPRESSION, COMPRESSION_PACKBITS);
    TIFFSetField(tif, TIFFTAG_PHOTOMETRIC, PHOTOMETRIC_RGB);
    TIFFSetField(tif, TIFFTAG_BITSPERSAMPLE, 8);
    TIFFSetField(tif, TIFFTAG_SAMPLESPERPIXEL, 3);
  }

  // Set the rows per strip to the image height, making the image one strip.
  // This avoids the problematic TIFFAppendToStrip logic by writing the
  // entire image data at once.
  TIFFSetField(tif, TIFFTAG_ROWSPERSTRIP, height);

  // Calculate the size of this single strip.
  tsize_t strip_size = TIFFStripSize(tif);
  if (strip_size > 0) {
    std::vector<uint8_t> strip_buf(strip_size);
    // Fill buffer with fuzzer data if available.
    if (fdp.remaining_bytes() >= strip_buf.size()) {
      fdp.ConsumeData(strip_buf.data(), strip_buf.size());
    }
    // Write the entire strip. This avoids the crash in TIFFClose.
    TIFFWriteEncodedStrip(tif, 0, strip_buf.data(), strip_size);
  }

  // Conditionally create and write a GPS directory.
  if (fdp.ConsumeBool()) {
    TIFFCreateGPSDirectory(tif);
    const uint8_t gps_version[] = {2, 2, 0, 0};
    TIFFSetField(tif, GPSTAG_VERSIONID, gps_version);
    // The directory is written by TIFFClose or the next TIFFWriteDirectory.
    // To ensure it's written, we can call TIFFWriteDirectory.
    TIFFWriteDirectory(tif);
  }

  // Close the TIFF handle.
  TIFFClose(tif);

  return 0;
}