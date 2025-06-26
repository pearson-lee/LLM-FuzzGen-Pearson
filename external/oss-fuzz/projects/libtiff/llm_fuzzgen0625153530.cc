#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <sstream>
#include <vector>

#include <fuzzer/FuzzedDataProvider.h>

// Required libtiff headers
#include "tiffio.h"
#include "tiffio.hxx"

// Suppress libtiff error/warning messages from polluting fuzzer output
void silent_error_handler(const char*, const char*, va_list) {}

// Main fuzzing function
extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
  FuzzedDataProvider fdp(data, size);

  // Set custom handlers to suppress console output
  TIFFSetErrorHandler(silent_error_handler);
  TIFFSetWarningHandler(silent_error_handler);

  // Use a stringstream for in-memory I/O, which is faster for fuzzing
  std::stringstream stream;

  // --- 1. Write a TIFF to the in-memory stream ---
  TIFF* write_tif = TIFFStreamOpen("mem_write.tif", static_cast<std::ostream*>(&stream));
  if (!write_tif) {
    return 0;
  }

  // Define image parameters, keeping them reasonably small to avoid timeouts
  const uint32_t width = fdp.ConsumeIntegralInRange<uint32_t>(1, 512);
  const uint32_t height = fdp.ConsumeIntegralInRange<uint32_t>(1, 512);
  const uint16_t samples_per_pixel = fdp.PickValueInArray<uint16_t>({1, 3, 4});
  const uint16_t bits_per_sample = fdp.PickValueInArray<uint16_t>({8, 16});
  const uint16_t photometric = (samples_per_pixel == 1) ? PHOTOMETRIC_MINISBLACK : PHOTOMETRIC_RGB;

  // Set mandatory TIFF fields to create a valid image structure
  TIFFSetField(write_tif, TIFFTAG_IMAGEWIDTH, width);
  TIFFSetField(write_tif, TIFFTAG_IMAGELENGTH, height);
  TIFFSetField(write_tif, TIFFTAG_SAMPLESPERPIXEL, samples_per_pixel);
  TIFFSetField(write_tif, TIFFTAG_BITSPERSAMPLE, bits_per_sample);
  TIFFSetField(write_tif, TIFFTAG_ORIENTATION, ORIENTATION_TOPLEFT);
  TIFFSetField(write_tif, TIFFTAG_PLANARCONFIG, PLANARCONFIG_CONTIG);
  TIFFSetField(write_tif, TIFFTAG_PHOTOMETRIC, photometric);
  TIFFSetField(write_tif, TIFFTAG_ROWSPERSTRIP, height); // Keep it simple with a single strip

  // Allocate buffer for one scanline using libtiff's allocator
  tmsize_t scanline_size = TIFFScanlineSize(write_tif);
  if (scanline_size <= 0) {
    TIFFClose(write_tif);
    return 0;
  }
  void* scanline_buf = _TIFFmalloc(scanline_size);
  if (!scanline_buf) {
    TIFFClose(write_tif);
    return 0;
  }

  // Fill the scanline buffer with fuzzer data
  std::vector<uint8_t> random_bytes = fdp.ConsumeBytes<uint8_t>(scanline_size);
  memcpy(scanline_buf, random_bytes.data(), random_bytes.size());
  // Zero-fill the remainder of the buffer if not enough bytes were consumed
  if (random_bytes.size() < scanline_size) {
    memset(static_cast<uint8_t*>(scanline_buf) + random_bytes.size(), 0, scanline_size - random_bytes.size());
  }

  // Write scanlines to the TIFF to populate it with image data
  for (uint32_t row = 0; row < height; ++row) {
    if (TIFFWriteScanline(write_tif, scanline_buf, row, 0) < 0) {
      break; // Stop if writing fails
    }
  }

  // Free the scanline buffer
  _TIFFfree(scanline_buf);

  // Write the directory to finalize this image
  TIFFWriteDirectory(write_tif);
  // Close the TIFF handle, which flushes all data to the stringstream
  TIFFClose(write_tif);

  // --- 2. Read the TIFF back and exercise target APIs ---
  stream.seekg(0); // Rewind stream to the beginning for reading
  TIFF* read_tif = TIFFStreamOpen("mem_read.tif", static_cast<std::istream*>(&stream));
  if (!read_tif) {
    return 0;
  }

  // --- 3. Target TIFFPrintDirectory (previously 0% coverage) ---
  // Redirect stdout to /dev/null to suppress verbose output during fuzzing
  FILE* dev_null = fopen("/dev/null", "w");
  if (dev_null) {
    // Fuzz the 'flags' parameter to exercise different printing logic
    long print_flags = fdp.ConsumeIntegral<long>();
    TIFFPrintDirectory(read_tif, dev_null, print_flags);
    fclose(dev_null);
  }

  // --- 4. Target TIFFUnlinkDirectory (previously low coverage) ---
  uint16_t num_dirs = TIFFNumberOfDirectories(read_tif);
  if (num_dirs > 0) {
    // Choose a directory to attempt to unlink, testing boundary conditions
    uint16_t dir_to_unlink = fdp.ConsumeIntegralInRange<uint16_t>(0, num_dirs);
    TIFFUnlinkDirectory(read_tif, dir_to_unlink);
  }

  // Final cleanup: ensure the read handle is closed
  TIFFClose(read_tif);

  return 0;
}