#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <sstream>
#include <string>
#include <vector>

#include <fuzzer/FuzzedDataProvider.h>
#include "/src/libtiff/libtiff/tiffio.h"
#include "/src/libtiff/libtiff/tiffio.hxx"

// Error and warning handlers to avoid printing to stderr during fuzzing.
static void silent_error_handler(const char *, const char *, va_list) {}
static void silent_warning_handler(const char *, const char *, va_list) {}

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  if (size < 100) {
    // Need enough data to be meaningful.
    return 0;
  }

  FuzzedDataProvider fdp(data, size);

  // Set custom error and warning handlers to suppress console output.
  TIFFSetErrorHandler(silent_error_handler);
  TIFFSetWarningHandler(silent_warning_handler);

  // Use a stringstream for in-memory TIFF data, which is safer than file I/O.
  std::stringstream tiff_stream;

  // --- Write Phase ---
  // Open the TIFF stream for writing.
  TIFF *tiff_write = TIFFStreamOpen("fuzz_write", static_cast<std::ostream*>(&tiff_stream));
  if (!tiff_write) {
    return 0;
  }

  // Define image parameters, keeping them reasonably small to avoid timeouts.
  const uint32_t width = fdp.ConsumeIntegralInRange<uint32_t>(1, 256);
  const uint32_t height = fdp.ConsumeIntegralInRange<uint32_t>(1, 256);
  const uint16_t samples_per_pixel = fdp.ConsumeIntegralInRange<uint16_t>(1, 4);
  const uint16_t bits_per_sample = fdp.PickValueInArray<uint16_t>({1, 2, 4, 8, 16});
  const uint16_t photometric = fdp.PickValueInArray<uint16_t>(
      {PHOTOMETRIC_MINISWHITE, PHOTOMETRIC_MINISBLACK, PHOTOMETRIC_RGB,
       PHOTOMETRIC_PALETTE, PHOTOMETRIC_MASK, PHOTOMETRIC_SEPARATED,
       PHOTOMETRIC_YCBCR, PHOTOMETRIC_CIELAB, PHOTOMETRIC_LOGL,
       PHOTOMETRIC_LOGLUV});
  const uint16_t sample_format = fdp.PickValueInArray<uint16_t>(
      {SAMPLEFORMAT_UINT, SAMPLEFORMAT_INT, SAMPLEFORMAT_IEEEFP,
       SAMPLEFORMAT_VOID, SAMPLEFORMAT_COMPLEXINT, SAMPLEFORMAT_COMPLEXIEEEFP});

  // Set fundamental TIFF tags.
  TIFFSetField(tiff_write, TIFFTAG_IMAGEWIDTH, width);
  TIFFSetField(tiff_write, TIFFTAG_IMAGELENGTH, height);
  TIFFSetField(tiff_write, TIFFTAG_SAMPLESPERPIXEL, samples_per_pixel);
  TIFFSetField(tiff_write, TIFFTAG_BITSPERSAMPLE, bits_per_sample);
  TIFFSetField(tiff_write, TIFFTAG_PLANARCONFIG, PLANARCONFIG_CONTIG);
  TIFFSetField(tiff_write, TIFFTAG_PHOTOMETRIC, photometric);
  TIFFSetField(tiff_write, TIFFTAG_SAMPLEFORMAT, sample_format);

  if (fdp.ConsumeBool()) {
    const uint32_t tile_width = fdp.ConsumeIntegralInRange<uint32_t>(1, 16) * 16;
    const uint32_t tile_height = fdp.ConsumeIntegralInRange<uint32_t>(1, 16) * 16;
    TIFFSetField(tiff_write, TIFFTAG_TILEWIDTH, tile_width);
    TIFFSetField(tiff_write, TIFFTAG_TILELENGTH, tile_height);
    tmsize_t tile_size = TIFFTileSize(tiff_write);
    if (tile_size > 0 && tile_size < fdp.remaining_bytes()) {
      std::vector<uint8_t> tile_buffer = fdp.ConsumeBytes<uint8_t>(tile_size);
      for (uint32_t y = 0; y < height; y += tile_height) {
        for (uint32_t x = 0; x < width; x += tile_width) {
          TIFFWriteEncodedTile(tiff_write, TIFFComputeTile(tiff_write, x, y, 0, 0),
                               tile_buffer.data(), tile_size);
        }
      }
    }
  } else {
    const uint32_t rows_per_strip = fdp.ConsumeIntegralInRange<uint32_t>(1, height);
    TIFFSetField(tiff_write, TIFFTAG_ROWSPERSTRIP, rows_per_strip);
    tmsize_t strip_size = TIFFStripSize(tiff_write);
    if (strip_size > 0 && strip_size < fdp.remaining_bytes()) {
      std::vector<uint8_t> strip_buffer = fdp.ConsumeBytes<uint8_t>(strip_size);
      for (uint32_t row = 0; row < height; row += rows_per_strip) {
        TIFFWriteEncodedStrip(tiff_write, TIFFComputeStrip(tiff_write, row, 0),
                              strip_buffer.data(), strip_size);
      }
    }
  }

  TIFFWriteDirectory(tiff_write);
  TIFFClose(tiff_write);

  // --- Read Phase ---
  std::string tiff_data = tiff_stream.str();
  if (tiff_data.empty()) {
    return 0;
  }
  
  std::stringstream read_stream(tiff_data);

  TIFF *tiff_read = TIFFStreamOpen("fuzz_read", static_cast<std::istream*>(&read_stream));
  if (!tiff_read) {
    return 0;
  }

  uint32_t read_width = 0, read_height = 0;
  TIFFGetField(tiff_read, TIFFTAG_IMAGEWIDTH, &read_width);
  TIFFGetField(tiff_read, TIFFTAG_IMAGELENGTH, &read_height);

  if (read_width == 0 || read_height == 0 || read_width > 2048 || read_height > 2048) {
      TIFFClose(tiff_read);
      return 0;
  }

  TIFFRGBAImage img;
  char emsg[1024] = {0};
  if (TIFFRGBAImageBegin(&img, tiff_read, 1, emsg)) {
    if (TIFFIsTiled(tiff_read)) {
        uint32_t tile_width = 0, tile_height = 0;
        TIFFGetField(tiff_read, TIFFTAG_TILEWIDTH, &tile_width);
        TIFFGetField(tiff_read, TIFFTAG_TILELENGTH, &tile_height);
        if (tile_width > 0 && tile_height > 0) {
            size_t tile_buf_size = (size_t)tile_width * tile_height;
            if (tile_buf_size > 0 && tile_buf_size < (1024 * 1024)) {
                std::vector<uint32_t> tile_buffer(tile_buf_size);
                for (uint32_t y = 0; y < read_height; y += tile_height) {
                    for (uint32_t x = 0; x < read_width; x += tile_width) {
                        TIFFReadRGBATileExt(tiff_read, x, y, tile_buffer.data(), 1);
                    }
                }
            }
        }
    } else {
        uint32_t rows_per_strip = 0;
        TIFFGetFieldDefaulted(tiff_read, TIFFTAG_ROWSPERSTRIP, &rows_per_strip);
        if (rows_per_strip > read_height) {
            rows_per_strip = read_height;
        }
        if (rows_per_strip > 0) {
            size_t strip_buf_size = (size_t)read_width * rows_per_strip;
            if (strip_buf_size > 0 && strip_buf_size < (1024 * 1024)) {
                std::vector<uint32_t> strip_buffer(strip_buf_size);
                for (uint32_t row = 0; row < read_height; row += rows_per_strip) {
                    TIFFReadRGBAStripExt(tiff_read, row, strip_buffer.data(), 1);
                }
            }
        }
    }
    TIFFRGBAImageEnd(&img);
  }

  do {
      uint32_t w, h;
      TIFFGetField(tiff_read, TIFFTAG_IMAGEWIDTH, &w);
      TIFFGetField(tiff_read, TIFFTAG_IMAGELENGTH, &h);
  } while (TIFFReadDirectory(tiff_read));

  TIFFClose(tiff_read);

  return 0;
}