#include <cstddef>
#include <cstdint>
#include <string>
#include <vector>
#include <fuzzer/FuzzedDataProvider.h>
#include "/src/libtiff/libtiff/tiffio.h"
#include "/src/libtiff/libtiff/tiffiop.h" // For _TIFFmalloc and _TIFFfree

// Custom memory-based I/O functions for libtiff
struct TiffInfo {
  uint8_t *data;
  size_t size;
  size_t offset;
};

static tmsize_t read_proc(thandle_t handle, void *buf, tmsize_t size) {
  TiffInfo *info = reinterpret_cast<TiffInfo *>(handle);
  if (info->offset + size > info->size) {
    size = info->size - info->offset;
  }
  memcpy(buf, info->data + info->offset, size);
  info->offset += size;
  return size;
}

static tmsize_t write_proc(thandle_t handle, void *buf, tmsize_t size) {
  TiffInfo *info = reinterpret_cast<TiffInfo *>(handle);
  // This is a dummy write function, as we are not interested in the output
  return size;
}

static toff_t seek_proc(thandle_t handle, toff_t offset, int whence) {
  TiffInfo *info = reinterpret_cast<TiffInfo *>(handle);
  toff_t new_offset = 0;
  switch (whence) {
  case SEEK_SET:
    new_offset = offset;
    break;
  case SEEK_CUR:
    new_offset = info->offset + offset;
    break;
  case SEEK_END:
    new_offset = info->size + offset;
    break;
  }
  if (new_offset > info->size) {
    return -1;
  }
  info->offset = new_offset;
  return info->offset;
}

static int close_proc(thandle_t handle) {
  // No-op
  return 0;
}

static toff_t size_proc(thandle_t handle) {
  TiffInfo *info = reinterpret_cast<TiffInfo *>(handle);
  return info->size;
}

// To cover error/warning handler functions, provide dummy handlers.
static void dummy_warning_handler(thandle_t, const char *, const char *, va_list) {}
static void dummy_error_handler(thandle_t, const char *, const char *, va_list) {}

// Fuzz target entry point
extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  FuzzedDataProvider fdp(data, size);

  // To cover TIFFSetWarningHandlerExt and TIFFSetErrorHandlerExt, set dummy handlers.
  TIFFSetWarningHandlerExt(dummy_warning_handler);
  TIFFSetErrorHandlerExt(dummy_error_handler);

  // Create a TiffInfo structure to manage the in-memory TIFF data
  TiffInfo info;
  std::vector<uint8_t> tiff_data = fdp.ConsumeRemainingBytes<uint8_t>();
  info.size = tiff_data.size();
  info.data = tiff_data.data();
  info.offset = 0;

  // Open the TIFF image from memory for writing
  TIFF *tif = TIFFClientOpen("fuzz_write", "w", &info, read_proc, write_proc,
                             seek_proc, close_proc, size_proc, nullptr, nullptr);
  if (!tif) {
    return 0;
  }

  // Set basic TIFF fields
  TIFFSetField(tif, TIFFTAG_IMAGEWIDTH, fdp.ConsumeIntegralInRange<uint32_t>(1, 512));
  TIFFSetField(tif, TIFFTAG_IMAGELENGTH, fdp.ConsumeIntegralInRange<uint32_t>(1, 512));
  TIFFSetField(tif, TIFFTAG_BITSPERSAMPLE, 8);
  TIFFSetField(tif, TIFFTAG_SAMPLESPERPIXEL,
               fdp.PickValueInArray<uint16_t>({1, 3, 4}));
  TIFFSetField(tif, TIFFTAG_PLANARCONFIG, PLANARCONFIG_CONTIG);

  // To improve coverage, select a compression type using the fuzzer input
  // instead of always using COMPRESSION_NONE. This will exercise the
  // encoding and decoding paths for various compression schemes.
  const uint16_t compression_types[] = {
      COMPRESSION_NONE,      COMPRESSION_LZW,         COMPRESSION_ADOBE_DEFLATE,
      COMPRESSION_DEFLATE,   COMPRESSION_PACKBITS,    COMPRESSION_JPEG,
      COMPRESSION_CCITTRLE,  COMPRESSION_CCITTFAX3,   COMPRESSION_CCITTFAX4,
      COMPRESSION_NEXT,      COMPRESSION_THUNDERSCAN, COMPRESSION_PIXARLOG,
      COMPRESSION_SGILOG,    COMPRESSION_SGILOG24};
  uint16_t compression = fdp.PickValueInArray(compression_types);
  TIFFSetField(tif, TIFFTAG_COMPRESSION, compression);

  // JPEG compression requires a specific photometric interpretation.
  if (compression == COMPRESSION_JPEG) {
    TIFFSetField(tif, TIFFTAG_PHOTOMETRIC, PHOTOMETRIC_YCBCR);
  } else {
    TIFFSetField(tif, TIFFTAG_PHOTOMETRIC, PHOTOMETRIC_MINISBLACK);
  }

  // Write a raw strip to the TIFF
  std::vector<uint8_t> strip_data =
      fdp.ConsumeBytes<uint8_t>(fdp.ConsumeIntegralInRange<size_t>(0, 1024));
  if (!strip_data.empty()) {
    TIFFWriteEncodedStrip(tif, 0, strip_data.data(), strip_data.size());
  }

  TIFFWriteDirectory(tif);
  TIFFClose(tif);

  // --- Reading Phase ---
  // Reset offset to read the TIFF data we just wrote. This will exercise
  // the decoding and image reading functions (e.g., in tif_getimage.c).
  info.offset = 0;
  tif = TIFFClientOpen("fuzz_read", "r", &info, read_proc, write_proc,
                       seek_proc, close_proc, size_proc, nullptr, nullptr);
  if (!tif) {
    return 0;
  }

  // Attempt to read the image to improve coverage in tif_getimage.c and decode paths.
  uint32_t w, h;
  TIFFGetField(tif, TIFFTAG_IMAGEWIDTH, &w);
  TIFFGetField(tif, TIFFTAG_IMAGELENGTH, &h);
  // Add size constraints to prevent excessive, fuzzer-crashing memory allocations.
  if (w > 0 && h > 0 && w < 2048 && h < 2048) {
    // Use _TIFFmalloc and _TIFFfree for memory management consistent with the library.
    uint32_t *raster = (uint32_t *)_TIFFmalloc(w * h * sizeof(uint32_t));
    if (raster) {
      TIFFReadRGBAImage(tif, w, h, raster, 0);
      _TIFFfree(raster);
    }
  }

  TIFFClose(tif);

  return 0;
}