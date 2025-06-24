#include <cstddef>
#include <cstdint>
#include <string>
#include <vector>
#include <fuzzer/FuzzedDataProvider.h>
#include "/src/libtiff/libtiff/tiffio.h"
#include "/src/libtiff/libtiff/tif_dir.h"
#include "/src/libtiff/libtiff/tiffiop.h" // For _TIFFmalloc and _TIFFfree

// A robust, vector-based structure for in-memory I/O.
// This fixes a critical bug where the original write_proc was a no-op,
// preventing the entire reading phase from being tested.
struct TiffInfo {
  std::vector<uint8_t> buffer;
  toff_t offset;
};

static tmsize_t read_proc(thandle_t handle, void *buf, tmsize_t size) {
  TiffInfo *info = reinterpret_cast<TiffInfo *>(handle);
  if (info->offset + size > info->buffer.size()) {
    size = info->buffer.size() - info->offset;
  }
  if (size > 0) {
    memcpy(buf, info->buffer.data() + info->offset, size);
  }
  info->offset += size;
  return size;
}

static tmsize_t write_proc(thandle_t handle, void *buf, tmsize_t size) {
  TiffInfo *info = reinterpret_cast<TiffInfo *>(handle);
  if (info->offset + size > info->buffer.size()) {
    info->buffer.resize(info->offset + size);
  }
  memcpy(info->buffer.data() + info->offset, buf, size);
  info->offset += size;
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
    new_offset = info->buffer.size() + offset;
    break;
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
  return info->buffer.size();
}

// To cover error/warning handler functions, provide dummy handlers.
static void dummy_warning_handler(thandle_t, const char *, const char *, va_list) {}
static void dummy_error_handler(thandle_t, const char *, const char *, va_list) {}

// Define a custom field array to test TIFFReadCustomDirectory.
// Using the modern TIFFField struct instead of the obsolete TIFFFieldInfo.
static char custom_tag_name_1[] = "CustomTag1";
static char custom_tag_name_2[] = "CustomTag2";
static TIFFField customFields[] = {
    {65000, 1, 1, TIFF_LONG, 0, TIFF_SETGET_UINT32, TIFF_SETGET_UNDEFINED, FIELD_CUSTOM, 1, 0, custom_tag_name_1, nullptr},
    {65001, -1, -1, TIFF_ASCII, 0, TIFF_SETGET_ASCII, TIFF_SETGET_UNDEFINED, FIELD_CUSTOM, 1, 0, custom_tag_name_2, nullptr}};
static const uint32_t numCustomFields = sizeof(customFields) / sizeof(customFields[0]);

// Fuzz target entry point
extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  FuzzedDataProvider fdp(data, size);

  TIFFSetWarningHandlerExt(dummy_warning_handler);
  TIFFSetErrorHandlerExt(dummy_error_handler);

  TiffInfo info;
  info.offset = 0;

  TIFF *tif = TIFFClientOpen("fuzz_write", "w", &info, read_proc, write_proc,
                             seek_proc, close_proc, size_proc, nullptr, nullptr);
  if (!tif) {
    return 0;
  }

  // Merge the custom fields.
  _TIFFMergeFields(tif, customFields, numCustomFields);

  // Set basic TIFF fields for the first directory
  TIFFSetField(tif, TIFFTAG_IMAGEWIDTH, fdp.ConsumeIntegralInRange<uint32_t>(1, 512));
  TIFFSetField(tif, TIFFTAG_IMAGELENGTH, fdp.ConsumeIntegralInRange<uint32_t>(1, 512));
  TIFFSetField(tif, TIFFTAG_BITSPERSAMPLE, 8);
  TIFFSetField(tif, TIFFTAG_PLANARCONFIG, PLANARCONFIG_CONTIG);
  TIFFSetField(tif, TIFFTAG_SAMPLESPERPIXEL, (uint16_t)3);
  TIFFSetField(tif, TIFFTAG_PHOTOMETRIC, PHOTOMETRIC_RGB);
  
  // Add an EXIF directory to improve coverage of EXIF tag handling.
  TIFFSetField(tif, TIFFTAG_EXIFIFD, (uint64_t)0);

  // Write the first directory.
  TIFFWriteDirectory(tif);

  // Create and write the EXIF directory itself.
  TIFFCreateEXIFDirectory(tif);
  TIFFSetField(tif, EXIFTAG_FOCALLENGTH, fdp.ConsumeFloatingPoint<float>());
  TIFFWriteDirectory(tif);


  // Add a second directory to improve coverage of multi-directory handling.
  TIFFSetField(tif, TIFFTAG_IMAGEWIDTH, fdp.ConsumeIntegralInRange<uint32_t>(1, 256));
  TIFFSetField(tif, TIFFTAG_IMAGELENGTH, fdp.ConsumeIntegralInRange<uint32_t>(1, 256));
  TIFFSetField(tif, TIFFTAG_BITSPERSAMPLE, 1);
  TIFFSetField(tif, TIFFTAG_COMPRESSION, COMPRESSION_CCITTFAX3);
  TIFFSetField(tif, TIFFTAG_PHOTOMETRIC, PHOTOMETRIC_MINISWHITE);
  TIFFSetField(tif, TIFFTAG_FILLORDER, FILLORDER_MSB2LSB);
  TIFFSetField(tif, TIFFTAG_SAMPLESPERPIXEL, 1);
  TIFFWriteDirectory(tif);

  // Add a custom directory to cover TIFFReadCustomDirectory.
  uint64_t custom_dir_offset = 0;
  TIFFSetField(tif, 65000, fdp.ConsumeIntegral<uint32_t>());
  std::string custom_str = fdp.ConsumeRandomLengthString(32);
  TIFFSetField(tif, 65001, custom_str.c_str());
  TIFFWriteCustomDirectory(tif, &custom_dir_offset);


  TIFFClose(tif);

  // --- Reading Phase ---
  // Reset offset to read the TIFF data we just wrote.
  info.offset = 0;
  tif = TIFFClientOpen("fuzz_read", "r", &info, read_proc, write_proc,
                       seek_proc, close_proc, size_proc, nullptr, nullptr);
  if (!tif) {
    return 0;
  }

  // Register the custom tags with the TIFF handle.
  _TIFFMergeFields(tif, customFields, numCustomFields);

  // Read the custom directory to cover the uncovered TIFFReadCustomDirectory function.
  if (custom_dir_offset > 0) {
    const TIFFFieldArray custom_field_array = {tfiatOther, 0, numCustomFields, customFields};
    TIFFReadCustomDirectory(tif, custom_dir_offset, &custom_field_array);
  }

  // Loop through all directories to improve coverage in tif_dirread.c
  do {
    uint32_t w, h;
    TIFFGetField(tif, TIFFTAG_IMAGEWIDTH, &w);
    TIFFGetField(tif, TIFFTAG_IMAGELENGTH, &h);
    if (w > 0 && h > 0 && w < 2048 && h < 2048) {
      uint32_t *raster = (uint32_t *)_TIFFmalloc(w * h * sizeof(uint32_t));
      if (raster) {
        TIFFReadRGBAImage(tif, w, h, raster, 0);
        _TIFFfree(raster);
      }
    }
  } while (TIFFReadDirectory(tif));

  TIFFClose(tif);

  return 0;
}