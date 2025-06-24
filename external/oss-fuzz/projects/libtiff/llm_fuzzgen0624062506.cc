#include <cstddef>
#include <cstdint>
#include <string>
#include <vector>
#include <fuzzer/FuzzedDataProvider.h>
#include "tiffio.h"

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

// Fuzz target entry point
extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  FuzzedDataProvider fdp(data, size);

  // Create a TiffInfo structure to manage the in-memory TIFF data
  TiffInfo info;
  info.size = fdp.remaining_bytes();
  info.data = (uint8_t *)data;
  info.offset = 0;

  // Open the TIFF image from memory
  TIFF *tif = TIFFClientOpen("fuzz", "w", &info, read_proc, write_proc,
                             seek_proc, close_proc, size_proc, nullptr, nullptr);
  if (!tif) {
    return 0;
  }

  // Set basic TIFF fields
  TIFFSetField(tif, TIFFTAG_IMAGEWIDTH, fdp.ConsumeIntegral<uint32_t>());
  TIFFSetField(tif, TIFFTAG_IMAGELENGTH, fdp.ConsumeIntegral<uint32_t>());
  TIFFSetField(tif, TIFFTAG_BITSPERSAMPLE, 8);
  TIFFSetField(tif, TIFFTAG_SAMPLESPERPIXEL, 1);
  TIFFSetField(tif, TIFFTAG_PLANARCONFIG, PLANARCONFIG_CONTIG);
  TIFFSetField(tif, TIFFTAG_COMPRESSION, COMPRESSION_NONE);
  TIFFSetField(tif, TIFFTAG_PHOTOMETRIC, PHOTOMETRIC_MINISBLACK);

  // Call TIFFCheckpointDirectory to exercise its logic
  TIFFCheckpointDirectory(tif);

  // Write a raw strip to the TIFF
  std::vector<uint8_t> strip_data =
      fdp.ConsumeBytes<uint8_t>(fdp.ConsumeIntegralInRange<size_t>(0, 1024));
  if (!strip_data.empty()) {
    TIFFWriteRawStrip(tif, 0, strip_data.data(), strip_data.size());
  }

  // Write a raw tile to the TIFF
  std::vector<uint8_t> tile_data =
      fdp.ConsumeBytes<uint8_t>(fdp.ConsumeIntegralInRange<size_t>(0, 1024));
  if (!tile_data.empty()) {
    TIFFWriteRawTile(tif, 0, tile_data.data(), tile_data.size());
  }

  // Create a second directory
  TIFFWriteDirectory(tif);
  TIFFSetField(tif, TIFFTAG_IMAGEWIDTH, fdp.ConsumeIntegral<uint32_t>());
  TIFFSetField(tif, TIFFTAG_IMAGELENGTH, fdp.ConsumeIntegral<uint32_t>());
  TIFFSetField(tif, TIFFTAG_BITSPERSAMPLE, 8);
  TIFFSetField(tif, TIFFTAG_SAMPLESPERPIXEL, 1);
  TIFFSetField(tif, TIFFTAG_PLANARCONFIG, PLANARCONFIG_CONTIG);
  TIFFSetField(tif, TIFFTAG_COMPRESSION, COMPRESSION_NONE);
  TIFFSetField(tif, TIFFTAG_PHOTOMETRIC, PHOTOMETRIC_MINISBLACK);

  // Set the subdirectory
  TIFFSetSubDirectory(tif, fdp.ConsumeIntegral<uint64_t>());

  // Unlink a directory
  TIFFUnlinkDirectory(tif, fdp.ConsumeIntegral<tdir_t>());

  // Clean up and close the TIFF handle
  TIFFClose(tif);

  return 0;
}