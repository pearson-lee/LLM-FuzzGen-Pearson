#include <cstddef>
#include <cstdint>
#include <vector>
#include <string>
#include <fuzzer/FuzzedDataProvider.h>
#include "/src/libtiff/libtiff/tiffio.h"
#include "/src/libtiff/libtiff/tiffiop.h"

// Custom data structure to hold in-memory TIFF data.
struct TiffInfo {
  FuzzedDataProvider* fdp;
  std::vector<uint8_t> data;
  tmsize_t pos;
};

// Custom read function for libtiff.
tmsize_t read_func(thandle_t handle, void* buffer, tmsize_t size) {
  TiffInfo* info = reinterpret_cast<TiffInfo*>(handle);
  if (info->pos + size > info->data.size()) {
    size = info->data.size() - info->pos;
  }
  if (size > 0) {
    memcpy(buffer, info->data.data() + info->pos, size);
    info->pos += size;
  }
  return size;
}

// Custom write function for libtiff.
tmsize_t write_func(thandle_t handle, void* buffer, tmsize_t size) {
  TiffInfo* info = reinterpret_cast<TiffInfo*>(handle);
  info->data.insert(info->data.end(), reinterpret_cast<uint8_t*>(buffer), reinterpret_cast<uint8_t*>(buffer) + size);
  info->pos += size;
  return size;
}

// Custom seek function for libtiff.
toff_t seek_func(thandle_t handle, toff_t offset, int whence) {
  TiffInfo* info = reinterpret_cast<TiffInfo*>(handle);
  tmsize_t new_pos = info->pos;
  if (whence == SEEK_SET) {
    new_pos = offset;
  } else if (whence == SEEK_CUR) {
    new_pos += offset;
  } else if (whence == SEEK_END) {
    new_pos = info->data.size() + offset;
  }
  if (new_pos > info->data.size()) {
    return -1;
  }
  info->pos = new_pos;
  return info->pos;
}

// Custom close function for libtiff.
int close_func(thandle_t) {
  return 0;
}

// Custom size function for libtiff.
toff_t size_func(thandle_t handle) {
  TiffInfo* info = reinterpret_cast<TiffInfo*>(handle);
  return info->data.size();
}

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
  FuzzedDataProvider fdp(data, size);
  TiffInfo info;
  info.fdp = &fdp;
  info.pos = 0;

  // Create an in-memory TIFF file for writing.
  TIFF* tif = TIFFClientOpen("fuzz.tif", "w", &info, read_func, write_func, seek_func, close_func, size_func, nullptr, nullptr);
  if (!tif) {
    return 0;
  }

  // Set basic TIFF fields.
  uint32_t width = fdp.ConsumeIntegralInRange<uint32_t>(1, 2048);
  uint32_t height = fdp.ConsumeIntegralInRange<uint32_t>(1, 2048);
  TIFFSetField(tif, TIFFTAG_IMAGEWIDTH, width);
  TIFFSetField(tif, TIFFTAG_IMAGELENGTH, height);
  TIFFSetField(tif, TIFFTAG_BITSPERSAMPLE, 8);
  TIFFSetField(tif, TIFFTAG_SAMPLESPERPIXEL, 3);
  TIFFSetField(tif, TIFFTAG_PLANARCONFIG, PLANARCONFIG_CONTIG);
  TIFFSetField(tif, TIFFTAG_PHOTOMETRIC, PHOTOMETRIC_RGB);
  TIFFSetField(tif, TIFFTAG_COMPRESSION, COMPRESSION_NONE);
  TIFFSetField(tif, TIFFTAG_ROWSPERSTRIP, height);

  // Write some image data.
  std::vector<uint8_t> image_data = fdp.ConsumeBytes<uint8_t>(width * height * 3);
  if (image_data.size() > 0) {
    TIFFWriteEncodedStrip(tif, 0, image_data.data(), image_data.size());
  }

  // Write the first directory.
  TIFFWriteDirectory(tif);

  // Write a second directory to test unlinking.
  TIFFSetField(tif, TIFFTAG_IMAGEWIDTH, width / 2 + 1);
  TIFFSetField(tif, TIFFTAG_IMAGELENGTH, height / 2 + 1);
  TIFFWriteDirectory(tif);

  // Unlink the second directory.
  TIFFUnlinkDirectory(tif, 2);

  // Call TIFFRawStripSize64.
  TIFFRawStripSize64(tif, 0);

  // Call TIFFGetConfiguredCODECs.
  // The result does not need to be used, just call the function to improve coverage.
  TIFFGetConfiguredCODECs();

  // Call TIFFMergeFieldInfo with fuzzed data.
  TIFFFieldInfo fi;
  fi.field_tag = fdp.ConsumeIntegral<uint32_t>();
  fi.field_readcount = fdp.ConsumeIntegralInRange<int16_t>(-1, 100);
  fi.field_writecount = fdp.ConsumeIntegralInRange<int16_t>(-1, 100);
  fi.field_type = static_cast<TIFFDataType>(fdp.ConsumeIntegralInRange<int>(0, 18));
  fi.field_bit = static_cast<uint16_t>(fdp.ConsumeIntegralInRange<int>(0, 32));
  fi.field_oktochange = fdp.ConsumeBool();
  fi.field_passcount = fdp.ConsumeBool();
  std::string field_name_str = fdp.ConsumeRandomLengthString(10);
  std::vector<char> field_name_vec(field_name_str.begin(), field_name_str.end());
  field_name_vec.push_back('\0');
  fi.field_name = field_name_vec.data();
  TIFFMergeFieldInfo(tif, &fi, 1);

  // Close the TIFF handle for writing and reopen for reading.
  TIFFClose(tif);
  info.pos = 0;
  tif = TIFFClientOpen("fuzz.tif", "r", &info, read_func, write_func, seek_func, close_func, size_func, nullptr, nullptr);
  if (!tif) {
    return 0;
  }

  // Call TIFFReadFromUserBuffer with fuzzed data.
  if (TIFFNumberOfStrips(tif) > 0) {
    uint32_t strip = fdp.ConsumeIntegralInRange<uint32_t>(0, TIFFNumberOfStrips(tif) - 1);
    std::vector<uint8_t> user_buffer = fdp.ConsumeRemainingBytes<uint8_t>();
    if (user_buffer.size() > 0) {
      TIFFReadFromUserBuffer(tif, strip, user_buffer.data(), user_buffer.size(), nullptr, 0);
    }
  }

  // Clean up.
  TIFFClose(tif);

  return 0;
}