#include <fuzzer/FuzzedDataProvider.h>
#include "/src/libtiff/libtiff/tiffio.h"
#include <sstream>
#include <vector>

// Custom I/O callbacks for TIFFClientOpen to work with std::stringstream
static tmsize_t read_proc(thandle_t fd, void* buf, tmsize_t size) {
    std::stringstream* ss = reinterpret_cast<std::stringstream*>(fd);
    ss->read(static_cast<char*>(buf), size);
    return ss->gcount();
}

static tmsize_t write_proc(thandle_t fd, void* buf, tmsize_t size) {
    std::stringstream* ss = reinterpret_cast<std::stringstream*>(fd);
    ss->write(static_cast<const char*>(buf), size);
    return size;
}

static toff_t seek_proc(thandle_t fd, toff_t off, int whence) {
    std::stringstream* ss = reinterpret_cast<std::stringstream*>(fd);
    std::ios_base::seekdir dir;
    switch (whence) {
        case SEEK_SET:
            dir = std::ios_base::beg;
            break;
        case SEEK_CUR:
            dir = std::ios_base::cur;
            break;
        case SEEK_END:
            dir = std::ios_base::end;
            break;
        default:
            return -1;
    }
    ss->seekg(off, dir);
    ss->seekp(off, dir);
    return ss->tellg();
}

static int close_proc(thandle_t) {
    return 0;
}

static toff_t size_proc(thandle_t fd) {
    std::stringstream* ss = reinterpret_cast<std::stringstream*>(fd);
    std::streampos current_pos = ss->tellg();
    ss->seekg(0, std::ios_base::end);
    toff_t size = ss->tellg();
    ss->seekg(current_pos, std::ios_base::beg);
    return size;
}

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size) {
  FuzzedDataProvider fdp(Data, Size);

  // Create an in-memory file stream
  std::stringstream stream;

  // Open the TIFF file from the stream for writing using TIFFClientOpen
  TIFF *tiff = TIFFClientOpen("fuzzer.tif", "w", reinterpret_cast<thandle_t>(&stream),
                             read_proc, write_proc, seek_proc, close_proc, size_proc,
                             nullptr, nullptr);
  if (!tiff) {
    return 0;
  }

  // Consume data for TIFF tags
  const uint32_t width = fdp.ConsumeIntegralInRange<uint32_t>(1, 512);
  const uint32_t height = fdp.ConsumeIntegralInRange<uint32_t>(1, 512);
  const uint16_t samples_per_pixel = fdp.PickValueInArray<uint16_t>({1, 3, 4});
  const uint16_t bits_per_sample = fdp.PickValueInArray<uint16_t>({8, 16});
  const uint16_t photometric =
      (samples_per_pixel == 1)
          ? PHOTOMETRIC_MINISBLACK
          : fdp.PickValueInArray<uint16_t>(
                {PHOTOMETRIC_RGB, PHOTOMETRIC_SEPARATED});
  const uint16_t compression = fdp.PickValueInArray<uint16_t>(
      {COMPRESSION_NONE, COMPRESSION_LZW, COMPRESSION_PACKBITS});

  // Set TIFF fields
  TIFFSetField(tiff, TIFFTAG_IMAGEWIDTH, width);
  TIFFSetField(tiff, TIFFTAG_IMAGELENGTH, height);
  TIFFSetField(tiff, TIFFTAG_SAMPLESPERPIXEL, samples_per_pixel);
  TIFFSetField(tiff, TIFFTAG_BITSPERSAMPLE, bits_per_sample);
  TIFFSetField(tiff, TIFFTAG_ORIENTATION, ORIENTATION_TOPLEFT);
  TIFFSetField(tiff, TIFFTAG_PLANARCONFIG, PLANARCONFIG_CONTIG);
  TIFFSetField(tiff, TIFFTAG_PHOTOMETRIC, photometric);
  TIFFSetField(tiff, TIFFTAG_COMPRESSION, compression);

  // For CMYK, we need to set the InkSet and NumberOfInks tags
  if (photometric == PHOTOMETRIC_SEPARATED) {
    TIFFSetField(tiff, TIFFTAG_INKSET, INKSET_CMYK);
    TIFFSetField(tiff, TIFFTAG_NUMBEROFINKS, (uint16_t)4);
  }

  // Allocate buffer for one scanline
  tmsize_t scanline_size = TIFFScanlineSize(tiff);
  if (scanline_size <= 0) {
    TIFFClose(tiff);
    return 0;
  }
  std::vector<uint8_t> scanline_buf(scanline_size);

  // Write scanlines with fuzzed data
  for (uint32_t row = 0; row < height; ++row) {
    if (fdp.remaining_bytes() < scanline_size) {
      break;
    }
    std::vector<uint8_t> scanline_data =
        fdp.ConsumeBytes<uint8_t>(scanline_size);
    if (TIFFWriteScanline(tiff, scanline_data.data(), row, 0) < 0) {
      break;
    }
  }

  // Write the directory to the file
  TIFFCheckpointDirectory(tiff);

  // Close the TIFF handle to free resources
  TIFFClose(tiff);

  return 0;
}