#include <cstddef>
#include <cstdint>
#include <sstream>
#include <vector>

#include "fuzzer/FuzzedDataProvider.h"
#include "tiffio.h"
#include "/src/libtiff/libtiff/tif_stream.cxx"

// Fuzz target entry point
extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  if (size == 0) {
    return 0;
  }

  FuzzedDataProvider fdp(data, size);

  // Use a stringstream for in-memory TIFF data handling
  std::stringstream out_stream(std::ios_base::in | std::ios_base::out | std::ios_base::binary);

  // ::tiffosOpen is defined in tiffio.cxx and allows using C++ streams
  // This targets TIFFStreamOpen and related stream handling functions
  TIFF *tif_out = TIFFStreamOpen("fuzzer_write", static_cast<std::ostream*>(&out_stream));
  if (!tif_out) {
    return 0;
  }

  // Define image parameters, fuzzed to explore different configurations
  const uint32_t width = fdp.ConsumeIntegralInRange<uint32_t>(1, 512);
  const uint32_t height = fdp.ConsumeIntegralInRange<uint32_t>(1, 512);
  const uint16_t samples_per_pixel = fdp.PickValueInArray<uint16_t>({1, 3, 4});
  const uint16_t bits_per_sample = fdp.PickValueInArray<uint16_t>({8, 16});
  const uint16_t photometric = (samples_per_pixel == 1) ? PHOTOMETRIC_MINISBLACK :
                               (samples_per_pixel == 3) ? PHOTOMETRIC_RGB : PHOTOMETRIC_SEPARATED;
  const uint16_t compression = fdp.PickValueInArray<uint16_t>({COMPRESSION_NONE, COMPRESSION_PACKBITS, COMPRESSION_LZW});
  const uint16_t planar_config = fdp.PickValueInArray<uint16_t>({PLANARCONFIG_CONTIG, PLANARCONFIG_SEPARATE});

  // Set TIFF fields to create a valid directory structure
  TIFFSetField(tif_out, TIFFTAG_IMAGEWIDTH, width);
  TIFFSetField(tif_out, TIFFTAG_IMAGELENGTH, height);
  TIFFSetField(tif_out, TIFFTAG_SAMPLESPERPIXEL, samples_per_pixel);
  TIFFSetField(tif_out, TIFFTAG_BITSPERSAMPLE, bits_per_sample);
  TIFFSetField(tif_out, TIFFTAG_ORIENTATION, ORIENTATION_TOPLEFT);
  TIFFSetField(tif_out, TIFFTAG_PLANARCONFIG, planar_config);
  TIFFSetField(tif_out, TIFFTAG_PHOTOMETRIC, photometric);
  TIFFSetField(tif_out, TIFFTAG_COMPRESSION, compression);

  // Write scanline data to the in-memory TIFF
  // This is a primary target, exercising TIFFWriteScanline and potentially
  // low-coverage functions it calls, like TIFFAppendToStrip.
  tsize_t scanline_size = TIFFScanlineSize(tif_out);
  if (scanline_size > 0) {
    std::vector<uint8_t> line_buf = fdp.ConsumeBytes<uint8_t>(scanline_size);
    if (line_buf.size() == scanline_size) {
      for (uint32_t row = 0; row < height; ++row) {
        TIFFWriteScanline(tif_out, line_buf.data(), row, 0);
      }
    }
  }

  // Close the TIFF handle to ensure all data is flushed to the stream
  TIFFClose(tif_out);

  // Get the generated TIFF data from the output stream
  std::string tiff_data = out_stream.str();
  if (tiff_data.empty()) {
    return 0;
  }

  // Prepare an input stream for reading the generated TIFF data
  std::stringstream in_stream(tiff_data);

  // Open the in-memory TIFF data for reading
  TIFF *tif_in = TIFFStreamOpen("fuzzer_read", static_cast<std::istream*>(&in_stream));
  if (!tif_in) {
    return 0;
  }

  // Use TIFFRGBAImageOK to check if the image can be read. This function
  // has many validation checks and is a good fuzzing target.
  char emsg[1024] = {0};
  if (TIFFRGBAImageOK(tif_in, emsg)) {
    TIFFRGBAImage img;
    if (TIFFRGBAImageBegin(&img, tif_in, 0, emsg)) {
      // Allocate memory for the raster. Must be freed with _TIFFfree.
      uint32_t* raster = (uint32_t *)_TIFFmalloc(width * height * sizeof(uint32_t));
      if (raster) {
        // Attempt to read the image. This high-level function triggers many
        // underlying low-coverage functions in tif_getimage.c, such as
        // gtStripContig, gtStripSeparate, and various color conversion routines.
        TIFFReadRGBAImage(tif_in, width, height, raster, 0);
        
        // Memory safety: free the raster buffer
        _TIFFfree(raster);
      }
      // Memory safety: clean up the TIFFRGBAImage structure
      TIFFRGBAImageEnd(&img);
    }
  }

  // Memory safety: close the input TIFF handle
  TIFFClose(tif_in);

  return 0;
}