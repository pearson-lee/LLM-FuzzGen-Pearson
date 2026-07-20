/* BLOCKER_STRATEGY_CONTRACT
required_state: The `td->td_stripsperimage` field in the TIFF directory structure must be zero at the predicate line. This is achieved by triggering an integer overflow in the `TIFFhowmany_32` macro during its calculation.
state_constructor: Set `TIFFTAG_ROWSPERSTRIP` to a large value (>= 0x80000000) using `TIFFSetField`. The `TIFFTAG_IMAGELENGTH` field is intentionally not set, allowing it to grow dynamically.
trigger_api: Call `TIFFWriteScanline` with a `row` parameter equal to the large `rowsperstrip` value. This forces the `imagegrew` flag to true and provides the necessary inputs to `TIFFhowmany_32` to cause the overflow.
preserved_invariants: The fuzzer must set `TIFFTAG_ROWSPERSTRIP` to a value in the upper half of the uint32_t range and then call `TIFFWriteScanline` with a `row` at least as large as `rowsperstrip`.
END_BLOCKER_STRATEGY_CONTRACT */

#include "tiffio.h"
#include <fuzzer/FuzzedDataProvider.h>
#include <string>
#include <vector>
#include <unistd.h>
#include <cstdint>
#include <cstdio>

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  if (size < 1) {
    return 0;
  }
  FuzzedDataProvider fdp(data, size);

  std::string filename = "/tmp/fuzz_tiff_write_scanline.tiff";
  
  TIFF *tif = TIFFOpen(filename.c_str(), "w");
  if (!tif) {
    return 0;
  }

  // Set mandatory fields for a valid TIFF file.
  TIFFSetField(tif, TIFFTAG_IMAGEWIDTH, fdp.ConsumeIntegralInRange<uint32_t>(1, 512));
  // Intentionally do not set TIFFTAG_IMAGELENGTH to allow it to grow, which is
  // necessary to set the `imagegrew` flag in TIFFWriteScanline.
  TIFFSetField(tif, TIFFTAG_BITSPERSAMPLE, 8);
  TIFFSetField(tif, TIFFTAG_SAMPLESPERPIXEL, 1);
  TIFFSetField(tif, TIFFTAG_PLANARCONFIG, PLANARCONFIG_CONTIG);
  TIFFSetField(tif, TIFFTAG_PHOTOMETRIC, PHOTOMETRIC_MINISBLACK);

  // Set ROWSPERSTRIP to a large value to cause an integer overflow when
  // calculating stripsperimage. This is the core of the strategy.
  uint32_t rowsperstrip = fdp.ConsumeIntegralInRange<uint32_t>(0x80000000, 0xFFFFFFFF);
  TIFFSetField(tif, TIFFTAG_ROWSPERSTRIP, rowsperstrip);

  tsize_t scanline_size = TIFFScanlineSize(tif);
  if (scanline_size > 0 && scanline_size < 1024 * 1024) {
    std::vector<uint8_t> scanline_buf(scanline_size);
    // Use ConsumeData to avoid shrinking the buffer if not enough data is available.
    size_t consumed_size = fdp.ConsumeData(scanline_buf.data(), scanline_size);
    if (consumed_size == scanline_size) {
      // Call TIFFWriteScanline with a row number equal to rowsperstrip.
      // This ensures that `strip` will be >= 1 and `imagegrew` will be true,
      // triggering the vulnerable calculation.
      TIFFWriteScanline(tif, scanline_buf.data(), rowsperstrip, 0);
    }
  }

  TIFFClose(tif);
  unlink(filename.c_str());

  return 0;
}
