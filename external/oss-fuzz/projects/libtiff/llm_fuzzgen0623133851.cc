#include <cstddef>
#include <cstdint>
#include <string>
#include <vector>

#include <fuzzer/FuzzedDataProvider.h>

#include "tiff.h"
#include "tiffio.h"

// Memory management functions for TIFF
static tmsize_t _tiffReadProc(thandle_t, void *, tmsize_t) { return -1; }

static tmsize_t _tiffWriteProc(thandle_t, void *, tmsize_t) { return -1; }

static toff_t _tiffSeekProc(thandle_t, toff_t, int) { return -1; }

static int _tiffCloseProc(thandle_t) { return 0; }

static toff_t _tiffSizeProc(thandle_t) { return 0; }

static int _tiffMapProc(thandle_t, void **, toff_t *) { return 0; }

static void _tiffUnmapProc(thandle_t, void *, toff_t) {}

// Error and warning handlers to suppress output
static void _tiffErrorHandler(const char *, const char *, va_list) {}
static void _tiffWarningHandler(const char *, const char *, va_list) {}

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  FuzzedDataProvider fdp(data, size);

  // Set up custom error and warning handlers to avoid noisy output
  TIFFSetErrorHandler(_tiffErrorHandler);
  TIFFSetWarningHandler(_tiffWarningHandler);

  // Create a TIFF object in memory
  TIFF *tif = TIFFClientOpen("fuzz", "w", nullptr, _tiffReadProc, _tiffWriteProc,
                             _tiffSeekProc, _tiffCloseProc, _tiffSizeProc,
                             _tiffMapProc, _tiffUnmapProc);
  if (!tif) {
    return 0;
  }

  // Clean up the TIFF object
  TIFFCleanup(tif);

  return 0;
}