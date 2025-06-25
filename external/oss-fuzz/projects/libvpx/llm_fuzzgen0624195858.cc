#include <cstddef>
#include <cstdint>
#include <vector>
#include <fuzzer/FuzzedDataProvider.h>
#include "vpx/vpx_decoder.h"
#include "vpx/vp8dx.h"

// Fuzz target entry point
extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  // Initialize the VP9 decoder
  vpx_codec_ctx_t codec;
  vpx_codec_dec_cfg_t cfg = {0};
  cfg.threads = 1;
  if (vpx_codec_dec_init(&codec, vpx_codec_vp9_dx(), &cfg, 0)) {
    return 0;
  }

  // Decode the frame
  vpx_codec_decode(&codec, data, size, NULL, 0);

  // Get decoded data
  vpx_codec_iter_t iter = NULL;
  const vpx_image_t *img = NULL;
  while ((img = vpx_codec_get_frame(&codec, &iter)) != NULL) {
    // Loop through decoded frames to exercise the decoder
  }

  // Clean up the decoder
  vpx_codec_destroy(&codec);

  return 0;
}