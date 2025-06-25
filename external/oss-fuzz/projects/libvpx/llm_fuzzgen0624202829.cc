#include <cstddef>
#include <cstdint>
#include <vector>
#include <fuzzer/FuzzedDataProvider.h>
#include "vpx/vpx_decoder.h"
#include "vpx/vp8dx.h"
#include "vpx/vp8.h"

// Fuzz target entry point
extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  FuzzedDataProvider fdp(data, size);

  // Added VP8 decoding to improve coverage in the vp8 directory.
  const vpx_codec_iface_t *iface = fdp.ConsumeBool() ? vpx_codec_vp9_dx() : vpx_codec_vp8_dx();

  // Initialize the decoder
  vpx_codec_ctx_t codec;
  vpx_codec_dec_cfg_t cfg = {0};
  cfg.threads = 1;
  if (vpx_codec_dec_init(&codec, iface, &cfg, 0)) {
    return 0;
  }

  // Added call to uncovered vp8_set_postproc function based on coverage report.
  if (iface == vpx_codec_vp8_dx()) {
    vp8_postproc_cfg_t pp_cfg = {};
    pp_cfg.post_proc_flag = fdp.ConsumeIntegral<int>();
    pp_cfg.deblocking_level = fdp.ConsumeIntegral<int>();
    pp_cfg.noise_level = fdp.ConsumeIntegral<int>();
    vpx_codec_control_(&codec, VP8_SET_POSTPROC, &pp_cfg);
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