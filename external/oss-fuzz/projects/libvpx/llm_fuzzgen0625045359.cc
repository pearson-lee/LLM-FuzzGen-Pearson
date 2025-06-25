#include <cstddef>
#include <cstdint>
#include <vector>
#include <string.h>
#include <fuzzer/FuzzedDataProvider.h>
#include "vpx/vpx_decoder.h"
#include "vpx/vp8dx.h"
#include "vpx/vpx_image.h"
#include "vpx/vp8.h"

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  FuzzedDataProvider fdp(data, size);

  // Initialize VP8 decoder
  vpx_codec_ctx_t vp8_decoder;
  vpx_codec_dec_cfg_t vp8_cfg = {0};
  vp8_cfg.threads = 1;
  vp8_cfg.w = fdp.ConsumeIntegralInRange<unsigned int>(16, 4096);
  vp8_cfg.h = fdp.ConsumeIntegralInRange<unsigned int>(16, 4096);

  // Enable post-processing during initialization.
  if (vpx_codec_dec_init(&vp8_decoder, vpx_codec_vp8_dx(), &vp8_cfg, VPX_CODEC_USE_POSTPROC)) {
    return 0;
  }

  // Set post-processing configuration *before* decoding any frames.
  vp8_postproc_cfg_t pp_cfg = {0};
  int post_proc_flag = 0;
  if (fdp.ConsumeBool()) {
    post_proc_flag |= VP8_DEBLOCK;
  }
  if (fdp.ConsumeBool()) {
    post_proc_flag |= VP8_DEMACROBLOCK;
  }
  if (fdp.ConsumeBool()) {
    post_proc_flag |= VP8_ADDNOISE;
  }
  pp_cfg.post_proc_flag = post_proc_flag;
  pp_cfg.deblocking_level = fdp.ConsumeIntegralInRange<int>(0, 16);
  pp_cfg.noise_level = fdp.ConsumeIntegralInRange<int>(0, 16);
  vpx_codec_control_(&vp8_decoder, 3, &pp_cfg);

  // Decode a frame to initialize the decoder's internal state.
  const size_t vp8_frame_size = fdp.ConsumeIntegralInRange<size_t>(0, fdp.remaining_bytes());
  std::vector<uint8_t> vp8_frame_data = fdp.ConsumeBytes<uint8_t>(vp8_frame_size);
  vpx_codec_decode(&vp8_decoder, vp8_frame_data.data(), vp8_frame_data.size(), nullptr, 0);

  // Check if a frame was actually decoded before proceeding.
  vpx_codec_iter_t iter = NULL;
  vpx_image_t *img = vpx_codec_get_frame(&vp8_decoder, &iter);

  // Added calls to uncovered functions based on coverage report.
  int ref_updates = 0;
  vpx_codec_control_(&vp8_decoder, 256, &ref_updates);
  int corrupted = 0;
  vpx_codec_control_(&vp8_decoder, 257, &corrupted);
  int ref_used = 0;
  vpx_codec_control_(&vp8_decoder, 258, &ref_used);
  vpx_codec_control_(&vp8_decoder, 8, nullptr);

  vpx_codec_destroy(&vp8_decoder);

  return 0;
}