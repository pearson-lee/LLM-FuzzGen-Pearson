#include <cstddef>
#include <cstdint>

#include "vpx/vpx_decoder.h"
#include "vpx/vp8dx.h"
#include <fuzzer/FuzzedDataProvider.h>

// Entry point for the fuzzer
extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  FuzzedDataProvider fdp(data, size);

  // Decide which codec to use, VP8 or VP9
  const bool use_vp9 = fdp.ConsumeBool();
  vpx_codec_iface_t *codec_iface =
      use_vp9 ? vpx_codec_vp9_dx() : vpx_codec_vp8_dx();

  // Initialize the decoder
  vpx_codec_ctx_t codec_ctx;
  vpx_codec_dec_cfg_t dec_cfg = {0, 0, 0};
  if (vpx_codec_dec_init(&codec_ctx, codec_iface, &dec_cfg, 0)) {
    return 0;
  }

  // Use FuzzedDataProvider to enable some decoder features randomly.
  // This helps to exercise more code paths.
  if (use_vp9) {
    // VP9 specific controls
    vpx_codec_control(&codec_ctx, VP9_SET_SKIP_LOOP_FILTER, fdp.ConsumeBool());
    vpx_codec_control(&codec_ctx, VP9_SET_BYTE_ALIGNMENT, fdp.ConsumeBool());
    vpx_codec_control(&codec_ctx, VP9_INVERT_TILE_DECODE_ORDER, fdp.ConsumeBool());
    vpx_codec_control(&codec_ctx, VP9D_SET_ROW_MT, fdp.ConsumeBool());
    vpx_codec_control(&codec_ctx, VP9D_SET_LOOP_FILTER_OPT, fdp.ConsumeBool());
  } else {
    // VP8 specific controls
    vp8_postproc_cfg_t pp_cfg = {};
    pp_cfg.post_proc_flag = fdp.ConsumeIntegral<int>();
    pp_cfg.deblocking_level = fdp.ConsumeIntegralInRange<int>(0, 16);
    pp_cfg.noise_level = fdp.ConsumeIntegralInRange<int>(0, 16);
    vpx_codec_control(&codec_ctx, VP8_SET_POSTPROC, &pp_cfg);
  }

  // Consume the rest of the data as video data
  std::vector<uint8_t> video_data = fdp.ConsumeRemainingBytes<uint8_t>();

  // Decode the video data
  vpx_codec_decode(&codec_ctx, video_data.data(), video_data.size(), nullptr, 0);

  // Get the decoded frames
  vpx_codec_iter_t iter = nullptr;
  vpx_image_t *img = nullptr;
  while ((img = vpx_codec_get_frame(&codec_ctx, &iter)) != nullptr) {
    // The image is owned by the decoder, so we don't need to free it.
    // We can do some operations on the image here if needed.
  }

  // Destroy the decoder context to free all allocated resources.
  vpx_codec_destroy(&codec_ctx);

  return 0;
}