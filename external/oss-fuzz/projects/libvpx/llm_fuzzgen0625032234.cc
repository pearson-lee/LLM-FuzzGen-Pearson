#include <cstddef>
#include <cstdint>
#include <vector>

#include "vpx/vpx_decoder.h"
#include "vpx/vp8dx.h"
#include "vpx/vp8.h"
#include <fuzzer/FuzzedDataProvider.h>

// Entry point for the fuzzer
extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  FuzzedDataProvider fdp(data, size);

  // Initialize the decoder configuration
  vpx_codec_ctx_t codec;
  vpx_codec_dec_cfg_t cfg = {0};
  cfg.threads = fdp.ConsumeIntegralInRange<unsigned int>(1, 4);

  // Initialize the decoder
  if (vpx_codec_dec_init(&codec, vpx_codec_vp8_dx(), &cfg, 0)) {
    return 0;
  }

  // Configure post-processing
  vp8_postproc_cfg_t pp_cfg = {0};
  pp_cfg.post_proc_flag = fdp.ConsumeIntegral<int>();
  pp_cfg.deblocking_level = fdp.ConsumeIntegral<int>();
  vpx_codec_control(&codec, VP8_SET_POSTPROC, &pp_cfg);

  // Loop to decode multiple frames, increasing the chance of a successful decode.
  const int num_frames = fdp.ConsumeIntegralInRange<int>(1, 5);
  for (int i = 0; i < num_frames; ++i) {
    const size_t frame_size = fdp.ConsumeIntegralInRange<size_t>(0, fdp.remaining_bytes());
    std::vector<uint8_t> frame_data = fdp.ConsumeBytes<uint8_t>(frame_size);
    if (vpx_codec_decode(&codec, frame_data.data(), frame_data.size(), nullptr,
                         0)) {
      // Failure to decode is a valid outcome.
      continue;
    }

    // Correctly iterate through decoded frames, which was a coverage gap.
    vpx_codec_iter_t iter = nullptr;
    vpx_image_t *img = nullptr;
    while ((img = vpx_codec_get_frame(&codec, &iter)) != nullptr) {
      // Set a reference frame to exercise more of the library.
      vpx_ref_frame_t ref_frame = {};
      ref_frame.frame_type = fdp.PickValueInArray<vpx_ref_frame_type_t>({VP8_LAST_FRAME, VP8_GOLD_FRAME, VP8_ALTR_FRAME});
      ref_frame.img = *img;
      vpx_codec_control(&codec, VP8_SET_REFERENCE, &ref_frame);
    }
  }

  // Destroy the decoder
  vpx_codec_destroy(&codec);

  return 0;
}