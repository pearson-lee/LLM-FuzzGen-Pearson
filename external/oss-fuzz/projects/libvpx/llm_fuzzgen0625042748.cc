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
  vpx_codec_control(&vp8_decoder, VP8_SET_POSTPROC, &pp_cfg);

  // Decode a frame to initialize the decoder's internal state.
  const size_t vp8_frame_size = fdp.ConsumeIntegralInRange<size_t>(0, fdp.remaining_bytes());
  std::vector<uint8_t> vp8_frame_data = fdp.ConsumeBytes<uint8_t>(vp8_frame_size);
  vpx_codec_decode(&vp8_decoder, vp8_frame_data.data(), vp8_frame_data.size(), nullptr, 0);

  // Check if a frame was actually decoded before proceeding.
  vpx_codec_iter_t iter = NULL;
  vpx_image_t *img = vpx_codec_get_frame(&vp8_decoder, &iter);
  if (img == NULL) {
    vpx_codec_destroy(&vp8_decoder);
    return 0;
  }

  // Create a reference frame for VP8.
  vpx_image_t vp8_ref_img;
  if (!vpx_img_alloc(&vp8_ref_img, VPX_IMG_FMT_I420, vp8_cfg.w, vp8_cfg.h, 1)) {
    vpx_codec_destroy(&vp8_decoder);
    return 0;
  }

  // Fill the VP8 reference frame with fuzzer data.
  for (int plane = 0; plane < 3; ++plane) {
    unsigned char *buf = vp8_ref_img.planes[plane];
    const int stride = vp8_ref_img.stride[plane];
    const int w = (plane == 0) ? vp8_ref_img.d_w : (vp8_ref_img.d_w + 1) / 2;
    const int h = (plane == 0) ? vp8_ref_img.d_h : (vp8_ref_img.d_h + 1) / 2;
    for (int y = 0; y < h; ++y) {
      std::vector<uint8_t> row_data = fdp.ConsumeBytes<uint8_t>(w);
      if (row_data.size() < w) {
        continue;
      }
      memcpy(buf + y * stride, row_data.data(), w);
    }
  }

  // Call VP8 reference frame functions.
  vpx_ref_frame_t vp8_ref;
  memset(&vp8_ref, 0, sizeof(vp8_ref));
  const vpx_ref_frame_type_t valid_frame_types[] = {VP8_LAST_FRAME, VP8_GOLD_FRAME, VP8_ALTR_FRAME};
  vp8_ref.frame_type = fdp.PickValueInArray(valid_frame_types);
  vp8_ref.img = vp8_ref_img;
  vpx_codec_control(&vp8_decoder, VP8_SET_REFERENCE, &vp8_ref);
  vpx_codec_control(&vp8_decoder, VP8_COPY_REFERENCE, &vp8_ref);

  vpx_img_free(&vp8_ref_img);
  vpx_codec_destroy(&vp8_decoder);

  return 0;
}