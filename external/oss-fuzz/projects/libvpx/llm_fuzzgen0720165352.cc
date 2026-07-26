#include <cstddef>
#include <cstdint>
#include <string>
#include <vector>
#include <memory>

#include "vpx/vpx_decoder.h"
#include "vpx/vp8dx.h"
#include "vpx/vpx_image.h"
#include "vpx_scale/yv12config.h"
#include "vp8/common/postproc.h"
#include "vpx/internal/vpx_codec_internal.h"
#include "vp8/decoder/onyxd_int.h"

#include <fuzzer/FuzzedDataProvider.h>

// A dummy callback function for vpx_codec_register_put_slice_cb
static void dummy_put_slice_cb(void *user_priv, const vpx_image_t *img,
                               const vpx_image_rect_t *valid,
                               const vpx_image_rect_t *update) {
  (void)user_priv;
  (void)img;
  (void)valid;
  (void)update;
}

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  FuzzedDataProvider fdp(data, size);

  // Initialize codec
  vpx_codec_ctx_t codec;
  vpx_codec_dec_cfg_t cfg = {0};
  cfg.w = fdp.ConsumeIntegralInRange<unsigned int>(1, 1280);
  cfg.h = fdp.ConsumeIntegralInRange<unsigned int>(1, 720);
  cfg.threads = 1;
  if (vpx_codec_dec_init(&codec, vpx_codec_vp8_dx(), &cfg, 0)) {
    return 0;
  }

  // Allocate a frame buffer
  YV12_BUFFER_CONFIG src_frame, dst_frame;
  memset(&src_frame, 0, sizeof(src_frame));
  memset(&dst_frame, 0, sizeof(dst_frame));

  if (vpx_alloc_frame_buffer(&src_frame, cfg.w, cfg.h, 1, 1, 0, 16, 32) != 0) {
    vpx_codec_destroy(&codec);
    return 0;
  }
  if (vpx_alloc_frame_buffer(&dst_frame, cfg.w, cfg.h, 1, 1, 0, 16, 32) != 0) {
    vpx_free_frame_buffer(&src_frame);
    vpx_codec_destroy(&codec);
    return 0;
  }

  // Fill the source frame with fuzzy data
  std::vector<uint8_t> frame_data = fdp.ConsumeBytes<uint8_t>(src_frame.frame_size);
  if (frame_data.size() == src_frame.frame_size) {
    memcpy(src_frame.buffer_alloc, frame_data.data(), frame_data.size());
  }

  /*
   * ANALYSIS: The function-level coverage report showed vp8_post_proc_frame
   *           had very low coverage. The line-level report confirmed this was
   *           due to the majority of branches not being taken.
   * IMPLEMENTATION: The following code block calls vp8_post_proc_frame with
   *                 fuzzed flags to exercise more of the conditional logic.
   */
  vp8_ppflags_t ppflags = {0};
  ppflags.post_proc_flag = fdp.ConsumeIntegral<int>();
  ppflags.deblocking_level = fdp.ConsumeIntegralInRange<int>(0, 10);
  ppflags.noise_level = fdp.ConsumeIntegralInRange<int>(0, 10);
  if (codec.priv) {
    VP8D_COMP *pbi = (VP8D_COMP *)codec.priv;
    pbi->common.frame_to_show = &src_frame;
    vp8_post_proc_frame(&pbi->common, &dst_frame, &ppflags);
  }

  /*
   * ANALYSIS: The function-level coverage report showed vpx_img_wrap had
   *           0% coverage.
   * IMPLEMENTATION: The following code block calls vpx_img_wrap with fuzzed
   *                 image parameters to exercise this function.
   */
  vpx_image_t img;
  memset(&img, 0, sizeof(img));
  vpx_img_fmt_t fmt = fdp.PickValueInArray({VPX_IMG_FMT_I420, VPX_IMG_FMT_I444, VPX_IMG_FMT_YV12});
  unsigned int d_w = fdp.ConsumeIntegralInRange<unsigned int>(1, 1280);
  unsigned int d_h = fdp.ConsumeIntegralInRange<unsigned int>(1, 720);
  unsigned int stride_align = fdp.ConsumeIntegralInRange<unsigned int>(1, 64);
  std::vector<uint8_t> img_data(d_w * d_h * 3 / 2);
  if (img_data.size() > 0) {
    vpx_img_wrap(&img, fmt, d_w, d_h, stride_align, img_data.data());
  }

  /*
   * ANALYSIS: The function-level coverage report showed vpx_codec_register_put_slice_cb
   *           had 0% coverage.
   * IMPLEMENTATION: The following code block calls vpx_codec_register_put_slice_cb with a
   *                 dummy callback to exercise this function.
   */
  vpx_codec_register_put_slice_cb(&codec, dummy_put_slice_cb, nullptr);

  // Free resources
  if (img.img_data) {
    vpx_img_free(&img);
  }
  vpx_free_frame_buffer(&src_frame);
  vpx_free_frame_buffer(&dst_frame);
  vpx_codec_destroy(&codec);

  return 0;
}