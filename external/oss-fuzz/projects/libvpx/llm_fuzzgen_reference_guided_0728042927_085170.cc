/* BLOCKER_STRATEGY_CONTRACT
required_state: The `vpx_image_t` object passed to `vpx_img_set_rect` must have its `fmt` field contain the `VPX_IMG_FMT_HAS_ALPHA` flag.
state_constructor: The `vpx_img_wrap` function is called with a `vpx_img_fmt_t` that is constructed by bitwise OR-ing a base image format (like `VPX_IMG_FMT_I420`) with `VPX_IMG_FMT_HAS_ALPHA`. This is selected from an expanded list of formats. The image data buffer is made large enough (`d_w * d_h * 4`) to accommodate the extra alpha plane.
trigger_api: `vpx_img_wrap()` is called, which internally calls `vpx_img_set_rect(img, 0, 0, d_w, d_h)`.
preserved_invariants: The fuzz target's input consumption order and overall API call sequence (`vpx_img_wrap`, `vpx_codec_dec_init_ver`, `vpx_codec_decode`, etc.) are preserved. The core logic of creating an image, initializing a decoder, and decoding a frame remains intact. END_BLOCKER_STRATEATEGY_CONTRACT
END_BLOCKER_STRATEGY_CONTRACT */

#include <cstddef>
#include <cstdint>
#include <memory>
#include <vector>
#include <fuzzer/FuzzedDataProvider.h>
#include "vpx/vpx_encoder.h"
#include "vpx/vp8cx.h"
#include "vpx/vpx_image.h"
#include "vpx/vpx_decoder.h"
#include "vpx/vp8dx.h"
#include "vpx/vp8.h"

// Dummy callback function for slice data
static void put_slice_cb(void *user_priv, const vpx_image_t *img,
                         const vpx_image_rect_t *valid,
                         const vpx_image_rect_t *update) {
  (void)user_priv;
  (void)img;
  (void)valid;
  (void)update;
}

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  FuzzedDataProvider fdp(data, size);

  vpx_image_t img;
  // Add image formats with an alpha channel to hit the blocker.
  const vpx_img_fmt_t fmt = fdp.PickValueInArray(
      {(vpx_img_fmt_t)VPX_IMG_FMT_I420, (vpx_img_fmt_t)VPX_IMG_FMT_I422,
       (vpx_img_fmt_t)VPX_IMG_FMT_I444, (vpx_img_fmt_t)VPX_IMG_FMT_I440,
       (vpx_img_fmt_t)VPX_IMG_FMT_NV12,
       (vpx_img_fmt_t)(VPX_IMG_FMT_I420 | VPX_IMG_FMT_HAS_ALPHA),
       (vpx_img_fmt_t)(VPX_IMG_FMT_I444 | VPX_IMG_FMT_HAS_ALPHA)});
  const unsigned int d_w = fdp.ConsumeIntegralInRange<unsigned int>(1, 128);
  const unsigned int d_h = fdp.ConsumeIntegralInRange<unsigned int>(1, 128);
  const unsigned int stride_align =
      fdp.ConsumeIntegralInRange<unsigned int>(1, 32);
  // Increase image data size to accommodate formats with an alpha channel.
  // 4 bytes per pixel is a safe upper bound for I444A.
  const size_t img_data_size = d_w * d_h * 4;
  if (img_data_size == 0) {
    return 0;
  }
  uint8_t *img_data = new uint8_t[img_data_size];
  const size_t consumed_bytes = fdp.ConsumeData(img_data, img_data_size);
  if (consumed_bytes != img_data_size) {
    delete[] img_data;
    return 0;
  }
  vpx_img_wrap(&img, fmt, d_w, d_h, stride_align, img_data);

  vpx_codec_iface_t *iface = vpx_codec_vp8_dx();
  vpx_codec_ctx_t codec;
  if (vpx_codec_dec_init_ver(&codec, iface, nullptr, 0, VPX_DECODER_ABI_VERSION) !=
      VPX_CODEC_OK) {
    delete[] img_data;
    return 0;
  }

  /*
   * ANALYSIS: The function-level coverage report from the initial run showed
   *           that functions related to post-processing, such as those in
   *           'postproc.c' and the 'VP8_SET_POSTPROC' control, were completely
   *           uncovered.
   * IMPLEMENTATION: The following block is added to enable post-processing
   *                 based on fuzzer input. It populates a 'vp8_postproc_cfg_t'
   *                 structure with data from the FuzzedDataProvider and then
   *                 calls 'vpx_codec_control_' with the 'VP8_SET_POSTPROC'
   *                 control ID. This directly targets the uncovered post-processing
   *                 code paths.
   */
  if (fdp.ConsumeBool()) {
    vp8_postproc_cfg_t cfg;
    cfg.post_proc_flag = fdp.ConsumeIntegral<int>();
    cfg.deblocking_level = fdp.ConsumeIntegral<int>();
    cfg.noise_level = fdp.ConsumeIntegral<int>();
    vpx_codec_control_(&codec, VP8_SET_POSTPROC, &cfg);
  }

  vpx_codec_register_put_slice_cb(&codec, put_slice_cb, nullptr);

  std::vector<uint8_t> decode_data = fdp.ConsumeRemainingBytes<uint8_t>();
  const long deadline = fdp.ConsumeIntegral<long>();
  vpx_codec_decode(&codec, decode_data.data(), decode_data.size(), nullptr,
                   deadline);

  /*
   * ANALYSIS: The function-level coverage report also indicated that several
   *           decoder control functions for getting state information were
   *           not being exercised. Specifically, 'VP8D_GET_LAST_REF_UPDATES'
   *           and 'VP8D_GET_FRAME_CORRUPTED' had zero coverage.
   * IMPLEMENTATION: These calls are added to query the decoder state after a
   *                 decode call. This exercises the logic within the decoder
   *                 to check and report if the frame was corrupted or if
   *                 reference frames were updated, improving coverage in the
   *                 decoder interface and state management functions.
   */
  int corrupted = 0;
  vpx_codec_control_(&codec, VP8D_GET_FRAME_CORRUPTED, &corrupted);
  int ref_updates = 0;
  vpx_codec_control_(&codec, VP8D_GET_LAST_REF_UPDATES, &ref_updates);

  vpx_codec_destroy(&codec);
  delete[] img_data;

  return 0;
}
