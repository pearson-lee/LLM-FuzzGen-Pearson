#include <cstddef>
#include <cstdint>
#include <vector>
#include <string.h>
#include <fuzzer/FuzzedDataProvider.h>
#include "/src/libvpx/vpx/vpx_decoder.h"
#include "/src/libvpx/vpx/vp8dx.h"
#include "/src/libvpx/vpx/vp8.h"
#include "/src/libvpx/vpx/vpx_image.h"
#include "/src/libvpx/vp9/common/vp9_enums.h"

// Fuzz target entry point
extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  FuzzedDataProvider fdp(data, size);

  // Added VP8 decoding to improve coverage in the vp8 directory.
  const vpx_codec_iface_t *iface = fdp.ConsumeBool() ? vpx_codec_vp9_dx() : vpx_codec_vp8_dx();

  // Initialize the decoder
  vpx_codec_ctx_t codec;
  vpx_codec_dec_cfg_t cfg = {0};
  cfg.threads = 1;
  // Added call with NULL interface to trigger error handling path.
  if (fdp.ConsumeBool()) {
    if (vpx_codec_dec_init(nullptr, iface, &cfg, 0) == VPX_CODEC_OK) {
      return 0;
    }
  }
  if (vpx_codec_dec_init(&codec, iface, &cfg, 0) != VPX_CODEC_OK) {
    return 0;
  }

  // Added call to vp8_set_decryptor to improve coverage.
  if (iface == vpx_codec_vp8_dx()) {
    if (fdp.ConsumeBool()) {
      vpx_decrypt_init di;
      di.decrypt_cb = nullptr;
      di.decrypt_state = nullptr;
      vpx_codec_control_(&codec, VP8D_SET_DECRYPTOR, &di);
    }
  }

  // Prepend a valid frame header to the input data to increase the chances of
  // vpx_codec_decode producing a frame. This helps to get inside the
  // `if (decoded_img)` block, which was previously dead code.
  std::vector<uint8_t> frame_data;
  if (iface == vpx_codec_vp8_dx()) {
    // VP8 keyframe header
    frame_data = {0x9d, 0x01, 0x2a, 0x01, 0x00};
  } else {
    // VP9 keyframe header
    frame_data = {0x82, 0x49, 0x83, 0x42, 0x00, 0x01, 0x00, 0x01, 0x00};
  }
  std::vector<uint8_t> remaining_data = fdp.ConsumeRemainingBytes<uint8_t>();
  frame_data.insert(frame_data.end(), remaining_data.begin(), remaining_data.end());

  // Decode the frame
  vpx_codec_decode(&codec, frame_data.data(), frame_data.size(), NULL, 0);

  // Relocated and added control calls to ensure execution, as the vpx_codec_get_frame loop is never entered.
  if (iface == vpx_codec_vp8_dx()) {
    // Call to uncovered vp8_set_postproc function based on coverage report.
    // The true branch of this if statement was not previously covered.
    if (fdp.ConsumeBool()) {
      vp8_postproc_cfg_t pp_cfg = {};
      pp_cfg.post_proc_flag = fdp.ConsumeIntegral<int>();
      pp_cfg.deblocking_level = fdp.ConsumeIntegral<int>();
      pp_cfg.noise_level = fdp.ConsumeIntegral<int>();
      vpx_codec_control_(&codec, VP8_SET_POSTPROC, &pp_cfg);
    } else {
      // Added call with NULL data to cover the else branch in vp8_set_postproc.
      vpx_codec_control_(&codec, VP8_SET_POSTPROC, NULL);
    }

    // Added calls to improve coverage in vp8_dx_iface.c.
    int updated = 0;
    vpx_codec_control_(&codec, VP8D_GET_LAST_REF_UPDATES, &updated);
    int corrupted = 0;
    vpx_codec_control_(&codec, VP8D_GET_FRAME_CORRUPTED, &corrupted);
    int ref_used = 0;
    vpx_codec_control_(&codec, VP8D_GET_LAST_REF_USED, &ref_used);

    // Added calls to cover vp8_set_reference. This call is only safe if a
    // frame has been decoded, which initializes internal state.
    vpx_codec_iter_t iter = NULL;
    const vpx_image_t *decoded_img = vpx_codec_get_frame(&codec, &iter);
    if (decoded_img) {
      vpx_image_t img;
      memset(&img, 0, sizeof(vpx_image_t));
      if (vpx_img_alloc(&img, decoded_img->fmt, decoded_img->d_w,
                        decoded_img->d_h, 1)) {
        vpx_ref_frame_t ref_frame = {};
        ref_frame.frame_type = static_cast<vpx_ref_frame_type_t>(
            fdp.ConsumeIntegralInRange<int>(VP8_LAST_FRAME, VP8_ALTR_FRAME));
        ref_frame.img = img;
        vpx_codec_control_(&codec, VP8_SET_REFERENCE, &ref_frame);
        vpx_img_free(&img);
      }
    }
  } else if (iface == vpx_codec_vp9_dx()) {
    // Call VP9_GET_REFERENCE to improve coverage.
    vp9_ref_frame_t ref_frame = {};
    ref_frame.idx = fdp.ConsumeIntegralInRange<int>(0, 7);
    vpx_codec_control_(&codec, VP9_GET_REFERENCE, &ref_frame);

    // Added calls to improve coverage in vp9_dx_iface.c.
    int q = 0;
    vpx_codec_control_(&codec, VPXD_GET_LAST_QUANTIZER, &q);
    int frame_size[2] = {0};
    vpx_codec_control_(&codec, VP9D_GET_FRAME_SIZE, frame_size);
    int display_size[2] = {0};
    vpx_codec_control_(&codec, VP9D_GET_DISPLAY_SIZE, display_size);
    unsigned int bit_depth = 0;
    vpx_codec_control_(&codec, VP9D_GET_BIT_DEPTH, &bit_depth);
    vpx_codec_control_(&codec, VP9_INVERT_TILE_DECODE_ORDER, fdp.ConsumeBool());
    vpx_codec_control_(&codec, VP9_SET_BYTE_ALIGNMENT, fdp.ConsumeIntegral<int>());
    // Set skip_loop_filter to 0 to ensure loop filter is not skipped, improving coverage.
    vpx_codec_control_(&codec, VP9_SET_SKIP_LOOP_FILTER, 0);
  }

  // Clean up the decoder
  vpx_codec_destroy(&codec);

  return 0;
}