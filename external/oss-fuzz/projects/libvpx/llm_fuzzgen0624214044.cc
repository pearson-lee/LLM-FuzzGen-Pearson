#include <cstddef>
#include <cstdint>
#include <vector>
#include <fuzzer/FuzzedDataProvider.h>
#include "/src/libvpx/vpx/vpx_decoder.h"
#include "/src/libvpx/vpx/vp8dx.h"
#include "/src/libvpx/vpx/vp8.h"
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
  if (vpx_codec_dec_init(&codec, iface, &cfg, 0)) {
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

  // Decode the frame
  vpx_codec_decode(&codec, data, size, NULL, 0);

  // Relocated and added control calls to ensure execution, as the vpx_codec_get_frame loop is never entered.
  if (iface == vpx_codec_vp8_dx()) {
    // Call to uncovered vp8_set_postproc function based on coverage report.
    vp8_postproc_cfg_t pp_cfg = {};
    pp_cfg.post_proc_flag = fdp.ConsumeIntegral<int>();
    pp_cfg.deblocking_level = fdp.ConsumeIntegral<int>();
    pp_cfg.noise_level = fdp.ConsumeIntegral<int>();
    vpx_codec_control_(&codec, VP8_SET_POSTPROC, &pp_cfg);

    // Added calls to improve coverage in vp8_dx_iface.c.
    int updated = 0;
    vpx_codec_control_(&codec, VP8D_GET_LAST_REF_UPDATES, &updated);
    int corrupted = 0;
    vpx_codec_control_(&codec, VP8D_GET_FRAME_CORRUPTED, &corrupted);
    int ref_used = 0;
    vpx_codec_control_(&codec, VP8D_GET_LAST_REF_USED, &ref_used);
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
    vpx_codec_control_(&codec, VP9_SET_SKIP_LOOP_FILTER, fdp.ConsumeBool());
  }

  // Clean up the decoder
  vpx_codec_destroy(&codec);

  return 0;
}