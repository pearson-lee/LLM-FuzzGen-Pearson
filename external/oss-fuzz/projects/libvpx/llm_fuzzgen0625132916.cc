#include <cstddef>
#include <cstdint>
#include <string.h>
#include <vector>
#include <algorithm>

#include "vpx/vpx_decoder.h"
#include "vpx/vp8dx.h"
#include "vpx/vpx_codec.h"
#include "vpx/vpx_image.h"
#include "vpx/vp8.h"
#include "vp9/vp9_dx_iface.h"

#include <fuzzer/FuzzedDataProvider.h>

// Dummy decryptor callback to improve coverage of VP9D_SET_DECRYPTOR
static void dummy_decrypt_cb(void *ctx, const unsigned char *in, unsigned char *out, int count) {
  (void)ctx;
  (void)in;
  (void)out;
  (void)count;
}

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  FuzzedDataProvider fdp(data, size);

  // Initialize VP9 decoder
  vpx_codec_ctx_t vp9_codec;
  if (vpx_codec_dec_init(&vp9_codec, vpx_codec_vp9_dx(), NULL, 0)) {
    return 0;
  }

  // Exercise other VP9 control functions
  int row_mt = fdp.ConsumeBool();
  vpx_codec_control(&vp9_codec, VP9D_SET_ROW_MT, row_mt);
  int loop_filter_opt = fdp.ConsumeBool();
  vpx_codec_control(&vp9_codec, VP9D_SET_LOOP_FILTER_OPT, loop_filter_opt);

  // Added to improve coverage of vp9_dx_iface.c:ctrl_set_decryptor
  vpx_decrypt_init di;
  di.decrypt_cb = dummy_decrypt_cb;
  di.decrypt_state = nullptr;
  vpx_codec_control(&vp9_codec, VPXD_SET_DECRYPTOR, &di);

  // Added to improve coverage of vp9_dx_iface.c:ctrl_set_spatial_layer_svc
  int spatial_layer = fdp.ConsumeIntegralInRange<int>(0, 5);
  vpx_codec_control(&vp9_codec, VP9_DECODE_SVC_SPATIAL_LAYER, spatial_layer);

  // Decode a VP9 frame
  size_t vp9_frame_size = fdp.ConsumeIntegralInRange<size_t>(0, fdp.remaining_bytes());
  std::vector<uint8_t> vp9_frame_data = fdp.ConsumeBytes<uint8_t>(vp9_frame_size);
  vpx_codec_decode(&vp9_codec, vp9_frame_data.data(), vp9_frame_data.size(), NULL, 0);
  
  // Added to improve coverage of vp9_dx_iface.c:ctrl_get_frame_size
  int frame_size[2];
  vpx_codec_control(&vp9_codec, VP9D_GET_FRAME_SIZE, frame_size);

  // Added to improve coverage of vp9_dx_iface.c:ctrl_copy_reference
  vp9_ref_frame_t vp9_ref_frame;
  vp9_ref_frame.idx = fdp.ConsumeIntegralInRange<int>(0, 7);
  vpx_codec_control(&vp9_codec, VP9_GET_REFERENCE, &vp9_ref_frame);

  // Cleanup VP9 decoder
  vpx_codec_destroy(&vp9_codec);

  // Initialize VP8 decoder
  vpx_codec_ctx_t vp8_codec;
  if (vpx_codec_dec_init(&vp8_codec, vpx_codec_vp8_dx(), NULL, 0)) {
    return 0;
  }

  // Added to improve coverage of vp8_peek_si and related functions
  vpx_codec_stream_info_t si;
  si.sz = sizeof(si);
  if (vpx_codec_peek_stream_info(vpx_codec_vp8_dx(), data, size, &si) != VPX_CODEC_OK) {
    vpx_codec_destroy(&vp8_codec);
    return 0;
  }
  
  // Added to improve coverage of vp8_get_si
  vpx_codec_stream_info_t si_after;
  si_after.sz = sizeof(si_after);
  vpx_codec_get_stream_info(&vp8_codec, &si_after);

  // Decode a VP8 frame to initialize decoder's internal state
  std::vector<uint8_t> vp8_frame_data = fdp.ConsumeRemainingBytes<uint8_t>();
  vpx_codec_decode(&vp8_codec, vp8_frame_data.data(), vp8_frame_data.size(), NULL, 0);

  // Check if a frame was decoded, which is required for reference frames to exist.
  vpx_codec_iter_t iter = NULL;
  vpx_image_t *img = NULL;
  bool frame_decoded = false;
  while ((img = vpx_codec_get_frame(&vp8_codec, &iter)) != NULL) {
    frame_decoded = true;
  }

  if (frame_decoded) {
    // Copy a reference frame from the decoder, modify it, and set it back.
    vpx_ref_frame_t ref_frame;
    memset(&ref_frame, 0, sizeof(ref_frame));
    ref_frame.frame_type = (vpx_ref_frame_type_t)fdp.ConsumeIntegralInRange<int>(VP8_LAST_FRAME, VP8_GOLD_FRAME);

    if (vpx_codec_control(&vp8_codec, VP8_COPY_REFERENCE, &ref_frame) == VPX_CODEC_OK) {
      // Fuzz the contents of the copied reference frame.
      for (int plane = 0; plane < 3; ++plane) {
        if (ref_frame.img.planes[plane]) {
          const unsigned int plane_w = (plane == 0) ? ref_frame.img.w : (ref_frame.img.w + 1) / 2;
          const unsigned int plane_h = (plane == 0) ? ref_frame.img.h : (ref_frame.img.h + 1) / 2;
          const size_t plane_size = plane_w * plane_h;
          std::vector<uint8_t> plane_data = fdp.ConsumeBytes<uint8_t>(plane_size);
          if (!plane_data.empty()) {
            memcpy(ref_frame.img.planes[plane], plane_data.data(), plane_data.size());
          }
        }
      }

      // Give the modified reference frame back to the decoder.
      vpx_codec_control(&vp8_codec, VP8_SET_REFERENCE, &ref_frame);

      // Free the buffer allocated by VP8_COPY_REFERENCE.
      vpx_img_free(&ref_frame.img);
    }
  }

  // Exercise VP8 post-processing control function
  vp8_postproc_cfg_t pp_cfg;
  // Use valid flags to improve coverage of postproc.c
  pp_cfg.post_proc_flag = fdp.ConsumeIntegralInRange<int>(0, VP8_MFQE | VP8_DEBLOCK | VP8_DEMACROBLOCK | VP8_ADDNOISE);
  pp_cfg.deblocking_level = fdp.ConsumeIntegralInRange<int>(0, 15);
  pp_cfg.noise_level = fdp.ConsumeIntegralInRange<int>(0, 15);
  vpx_codec_control(&vp8_codec, VP8_SET_POSTPROC, &pp_cfg);

  // Added to improve coverage of vp8_dx_iface.c
  int updates = 0;
  vpx_codec_control(&vp8_codec, VP8D_GET_LAST_REF_UPDATES, &updates);
  int corrupted = 0;
  vpx_codec_control(&vp8_codec, VP8D_GET_FRAME_CORRUPTED, &corrupted);
  int last_ref = 0;
  vpx_codec_control(&vp8_codec, VP8D_GET_LAST_REF_USED, &last_ref);

  // Cleanup VP8 decoder
  vpx_codec_destroy(&vp8_codec);

  return 0;
}