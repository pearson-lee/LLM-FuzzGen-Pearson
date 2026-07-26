#include <cstddef>
#include <cstdint>
#include <vector>
#include <string.h>

#include "vpx/vpx_decoder.h"
#include "vpx/vp8dx.h"
#include "fuzzer/FuzzedDataProvider.h"
#include "vpx/vpx_frame_buffer.h"
#include "vp9/common/vp9_enums.h"

// Define a simple struct to hold frame buffer data.
struct FrameBuffer {
  uint8_t *data;
  size_t size;
};

// Callback function to get a frame buffer.
static int get_fb(void *priv, size_t min_size, vpx_codec_frame_buffer_t *fb) {
  auto *fbs = static_cast<std::vector<FrameBuffer> *>(priv);
  FrameBuffer new_fb;
  new_fb.size = min_size;
  new_fb.data = new uint8_t[min_size];
  fbs->push_back(new_fb);
  fb->data = new_fb.data;
  fb->size = new_fb.size;
  fb->priv = &fbs->back();
  return 0;
}

// Callback function to release a frame buffer.
static int release_fb(void *priv, vpx_codec_frame_buffer_t *fb) {
  // The allocated data will be freed at the end of the fuzz input.
  (void)priv;
  (void)fb;
  return 0;
}

// Callback function for slice-based decoding.
static void put_slice_cb(void *user_priv, const vpx_image_t *img,
                         const vpx_image_rect_t *valid,
                         const vpx_image_rect_t *update) {
  (void)user_priv;
  (void)img;
  (void)valid;
  (void)update;
}

// Dummy callback for decryption.
static void decrypt_cb(void *state, const unsigned char *in, unsigned char *out,
                       int count) {
  // This is a dummy callback. In a real application, decryption would happen.
  // For fuzzing, we can just copy the data to simulate a valid operation.
  memcpy(out, in, count);
}

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  FuzzedDataProvider fdp(data, size);
  vpx_codec_iface_t *iface = vpx_codec_vp9_dx();
  vpx_codec_ctx_t codec;

  if (fdp.ConsumeBool()) {
    if (vpx_codec_dec_init(&codec, NULL, NULL, 0) == VPX_CODEC_OK) {
      vpx_codec_destroy(&codec);
    }
    return 0;
  }

  vpx_codec_dec_cfg_t cfg = {0};
  cfg.w = fdp.ConsumeIntegralInRange<unsigned int>(0, 4096);
  cfg.h = fdp.ConsumeIntegralInRange<unsigned int>(0, 4096);
  cfg.threads = fdp.ConsumeIntegralInRange<unsigned int>(1, 8);

  if (fdp.ConsumeIntegralInRange<int>(0, 9) == 0) {
    if (fdp.ConsumeBool()) {
      cfg.w = 0;
    } else {
      cfg.h = 0;
    }
  }

  if (vpx_codec_dec_init(&codec, iface, &cfg, 0) != VPX_CODEC_OK) {
    return 0;
  }

  std::vector<FrameBuffer> fbs;
  if (fdp.ConsumeBool()) {
    vpx_codec_set_frame_buffer_functions(&codec, get_fb, release_fb, &fbs);
  }

  if (fdp.ConsumeBool()) {
    vpx_codec_register_put_slice_cb(&codec, put_slice_cb, nullptr);
  }

  if (fdp.ConsumeBool()) {
    vpx_codec_control_(&codec, VP9_SET_SKIP_LOOP_FILTER, fdp.ConsumeIntegral<int>());
  }
  if (fdp.ConsumeBool()) {
    vpx_codec_control_(&codec, VP9D_SET_ROW_MT, fdp.ConsumeIntegral<int>());
  }
  if (fdp.ConsumeBool()) {
    vpx_codec_control_(&codec, VP9_INVERT_TILE_DECODE_ORDER, fdp.ConsumeIntegral<int>());
  }
  if (fdp.ConsumeBool()) {
    vpx_codec_control_(&codec, VP9D_SET_LOOP_FILTER_OPT, fdp.ConsumeIntegral<int>());
  }
  if (fdp.ConsumeBool()) {
    vpx_decrypt_init di;
    di.decrypt_cb = decrypt_cb;
    di.decrypt_state = nullptr;
    vpx_codec_control_(&codec, VPXD_SET_DECRYPTOR, &di);
  }
  if (fdp.ConsumeBool()) {
    vp8_postproc_cfg_t pp_cfg = {0};
    pp_cfg.post_proc_flag = fdp.ConsumeIntegral<int>();
    pp_cfg.deblocking_level = fdp.ConsumeIntegral<int>();
    pp_cfg.noise_level = fdp.ConsumeIntegral<int>();
    vpx_codec_control_(&codec, VP8_SET_POSTPROC, &pp_cfg);
  }

  const std::vector<uint8_t> frame = fdp.ConsumeRemainingBytes<uint8_t>();
  vpx_codec_decode(&codec, frame.data(), frame.size(), NULL, 0);

  vpx_codec_iter_t iter = NULL;
  vpx_image_t *img = NULL;
  while ((img = vpx_codec_get_frame(&codec, &iter)) != NULL) {
    // The image is owned by the decoder, so no freeing is necessary.
  }

  vpx_codec_destroy(&codec);

  // Free any memory allocated by the custom frame buffer callbacks.
  for (const auto& fb : fbs) {
    delete[] fb.data;
  }

  return 0;
}