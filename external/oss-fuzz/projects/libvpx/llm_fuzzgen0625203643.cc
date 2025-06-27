#include <cstddef>
#include <cstdint>
#include <memory>
#include <vector>
#include <string.h>
#include <fuzzer/FuzzedDataProvider.h>

#include "vpx/vpx_decoder.h"
#include "vpx/vp8dx.h"

// RAII wrapper for vpx_codec_ctx_t
struct VpxCodecCtx {
  vpx_codec_ctx_t *ctx = nullptr;
  VpxCodecCtx() {
    ctx = new vpx_codec_ctx_t();
    vpx_codec_dec_cfg_t cfg = {0};
    cfg.threads = 1;
    if (vpx_codec_dec_init(ctx, vpx_codec_vp8_dx(), &cfg, 0)) {
      delete ctx;
      ctx = nullptr;
    }
  }
  ~VpxCodecCtx() {
    if (ctx) {
      vpx_codec_destroy(ctx);
      delete ctx;
    }
  }
};

// RAII wrapper for vpx_image_t
struct VpxImage {
  vpx_image_t *img = nullptr;
  VpxImage() {
    img = new vpx_image_t();
    memset(img, 0, sizeof(vpx_image_t));
  }
  ~VpxImage() {
    if (img) {
      vpx_img_free(img);
      delete img;
    }
  }
};

// Callback functions for frame buffer management
static int get_frame_buffer(void *priv, size_t min_size,
                            vpx_codec_frame_buffer_t *fb) {
  // Allocate a frame buffer
  uint8_t *buffer = new uint8_t[min_size];
  if (!buffer) {
    return -1;
  }
  fb->data = buffer;
  fb->size = min_size;
  fb->priv = priv;
  return 0;
}

static int release_frame_buffer(void *priv, vpx_codec_frame_buffer_t *fb) {
  // Free the frame buffer
  if (fb->data) {
    delete[] static_cast<uint8_t *>(fb->data);
  }
  return 0;
}

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  FuzzedDataProvider fdp(data, size);
  VpxCodecCtx codec;
  if (!codec.ctx) {
    return 0;
  }

  // Set frame buffer functions
  if (vpx_codec_set_frame_buffer_functions(codec.ctx, get_frame_buffer,
                                           release_frame_buffer, nullptr)) {
    return 0;
  }

  // Create and set a reference frame
  VpxImage ref_img;
  if (!ref_img.img) {
    return 0;
  }
  if (!vpx_img_alloc(ref_img.img, VPX_IMG_FMT_I420,
                   fdp.ConsumeIntegralInRange<unsigned int>(1, 1280),
                   fdp.ConsumeIntegralInRange<unsigned int>(1, 720), 16)) {
    return 0;
  }

  vpx_ref_frame_t ref_frame;
  memset(&ref_frame, 0, sizeof(ref_frame));
  const vpx_ref_frame_type_t frame_types[] = {VP8_LAST_FRAME, VP8_GOLD_FRAME,
                                              VP8_ALTR_FRAME};
  ref_frame.frame_type = fdp.PickValueInArray(frame_types);
  ref_frame.img = *ref_img.img;
  vpx_codec_control(codec.ctx, VP8_SET_REFERENCE, &ref_frame);

  // Create and copy a reference frame
  VpxImage copy_img;
  if (!copy_img.img) {
    return 0;
  }
  if (!vpx_img_alloc(copy_img.img, VPX_IMG_FMT_I420,
                   fdp.ConsumeIntegralInRange<unsigned int>(1, 1280),
                   fdp.ConsumeIntegralInRange<unsigned int>(1, 720), 16)) {
    return 0;
  }

  vpx_ref_frame_t copy_frame;
  memset(&copy_frame, 0, sizeof(copy_frame));
  copy_frame.frame_type = fdp.PickValueInArray(frame_types);
  copy_frame.img = *copy_img.img;
  vpx_codec_control(codec.ctx, VP8_COPY_REFERENCE, &copy_frame);

  // Decode some data
  const std::vector<uint8_t> decode_data =
      fdp.ConsumeRemainingBytes<uint8_t>();
  vpx_codec_decode(codec.ctx, decode_data.data(), decode_data.size(), nullptr, 0);

  return 0;
}