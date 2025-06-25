#include <cstddef>
#include <cstdint>
#include <vector>
#include <cstring>
#include <fuzzer/FuzzedDataProvider.h>
#include "/src/libvpx/vpx/vpx_decoder.h"
#include "/src/libvpx/vpx/vp8dx.h"
#include "/src/libvpx/vpx/vp8.h"
#include "/src/libvpx/vpx/vpx_image.h"

// A RAII wrapper to create and manage a vpx_image_t and its buffer.
struct ScopedVpxImage {
  std::vector<uint8_t> buffer;

  ScopedVpxImage(vpx_image_t *img, FuzzedDataProvider &fdp) {
    memset(img, 0, sizeof(*img));
    const unsigned int width = fdp.ConsumeIntegralInRange<unsigned int>(1, 4096);
    const unsigned int height = fdp.ConsumeIntegralInRange<unsigned int>(1, 4096);
    const unsigned int align = 1;
    const vpx_img_fmt_t fmt = VPX_IMG_FMT_I420;

    const size_t image_size = (width * height * 3) / 2;
    buffer = fdp.ConsumeBytes<uint8_t>(image_size);
    if (buffer.size() < image_size) {
      buffer.resize(image_size, 0);
    }

    vpx_img_wrap(img, fmt, width, height, align, buffer.data());
  }

  ScopedVpxImage(vpx_image_t *img, const vpx_image_t *source_img, FuzzedDataProvider &fdp) {
    memset(img, 0, sizeof(*img));
    const size_t image_size = (source_img->d_w * source_img->d_h * 3) / 2;
    buffer = fdp.ConsumeBytes<uint8_t>(image_size);
    if (buffer.size() < image_size) {
      buffer.resize(image_size, 0);
    }
    vpx_img_wrap(img, source_img->fmt, source_img->d_w, source_img->d_h, 1, buffer.data());
  }
};

// Fuzz target entry point.
extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  FuzzedDataProvider fdp(data, size);

  // Create VP8 codec.
  vpx_codec_ctx_t *vp8_codec = new vpx_codec_ctx_t();
  if (vpx_codec_dec_init(vp8_codec, vpx_codec_vp8_dx(), NULL, 0)) {
    delete vp8_codec;
    vp8_codec = nullptr;
  }

  // Create VP9 codec.
  vpx_codec_ctx_t *vp9_codec = new vpx_codec_ctx_t();
  if (vpx_codec_dec_init(vp9_codec, vpx_codec_vp9_dx(), NULL, 0)) {
    delete vp9_codec;
    vp9_codec = nullptr;
  }

  const std::vector<uint8_t> decode_data = fdp.ConsumeBytes<uint8_t>(fdp.ConsumeIntegralInRange<size_t>(0, fdp.remaining_bytes()));

  if (vp8_codec) {
    vpx_codec_decode(vp8_codec, decode_data.data(), decode_data.size(), NULL, 0);
    vpx_codec_iter_t iter = NULL;
    vpx_image_t *img = vpx_codec_get_frame(vp8_codec, &iter);
    if (img) {
      vpx_ref_frame_t ref_frame;
      memset(&ref_frame, 0, sizeof(ref_frame));
      const vpx_ref_frame_type_t frame_types[] = {VP8_LAST_FRAME, VP8_GOLD_FRAME, VP8_ALTR_FRAME};
      ref_frame.frame_type = fdp.PickValueInArray(frame_types);
      ScopedVpxImage scoped_img(&ref_frame.img, img, fdp);

      vpx_codec_control(vp8_codec, VP8_SET_REFERENCE, &ref_frame);
      vpx_codec_control(vp8_codec, VP8_COPY_REFERENCE, &ref_frame);
    }

    int corrupted = 0;
    vpx_codec_control(vp8_codec, VP8D_GET_FRAME_CORRUPTED, &corrupted);
    int quantizer = 0;
    vpx_codec_control(vp8_codec, VPXD_GET_LAST_QUANTIZER, &quantizer);
    int ref_updates = 0;
    vpx_codec_control(vp8_codec, VP8D_GET_LAST_REF_UPDATES, &ref_updates);
  }

  if (vp9_codec) {
    vpx_codec_decode(vp9_codec, decode_data.data(), decode_data.size(), NULL, 0);
    vpx_codec_iter_t iter = NULL;
    vpx_image_t *img = vpx_codec_get_frame(vp9_codec, &iter);
    if (img) {
      vpx_ref_frame_t ref_frame;
      memset(&ref_frame, 0, sizeof(ref_frame));
      const vpx_ref_frame_type_t frame_types[] = {VP8_LAST_FRAME, VP8_GOLD_FRAME, VP8_ALTR_FRAME};
      ref_frame.frame_type = fdp.PickValueInArray(frame_types);
      ScopedVpxImage scoped_img(&ref_frame.img, img, fdp);

      vpx_codec_control(vp9_codec, VP8_SET_REFERENCE, &ref_frame);
      vpx_codec_control(vp9_codec, VP8_COPY_REFERENCE, &ref_frame);
    }
  }

  // Clean up codecs.
  if (vp8_codec) {
    vpx_codec_destroy(vp8_codec);
    delete vp8_codec;
  }
  if (vp9_codec) {
    vpx_codec_destroy(vp9_codec);
    delete vp9_codec;
  }

  return 0;
}