#include <cstddef>
#include <cstdint>
#include <vector>
#include <fuzzer/FuzzedDataProvider.h>

#include "vpx/vpx_decoder.h"
#include "vpx/vp8dx.h"
#include "vpx_scale/yv12config.h"
#include "vp8/common/postproc.h"
#include "vp8/common/onyxd.h"
#include "vp8/decoder/onyxd_int.h"
#include "vp8/common/ppflags.h"
#include "vpx/internal/vpx_codec_internal.h"

namespace {

void drain_decoder(vpx_codec_ctx_t *decoder) {
  vpx_codec_iter_t iter = nullptr;
  vpx_image_t *img = nullptr;
  while ((img = vpx_codec_get_frame(decoder, &iter)) != nullptr) {
  }
}

} // namespace

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  FuzzedDataProvider fdp(data, size);

  vpx_codec_dec_cfg_t vp8_cfg = {0};
  vp8_cfg.threads = fdp.ConsumeIntegralInRange<unsigned int>(1, 4);
  vpx_codec_dec_cfg_t vp9_cfg = {0};
  vp9_cfg.threads = fdp.ConsumeIntegralInRange<unsigned int>(1, 4);

  vpx_codec_ctx_t vp8_decoder;
  if (vpx_codec_dec_init(&vp8_decoder, vpx_codec_vp8_dx(), &vp8_cfg, 0)) {
    return 0;
  }
  vpx_codec_ctx_t vp9_decoder;
  if (vpx_codec_dec_init(&vp9_decoder, vpx_codec_vp9_dx(), &vp9_cfg, 0)) {
    vpx_codec_destroy(&vp8_decoder);
    return 0;
  }

  const size_t decode_size = fdp.ConsumeIntegralInRange<size_t>(0, fdp.remaining_bytes());
  auto decode_data = fdp.ConsumeBytes<uint8_t>(decode_size);

  if (vpx_codec_decode(&vp8_decoder, decode_data.data(), decode_data.size(), nullptr, 0)) {
    drain_decoder(&vp8_decoder);
  }
  if (vpx_codec_decode(&vp9_decoder, decode_data.data(), decode_data.size(), nullptr, 0)) {
    drain_decoder(&vp9_decoder);
  }

  vpx_codec_iter_t vp8_iter = nullptr;
  vpx_image_t *vp8_img = vpx_codec_get_frame(&vp8_decoder, &vp8_iter);
  vpx_codec_iter_t vp9_iter = nullptr;
  vpx_image_t *vp9_img = vpx_codec_get_frame(&vp9_decoder, &vp9_iter);

  if (vp8_img) {
    if (vp8_img->d_w == 0 || vp8_img->d_h == 0) {
      // Avoid post-processing with invalid image dimensions.
    } else {
      YV12_BUFFER_CONFIG dest_buf;
      if (vpx_realloc_frame_buffer(&dest_buf, vp8_img->d_w, vp8_img->d_h,
                                   vp8_img->x_chroma_shift, vp8_img->y_chroma_shift,
                                   (vp8_img->fmt & VPX_IMG_FMT_HIGHBITDEPTH) != 0,
                                   32, 0, nullptr, nullptr, nullptr) == 0) {
        void *priv = vp8_decoder.priv;
        if (priv) {
          VP8D_COMP *pbi = (VP8D_COMP *)priv;
          VP8_COMMON *oci = &pbi->common;
          vp8_ppflags_t ppflags = {0};
          ppflags.post_proc_flag = fdp.ConsumeIntegral<int>();
          ppflags.deblocking_level = fdp.ConsumeIntegralInRange(0, 16);
          ppflags.noise_level = fdp.ConsumeIntegralInRange(0, 16);
          vp8_post_proc_frame(oci, &dest_buf, &ppflags);
        }
        vpx_free_frame_buffer(&dest_buf);
      }
    }
  }

  vpx_codec_destroy(&vp8_decoder);
  vpx_codec_destroy(&vp9_decoder);

  return 0;
}