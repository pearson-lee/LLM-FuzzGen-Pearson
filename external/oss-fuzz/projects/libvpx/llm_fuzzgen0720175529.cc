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
  const vpx_img_fmt_t fmt =
      fdp.PickValueInArray({VPX_IMG_FMT_I420, VPX_IMG_FMT_I422, VPX_IMG_FMT_I444,
                            VPX_IMG_FMT_I440, VPX_IMG_FMT_NV12});
  const unsigned int d_w = fdp.ConsumeIntegralInRange<unsigned int>(1, 128);
  const unsigned int d_h = fdp.ConsumeIntegralInRange<unsigned int>(1, 128);
  const unsigned int stride_align =
      fdp.ConsumeIntegralInRange<unsigned int>(1, 32);
  const size_t img_data_size = d_w * d_h * 3 / 2;
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

  vpx_codec_register_put_slice_cb(&codec, put_slice_cb, nullptr);

  std::vector<uint8_t> decode_data = fdp.ConsumeRemainingBytes<uint8_t>();
  const long deadline = fdp.ConsumeIntegral<long>();
  vpx_codec_decode(&codec, decode_data.data(), decode_data.size(), nullptr,
                   deadline);

  vpx_codec_destroy(&codec);
  delete[] img_data;

  return 0;
}