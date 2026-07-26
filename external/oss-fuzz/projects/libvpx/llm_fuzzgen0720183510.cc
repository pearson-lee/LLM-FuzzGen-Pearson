#include <cstddef>
#include <cstdint>

#include "vpx/vpx_decoder.h"
#include "vpx/vp8dx.h"

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  vpx_codec_iface_t *iface = vpx_codec_vp9_dx();
  vpx_codec_ctx_t codec;
  if (vpx_codec_dec_init(&codec, iface, NULL, 0) != VPX_CODEC_OK) {
    return 0;
  }

  vpx_codec_decode(&codec, data, size, NULL, 0);

  vpx_codec_destroy(&codec);

  return 0;
}