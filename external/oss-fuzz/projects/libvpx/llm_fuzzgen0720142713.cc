#include <cstddef>
#include <cstdint>
#include <memory>
#include <vector>

#include "fuzzer/FuzzedDataProvider.h"
#include "vpx/vpx_decoder.h"
#include "vpx/vp8dx.h"

// Deleter for vpx_codec_ctx_t
struct VpxCodecCtxDeleter {
  void operator()(vpx_codec_ctx_t *ctx) const {
    if (ctx) {
      vpx_codec_destroy(ctx);
      delete ctx;
    }
  }
};

using VpxCodecCtxPtr = std::unique_ptr<vpx_codec_ctx_t, VpxCodecCtxDeleter>;

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  // Use the VP8 decoder interface.
  vpx_codec_iface_t *iface = vpx_codec_vp8_dx();
  if (!iface) {
    return 0;
  }

  VpxCodecCtxPtr codec(new vpx_codec_ctx_t());

  // Initialize the decoder.
  if (vpx_codec_dec_init_ver(codec.get(), iface, nullptr, 0, VPX_DECODER_ABI_VERSION) != VPX_CODEC_OK) {
    return 0;
  }

  // Decode the fuzzer-provided data.
  vpx_codec_decode(codec.get(), data, size, nullptr, 0);

  // Retrieve and discard any decoded frames.
  vpx_codec_iter_t iter = nullptr;
  while (vpx_codec_get_frame(codec.get(), &iter)) {
    // Loop to process all frames.
  }

  return 0;
}