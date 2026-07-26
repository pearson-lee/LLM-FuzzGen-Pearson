#include <cstddef>
#include <cstdint>
#include <string>
#include <vector>

#include "fuzzer/FuzzedDataProvider.h"
#include "vpx/vpx_decoder.h"
#include "vpx/vp8dx.h"

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  FuzzedDataProvider fdp(data, size);

  vpx_codec_iface_t *decoder_iface = vpx_codec_vp9_dx();
  vpx_codec_ctx_t decoder_ctx;
  vpx_codec_dec_cfg_t decoder_cfg = {0};

  // Target the VPX_CODEC_ABI_MISMATCH branch.
  if (vpx_codec_dec_init_ver(&decoder_ctx, decoder_iface, &decoder_cfg, 0, VPX_DECODER_ABI_VERSION - 1) == VPX_CODEC_OK) {
    vpx_codec_destroy(&decoder_ctx);
  }

  // Target the VPX_CODEC_INVALID_PARAM branch.
  vpx_codec_dec_init_ver(nullptr, decoder_iface, &decoder_cfg, 0, VPX_DECODER_ABI_VERSION);

  // Target capability flag branches.
  const vpx_codec_flags_t flags = fdp.ConsumeIntegral<vpx_codec_flags_t>();
  if (vpx_codec_dec_init_ver(&decoder_ctx, decoder_iface, &decoder_cfg, flags, VPX_DECODER_ABI_VERSION) == VPX_CODEC_OK) {
    vpx_codec_destroy(&decoder_ctx);
  }

  // Also exercise vpx_codec_err_to_string which has some missing coverage.
  vpx_codec_err_t err = static_cast<vpx_codec_err_t>(fdp.ConsumeIntegral<int>());
  vpx_codec_err_to_string(err);

  return 0;
}