/* BLOCKER_STRATEGY_CONTRACT
required_state: br->decrypt_cb must be a non-null function pointer.
state_constructor: Call vpx_codec_control with VP8_SET_DECRYPTOR and a valid vpx_decrypt_init structure containing a decrypt callback.
trigger_api: vpx_codec_decode, which leads to the eventual call of vp8dx_bool_decoder_fill.
preserved_invariants: The vpx_codec_control call with VP8_SET_DECRYPTOR must be preserved to ensure the decrypt_cb is set.
END_BLOCKER_STRATEGY_CONTRACT */

#include <stddef.h>
#include <stdint.h>
#include <string.h>
#include <vector>
#include <fuzzer/FuzzedDataProvider.h>

#include "vpx/vp8dx.h"
#include "vpx/vpx_decoder.h"

// A simple decryptor that just copies the data.
void decrypt_cb(void *decrypt_state, const uint8_t *input, uint8_t *output,
                int count) {
  (void)decrypt_state;
  if (input && output && count > 0) {
    memcpy(output, input, count);
  }
}

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  FuzzedDataProvider fdp(data, size);

  vpx_codec_ctx_t codec;
  vpx_codec_dec_cfg_t cfg = {0};
  cfg.threads = fdp.ConsumeIntegralInRange<unsigned int>(1, 4);

  if (vpx_codec_dec_init(&codec, vpx_codec_vp8_dx(), &cfg, 0)) {
    return 0;
  }

  vpx_decrypt_init decrypt_init;
  decrypt_init.decrypt_cb = decrypt_cb;
  decrypt_init.decrypt_state = nullptr;
  vpx_codec_control(&codec, VPXD_SET_DECRYPTOR, &decrypt_init);

  std::vector<uint8_t> frame_data = fdp.ConsumeRemainingBytes<uint8_t>();
  if (frame_data.empty()) {
    vpx_codec_destroy(&codec);
    return 0;
  }

  vpx_codec_decode(&codec, frame_data.data(), frame_data.size(), nullptr, 0);

  vpx_codec_iter_t iter = nullptr;
  vpx_image_t *img = nullptr;
  while ((img = vpx_codec_get_frame(&codec, &iter)) != nullptr) {
  }

  vpx_codec_destroy(&codec);
  return 0;
}