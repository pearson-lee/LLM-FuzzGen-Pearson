/* BLOCKER_STRATEGY_CONTRACT
required_state: pbi->max_threads > 1, pbi->row_mt == 1, and the input bitstream must have log2_tile_rows set to 0.
state_constructor: The decoder is configured with vpx_codec_dec_cfg_t.threads > 1 during initialization. Then, vpx_codec_control_ is called with VP9D_SET_ROW_MT and an argument of 1.
trigger_api: vpx_codec_decode()
preserved_invariants: The decoder must be initialized with multiple threads and row-based multi-threading must be enabled.
END_BLOCKER_STRATEGY_CONTRACT */

#include <cstddef>
#include <cstdint>
#include <vector>
#include <memory>
#include <algorithm>

#include "fuzzer/FuzzedDataProvider.h"

// The libvpx headers are C headers, and must be wrapped in extern "C"
// when included from C++ to prevent name-mangling issues during linking.
extern "C" {
#include "vpx/vpx_decoder.h"
#include "vpx/vp8dx.h"
}

// Cleanup utility to safely destroy the codec context.
struct VpxCodecCtxDeleter {
  void operator()(vpx_codec_ctx_t* codec) const {
    if (codec) {
      vpx_codec_destroy(codec);
      delete codec;
    }
  }
};

using VpxCodecCtxPtr = std::unique_ptr<vpx_codec_ctx_t, VpxCodecCtxDeleter>;

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
  FuzzedDataProvider fdp(data, size);

  // We must use the vp9 decoder to reach the target function.
  vpx_codec_iface_t* iface = vpx_codec_vp9_dx();

  // Configure the decoder for multi-threaded decoding.
  // This is to satisfy `pbi->max_threads > 1`.
  vpx_codec_dec_cfg_t cfg = {0};
  cfg.threads = fdp.ConsumeIntegralInRange<unsigned int>(2, 16);
  cfg.w = fdp.ConsumeIntegralInRange<unsigned int>(1, 4096);
  cfg.h = fdp.ConsumeIntegralInRange<unsigned int>(1, 4096);

  VpxCodecCtxPtr codec(new vpx_codec_ctx_t());

  // Initialize the decoder with the multi-threading config.
  if (vpx_codec_dec_init_ver(codec.get(), iface, &cfg, 0, VPX_DECODER_ABI_VERSION) != VPX_CODEC_OK) {
    return 0;
  }

  // Enable row-based multi-threading to satisfy `pbi->row_mt == 1`.
  // This is a key part of the condition to enter the desired branch.
  vpx_codec_control_(codec.get(), VP9D_SET_ROW_MT, 1);

  // The condition `tile_rows == 1` depends on the bitstream content
  // (specifically `log2_tile_rows` being 0), which is left for the
  // fuzzer to generate.

  while (fdp.remaining_bytes() > 0) {
    size_t frame_size = fdp.ConsumeIntegralInRange<size_t>(1, fdp.remaining_bytes());
    std::vector<uint8_t> frame_data = fdp.ConsumeBytes<uint8_t>(frame_size);

    // Decode the frame. This is the trigger for the blocker.
    vpx_codec_decode(codec.get(), frame_data.data(), frame_data.size(), nullptr, 0);

    // Retrieve any decoded data to improve coverage and emulate a real use case.
    vpx_codec_iter_t iter = nullptr;
    vpx_image_t* img = nullptr;
    while ((img = vpx_codec_get_frame(codec.get(), &iter)) != nullptr) {
      // In a real application, the decoded image would be processed here.
    }
  }

  return 0;
}