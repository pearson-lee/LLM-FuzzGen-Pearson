#include <cstddef>
#include <cstdint>
#include <vector>
#include <memory>

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

  // Select a decoder interface.
  vpx_codec_iface_t* iface = fdp.PickValueInArray({
      vpx_codec_vp8_dx(),
      vpx_codec_vp9_dx(),
  });
  if (!iface) {
    return 0;
  }

  VpxCodecCtxPtr codec(new vpx_codec_ctx_t());

  // Initialize the decoder.
  if (vpx_codec_dec_init_ver(codec.get(), iface, nullptr, 0, VPX_DECODER_ABI_VERSION) != VPX_CODEC_OK) {
    return 0;
  }

  if (fdp.ConsumeBool()) {
    int ctrl_id = fdp.PickValueInArray({
        VP8D_SET_DECRYPTOR,
        VP8D_GET_LAST_REF_UPDATES,
        VP8D_GET_FRAME_CORRUPTED,
        VP8D_GET_LAST_REF_USED,
        VP9D_GET_FRAME_SIZE,
        VP9D_GET_DISPLAY_SIZE,
        VP9D_GET_BIT_DEPTH,
        VP9_SET_BYTE_ALIGNMENT,
        VP9_INVERT_TILE_DECODE_ORDER,
        VP9_SET_SKIP_LOOP_FILTER,
        VP9D_SET_ROW_MT,
        VP9D_SET_LOOP_FILTER_OPT,
    });

    if (ctrl_id == VP8D_SET_DECRYPTOR) {
      if (fdp.ConsumeBool()) {
        vpx_decrypt_init decrypt_init = {nullptr, nullptr};
        vpx_codec_control_(codec.get(), ctrl_id, &decrypt_init);
      } else {
        vpx_codec_control_(codec.get(), ctrl_id, nullptr);
      }
    } else if (ctrl_id == VP8D_GET_LAST_REF_UPDATES ||
               ctrl_id == VP8D_GET_FRAME_CORRUPTED ||
               ctrl_id == VP8D_GET_LAST_REF_USED ||
               ctrl_id == VP9D_GET_FRAME_SIZE ||
               ctrl_id == VP9D_GET_DISPLAY_SIZE ||
               ctrl_id == VP9D_GET_BIT_DEPTH) {
      int arg = 0;
      vpx_codec_control_(codec.get(), ctrl_id, &arg);
    } else {
      int arg = fdp.ConsumeIntegral<int>();
      vpx_codec_control_(codec.get(), ctrl_id, arg);
    }
  }

  while (fdp.remaining_bytes() > 0) {
    size_t frame_size = fdp.ConsumeIntegralInRange<size_t>(1, fdp.remaining_bytes());
    std::vector<uint8_t> frame_data = fdp.ConsumeBytes<uint8_t>(frame_size);

    // Decode the frame. It's expected that this will often fail with random data.
    vpx_codec_decode(codec.get(), frame_data.data(), frame_data.size(), nullptr, 0);

    // Retrieve any decoded data to improve coverage.
    vpx_codec_iter_t iter = nullptr;
    vpx_image_t* img = nullptr;
    while ((img = vpx_codec_get_frame(codec.get(), &iter)) != nullptr) {
      // In a real application, the decoded image would be processed here.
    }
  }

  return 0;
}