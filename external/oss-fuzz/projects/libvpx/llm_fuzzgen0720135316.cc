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
#include "vpx/vpx_frame_buffer.h"
}

// A simple struct to hold our frame buffers.
struct FrameBuffer {
  std::vector<uint8_t> data;
};

// Callback to allocate a frame buffer.
int get_fb(void* user_priv, size_t min_size, vpx_codec_frame_buffer_t* fb) {
  auto* frame_buffers = static_cast<std::vector<FrameBuffer*>*>(user_priv);
  try {
    auto* new_buffer = new FrameBuffer();
    new_buffer->data.resize(min_size);
    fb->data = new_buffer->data.data();
    fb->size = min_size;
    fb->priv = new_buffer; // Link fb to our buffer object.
    frame_buffers->push_back(new_buffer);
  } catch (const std::bad_alloc&) {
    return -1;
  }
  return 0;
}

// Callback to release a frame buffer.
int release_fb(void* user_priv, vpx_codec_frame_buffer_t* fb) {
  if (fb && fb->priv) {
    auto* buffer_to_release = static_cast<FrameBuffer*>(fb->priv);
    auto* frame_buffers = static_cast<std::vector<FrameBuffer*>*>(user_priv);
    // Find and remove the buffer from our tracking list before deleting.
    auto it = std::find(frame_buffers->begin(), frame_buffers->end(), buffer_to_release);
    if (it != frame_buffers->end()) {
      frame_buffers->erase(it);
    }
    delete buffer_to_release;
    fb->priv = nullptr;
  }
  return 0;
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

  if (fdp.ConsumeBool()) {
    vpx_codec_stream_info_t si = {0};
    si.sz = sizeof(si);
    const size_t peek_size = fdp.ConsumeIntegralInRange<size_t>(0, 1024);
    if (peek_size <= fdp.remaining_bytes()) {
      std::vector<uint8_t> peek_data = fdp.ConsumeBytes<uint8_t>(peek_size);
      /*
       * ANALYSIS: The function-level coverage report showed that
       *           vpx_codec_get_stream_info was never called.
       * IMPLEMENTATION: This block calls vpx_codec_peek_stream_info to exercise
       *                 the code path responsible for retrieving stream
       *                 information, which was previously uncovered.
       */
      vpx_codec_peek_stream_info(iface, peek_data.data(), peek_data.size(), &si);
    }
  }

  VpxCodecCtxPtr codec(new vpx_codec_ctx_t());

  // Initialize the decoder.
  if (vpx_codec_dec_init_ver(codec.get(), iface, nullptr, 0, VPX_DECODER_ABI_VERSION) != VPX_CODEC_OK) {
    return 0;
  }

  std::vector<FrameBuffer*> frame_buffers;
  if (fdp.ConsumeBool()) {
    /*
     * ANALYSIS: The function-level coverage report showed that
     *           vpx_codec_set_frame_buffer_functions was completely uncovered.
     * IMPLEMENTATION: The following code block defines and sets custom frame
     *                 buffer allocation/release callbacks. This exercises the
     *                 library's ability to work with an external frame buffer
     *                 management system. Memory safety is handled by tracking
     *                 allocations in the `frame_buffers` vector and cleaning
     *                 them up before the function returns.
     */
    vpx_codec_set_frame_buffer_functions(codec.get(), get_fb, release_fb, &frame_buffers);
  }

  if (fdp.ConsumeBool()) {
    /*
     * ANALYSIS: The function-level coverage report showed that
     *           vpx_codec_err_to_string was never called.
     * IMPLEMENTATION: This block calls vpx_codec_err_to_string with a fuzzed
     *                 error code to improve coverage in error-reporting logic.
     */
    vpx_codec_err_t err = fdp.PickValueInArray({
        VPX_CODEC_OK, VPX_CODEC_ERROR, VPX_CODEC_MEM_ERROR,
        VPX_CODEC_ABI_MISMATCH, VPX_CODEC_INCAPABLE,
        VPX_CODEC_UNSUP_BITSTREAM, VPX_CODEC_UNSUP_FEATURE,
        VPX_CODEC_CORRUPT_FRAME, VPX_CODEC_INVALID_PARAM,
        VPX_CODEC_LIST_END
    });
    vpx_codec_err_to_string(err);
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
  
  // Explicitly destroy the codec to trigger release_fb callbacks before cleanup.
  codec.reset();

  // Clean up any remaining buffers that the codec didn't release.
  for (auto* fb : frame_buffers) {
    delete fb;
  }
  frame_buffers.clear();

  return 0;
}