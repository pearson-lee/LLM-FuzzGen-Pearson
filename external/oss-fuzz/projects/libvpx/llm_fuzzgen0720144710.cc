#include <cstddef>
#include <cstdint>
#include <memory>
#include <vector>
#include <cstdlib>

#include "fuzzer/FuzzedDataProvider.h"
#include "vpx/vpx_decoder.h"
#include "vpx/vp8dx.h"
#include "vpx/vpx_frame_buffer.h"

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

// Custom callback to allocate a frame buffer.
static int get_frame_buffer(void *priv, size_t min_size, vpx_codec_frame_buffer_t *fb) {
    (void)priv;
    size_t size = min_size;
    // The lifetime of this buffer is managed by the codec, which will call
    // release_frame_buffer() when it is no longer needed.
    uint8_t *data = (uint8_t *)malloc(size);
    if (!data) {
        return -1;
    }
    fb->data = data;
    fb->size = size;
    fb->priv = nullptr;
    return 0;
}

// Custom callback to release a frame buffer.
static int release_frame_buffer(void *priv, vpx_codec_frame_buffer_t *fb) {
    (void)priv;
    if (fb->data) {
        free(fb->data);
    }
    return 0;
}

// Dummy callback for put_frame_cb
static void put_frame_cb(void *user_priv, const vpx_image_t *img) {
  (void)user_priv;
  (void)img;
}

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  FuzzedDataProvider fdp(data, size);

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

  /*
   * ANALYSIS: The function-level coverage report showed that a large number
   * of vpx_codec_control_ related functions were completely uncovered (0% coverage).
   * One of these is VP8_SET_POSTPROC, which allows configuring post-processing filters.
   * IMPLEMENTATION: The following block creates and populates a vp8_postproc_cfg
   * struct using the FuzzedDataProvider and calls vpx_codec_control_ to enable
   * and configure the post-processing stage, thereby exercising these uncovered code paths.
   */
  if (fdp.ConsumeBool()) {
    vp8_postproc_cfg_t pp_cfg;
    pp_cfg.post_proc_flag = fdp.ConsumeIntegral<int>();
    pp_cfg.deblocking_level = fdp.ConsumeIntegralInRange<int>(0, 16);
    pp_cfg.noise_level = fdp.ConsumeIntegralInRange<int>(0, 16);
    vpx_codec_control_(codec.get(), VP8_SET_POSTPROC, &pp_cfg);
  }

  /*
   * ANALYSIS: The function-level coverage report showed vpx_codec_register_put_frame_cb
   * had 0% coverage. This function registers a callback for when a decoded frame is available.
   * IMPLEMENTATION: The following block defines and registers a dummy callback function.
   * This will be triggered once a frame is successfully decoded, covering this previously
   * untouched API.
   */
  if (fdp.ConsumeBool()) {
    vpx_codec_register_put_frame_cb(codec.get(), put_frame_cb, nullptr);
  }

  /*
   * ANALYSIS: The function-level coverage report showed many vpx_codec_control_ functions
   * like VP8D_GET_FRAME_CORRUPTED were uncovered.
   * IMPLEMENTATION: The following block calls the VP8D_GET_FRAME_CORRUPTED control to
   * exercise this uncovered error-checking path.
   */
  if (fdp.ConsumeBool()) {
    int corrupted = 0;
    vpx_codec_control_(codec.get(), VP8D_GET_FRAME_CORRUPTED, &corrupted);
  }

  /*
   * ANALYSIS: The function-level coverage report indicated that
   * vpx_codec_set_frame_buffer_functions and related memory allocation functions
   * like vpx_alloc_frame_buffer were either completely uncovered or had very low coverage.
   * This is because the fuzzer was using the default internal memory management.
   * IMPLEMENTATION: The following call registers custom get/release callback functions.
   * This forces the decoder to use our fuzzer-controlled memory management,
   * exercising these critical, previously untested code paths.
   */
  if (fdp.ConsumeBool()) {
      vpx_codec_set_frame_buffer_functions(codec.get(), get_frame_buffer, release_frame_buffer, nullptr);
  }

  /*
   * ANALYSIS: The fuzzer coverage report showed that the vpx_codec_get_frame loop was
   * never entered, indicating that random data is not sufficient to produce a valid frame.
   * This prevents coverage of all frame-level processing, including post-processing and
   * custom memory allocation.
   * IMPLEMENTATION: Prepend a minimal, valid VP8 keyframe header to the fuzzer data.
   * This allows the decoder to successfully decode at least one frame, unlocking
   * coverage for a wide range of downstream functions.
   */
  const uint8_t kValidVp8Frame[] = {0x9d, 0x01, 0x2a, 0x01, 0x00, 0x01, 0x00};
  const size_t decode_size = fdp.ConsumeIntegralInRange<size_t>(0, fdp.remaining_bytes());
  auto decode_data = fdp.ConsumeBytes<uint8_t>(decode_size);
  std::vector<uint8_t> frame_with_header;
  frame_with_header.insert(frame_with_header.end(), kValidVp8Frame, kValidVp8Frame + sizeof(kValidVp8Frame));
  frame_with_header.insert(frame_with_header.end(), decode_data.begin(), decode_data.end());
  vpx_codec_decode(codec.get(), frame_with_header.data(), frame_with_header.size(), nullptr, 0);

  // Retrieve and discard any decoded frames.
  vpx_codec_iter_t iter = nullptr;
  while (vpx_codec_get_frame(codec.get(), &iter)) {
    // Loop to process all frames.
  }

  // All memory is released by the VpxCodecCtxPtr's deleter, which calls
  // vpx_codec_destroy(). This in turn triggers the release_frame_buffer
  // callback for any outstanding frame buffers.
  return 0;
}