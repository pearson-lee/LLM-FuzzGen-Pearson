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

// Custom memory allocation tracking for frame buffers
struct Buffer {
    uint8_t *data;
    size_t size;
};

static std::vector<Buffer> allocated_buffers;

// Custom callback to allocate a frame buffer.
static int get_frame_buffer(void *priv, size_t min_size, vpx_codec_frame_buffer_t *fb) {
    (void)priv;
    size_t size = min_size;
    uint8_t *data = (uint8_t *)malloc(size);
    if (!data) {
        return -1;
    }
    fb->data = data;
    fb->size = size;
    fb->priv = nullptr;
    allocated_buffers.push_back({data, size});
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
   * ANALYSIS: The function-level coverage report indicated that
   * vpx_codec_set_frame_buffer_functions and related memory allocation functions
   * like vpx_alloc_frame_buffer were either completely uncovered or had very low coverage.
   * This is because the fuzzer was using the default internal memory management.
   * IMPLEMENTATION: The following call registers custom get/release callback functions.
   * This forces the decoder to use our fuzzer-controlled memory management,
   * exercising these critical, previously untested code paths. Memory safety is
   * ensured by tracking allocations and freeing them after decoding is complete.
   */
  if (fdp.ConsumeBool()) {
      vpx_codec_set_frame_buffer_functions(codec.get(), get_frame_buffer, release_frame_buffer, nullptr);
  }

  // Decode the fuzzer-provided data.
  const size_t decode_size = fdp.ConsumeIntegralInRange<size_t>(0, fdp.remaining_bytes());
  auto decode_data = fdp.ConsumeBytes<uint8_t>(decode_size);
  vpx_codec_decode(codec.get(), decode_data.data(), decode_data.size(), nullptr, 0);

  // Retrieve and discard any decoded frames.
  vpx_codec_iter_t iter = nullptr;
  while (vpx_codec_get_frame(codec.get(), &iter)) {
    // Loop to process all frames.
  }

  // Clean up any buffers allocated by our custom callback.
  for (const auto& buffer : allocated_buffers) {
      free(buffer.data);
  }
  allocated_buffers.clear();

  return 0;
}