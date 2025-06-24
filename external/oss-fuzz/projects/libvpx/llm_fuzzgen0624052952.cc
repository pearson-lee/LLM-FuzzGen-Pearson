#include <cstddef>
#include <cstdint>
#include <memory>
#include <vector>
#include <fuzzer/FuzzedDataProvider.h>

#include "vpx/vpx_decoder.h"
#include "vpx/vp8dx.h"
#include "vpx/vpx_frame_buffer.h"
#include "vpx/vpx_image.h"
#include "vpx/internal/vpx_codec_internal.h"

// Forward declare the VP9 decoder interface, as it's not in a public header.
extern "C" {
// Use extern to declare the variable, not define it.
extern vpx_codec_iface_t vpx_codec_vp9_dx_algo;
}

// Helper function to create a valid vpx_image_t for reference frames.
static std::unique_ptr<vpx_image_t, decltype(&vpx_img_free)> make_vpx_image(
    FuzzedDataProvider& fdp) {
  // Fuzz the image format, width, and height.
  vpx_img_fmt_t fmt = (vpx_img_fmt_t)fdp.ConsumeIntegralInRange<int>(0, VPX_IMG_FMT_I44416);
  unsigned int w = fdp.ConsumeIntegralInRange<unsigned int>(1, 1024);
  unsigned int h = fdp.ConsumeIntegralInRange<unsigned int>(1, 1024);
  
  // Allocate the image. vpx_img_alloc will correctly set derived fields.
  vpx_image_t* img = vpx_img_alloc(nullptr, fmt, w, h, 1);
  
  // Return the allocated image wrapped in a unique_ptr with a custom deleter.
  return {img, &vpx_img_free};
}

// The main fuzzing entry point.
extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
  FuzzedDataProvider fdp(data, size);

  // Initialize the VP9 decoder.
  vpx_codec_ctx_t codec;
  vpx_codec_dec_cfg_t cfg = {0};
  cfg.threads = fdp.ConsumeIntegralInRange<unsigned int>(1, 8);
  if (vpx_codec_dec_init(&codec, &vpx_codec_vp9_dx_algo, &cfg, 0)) {
    return 0;
  }

  // Enable multi-threaded row decoding.
  vpx_codec_control(&codec, VP9D_SET_ROW_MT, 1);

  // The decoder must be initialized with some data before reference frames can
  // be set.
  size_t initial_size = fdp.ConsumeIntegralInRange<size_t>(0, fdp.remaining_bytes());
  std::vector<uint8_t> initial_data = fdp.ConsumeBytes<uint8_t>(initial_size);
  vpx_codec_decode(&codec, initial_data.data(), initial_data.size(), nullptr, 0);

  // A frame must be successfully decoded before we can copy a reference from it.
  vpx_codec_iter_t iter = nullptr;
  vpx_image_t* decoded_img = vpx_codec_get_frame(&codec, &iter);

  // Only attempt to set/copy a reference frame if a frame has been decoded.
  if (decoded_img != nullptr) {
    if (fdp.ConsumeBool()) {
      auto img = make_vpx_image(fdp);
      if (img) {
        vpx_ref_frame_t ref_frame;
        memset(&ref_frame, 0, sizeof(ref_frame));
        ref_frame.img = *img;

        if (fdp.ConsumeBool()) { // Set reference
          const vpx_ref_frame_type_t frame_types[] = {VP8_LAST_FRAME, VP8_GOLD_FRAME, VP8_ALTR_FRAME};
          ref_frame.frame_type = fdp.PickValueInArray(frame_types);
          vpx_codec_control(&codec, VP8_SET_REFERENCE, &ref_frame);
        } else { // Copy reference
          // vp9_copy_reference_dec is a stub that only supports VP9_LAST_FLAG.
          ref_frame.frame_type = VP8_LAST_FRAME;
          vpx_codec_control(&codec, VP8_COPY_REFERENCE, &ref_frame);
        }
      }
    }
  }

  // Provide the remaining fuzzer-generated data to the decoder.
  const std::vector<uint8_t> fuzzed_data = fdp.ConsumeRemainingBytes<uint8_t>();
  if (fuzzed_data.size() > 0) {
    vpx_codec_decode(&codec, fuzzed_data.data(), fuzzed_data.size(), nullptr, 0);
  }

  // Consume any remaining decoded frames.
  while ((decoded_img = vpx_codec_get_frame(&codec, &iter)) != nullptr) {
    // Frames are ignored.
  }

  // Destroy the decoder context to free all allocated resources.
  vpx_codec_destroy(&codec);

  return 0;
}