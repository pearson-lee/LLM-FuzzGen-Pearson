#include <cstddef>
#include <cstdint>
#include <vector>

#include "vpx/vpx_decoder.h"
#include "vpx/vp8dx.h"
#include "fuzzer/FuzzedDataProvider.h"
#include "vpx/vpx_frame_buffer.h"

// Define a simple struct to hold frame buffer data.
struct FrameBuffer {
  uint8_t *data;
  size_t size;
};

// Callback function to get a frame buffer.
static int get_fb(void *priv, size_t min_size, vpx_codec_frame_buffer_t *fb) {
  auto *fbs = static_cast<std::vector<FrameBuffer> *>(priv);
  FrameBuffer new_fb;
  new_fb.size = min_size;
  new_fb.data = new uint8_t[min_size];
  fbs->push_back(new_fb);
  fb->data = new_fb.data;
  fb->size = new_fb.size;
  fb->priv = &fbs->back();
  return 0;
}

// Callback function to release a frame buffer.
static int release_fb(void *priv, vpx_codec_frame_buffer_t *fb) {
  // The allocated data will be freed at the end of the fuzz input.
  (void)priv;
  (void)fb;
  return 0;
}

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  FuzzedDataProvider fdp(data, size);
  vpx_codec_iface_t *iface = vpx_codec_vp9_dx();
  vpx_codec_ctx_t codec;

  /*
   * ANALYSIS: The fuzz target coverage report shows that the error handling
   *           path of vpx_codec_dec_init is never taken (Branch [True: 0]).
   * IMPLEMENTATION: Consume a boolean from the fuzzer to sometimes pass a
   *                 NULL interface to vpx_codec_dec_init, triggering the
   *                 error handling path.
   */
  if (fdp.ConsumeBool()) {
    if (vpx_codec_dec_init(&codec, NULL, NULL, 0) == VPX_CODEC_OK) {
      vpx_codec_destroy(&codec);
    }
    return 0;
  }
  
  vpx_codec_dec_cfg_t cfg = {0};
  cfg.w = fdp.ConsumeIntegralInRange<unsigned int>(0, 4096);
  cfg.h = fdp.ConsumeIntegralInRange<unsigned int>(0, 4096);
  cfg.threads = fdp.ConsumeIntegralInRange<unsigned int>(1, 8);

  /*
   * ANALYSIS: The coverage report for the fuzz target shows that the failure
   *           path for vpx_codec_dec_init is never exercised.
   * IMPLEMENTATION: Introduce a 10% chance of passing an invalid config
   *                 (width or height is 0) to trigger the initialization
   *                 error handling logic.
   */
  if (fdp.ConsumeIntegralInRange<int>(0, 9) == 0) {
    if (fdp.ConsumeBool()) {
      cfg.w = 0;
    } else {
      cfg.h = 0;
    }
  }

  if (vpx_codec_dec_init(&codec, iface, &cfg, 0) != VPX_CODEC_OK) {
    return 0;
  }

  std::vector<FrameBuffer> fbs;
  /*
   * ANALYSIS: The function-level coverage report shows that
   *           vpx_codec_set_frame_buffer_functions has low coverage.
   * IMPLEMENTATION: Add a call to vpx_codec_set_frame_buffer_functions with
   *                 custom callback functions to exercise this uncovered API.
   *                 Memory allocated by the callbacks is tracked in a vector
   *                 and freed at the end of the test case to prevent leaks.
   */
  if (fdp.ConsumeBool()) {
    vpx_codec_set_frame_buffer_functions(&codec, get_fb, release_fb, &fbs);
  }

  /*
   * ANALYSIS: The function-level coverage report shows that many vpx_codec_control
   *           functions for VP9 are completely uncovered (0% coverage).
   * IMPLEMENTATION: Add calls to various VP9-specific control functions with
   *                 fuzzer-driven values to increase coverage in these areas.
   */
  if (fdp.ConsumeBool()) {
    vpx_codec_control_(&codec, VP9_SET_SKIP_LOOP_FILTER, fdp.ConsumeIntegral<int>());
  }
  if (fdp.ConsumeBool()) {
    vpx_codec_control_(&codec, VP9D_SET_ROW_MT, fdp.ConsumeIntegral<int>());
  }
  if (fdp.ConsumeBool()) {
    vpx_codec_control_(&codec, VP9_INVERT_TILE_DECODE_ORDER, fdp.ConsumeIntegral<int>());
  }
  /*
   * ANALYSIS: The function-level coverage report shows that post-processing
   *           functions related to VP8 are uncovered.
   * IMPLEMENTATION: Add a call to the VP8_SET_POSTPROC control function to
   *                 exercise the post-processing code paths.
   */
  if (fdp.ConsumeBool()) {
    vp8_postproc_cfg_t pp_cfg = {0};
    pp_cfg.post_proc_flag = fdp.ConsumeIntegral<int>();
    pp_cfg.deblocking_level = fdp.ConsumeIntegral<int>();
    pp_cfg.noise_level = fdp.ConsumeIntegral<int>();
    vpx_codec_control_(&codec, VP8_SET_POSTPROC, &pp_cfg);
  }


  const std::vector<uint8_t> frame = fdp.ConsumeRemainingBytes<uint8_t>();
  vpx_codec_decode(&codec, frame.data(), frame.size(), NULL, 0);

  /*
   * ANALYSIS: The original fuzzer did not retrieve decoded frames, missing
   *           coverage in frame buffer management and scaling code.
   * IMPLEMENTATION: Add a loop to retrieve all decoded frames using
   *                 vpx_codec_get_frame. This is a more realistic use of the
   *                 decoder and exercises frame buffer logic.
   */
  vpx_codec_iter_t iter = NULL;
  vpx_image_t *img = NULL;
  while ((img = vpx_codec_get_frame(&codec, &iter)) != NULL) {
    // The image is owned by the decoder, so no freeing is necessary.
  }

  vpx_codec_destroy(&codec);

  // Free any memory allocated by the custom frame buffer callbacks.
  for (const auto& fb : fbs) {
    delete[] fb.data;
  }

  return 0;
}