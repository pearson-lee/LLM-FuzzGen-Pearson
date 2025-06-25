#include <cstddef>
#include <cstdint>
#include <fuzzer/FuzzedDataProvider.h>
#include <vector>

// Required for the vpx_codec_* functions and structures.
#include "/src/libvpx/vpx/vpx_decoder.h"

// Required for the VP9 decoder interface and control flags.
#include "/src/libvpx/vpx/vp8.h"
#include "/src/libvpx/vpx/vp8dx.h"

// Fuzz target entry point.
extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  if (size == 0) {
    return 0;
  }

  FuzzedDataProvider fdp(data, size);

  // Initialize the VP9 decoder configuration.
  vpx_codec_ctx_t codec;
  vpx_codec_dec_cfg_t cfg = {0};

  // Use the fuzzer input to determine the number of threads, from 1 to 8.
  // This allows the fuzzer to explore both single-threaded and multi-threaded paths.
  cfg.threads = fdp.ConsumeIntegralInRange<unsigned int>(1, 8);

  // Initialize the decoder. If initialization fails, we can't proceed.
  if (vpx_codec_dec_init(&codec, vpx_codec_vp9_dx(), &cfg, 0)) {
    return 0;
  }

  // Set a non-zero loop filter level to improve coverage of loop filter functions.
  // The VP9D_SET_FILTER_LEVEL identifier does not exist in the public API.
  // The correct way to control the deblocking/loop filter level is via post-processing.
  vp8_postproc_cfg_t pp_cfg = {0};
  pp_cfg.post_proc_flag = VP8_DEBLOCK;
  pp_cfg.deblocking_level = fdp.ConsumeIntegralInRange<int>(0, 16);
  vpx_codec_control(&codec, VP8_SET_POSTPROC, &pp_cfg);

  // Enable row-based multi-threading to target uncovered functions like
  // row_decode_worker_hook and tile_worker_hook.
  vpx_codec_control(&codec, VP9D_SET_ROW_MT, 1);

  // Enable loop filter optimization to target uncovered functions like
  // vp9_loop_filter_frame_mt.
  vpx_codec_control(&codec, VP9D_SET_LOOP_FILTER_OPT, 1);

  // The rest of the data is used as input for the decoder.
  const std::vector<uint8_t> frame_data = fdp.ConsumeRemainingBytes<uint8_t>();
  if (frame_data.empty()) {
    vpx_codec_destroy(&codec);
    return 0;
  }

  // Attempt to decode the provided data.
  vpx_codec_decode(&codec, frame_data.data(), frame_data.size(), nullptr, -1);

  // Retrieve any decoded frames. The returned image is owned by the decoder
  // and does not need to be freed separately.
  vpx_codec_iter_t iter = nullptr;
  vpx_image_t *img = nullptr;
  while ((img = vpx_codec_get_frame(&codec, &iter)) != nullptr) {
    // Do nothing with the decoded frame.
  }

  // Destroy the decoder context to free all allocated resources and prevent
  // memory leaks.
  vpx_codec_destroy(&codec);

  return 0;
}