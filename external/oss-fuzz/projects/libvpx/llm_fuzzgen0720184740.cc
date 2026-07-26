#include <cstddef>
#include <cstdint>
#include <vector>

#include "vpx/vpx_decoder.h"
#include "vpx/vp8dx.h"
#include "fuzzer/FuzzedDataProvider.h"

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

  if (vpx_codec_dec_init(&codec, iface, NULL, 0) != VPX_CODEC_OK) {
    return 0;
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

  return 0;
}