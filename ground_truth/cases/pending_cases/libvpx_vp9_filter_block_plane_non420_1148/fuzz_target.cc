#include <cstddef>
#include <cstdint>
#include <string>
#include <vector>

#include "fuzzer/FuzzedDataProvider.h"
#include "vpx/vpx_decoder.h"
#include "vp9/vp9_dx_iface.h"

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  FuzzedDataProvider fdp(data, size);

  vpx_codec_iface_t *decoder_iface = vpx_codec_vp9_dx();
  vpx_codec_ctx_t decoder_ctx;
  vpx_codec_dec_cfg_t decoder_cfg = {0};

  // Target the VPX_CODEC_ABI_MISMATCH branch.
  if (vpx_codec_dec_init_ver(&decoder_ctx, decoder_iface, &decoder_cfg, 0, VPX_DECODER_ABI_VERSION - 1) == VPX_CODEC_OK) {
    vpx_codec_destroy(&decoder_ctx);
  }

  // Target the VPX_CODEC_INVALID_PARAM branch.
  vpx_codec_dec_init_ver(nullptr, decoder_iface, &decoder_cfg, 0, VPX_DECODER_ABI_VERSION);

  // Target capability flag branches and exercise control functions.
  const vpx_codec_flags_t flags = fdp.ConsumeIntegral<vpx_codec_flags_t>();
  if (vpx_codec_dec_init_ver(&decoder_ctx, decoder_iface, &decoder_cfg, flags, VPX_DECODER_ABI_VERSION) == VPX_CODEC_OK) {
    /*
     * ANALYSIS: The function-level coverage report showed many vpx_codec_control
     *           wrapper functions were completely uncovered.
     * IMPLEMENTATION: The following code block calls several of these uncovered
     *                 control functions after a successful decoder initialization
     *                 to improve their coverage.
     */
    int frame_size[2];
    vpx_codec_control(&decoder_ctx, VP9D_GET_FRAME_SIZE, frame_size);
    int display_size[2];
    vpx_codec_control(&decoder_ctx, VP9D_GET_DISPLAY_SIZE, display_size);
    unsigned int bit_depth;
    vpx_codec_control(&decoder_ctx, VP9D_GET_BIT_DEPTH, &bit_depth);
    int last_quantizer;
    vpx_codec_control(&decoder_ctx, VPXD_GET_LAST_QUANTIZER, &last_quantizer);

    /*
     * ANALYSIS: The coverage report shows that the core decoding functions
     *           `vpx_codec_decode` and `vpx_codec_get_frame` have branch
     *           coverage gaps.
     * IMPLEMENTATION: Call the decode and get_frame functions with fuzzer
     *                 data to exercise the main decoding path.
     */
    const std::vector<uint8_t> frame_data = fdp.ConsumeRemainingBytes<uint8_t>();
    vpx_codec_decode(&decoder_ctx, frame_data.data(), frame_data.size(), nullptr, 0);
    vpx_codec_iter_t iter = nullptr;
    vpx_codec_get_frame(&decoder_ctx, &iter);

    /*
     * ANALYSIS: The function-level coverage report showed vpx_codec_error
     *           was uncovered.
     * IMPLEMENTATION: Call vpx_codec_error to improve coverage.
     */
    vpx_codec_error(&decoder_ctx);

    vpx_codec_destroy(&decoder_ctx);
  }

  // Also exercise vpx_codec_err_to_string which has some missing coverage.
  vpx_codec_err_t err = static_cast<vpx_codec_err_t>(fdp.ConsumeIntegral<int>());
  vpx_codec_err_to_string(err);

  /*
   * ANALYSIS: The function-level coverage report showed vpx_codec_version
   *           was uncovered.
   * IMPLEMENTATION: Call vpx_codec_version to get 100% coverage.
   */
  vpx_codec_version();

  return 0;
}