/* BLOCKER_STRATEGY_CONTRACT
required_state: The 'mode_info_context->mbmi.mb_skip_coeff' field must be non-zero within the 'qualify_inter_mb' function to execute the target branch.
state_constructor: In the loop that initializes the 'MODE_INFO' array, 'mi->mbmi.mb_skip_coeff' is set to '(i % 2)', where 'i' is the loop index. This sets the required field to 1 for every other macroblock, ensuring the blocker is crossed without altering the fuzzer's input consumption sequence.
trigger_api: The 'vp8_post_proc_frame' function is called, which internally calls 'vp8_multiframe_quality_enhance' and subsequently the blocker function 'qualify_inter_mb'.
preserved_invariants: The fuzzer maintains the original input consumption contract. It continues to set up a 'VP8_COMMON' structure for an 'INTER_FRAME' and calls 'vp8_post_proc_frame' with the 'VP8D_MFQE' flag enabled.
END_BLOCKER_STRATEGY_CONTRACT */

#include <cstddef>
#include <cstdint>
#include <memory>
#include <vector>
#include <climits>

#include "vpx/vpx_encoder.h"
#include "vpx/vp8cx.h"
#include "vpx/vpx_decoder.h"
#include "vpx/vp8dx.h"
#include "vpx_ports/mem.h"
#include "vpx_scale/yv12config.h"
#include "vp8/common/onyxd.h"
#include "vp8/common/postproc.h"
#include "vp8/common/ppflags.h"
#include "vpx_mem/vpx_mem.h"
#include "vp8/common/onyxc_int.h"

#include <fuzzer/FuzzedDataProvider.h>

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  FuzzedDataProvider fdp(data, size);

  vpx_codec_iface_t *decoder_iface = vpx_codec_vp8_dx();
  vpx_codec_ctx_t decoder;
  if (vpx_codec_dec_init_ver(&decoder, decoder_iface, nullptr, 0, VPX_DECODER_ABI_VERSION) != VPX_CODEC_OK) {
    return 0;
  }

  YV12_BUFFER_CONFIG frame_to_show_config;
  memset(&frame_to_show_config, 0, sizeof(frame_to_show_config));
  const unsigned int width = fdp.ConsumeIntegralInRange<unsigned int>(16, 128);
  const unsigned int height = fdp.ConsumeIntegralInRange<unsigned int>(16, 128);

  if (vp8_yv12_alloc_frame_buffer(&frame_to_show_config, width, height, VP8BORDERINPIXELS) == 0) {
    VP8_COMMON oci;
    memset(&oci, 0, sizeof(oci));
    oci.Width = width;
    oci.Height = height;

    oci.mb_rows = (oci.Height + 15) / 16;
    oci.mb_cols = (oci.Width + 15) / 16;
    const int mi_size = (oci.mb_rows + 1) * (oci.mb_cols + 1);
    oci.mi = (MODE_INFO *)vpx_calloc(mi_size, sizeof(MODE_INFO));
    if (!oci.mi) {
      vp8_yv12_de_alloc_frame_buffer(&frame_to_show_config);
      vpx_codec_destroy(&decoder);
      return 0;
    }
    oci.mip = oci.mi;
    oci.pp_limits_buffer = (unsigned char *)vpx_calloc(24 * oci.mb_cols, sizeof(unsigned char));
    if (!oci.pp_limits_buffer) {
      vpx_free(oci.mi);
      vp8_yv12_de_alloc_frame_buffer(&frame_to_show_config);
      vpx_codec_destroy(&decoder);
      return 0;
    }
    
    oci.frame_type = INTER_FRAME;
    for (int i = 0; i < mi_size; ++i) {
        MODE_INFO *mi = oci.mi + i;
        mi->mbmi.ref_frame = LAST_FRAME;
        mi->mbmi.mode = SPLITMV;

        // Set mb_skip_coeff for some macroblocks to satisfy the blocker condition
        // without changing the input consumption contract.
        mi->mbmi.mb_skip_coeff = (i % 2);

        for (int b = 0; b < 16; ++b) {
            if (fdp.ConsumeBool()) {
                mi->bmi[b].mv.as_int = fdp.ConsumeIntegralInRange<int>(1, INT_MAX);
            } else {
                mi->bmi[b].mv.as_int = 0;
            }
        }
    }

    oci.current_video_frame = fdp.ConsumeIntegralInRange<int>(11, 100);
    oci.postproc_state.last_frame_valid = true;
    oci.postproc_state.last_base_qindex = fdp.ConsumeIntegralInRange<int>(0, 59);
    oci.base_qindex = oci.postproc_state.last_base_qindex + fdp.ConsumeIntegralInRange<int>(20, 40);

    oci.filter_level = fdp.ConsumeIntegral<int>();
    oci.frame_to_show = &frame_to_show_config;

    if (vp8_yv12_alloc_frame_buffer(&oci.post_proc_buffer, oci.Width, oci.Height, VP8BORDERINPIXELS)) {
      vpx_free(oci.pp_limits_buffer);
      vpx_free(oci.mi);
      vp8_yv12_de_alloc_frame_buffer(&frame_to_show_config);
      vpx_codec_destroy(&decoder);
      return 0;
    }

    vp8_ppflags_t ppflags;
    ppflags.post_proc_flag = fdp.ConsumeIntegral<int>();
    ppflags.post_proc_flag |= VP8D_MFQE;
    ppflags.deblocking_level = fdp.ConsumeIntegral<int>();
    ppflags.noise_level = fdp.ConsumeIntegral<int>();

    YV12_BUFFER_CONFIG dest;
    memset(&dest, 0, sizeof(dest));

    vp8_post_proc_frame(&oci, &dest, &ppflags);
    
    vp8_yv12_de_alloc_frame_buffer(&oci.post_proc_buffer);

    if (oci.postproc_state.generated_noise) {
      vpx_free(oci.postproc_state.generated_noise);
    }
    if (oci.post_proc_buffer_int_used) {
      vp8_yv12_de_alloc_frame_buffer(&oci.post_proc_buffer_int);
    }
    vpx_free(oci.pp_limits_buffer);
    vpx_free(oci.mi);
    vp8_yv12_de_alloc_frame_buffer(&frame_to_show_config);
  }

  vpx_codec_destroy(&decoder);

  return 0;
}