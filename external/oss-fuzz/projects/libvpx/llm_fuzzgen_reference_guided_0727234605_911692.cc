/* BLOCKER_STRATEGY_CONTRACT
required_state: The 'vp8_yv12_alloc_frame_buffer' function must fail (return non-zero). This is achieved by passing extremely large width and height values, causing the underlying memory allocation to fail.
state_constructor: The 'oci.Width' and 'oci.Height' fields are set to a large value (INT_MAX / 2) immediately before calling 'vp8_post_proc_frame'. This overrides the small, fuzzer-derived values used for initial buffer allocations, creating an inconsistent state that is specifically crafted to trigger the allocation failure within the target function. The 'ppflags.post_proc_flag' is also manipulated to ensure the correct path to the failing allocation is taken, by adding 'VP8D_DEBLOCK' and removing 'VP8D_ADDNOISE'.
trigger_api: The 'vp8_post_proc_frame' function is called, which attempts to allocate 'oci->post_proc_buffer_int' with the oversized dimensions.
preserved_invariants: The fuzzer maintains the original input consumption contract. All 'Consume' calls from FuzzedDataProvider are preserved in their original order and type. The core logic of setting up the 'VP8_COMMON' structure and calling 'vp8_post_proc_frame' remains intact, with the state modification being a targeted addition.
END_BLOCKER_STRATEGY_CONTRACT */

#include <cstddef>
#include <cstdint>
#include <memory>
#include <vector>
#include <climits>
#include <setjmp.h>

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

    // BLOCKER-SPECIFIC CODE
    // Set up a jump point to handle the expected error gracefully.
    // vpx_internal_error will longjmp here if oci.error.setjmp is true.
    if (setjmp(oci.error.jmp)) {
      // Cleanup after longjmp
      if (oci.mi) vpx_free(oci.mi);
      if (oci.pp_limits_buffer) vpx_free(oci.pp_limits_buffer);
      vp8_yv12_de_alloc_frame_buffer(&oci.post_proc_buffer);
      if (oci.postproc_state.generated_noise) vpx_free(oci.postproc_state.generated_noise);
      if (oci.post_proc_buffer_int_used) vp8_yv12_de_alloc_frame_buffer(&oci.post_proc_buffer_int);
      vp8_yv12_de_alloc_frame_buffer(&frame_to_show_config);
      vpx_codec_destroy(&decoder);
      return 0;
    }
    oci.error.setjmp = 1;

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

    // BLOCKER-SPECIFIC CODE
    // Set a large width and height to trigger an allocation failure inside vp8_post_proc_frame.
    oci.Width = 30000;
    oci.Height = 30000;

    vp8_ppflags_t ppflags;
    ppflags.post_proc_flag = fdp.ConsumeIntegral<int>();
    ppflags.post_proc_flag |= VP8D_MFQE;
    ppflags.post_proc_flag |= VP8D_DEBLOCK;
    ppflags.post_proc_flag &= ~VP8D_ADDNOISE;
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
