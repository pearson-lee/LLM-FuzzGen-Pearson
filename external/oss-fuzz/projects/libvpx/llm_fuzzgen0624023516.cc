#include <cstddef>
#include <cstdint>
#include <string>
#include <vector>

#include "fuzzer/FuzzedDataProvider.h"
#include "vpx/vp8.h"
#include "vpx/vp8dx.h"
#include "vpx/vpx_decoder.h"
#include "vpx_mem/vpx_mem.h"
#include "/work/build/vp8_rtcd.h"
#include "vp9/common/vp9_loopfilter.h"
#include "vp9/common/vp9_mvref_common.h"
#include "vpx_scale/yv12config.h"
#include "vp9/common/vp9_blockd.h"


extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
  FuzzedDataProvider fdp(data, size);

  // vp9_loop_filter_frame
  if (fdp.remaining_bytes() > sizeof(VP9_COMMON) + sizeof(MACROBLOCKD)) {
    VP9_COMMON vp9_cm;
    memset(&vp9_cm, 0, sizeof(vp9_cm));
    vp9_cm.mi_rows = 1;
    vp9_cm.mi_cols = 1;
    vp9_cm.lf.filter_level = fdp.ConsumeIntegralInRange<int>(0, 63);
    vp9_cm.lf.sharpness_level = fdp.ConsumeIntegralInRange<int>(0, 7);
    vp9_cm.seg.enabled = fdp.ConsumeBool();
    vp9_cm.seg.abs_delta = fdp.ConsumeBool();
    for (int i = 0; i < MAX_SEGMENTS; ++i) {
        vp9_cm.seg.feature_data[i][SEG_LVL_ALT_LF] = fdp.ConsumeIntegralInRange<int16_t>(-255, 255);
    }
    vp9_cm.lf.mode_ref_delta_enabled = fdp.ConsumeBool();
    for (int i = 0; i < MAX_REF_FRAMES; ++i) {
        vp9_cm.lf.ref_deltas[i] = fdp.ConsumeIntegralInRange<int>(-63, 63);
    }
    for (int i = 0; i < MAX_MODE_LF_DELTAS; ++i) {
        vp9_cm.lf.mode_deltas[i] = fdp.ConsumeIntegralInRange<int>(-63, 63);
    }

    YV12_BUFFER_CONFIG frame;
    memset(&frame, 0, sizeof(frame));
    frame.y_buffer = (uint8_t*)malloc(16 * 16);
    frame.u_buffer = (uint8_t*)malloc(8 * 8);
    frame.v_buffer = (uint8_t*)malloc(8 * 8);
    if (frame.y_buffer && frame.u_buffer && frame.v_buffer) {
        fdp.ConsumeData(frame.y_buffer, 16 * 16);
        fdp.ConsumeData(frame.u_buffer, 8 * 8);
        fdp.ConsumeData(frame.v_buffer, 8 * 8);
        
        MACROBLOCKD xd;
        memset(&xd, 0, sizeof(xd));

        vp9_loop_filter_frame(&frame, &vp9_cm, &xd, fdp.ConsumeIntegralInRange<int>(0, 63), fdp.ConsumeBool(), fdp.ConsumeBool());
    }

    if (frame.y_buffer) free(frame.y_buffer);
    if (frame.u_buffer) free(frame.u_buffer);
    if (frame.v_buffer) free(frame.v_buffer);
  }

  // vp8_dequant_idct_add_y_block_c
  const size_t y_block_q_dq_size = 256;
  const size_t y_block_needed = y_block_q_dq_size * sizeof(short) + y_block_q_dq_size * sizeof(short) + 16 * 16 + 16;
  if (fdp.remaining_bytes() >= y_block_needed) {
    std::vector<short> q(y_block_q_dq_size);
    fdp.ConsumeData(q.data(), y_block_q_dq_size * sizeof(short));
    std::vector<short> dq(y_block_q_dq_size);
    fdp.ConsumeData(dq.data(), y_block_q_dq_size * sizeof(short));
    std::vector<unsigned char> dst = fdp.ConsumeBytes<unsigned char>(16 * 16);
    int stride = 16;
    std::vector<char> eob = fdp.ConsumeBytes<char>(16);
    vp8_dequant_idct_add_y_block_c(q.data(), dq.data(), dst.data(), stride, eob.data());
  }

  // vp8_dequant_idct_add_uv_block_c
  const size_t uv_block_q_dq_size = 256;
  const size_t uv_block_needed = uv_block_q_dq_size * sizeof(short) + uv_block_q_dq_size * sizeof(short) + 8 * 8 + 8 * 8 + 16;
  if (fdp.remaining_bytes() >= uv_block_needed) {
    std::vector<short> q(uv_block_q_dq_size);
    fdp.ConsumeData(q.data(), uv_block_q_dq_size * sizeof(short));
    std::vector<short> dq(uv_block_q_dq_size);
    fdp.ConsumeData(dq.data(), uv_block_q_dq_size * sizeof(short));
    std::vector<unsigned char> dst_u = fdp.ConsumeBytes<unsigned char>(8 * 8);
    std::vector<unsigned char> dst_v = fdp.ConsumeBytes<unsigned char>(8 * 8);
    int stride = 8;
    std::vector<char> eob = fdp.ConsumeBytes<char>(16);
    vp8_dequant_idct_add_uv_block_c(q.data(), dq.data(), dst_u.data(), dst_v.data(), stride, eob.data());
  }

  // vp9_find_mv_refs
  if (fdp.remaining_bytes() > sizeof(VP9_COMMON) + sizeof(MACROBLOCKD) + sizeof(MODE_INFO) + sizeof(int_mv) * 8) {
    VP9_COMMON cm;
    memset(&cm, 0, sizeof(cm));
    MACROBLOCKD xd;
    memset(&xd, 0, sizeof(xd));
    MODE_INFO mi;
    memset(&mi, 0, sizeof(mi));
    int_mv mv_ref_list[MAX_MV_REF_CANDIDATES];
    uint8_t ref_mv_count;
    vp9_find_mv_refs(&cm, &xd, &mi, (MV_REFERENCE_FRAME)fdp.ConsumeIntegralInRange<int>(0, 2), mv_ref_list, fdp.ConsumeIntegral<int>(), fdp.ConsumeIntegral<int>(), &ref_mv_count);
  }

  return 0;
}