#include "vpx/vpx_decoder.h"
#include "vpx/vp8dx.h"
#include "vp9/common/vp9_mvref_common.h"
#include "vp9/common/vp9_onyxc_int.h"
#include <fuzzer/FuzzedDataProvider.h>

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  if (size < 1) {
    return 0;
  }
  FuzzedDataProvider fdp(data, size);

  // Initialize VP9_COMMON
  VP9_COMMON cm;
  memset(&cm, 0, sizeof(cm));
  cm.mi_rows = fdp.ConsumeIntegralInRange<unsigned int>(1, 100);
  cm.mi_cols = fdp.ConsumeIntegralInRange<unsigned int>(1, 100);
  cm.use_prev_frame_mvs = fdp.ConsumeBool();
  if (cm.use_prev_frame_mvs) {
    cm.prev_frame = (RefCntBuffer *)calloc(1, sizeof(RefCntBuffer));
    if (!cm.prev_frame) {
      return 0;
    }
    cm.prev_frame->mvs = (MV_REF *)calloc(cm.mi_rows * cm.mi_cols, sizeof(MV_REF));
    if (!cm.prev_frame->mvs) {
      free(cm.prev_frame);
      return 0;
    }
  }

  // Initialize MACROBLOCKD
  MACROBLOCKD xd;
  memset(&xd, 0, sizeof(xd));
  xd.mi_stride = cm.mi_cols;
  xd.mi = (MODE_INFO **)calloc(cm.mi_rows * cm.mi_cols, sizeof(MODE_INFO *));
  if (!xd.mi) {
    if (cm.use_prev_frame_mvs) {
      free(cm.prev_frame->mvs);
      free(cm.prev_frame);
    }
    return 0;
  }
  for (unsigned int i = 0; i < cm.mi_rows * cm.mi_cols; ++i) {
    xd.mi[i] = (MODE_INFO *)calloc(1, sizeof(MODE_INFO));
    if (!xd.mi[i]) {
      for (unsigned int j = 0; j < i; ++j) {
        free(xd.mi[j]);
      }
      free(xd.mi);
      if (cm.use_prev_frame_mvs) {
        free(cm.prev_frame->mvs);
        free(cm.prev_frame);
      }
      return 0;
    }
  }

  // Fuzz parameters
  int block = fdp.ConsumeIntegralInRange<int>(0, 3);
  int ref = fdp.ConsumeIntegralInRange<int>(0, 1);
  int mi_row = fdp.ConsumeIntegralInRange<int>(0, cm.mi_rows - 1);
  int mi_col = fdp.ConsumeIntegralInRange<int>(0, cm.mi_cols - 1);
  int_mv nearest_mv, near_mv;
  uint8_t mode_context[MAX_REF_FRAMES];

  // Call the target function
  vp9_append_sub8x8_mvs_for_idx(&cm, &xd, block, ref, mi_row, mi_col,
                                &nearest_mv, &near_mv, mode_context);

  // Cleanup
  for (unsigned int i = 0; i < cm.mi_rows * cm.mi_cols; ++i) {
    free(xd.mi[i]);
  }
  free(xd.mi);
  if (cm.use_prev_frame_mvs) {
    free(cm.prev_frame->mvs);
    free(cm.prev_frame);
  }

  return 0;
}