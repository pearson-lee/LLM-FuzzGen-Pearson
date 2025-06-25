#include <cstddef>
#include <cstdint>
#include <fuzzer/FuzzedDataProvider.h>

#include "vpx/vpx_decoder.h"
#include "vpx/vp8dx.h"
#include "vp8/common/onyxc_int.h"
#include "vp8/common/postproc.h"
#include "vp8/common/loopfilter.h"

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  if (size < 1) {
    return 0;
  }

  FuzzedDataProvider fdp(data, size);

  // Initialize VP8_COMMON structure
  VP8_COMMON cm;
  memset(&cm, 0, sizeof(cm));
  cm.Width = fdp.ConsumeIntegralInRange<int>(16, 4096);
  cm.Height = fdp.ConsumeIntegralInRange<int>(16, 4096);
  cm.mb_rows = (cm.Height + 15) / 16;
  cm.mb_cols = (cm.Width + 15) / 16;
  cm.frame_type = static_cast<FRAME_TYPE>(fdp.ConsumeIntegralInRange<int>(0, 1));
  cm.filter_type = static_cast<LOOPFILTERTYPE>(fdp.ConsumeIntegralInRange<int>(0, 1));
  cm.filter_level = fdp.ConsumeIntegralInRange<int>(0, 63);
  cm.sharpness_level = fdp.ConsumeIntegralInRange<int>(0, 7);
  cm.base_qindex = fdp.ConsumeIntegralInRange<int>(0, 127);
  cm.postproc_state.last_base_qindex = fdp.ConsumeIntegralInRange<int>(0, 127);

  // Allocate and initialize frame_to_show and post_proc_buffer
  YV12_BUFFER_CONFIG frame_to_show;
  YV12_BUFFER_CONFIG post_proc_buffer;
  memset(&frame_to_show, 0, sizeof(frame_to_show));
  memset(&post_proc_buffer, 0, sizeof(post_proc_buffer));

  if (vpx_alloc_frame_buffer(&frame_to_show, cm.Width, cm.Height, cm.Width, cm.Height / 2, cm.Width / 2, VPX_IMG_FMT_I420, 16) != 0) {
    return 0;
  }
  if (vpx_alloc_frame_buffer(&post_proc_buffer, cm.Width, cm.Height, cm.Width, cm.Height / 2, cm.Width / 2, VPX_IMG_FMT_I420, 16) != 0) {
    vpx_free_frame_buffer(&frame_to_show);
    return 0;
  }

  // Fill buffers with fuzzed data
  std::vector<uint8_t> y_buffer_data = fdp.ConsumeBytes<uint8_t>(frame_to_show.y_stride * frame_to_show.y_height);
  memcpy(frame_to_show.y_buffer, y_buffer_data.data(), y_buffer_data.size());
  std::vector<uint8_t> u_buffer_data = fdp.ConsumeBytes<uint8_t>(frame_to_show.uv_stride * frame_to_show.uv_height);
  memcpy(frame_to_show.u_buffer, u_buffer_data.data(), u_buffer_data.size());
  std::vector<uint8_t> v_buffer_data = fdp.ConsumeBytes<uint8_t>(frame_to_show.uv_stride * frame_to_show.uv_height);
  memcpy(frame_to_show.v_buffer, v_buffer_data.data(), v_buffer_data.size());

  cm.frame_to_show = &frame_to_show;
  cm.post_proc_buffer = post_proc_buffer;

  // Initialize MACROBLOCKD
  MACROBLOCKD mbd;
  memset(&mbd, 0, sizeof(mbd));
  mbd.mode_info_context = (MODE_INFO*) calloc(cm.mb_rows * cm.mb_cols, sizeof(MODE_INFO));
  if (mbd.mode_info_context == nullptr) {
    vpx_free_frame_buffer(&frame_to_show);
    vpx_free_frame_buffer(&post_proc_buffer);
    return 0;
  }
  cm.mi = mbd.mode_info_context;

  // Fuzz the target functions
  vp8_multiframe_quality_enhance(&cm);
  vp8_loop_filter_frame(&cm, &mbd, cm.frame_type);
  vp8_loop_filter_frame_yonly(&cm, &mbd, cm.filter_level);
  vp8_loop_filter_partial_frame(&cm, &mbd, fdp.ConsumeIntegralInRange<int>(0, cm.mb_rows));
  vp8_deblock(&cm, cm.frame_to_show, &post_proc_buffer, cm.base_qindex);

  // Clean up
  free(mbd.mode_info_context);
  vpx_free_frame_buffer(&frame_to_show);
  vpx_free_frame_buffer(&post_proc_buffer);

  return 0;
}