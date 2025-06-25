#include <cstddef>
#include <cstdint>
#include <vector>
#include <fuzzer/FuzzedDataProvider.h>

#include "/src/libvpx/vpx_scale/yv12config.h"
#include "/work/build/vpx_scale_rtcd.h"
#include "/work/build/vp8_rtcd.h"
#include "/src/libvpx/vpx/vpx_frame_buffer.h"
#include "/src/libvpx/vp8/common/blockd.h"
#include "/src/libvpx/vp8/common/loopfilter.h"

// Forward declaration for vp8_swap_yv12_buffer from swapyv12buffer.c, which is not in a public header.
extern "C" void vp8_swap_yv12_buffer(YV12_BUFFER_CONFIG *new_frame, YV12_BUFFER_CONFIG *last_frame);
// Forward declaration for vp8_copy_and_extend_frame from extend.c, which is not in a public header.
extern "C" void vp8_copy_and_extend_frame(const YV12_BUFFER_CONFIG *src, YV12_BUFFER_CONFIG *dst);

// Constants for frame dimensions
constexpr int kMaxWidth = 256;
constexpr int kMaxHeight = 256;
constexpr int kBorder = 32;

// Fuzz target for vpx_yv12_copy_frame_c and related memory copy functions
extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  FuzzedDataProvider fdp(data, size);

  // Create source and destination YV12_BUFFER_CONFIG objects
  YV12_BUFFER_CONFIG src_ybc, dst_ybc;
  
  // Initialize buffer configs to 0 to avoid garbage values
  memset(&src_ybc, 0, sizeof(src_ybc));
  memset(&dst_ybc, 0, sizeof(dst_ybc));

  // Consume random dimensions for the frame
  const int width = fdp.ConsumeIntegralInRange<int>(1, kMaxWidth);
  const int height = fdp.ConsumeIntegralInRange<int>(1, kMaxHeight);

  // Allocate frame buffers for source and destination
  // vpx_alloc_frame_buffer is used to ensure proper allocation and alignment
  if (vpx_alloc_frame_buffer(&src_ybc, width, height, 1, 1, 0, kBorder, 0) < 0) {
    return 0;
  }
  if (vpx_alloc_frame_buffer(&dst_ybc, width, height, 1, 1, 0, kBorder, 0) < 0) {
    vpx_free_frame_buffer(&src_ybc);
    return 0;
  }

  // Fill the source buffer with fuzzer data.
  const size_t y_size = src_ybc.y_stride * (src_ybc.y_height + 2 * kBorder);
  const size_t uv_size = src_ybc.uv_stride * (src_ybc.uv_height + 2 * kBorder);
  const size_t buffer_size = y_size + 2 * uv_size;
  std::vector<uint8_t> buffer_data = fdp.ConsumeBytes<uint8_t>(buffer_size);
  if (!buffer_data.empty()) {
    memcpy(src_ybc.buffer_alloc, buffer_data.data(), buffer_data.size());
  }

  // Call the target function to copy the frame
  vpx_yv12_copy_frame_c(&src_ybc, &dst_ybc);

  // Added call to uncovered function vpx_yv12_copy_y_c based on coverage report.
  vpx_yv12_copy_y_c(&src_ybc, &dst_ybc);

  // Added call to uncovered function vpx_extend_frame_borders_c based on coverage report.
  vpx_extend_frame_borders_c(&dst_ybc);
  
  // Added call to uncovered function vpx_extend_frame_inner_borders_c based on coverage report.
  vpx_extend_frame_inner_borders_c(&dst_ybc);

  // Added calls to uncovered functions from dequantize.c and idctllm.c to improve coverage.
  BLOCKD blockd;
  memset(&blockd, 0, sizeof(blockd));
  short dqc[16];
  short qcoeff[16];
  short dqcoeff[256];
  for (int i = 0; i < 16; ++i) {
    dqc[i] = fdp.ConsumeIntegral<short>();
    qcoeff[i] = fdp.ConsumeIntegral<short>();
  }
  blockd.qcoeff = qcoeff;
  blockd.dqcoeff = dqcoeff;
  vp8_dequantize_b_c(&blockd, dqc);
  vp8_dequant_idct_add_c(blockd.dqcoeff, dqc, dst_ybc.y_buffer, dst_ybc.y_stride);
  vp8_short_inv_walsh4x4_c(blockd.qcoeff, blockd.dqcoeff);

  // Added call to uncovered function vp8_swap_yv12_buffer based on coverage report.
  vp8_swap_yv12_buffer(&src_ybc, &dst_ybc);

  // Added call to uncovered function vp8_copy_and_extend_frame based on coverage report.
  vp8_copy_and_extend_frame(&src_ybc, &dst_ybc);

  // Added calls to uncovered functions from loopfilter_filters.c to improve coverage.
  loop_filter_info lfi;
  unsigned char mblim[16], lim[16], blim[16];
  for (int i = 0; i < 16; ++i) {
    mblim[i] = fdp.ConsumeIntegral<unsigned char>();
    lim[i] = fdp.ConsumeIntegral<unsigned char>();
    blim[i] = fdp.ConsumeIntegral<unsigned char>();
  }
  unsigned char hev_thr[4];
  for (int i = 0; i < 4; ++i) {
    hev_thr[i] = fdp.ConsumeIntegral<unsigned char>();
  }
  lfi.mblim = mblim;
  lfi.lim = lim;
  lfi.blim = blim;
  lfi.hev_thr = hev_thr;
  unsigned char blimit[16];
  for (int i = 0; i < 16; ++i) {
    blimit[i] = fdp.ConsumeIntegral<unsigned char>();
  }
  vp8_loop_filter_mbh_c(src_ybc.y_buffer, src_ybc.u_buffer, src_ybc.v_buffer, src_ybc.y_stride, src_ybc.uv_stride, &lfi);
  vp8_loop_filter_mbv_c(src_ybc.y_buffer, src_ybc.u_buffer, src_ybc.v_buffer, src_ybc.y_stride, src_ybc.uv_stride, &lfi);
  vp8_loop_filter_bh_c(src_ybc.y_buffer, src_ybc.u_buffer, src_ybc.v_buffer, src_ybc.y_stride, src_ybc.uv_stride, &lfi);
  vp8_loop_filter_bhs_c(src_ybc.y_buffer, src_ybc.y_stride, blimit);
  vp8_loop_filter_bv_c(src_ybc.y_buffer, src_ybc.u_buffer, src_ybc.v_buffer, src_ybc.y_stride, src_ybc.uv_stride, &lfi);
  vp8_loop_filter_bvs_c(src_ybc.y_buffer, src_ybc.y_stride, blimit);

  // Call related memory copy functions on the buffer data
  if (width >= 16 && height >= 16) {
    vp8_copy_mem16x16_c(src_ybc.y_buffer, src_ybc.y_stride, dst_ybc.y_buffer, dst_ybc.y_stride);
  }
  if (width >= 8 && height >= 8) {
    vp8_copy_mem8x8_c(src_ybc.u_buffer, src_ybc.uv_stride, dst_ybc.u_buffer, dst_ybc.uv_stride);
  }
  if (width >= 8 && height >= 4) {
    vp8_copy_mem8x4_c(src_ybc.v_buffer, src_ybc.uv_stride, dst_ybc.v_buffer, dst_ybc.uv_stride);
  }

  // Free the allocated frame buffers to prevent memory leaks
  vpx_free_frame_buffer(&src_ybc);
  vpx_free_frame_buffer(&dst_ybc);

  return 0;
}