#include <cstddef>
#include <cstdint>
#include <vector>
#include <fuzzer/FuzzedDataProvider.h>

#include "/src/libvpx/vpx_scale/yv12config.h"
#include "/work/build/vpx_scale_rtcd.h"
#include "/work/build/vp8_rtcd.h"
#include "/src/libvpx/vpx/vpx_frame_buffer.h"

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

  // Fill the source buffer with fuzzer data
  const size_t y_size = src_ybc.y_stride * (src_ybc.y_height + 2 * kBorder);
  const size_t uv_size = src_ybc.uv_stride * (src_ybc.uv_height + 2 * kBorder);
  std::vector<uint8_t> buffer_data = fdp.ConsumeBytes<uint8_t>(y_size + 2 * uv_size);
  if (buffer_data.size() == y_size + 2 * uv_size) {
    memcpy(src_ybc.buffer_alloc, buffer_data.data(), buffer_data.size());
  }

  // Call the target function to copy the frame
  vpx_yv12_copy_frame_c(&src_ybc, &dst_ybc);

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