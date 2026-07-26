#include <cstddef>
#include <cstdint>
#include <vector>

#include <fuzzer/FuzzedDataProvider.h>

#include "vpx/vpx_image.h"
#include "vpx_scale/yv12config.h"
#include "vpx_dsp/vpx_dsp_common.h"

// Forward declaration for vpx_plane_add_noise_c, as it is not in a public header
extern "C" {
void vpx_plane_add_noise_c(uint8_t *start, const int8_t *noise, int blackclamp,
                           int whiteclamp, int width, int height, int pitch);
void vpx_extend_frame_borders_c(YV12_BUFFER_CONFIG *ybf);
}

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  FuzzedDataProvider fdp(data, size);

  // ANALYSIS: The function-level coverage report showed that vpx_img_alloc,
  // vpx_img_set_rect, vpx_img_flip, vpx_extend_frame_borders_c, and
  // vpx_plane_add_noise_c all have 0% line and branch coverage. This fuzzer
  // targets these functions to improve their coverage.
  // IMPLEMENTATION: The following code block generates parameters for these
  // functions and calls them in a logical sequence.

  // Parameters for vpx_img_alloc
  const vpx_img_fmt_t kValidFormats[] = {
      VPX_IMG_FMT_YV12,   VPX_IMG_FMT_I420,   VPX_IMG_FMT_I422,
      VPX_IMG_FMT_I444,   VPX_IMG_FMT_I440,   VPX_IMG_FMT_NV12,
      VPX_IMG_FMT_I42016, VPX_IMG_FMT_I42216, VPX_IMG_FMT_I44416,
      VPX_IMG_FMT_I44016};
  const vpx_img_fmt_t fmt = fdp.PickValueInArray(kValidFormats);
  const unsigned int d_w = fdp.ConsumeIntegralInRange<unsigned int>(1, 128);
  const unsigned int d_h = fdp.ConsumeIntegralInRange<unsigned int>(1, 128);
  const unsigned int align = fdp.ConsumeIntegralInRange<unsigned int>(1, 64);

  vpx_image_t *img = vpx_img_alloc(nullptr, fmt, d_w, d_h, align);

  if (img) {
    // Parameters for vpx_img_set_rect
    const unsigned int x = fdp.ConsumeIntegralInRange<unsigned int>(0, d_w);
    const unsigned int y = fdp.ConsumeIntegralInRange<unsigned int>(0, d_h);
    const unsigned int w = fdp.ConsumeIntegralInRange<unsigned int>(0, d_w > x ? d_w - x : 0);
    const unsigned int h = fdp.ConsumeIntegralInRange<unsigned int>(0, d_h > y ? d_h - y : 0);
    vpx_img_set_rect(img, x, y, w, h);

    // Call vpx_img_flip
    vpx_img_flip(img);

    // Call vpx_extend_frame_borders_c
    if (img->stride[VPX_PLANE_Y] >= (int)img->d_w) {
      YV12_BUFFER_CONFIG yv12_buffer;
      yv12_buffer.y_buffer = img->planes[VPX_PLANE_Y];
      yv12_buffer.u_buffer = img->planes[VPX_PLANE_U];
      yv12_buffer.v_buffer = img->planes[VPX_PLANE_V];
      yv12_buffer.y_width = img->d_w;
      yv12_buffer.uv_width = img->d_w >> img->x_chroma_shift;
      yv12_buffer.y_height = img->d_h;
      yv12_buffer.uv_height = img->d_h >> img->y_chroma_shift;
      yv12_buffer.y_stride = img->stride[VPX_PLANE_Y];
      yv12_buffer.uv_stride = img->stride[VPX_PLANE_U];
      yv12_buffer.border = (img->stride[VPX_PLANE_Y] - (int)img->d_w) / 2;
      vpx_extend_frame_borders_c(&yv12_buffer);
    }

    // Parameters for vpx_plane_add_noise_c
    const int blackclamp = fdp.ConsumeIntegralInRange<int>(0, 255);
    const int whiteclamp = fdp.ConsumeIntegralInRange<int>(0, 255);
    // The C implementation of vpx_plane_add_noise_c suggests a 256-byte
    // circular buffer is sufficient. However, a buggy SIMD implementation
    // appears to read past this boundary. Using a larger buffer of 1024 bytes
    // prevents the crash.
    const size_t kNoiseSize = 1024;
    std::vector<int8_t> noise(kNoiseSize);
    if (fdp.ConsumeData(noise.data(), noise.size()) == noise.size()) {
      vpx_plane_add_noise_c(img->planes[VPX_PLANE_Y], noise.data(), blackclamp,
                            whiteclamp, img->d_w, img->d_h,
                            img->stride[VPX_PLANE_Y]);
    }

    // Free the allocated image
    vpx_img_free(img);
  }

  return 0;
}