#include <cstddef>
#include <cstdint>
#include <vector>
#include <cstring>

#include <fuzzer/FuzzedDataProvider.h>

#include "vpx/vpx_image.h"
#include "vpx_scale/yv12config.h"
#include "vpx_dsp/vpx_dsp_common.h"

// Forward declaration for functions not in public headers
extern "C" {
void vpx_plane_add_noise_c(uint8_t *start, const int8_t *noise, int blackclamp,
                           int whiteclamp, int width, int height, int pitch);
void vpx_extend_frame_borders_c(YV12_BUFFER_CONFIG *ybf);
void vpx_extend_frame_inner_borders_c(YV12_BUFFER_CONFIG *ybf);
void vpx_yv12_copy_y_c(const YV12_BUFFER_CONFIG *src_ybc,
                     YV12_BUFFER_CONFIG *dst_ybc);
void vpx_yv12_copy_frame_c(const YV12_BUFFER_CONFIG *src_ybc,
                         YV12_BUFFER_CONFIG *dst_ybc);
void vp8_yv12_copy_frame_c(const YV12_BUFFER_CONFIG *src_ybc,
                         YV12_BUFFER_CONFIG *dst_ybc);
}

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  FuzzedDataProvider fdp(data, size);

  // Block 1: Target functions related to vpx_image_t
  {
    // ANALYSIS: The function-level coverage report showed that vpx_img_alloc,
    // vpx_img_set_rect, vpx_img_flip, and vpx_plane_add_noise_c all have low
    // or 0% coverage. This fuzzer targets these functions to improve their
    // coverage.
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
    // ANALYSIS: vpx_img_alloc requires the alignment to be a power of 2.
    // The previous implementation generated random values, causing alloc to fail often.
    // IMPLEMENTATION: Pick from a list of valid power-of-2 alignment values.
    const unsigned int align_opts[] = {1, 2, 4, 8, 16, 32, 64};
    const unsigned int align = fdp.PickValueInArray(align_opts);

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
      if (img->stride[VPX_PLANE_Y] > (int)img->d_w) {
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
      const size_t kNoiseSize = 1024;
      std::vector<int8_t> noise(kNoiseSize);
      if (fdp.ConsumeData(noise.data(), noise.size()) == noise.size()) {
        vpx_plane_add_noise_c(img->planes[VPX_PLANE_Y], noise.data(), blackclamp,
                              whiteclamp, img->d_w, img->d_h,
                              img->stride[VPX_PLANE_Y]);
      }

      vpx_img_free(img);
    }
  }

  // Block 2: Target functions from yv12extend.c
  if (fdp.remaining_bytes() > 100) {
    /*
     * ANALYSIS: The function-level coverage report showed that functions in
     *           yv12extend.c, such as vpx_extend_frame_borders_c,
     *           vpx_extend_frame_inner_borders_c, and various frame copy
     *           functions, had 0% coverage. The original fuzzer logic did not
     *           reliably create the conditions to call these functions.
     * IMPLEMENTATION: This block manually constructs two YV12_BUFFER_CONFIG
     *                 structs with valid, fuzzer-generated parameters and
     *                 appropriately sized buffers. This allows for direct calls
     *                 to the uncovered functions, ensuring they are exercised.
     *                 Using std::vector ensures memory safety.
     */
    YV12_BUFFER_CONFIG src_ybf, dst_ybf;
    memset(&src_ybf, 0, sizeof(src_ybf));
    memset(&dst_ybf, 0, sizeof(dst_ybf));

    const int width = fdp.ConsumeIntegralInRange<int>(1, 256);
    const int height = fdp.ConsumeIntegralInRange<int>(1, 256);
    const int border = fdp.ConsumeIntegralInRange<int>(1, 16) * 2;
    const int uv_subsample = 1;
    const int uv_border = border >> uv_subsample;

    src_ybf.y_width = width;
    src_ybf.y_height = height;
    src_ybf.uv_width = width >> uv_subsample;
    src_ybf.uv_height = height >> uv_subsample;
    src_ybf.y_stride = width + 2 * border;
    src_ybf.uv_stride = src_ybf.uv_width + 2 * uv_border;
    src_ybf.border = border;
    src_ybf.y_crop_width = width;
    src_ybf.y_crop_height = height;
    src_ybf.uv_crop_width = src_ybf.uv_width;
    src_ybf.uv_crop_height = src_ybf.uv_height;

    dst_ybf = src_ybf;

    const size_t y_size = (src_ybf.y_height + 2 * border) * src_ybf.y_stride;
    const size_t uv_size = (src_ybf.uv_height + 2 * uv_border) * src_ybf.uv_stride;
    
    // Limit allocations to prevent timeouts.
    if (y_size > 0 && uv_size > 0 && y_size < 500000 && uv_size < 250000) {
        std::vector<uint8_t> src_y(y_size);
        std::vector<uint8_t> src_u(uv_size);
        std::vector<uint8_t> src_v(uv_size);
        std::vector<uint8_t> dst_y(y_size);
        std::vector<uint8_t> dst_u(uv_size);
        std::vector<uint8_t> dst_v(uv_size);

        src_ybf.y_buffer = src_y.data() + border * src_ybf.y_stride + border;
        src_ybf.u_buffer = src_u.data() + uv_border * src_ybf.uv_stride + uv_border;
        src_ybf.v_buffer = src_v.data() + uv_border * src_ybf.uv_stride + uv_border;
        dst_ybf.y_buffer = dst_y.data() + border * dst_ybf.y_stride + border;
        dst_ybf.u_buffer = dst_u.data() + uv_border * dst_ybf.uv_stride + uv_border;
        dst_ybf.v_buffer = dst_v.data() + uv_border * dst_ybf.uv_stride + uv_border;

        vpx_extend_frame_borders_c(&src_ybf);
        vpx_extend_frame_inner_borders_c(&src_ybf);
        vpx_yv12_copy_y_c(&src_ybf, &dst_ybf);
        vpx_yv12_copy_frame_c(&src_ybf, &dst_ybf);
        vp8_yv12_copy_frame_c(&src_ybf, &dst_ybf);
    }
  }

  return 0;
}