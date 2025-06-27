#include <cstddef>
#include <cstdint>
#include <vector>
#include <fuzzer/FuzzedDataProvider.h>

#include "vpx/vpx_integer.h"
#include "vpx_dsp/vpx_dsp_common.h"
#include "vpx_dsp/inv_txfm.h"
#include "vpx_dsp/txfm_common.h"
#include "vpx_dsp/vpx_filter.h"

extern "C" {
#include "/work/build/vpx_dsp_rtcd.h"
}

// Target a variety of DSP functions to improve coverage.
// 1. vpx_sub_pixel_variance4x4_c: Calculates the variance between two sub-pixel shifted blocks.
// 2. vpx_highbd_idct4x4_16_add_sse2: High-bit-depth inverse DCT.
// 3. vpx_convolve8_c: 8-tap convolution filter.
// 4. vpx_dc_predictor_4x4_c: DC intra-prediction.
// 5. vpx_d153_predictor_4x4_c: Directional intra-prediction.

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  FuzzedDataProvider fdp(data, size);

  // Allocate and fill buffers with fuzzer data.
  const size_t block_size = 16;
  const size_t src_buf_size = 97;
  const size_t conv_src_offset = 24;
  const size_t pred_src_offset = 1;
  std::vector<uint8_t> src_buf = fdp.ConsumeBytes<uint8_t>(src_buf_size);
  std::vector<uint8_t> dst_buf = fdp.ConsumeBytes<uint8_t>(block_size);

  std::vector<uint16_t> dst_buf16;
  dst_buf16.reserve(block_size);
  for (size_t i = 0; i < block_size; ++i) {
    if (fdp.remaining_bytes() < sizeof(uint16_t)) break;
    dst_buf16.push_back(fdp.ConsumeIntegral<uint16_t>());
  }

  std::vector<tran_low_t> coeffs;
  coeffs.reserve(block_size);
  for (size_t i = 0; i < block_size; ++i) {
    if (fdp.remaining_bytes() < sizeof(tran_low_t)) break;
    coeffs.push_back(fdp.ConsumeIntegral<tran_low_t>());
  }

  if (src_buf.size() < src_buf_size || dst_buf.size() < block_size ||
      dst_buf16.size() < block_size || coeffs.size() < block_size) {
    return 0;
  }

  // Target: vpx_sub_pixel_variance4x4_c
  uint32_t sse;
  vpx_sub_pixel_variance4x4_c(src_buf.data(), 4, fdp.ConsumeIntegralInRange<int>(0, 7),
                              fdp.ConsumeIntegralInRange<int>(0, 7), dst_buf.data(), 4,
                              &sse);

  // Target: vpx_highbd_idct4x4_16_add_sse2
  vpx_highbd_idct4x4_16_add_sse2(
      coeffs.data(), dst_buf16.data(), 4,
      fdp.ConsumeIntegralInRange<int>(8, 12));

  // Target: vpx_convolve8_c
  InterpKernel kernel[16];
  for (int i = 0; i < 16; ++i) {
    for (int j = 0; j < 8; ++j) {
      if (fdp.remaining_bytes() < sizeof(int16_t)) {
        i = 16; // break outer loop
        break;
      }
      kernel[i][j] = fdp.ConsumeIntegral<int16_t>();
    }
  }
  vpx_convolve8_c(src_buf.data() + conv_src_offset, 4, dst_buf.data(), 4, kernel,
                  fdp.ConsumeIntegralInRange<int>(0, 15), fdp.ConsumeIntegralInRange<int>(0, 64),
                  fdp.ConsumeIntegralInRange<int>(0, 15), fdp.ConsumeIntegralInRange<int>(0, 32), 4, 4);

  // Target: vpx_dc_predictor_4x4_c
  vpx_dc_predictor_4x4_c(dst_buf.data(), 4, src_buf.data() + pred_src_offset, src_buf.data() + pred_src_offset);

  // Target: vpx_d153_predictor_4x4_c
  vpx_d153_predictor_4x4_c(dst_buf.data(), 4, src_buf.data() + pred_src_offset, src_buf.data() + pred_src_offset);

  return 0;
}