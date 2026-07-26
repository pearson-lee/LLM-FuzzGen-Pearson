#include <cstddef>
#include <cstdint>
#include <string>
#include <vector>

#include <fuzzer/FuzzedDataProvider.h>

#include "vpx_ports/mem.h"
#include "vpx_dsp/vpx_filter.h"
#include "vp9/common/vp9_scale.h"
#include "vp8_rtcd.h"

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
  FuzzedDataProvider fdp(data, size);

  // Setup scale factors
  struct scale_factors sf;
  int other_w = fdp.ConsumeIntegralInRange<int>(1, 1280);
  int other_h = fdp.ConsumeIntegralInRange<int>(1, 720);
  int this_w = fdp.ConsumeIntegralInRange<int>(1, 1280);
  int this_h = fdp.ConsumeIntegralInRange<int>(1, 720);

  /*
   * ANALYSIS: The line-level coverage report for
   *           vp9_setup_scale_factors_for_frame showed that the branch for
   *           invalid frame sizes was never taken.
   * IMPLEMENTATION: The following code block sometimes passes invalid frame
   *                 sizes to exercise this error-handling path.
   */
  if (fdp.ConsumeBool()) {
    vp9_setup_scale_factors_for_frame(&sf, 0, 0, this_w, this_h,
                                      fdp.ConsumeBool());
  } else {
    vp9_setup_scale_factors_for_frame(&sf, other_w, other_h, this_w, this_h,
                                      fdp.ConsumeBool());
  }

  // IDCT
  short input[16];
  unsigned char pred[16];
  unsigned char dst_ptr[16];
  for (int i = 0; i < 16; ++i) {
    input[i] = fdp.ConsumeIntegral<short>();
    pred[i] = fdp.ConsumeIntegral<unsigned char>();
  }

  /*
   * ANALYSIS: The function-level coverage report showed
   *           vp8_short_idct4x4llm_c had zero coverage.
   * IMPLEMENTATION: The following code block calls vp8_short_idct4x4llm_c to
   *                 exercise the inverse transform logic.
   */
  vp8_short_idct4x4llm_c(input, pred, 4, dst_ptr, 4);

  return 0;
}