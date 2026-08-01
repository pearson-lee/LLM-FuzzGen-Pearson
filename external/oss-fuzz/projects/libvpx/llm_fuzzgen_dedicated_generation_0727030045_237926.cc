/* BLOCKER_STRATEGY_CONTRACT
required_state: The `bd` parameter must be equal to 8 when calling `vp9_highbd_iht4x4_16_add_sse4_1`.
state_constructor: The fuzzer bypasses the high-level decoder APIs which previously led to `bd=10`. Instead, it directly calls the target function `vp9_highbd_iht4x4_16_add_sse4_1` and explicitly sets the `bd` parameter to 8.
trigger_api: vp9_highbd_iht4x4_16_add_sse4_1
preserved_invariants: The fuzzer must directly invoke `vp9_highbd_iht4x4_16_add_sse4_1` with `bd=8` to ensure the correct branch is taken.
END_BLOCKER_STRATEGY_CONTRACT */

#include <fuzzer/FuzzedDataProvider.h>
#include <cstdint>
#include <vector>

// Forward declaration for the target function, which is not exposed in public headers.
// The function is expected to be available for linking from libvpx.a.
// The input type is tran_low_t, which is int32_t.
extern "C" void vp9_highbd_iht4x4_16_add_sse4_1(
    int32_t *input, uint8_t *dest, int stride, int tx_type, int bd);

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  FuzzedDataProvider fdp(data, size);

  // The function reads 16 32-bit coefficients from the input buffer.
  const size_t kInputCoeffs = 16;
  std::vector<int32_t> input_data(kInputCoeffs);
  fdp.ConsumeData(input_data.data(), kInputCoeffs * sizeof(int32_t));

  // Constrain stride to a reasonable range to avoid excessive memory allocation.
  int stride = fdp.ConsumeIntegralInRange<int>(4, 64);
  int tx_type = fdp.ConsumeIntegralInRange<int>(0, 3);

  // The destination buffer is written to in a 4x4 block pattern. A downstream
  // function, recon_and_store_4x4, is called with a byte stride that is
  // misinterpreted as an element stride for a uint16_t pointer. This leads
  // to an access at an offset of 6 * stride bytes. We allocate enough memory
  // to avoid a crash, plus 16 bytes for the SSE instruction.
  std::vector<uint8_t> dest_data(6 * stride + 16);

  // The primary goal is to hit the branch where bd is 8.
  const int bd = 8;

  vp9_highbd_iht4x4_16_add_sse4_1(
      input_data.data(), dest_data.data(), stride, tx_type, bd);

  return 0;
}
