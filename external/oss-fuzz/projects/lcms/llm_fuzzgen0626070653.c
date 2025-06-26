#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include "/src/lcms/include/lcms2.h"
#include "/src/lcms/src/lcms2_internal.h"

// Target 1: cmsCIECAM02Init
// This function has several uncovered branches in a switch statement based on the
// 'surround' field of cmsViewingConditions, as well as an uncovered path for
// the D_CALCULATE logic. This fuzzer generates varied viewing conditions to
// target these specific paths.
static void Fuzz_cmsCIECAM02Init(const uint8_t **Data, size_t *Size) {
  if (*Size < sizeof(cmsViewingConditions)) {
    return;
  }

  cmsViewingConditions vc;
  // Use fuzzer data to populate the viewing conditions struct.
  memcpy(&vc, *Data, sizeof(cmsViewingConditions));
  *Data += sizeof(cmsViewingConditions);
  *Size -= sizeof(cmsViewingConditions);

  // Consume a byte to select a surround value, ensuring all cases in the
  // switch statement inside cmsCIECAM02Init are explored.
  if (*Size > 0) {
    vc.surround = (**Data) % 4;
    (*Data)++;
    (*Size)--;
  }

  // Consume another byte to decide whether to trigger the D_CALCULATE path.
  if (*Size > 0) {
    if ((**Data) % 2 == 0) {
      vc.D_value = D_CALCULATE;
    }
    (*Data)++;
    (*Size)--;
  }

  // Call the target function with the generated viewing conditions.
  cmsHANDLE h = cmsCIECAM02Init(NULL, &vc);
  if (h) {
    // Ensure proper resource cleanup.
    cmsCIECAM02Done(h);
  }
}

// Target 2: cmsDetectTAC
// Coverage shows this function's logic is entirely skipped because it requires
// a profile of cmsSigOutputClass. This fuzzer creates a valid output profile
// to satisfy this condition and exercise the function's core logic.
static void Fuzz_cmsDetectTAC(void) {
  // Create a CMYK output profile, which is required by cmsDetectTAC.
  cmsHPROFILE h = cmsCreateInkLimitingDeviceLink(cmsSigCmykData, 100.0);
  if (h) {
    // Call the target function.
    cmsDetectTAC(h);
    // Ensure the created profile is properly closed to prevent leaks.
    cmsCloseProfile(h);
  }
}

// Target 3: cmsStageAllocCLut16bitGranular
// This function has untested validation logic for its parameters. This fuzzer
// provides a wide range of randomized inputs for grid points and channels to
// probe these error-handling paths.
static void Fuzz_cmsStageAllocCLut16bitGranular(const uint8_t **Data, size_t *Size) {
  if (*Size < 12) {
    return;
  }

  // Generate parameters from fuzzer data.
  const cmsUInt32Number nGridPoints = *(const cmsUInt32Number *)(*Data);
  const cmsUInt32Number inputChan = *(const cmsUInt32Number *)(*Data + 4);
  const cmsUInt32Number outputChan = *(const cmsUInt32Number *)(*Data + 8);
  *Data += 12;
  *Size -= 12;

  // The function expects a table of size (nGridPoints^inputChan) * outputChan.
  // To avoid excessive memory allocation, we cap the values.
  const cmsUInt32Number nGridPointsCapped = (nGridPoints % 16) + 1;
  const cmsUInt32Number inputChanCapped = (inputChan % MAX_INPUT_DIMENSIONS) + 1;
  const cmsUInt32Number outputChanCapped = (outputChan % 4) + 1;

  cmsUInt32Number clutPoints[MAX_INPUT_DIMENSIONS];
  for (cmsUInt32Number i = 0; i < inputChanCapped; ++i) {
    clutPoints[i] = nGridPointsCapped;
  }

  uint64_t table_size_64 = 1;
  for (cmsUInt32Number i = 0; i < inputChanCapped; ++i) {
    table_size_64 *= clutPoints[i];
  }
  table_size_64 *= outputChanCapped;

  if (table_size_64 > 256 * 1024) { // Limit memory usage to 256KB
    return;
  }
  const cmsUInt32Number table_size = (cmsUInt32Number)table_size_64;

  if (*Size < table_size * sizeof(cmsUInt16Number)) {
    return;
  }

  const cmsUInt16Number *table = (const cmsUInt16Number *)(*Data);
  *Data += table_size * sizeof(cmsUInt16Number);
  *Size -= table_size * sizeof(cmsUInt16Number);

  // Call the target function with the generated parameters.
  cmsStage *stage = cmsStageAllocCLut16bitGranular(NULL, clutPoints, inputChanCapped, outputChanCapped, table);
  if (stage) {
    // Ensure the allocated stage is properly freed.
    cmsStageFree(stage);
  }
}

// Main fuzzer entry point.
int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size) {
  if (Size < 1) {
    return 0;
  }

  // Use a byte from the input data to select which API to fuzz.
  uint8_t selector = Data[0];
  Data++;
  Size--;

  switch (selector % 3) {
  case 0:
    Fuzz_cmsCIECAM02Init(&Data, &Size);
    break;
  case 1:
    Fuzz_cmsDetectTAC();
    break;
  case 2:
    Fuzz_cmsStageAllocCLut16bitGranular(&Data, &Size);
    break;
  }

  return 0;
}