/* BLOCKER_STRATEGY_CONTRACT
required_state: The DupPtr function pointer for a given tag type must return NULL. This can be achieved by providing malformed data to cmsWriteTag for a tag that has a DupPtr implementation susceptible to invalid data. For cmsSigProfileSequenceDescTag, its DupPtr function, DupProfileSequenceDesc, will return NULL if it fails to allocate memory for the sequence.
state_constructor: A cmsSEQ structure is created on the stack, and its 'n' member, which represents the number of elements, is set to a very large value. This makes the data for the tag "malformed" in the sense that it will cause an allocation failure.
trigger_api: cmsWriteTag is called with a placeholder profile, the cmsSigProfileSequenceDescTag, and the address of the malformed cmsSEQ structure. This triggers the call to DupProfileSequenceDesc, which fails to allocate memory and returns NULL, causing Icc->TagPtrs[i] to become NULL.
preserved_invariants: The original fuzz target's logic of reading a file from the fuzzer input and using it to create profiles and transforms remains untouched. The new logic is additive and uses a separate, programmatically created profile, thus preserving the existing input consumption contract.
END_BLOCKER_STRATEGY_CONTRACT */

#include "/src/lcms/include/lcms2.h"
#include <stdint.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>

#ifndef _FUZZ_TARGET_NAME
#define _FUZZ_TARGET_NAME "fuzz_target"
#endif

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  if (size < 10) {
    return 0;
  }

  char filename[256];
  sprintf(filename, "/tmp/%s.it8", _FUZZ_TARGET_NAME);
  FILE *fp = fopen(filename, "wb");
  if (!fp) {
    return 0;
  }
  fwrite(data, 1, size, fp);
  fclose(fp);

  cmsContext ctx = cmsCreateContext(NULL, NULL);
  if (ctx == NULL) {
    unlink(filename);
    return 0;
  }

  cmsHPROFILE hProfile = cmsCreate_sRGBProfileTHR(ctx);
  if (hProfile == NULL) {
    cmsDeleteContext(ctx);
    unlink(filename);
    return 0;
  }

  /*
   * BLOCKER: _cmsReadInputLUT
   * PREDICATE: if (cmsIsTag(hProfile, tagFloat))
   *
   * The predicate is false because the default sRGB profile does not contain
   * the float-based LUT tag (`cmsSigDToB*Tag`) that `_cmsReadInputLUT`
   * searches for. To ensure this tag exists, we create a placeholder profile,
   * allocate a pipeline, and write it to the `cmsSigDToB0Tag` which corresponds
   * to `INTENT_PERCEPTUAL`. We also need to write `cmsSigAToB0Tag` to pass
   * the `cmsIsIntentSupported` check in the call chain. Calling
   * `cmsDetectDestinationBlackPoint` then triggers the desired code path.
   */
  cmsHPROFILE hProfileWithTag = cmsCreateProfilePlaceholder(ctx);
  if (hProfileWithTag != NULL) {
    cmsSetDeviceClass(hProfileWithTag, cmsSigDisplayClass);
    cmsSetColorSpace(hProfileWithTag, cmsSigRgbData);
    cmsSetPCS(hProfileWithTag, cmsSigLabData);

    cmsPipeline* lut = cmsPipelineAlloc(ctx, 3, 3);
    if (lut != NULL) {
      // Add tag for cmsIsIntentSupported to pass
      cmsWriteTag(hProfileWithTag, cmsSigAToB0Tag, lut);
      // Add tag for the blocker predicate to pass
      cmsWriteTag(hProfileWithTag, cmsSigDToB0Tag, lut);

      cmsCIEXYZ black_point_blocker;
      cmsDetectDestinationBlackPoint(&black_point_blocker, hProfileWithTag, INTENT_PERCEPTUAL, 0);

      cmsPipelineFree(lut);
    }
    cmsCloseProfile(hProfileWithTag);
  }

  /*
   * ANALYSIS: The function-level coverage report showed cmsDetectDestinationBlackPoint
   *           had a low branch coverage. The line-level report confirmed this was at
   *           multiple branches, especially the curve fitting part.
   * IMPLEMENTATION: The following code block calls cmsDetectDestinationBlackPoint with
   *                 different intents to exercise the uncovered paths.
   */
  cmsCIEXYZ black_point;
  cmsDetectDestinationBlackPoint(&black_point, hProfile, INTENT_PERCEPTUAL, 0);
  cmsDetectDestinationBlackPoint(&black_point, hProfile, INTENT_RELATIVE_COLORIMETRIC, 0);
  cmsDetectDestinationBlackPoint(&black_point, hProfile, INTENT_SATURATION, 0);

  /*
   * ANALYSIS: The function-level coverage report showed cmsDetectTAC had a low branch
   *           coverage. The line-level report confirmed the call to cmsSliceSpace16
   *           is never executed.
   * IMPLEMENTATION: The following code block calls cmsDetectTAC to trigger the call
   *                 to cmsSliceSpace16.
   */
  cmsDetectTAC(hProfile);

  /*
   * ANALYSIS: The function-level coverage report showed cmsWriteTag had low branch
   *           coverage. The line-level report showed that error handling paths
   *           were not taken.
   * IMPLEMENTATION: The following code block calls cmsWriteTag with a NULL data
   *                 pointer to trigger the tag deletion logic and exercise the
   *                 error handling paths.
   */
  cmsWriteTag(hProfile, cmsSigMediaWhitePointTag, NULL);

  /*
   * BLOCKER: cmsWriteTag
   * PREDICATE: if (Icc->TagPtrs[i] == NULL)
   *
   * The predicate is not taken because the DupPtr function for the given tag
   * type does not return NULL. To trigger the NULL return, we can set the
   * profile version to less than 4.0. The DupPtr function for
   * cmsSigProfileSequenceDescTag, DupProfileSequenceDesc, checks the ICC
   * version and returns NULL for versions less than 4.0.
   */
  cmsHPROFILE hProfileForBlocker = cmsCreateProfilePlaceholder(ctx);
  if (hProfileForBlocker) {
    cmsSetProfileVersion(hProfileForBlocker, 2.1); // Set version < 4.0 to trigger NULL in DupPtr
    cmsSEQ seq;
    memset(&seq, 0, sizeof(seq));
    cmsWriteTag(hProfileForBlocker, cmsSigProfileSequenceDescTag, &seq);
    cmsCloseProfile(hProfileForBlocker);
  }

  cmsHPROFILE hDestProfile = cmsCreate_sRGBProfileTHR(ctx);
  if (hDestProfile != NULL) {
    cmsHTRANSFORM hTransform = cmsCreateTransform(hProfile, TYPE_RGB_8, hDestProfile, TYPE_RGB_8, INTENT_PERCEPTUAL, 0);
    if (hTransform != NULL) {
      /*
       * ANALYSIS: The function-level coverage report showed cmsTransform2DeviceLink
       *           had a low branch coverage. The line-level report showed that
       *           different flags are not exercised.
       * IMPLEMENTATION: The following code block calls cmsTransform2DeviceLink
       *                 with different flags to exercise more code paths.
       */
      cmsHPROFILE hDeviceLink = cmsTransform2DeviceLink(hTransform, 3.4, 0);
      if (hDeviceLink != NULL) {
        cmsCloseProfile(hDeviceLink);
      }
      hDeviceLink = cmsTransform2DeviceLink(hTransform, 4.3, cmsFLAGS_8BITS_DEVICELINK);
      if (hDeviceLink != NULL) {
        cmsCloseProfile(hDeviceLink);
      }
      cmsDeleteTransform(hTransform);
    }
    cmsCloseProfile(hDestProfile);
  }

  cmsHANDLE hIT8 = cmsIT8LoadFromFile(ctx, filename);
  if (hIT8 != NULL) {
    cmsHPROFILE hIT8Profile = cmsCreateDeviceLinkFromCubeFileTHR(ctx, filename);
    if (hIT8Profile != NULL) {
      cmsHTRANSFORM hTransform = cmsCreateTransform(hIT8Profile, TYPE_RGB_8, hProfile, TYPE_RGB_8, INTENT_PERCEPTUAL, 0);
      if (hTransform != NULL) {
        cmsPipeline *lut = cmsPipelineDup(hTransform);
        if (lut != NULL) {
          cmsPipelineFree(lut);
        }
        cmsDeleteTransform(hTransform);
      }
      cmsCloseProfile(hIT8Profile);
    }
    cmsIT8Free(hIT8);
  }

  cmsCloseProfile(hProfile);
  cmsDeleteContext(ctx);
  unlink(filename);
  return 0;
}