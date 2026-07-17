/* BLOCKER_STRATEGY_CONTRACT
required_state: The `nGamutPCSposition` parameter in `_cmsCreateGamutCheckPipeline` must be an invalid value, i.e., less than or equal to 0, or greater than 255.
state_constructor: Instead of calling `cmsCreateProofingTransformTHR` which hardcodes `nGamutPCSposition` to a valid value (1), we directly call `cmsCreateExtendedTransform`. This allows us to pass a custom value for `nGamutPCSposition`. We derive an invalid value (0 or 256) from the fuzzer input `data` buffer.
trigger_api: `cmsCreateExtendedTransform` is called with `cmsFLAGS_GAMUTCHECK`, which in turn calls the blocker function `_cmsCreateGamutCheckPipeline`.
preserved_invariants: The existing input contract is preserved. The new logic uses a previously unused byte from the input buffer (`data[1]`) and does not alter the consumption of `data[0]`. The core structure of creating contexts and profiles remains intact.
END_BLOCKER_STRATEGY_CONTRACT */

#include "/src/lcms/include/lcms2.h"
#include "/src/lcms/src/lcms2_internal.h"
#include <stdint.h>
#include <string.h>

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  if (size < 4) {
    return 0;
  }

  cmsContext context = cmsCreateContext(NULL, NULL);
  if (context == NULL) {
    return 0;
  }

  cmsHPROFILE hProfile = cmsCreate_sRGBProfileTHR(context);
  if (hProfile == NULL) {
    cmsDeleteContext(context);
    return 0;
  }

  cmsCIEXYZ blackPoint;
  int intent = data[0] % 4;
  cmsDetectDestinationBlackPoint(&blackPoint, hProfile, intent, 0);

  cmsHPROFILE hPlaceholder = cmsCreateProfilePlaceholder(context);
  if (hPlaceholder) {
    cmsSetDeviceClass(hPlaceholder, cmsSigLinkClass);
    cmsDetectDestinationBlackPoint(&blackPoint, hPlaceholder, intent, 0);
    cmsCloseProfile(hPlaceholder);
  }

  cmsHTRANSFORM hTransform = cmsCreateTransformTHR(context, hProfile, TYPE_RGB_8, hProfile, TYPE_RGB_8, intent, cmsFLAGS_CAN_CHANGE_FORMATTER);
  if (hTransform) {
    uint32_t inputFormat = TYPE_BGR_8;
    uint32_t outputFormat = TYPE_BGR_8;
    cmsChangeBuffersFormat(hTransform, inputFormat, outputFormat);

    cmsHPROFILE hDeviceLink = cmsTransform2DeviceLink(hTransform, 2.0, 0);
    if (hDeviceLink) {
      cmsCloseProfile(hDeviceLink);
    }
    hDeviceLink = cmsTransform2DeviceLink(hTransform, 2.0, cmsFLAGS_8BITS_DEVICELINK);
    if (hDeviceLink) {
      cmsCloseProfile(hDeviceLink);
    }

    cmsDeleteTransform(hTransform);
  }

  cmsHPROFILE hLabProfile = cmsCreateLab4ProfileTHR(context, NULL);
  if (hLabProfile) {
    cmsDetectDestinationBlackPoint(&blackPoint, hLabProfile, intent, 0);

    cmsHPROFILE profiles[] = {hProfile, hLabProfile};
    cmsHTRANSFORM hMultiTransform = cmsCreateMultiprofileTransformTHR(context, profiles, 2, TYPE_RGB_8, TYPE_Lab_8, intent, 0);
    if (hMultiTransform) {
      cmsDeleteTransform(hMultiTransform);
    }

    cmsCloseProfile(hLabProfile);
  }

  /*
   * BLOCKER_STRATEGY
   * The blocker is in `_cmsCreateGamutCheckPipeline` on the line:
   * `if (nGamutPCSposition <= 0 || nGamutPCSposition > 255)`
   * The call chain `cmsCreateProofingTransformTHR` -> `cmsCreateExtendedTransform`
   * hardcodes `nGamutPCSposition` to 1, which prevents the error from being triggered.
   * To overcome this, we replace the call to `cmsCreateProofingTransformTHR` with a
   * direct call to `cmsCreateExtendedTransform`, which allows us to control the
   * `nGamutPCSposition` parameter. We derive an out-of-range value from the fuzzing
   * input to trigger the desired error condition.
   */
  cmsHPROFILE hProofProfile = cmsCreate_sRGBProfileTHR(context);
  if (hProofProfile) {
    cmsHPROFILE hProfiles[] = {hProfile, hProofProfile, hProofProfile, hProfile};
    cmsUInt32Number intents[] = {(cmsUInt32Number)intent, (cmsUInt32Number)intent, INTENT_RELATIVE_COLORIMETRIC, (cmsUInt32Number)intent};
    cmsBool bpc[] = {0, 0, 0, 0};
    cmsFloat64Number adaptationState = cmsSetAdaptationStateTHR(context, -1);
    cmsFloat64Number adaptationStates[] = {adaptationState, adaptationState, adaptationState, adaptationState};

    // Use a byte from the input to select an invalid nGamutPCSposition.
    // This will trigger the error condition in _cmsCreateGamutCheckPipeline.
    cmsUInt32Number nGamutPCSposition = (data[1] % 2 == 0) ? 0 : 256;

    cmsHTRANSFORM hProofTransform = cmsCreateExtendedTransform(context, 4, hProfiles, bpc, intents, adaptationStates, hProofProfile, nGamutPCSposition, TYPE_RGB_8, TYPE_RGB_8, cmsFLAGS_GAMUTCHECK);
    if (hProofTransform) {
      cmsDeleteTransform(hProofTransform);
    }
    cmsCloseProfile(hProofProfile);
  }

  cmsCloseProfile(hProfile);
  cmsDeleteContext(context);
  return 0;
}