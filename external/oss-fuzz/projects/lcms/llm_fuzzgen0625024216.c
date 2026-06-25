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

    cmsDeleteTransform(hTransform);
  }

  cmsCloseProfile(hProfile);
  cmsDeleteContext(context);
  return 0;
}