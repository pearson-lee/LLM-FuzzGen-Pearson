#include "/src/lcms/include/lcms2.h"
#include "/src/lcms/include/lcms2_plugin.h"
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

// Fuzzer for cmsTransform2DeviceLink, CreateNamedColorDevicelink, and
// cmsGetToneCurveParams
int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  if (size < 30) {
    return 0;
  }

  // Create a context
  cmsContext ctx = cmsCreateContext(NULL, NULL);
  if (ctx == NULL) {
    return 0;
  }

  // Part 1: Fuzz cmsTransform2DeviceLink and CreateNamedColorDevicelink
  // Create a placeholder for the named color profile
  cmsHPROFILE hNamedColorProfile = cmsCreateProfilePlaceholder(ctx);
  if (hNamedColorProfile != NULL) {
    // Set profile metadata
    cmsSetPCS(hNamedColorProfile, cmsSigLabData);
    cmsSetColorSpace(hNamedColorProfile, cmsSigGrayData);
    cmsSetDeviceClass(hNamedColorProfile, cmsSigNamedColorClass);

    // Use a portion of the data for the named color list
    size_t nc_size = size / 2;
    const uint8_t *nc_data = data;

    // Consume one byte to determine the number of colors to create
    int num_colors = nc_data[0] % 17; // 0-16 colors
    nc_data++;
    nc_size--;

    // Check if there is enough data to create the colors
    if (nc_size > num_colors * (16 + 6 + 2)) {
      // Allocate a named color list
      cmsNAMEDCOLORLIST *namedColorList =
          cmsAllocNamedColorList(ctx, num_colors, 1, "p", "s");
      if (namedColorList != NULL) {
        // Append colors to the list
        for (int i = 0; i < num_colors; i++) {
          char name[17];
          uint16_t PCS[3];
          uint16_t Device[1];

          memcpy(name, nc_data, 16);
          name[16] = '\0';
          nc_data += 16;

          memcpy(PCS, nc_data, 6);
          nc_data += 6;

          memcpy(Device, nc_data, 2);
          nc_data += 2;

          cmsAppendNamedColor(namedColorList, name, PCS, Device);
        }

        // Write the named color list to the profile
        if (cmsWriteTag(hNamedColorProfile, cmsSigNamedColor2Tag,
                        namedColorList)) {
          // Create a destination profile (e.g., sRGB)
          cmsHPROFILE hDestProfile = cmsCreate_sRGBProfile();
          if (hDestProfile != NULL) {
            // Create a transform from the named color profile to the
            // destination profile
            cmsHTRANSFORM hTransform = cmsCreateTransform(
                hNamedColorProfile, TYPE_NAMED_COLOR_INDEX, hDestProfile,
                TYPE_RGB_8, INTENT_PERCEPTUAL, 0);
            if (hTransform != NULL) {
              // This is the function we want to fuzz. It will call
              // CreateNamedColorDevicelink internally.
              cmsHPROFILE hDeviceLink =
                  cmsTransform2DeviceLink(hTransform, 1.0, 0);
              if (hDeviceLink != NULL) {
                cmsCloseProfile(hDeviceLink);
              }
              cmsDeleteTransform(hTransform);
            }
            cmsCloseProfile(hDestProfile);
          }
        }
        // The named color list is duplicated by cmsWriteTag, so we can free
        // ours.
        cmsFreeNamedColorList(namedColorList);
      }
    }
    // Close the named color profile
    cmsCloseProfile(hNamedColorProfile);
  }

  // Part 2: Fuzz cmsGetToneCurveParams
  const uint8_t *tc_data = data + size / 2;
  size_t tc_size = size - size / 2;

  // Check if there is enough data to create a parametric curve
  if (tc_size >= sizeof(int) + sizeof(double) * 7) {
    int type;
    memcpy(&type, tc_data, sizeof(int));
    tc_data += sizeof(int);
    double params[7];
    memcpy(params, tc_data, sizeof(double) * 7);

    // Valid types are 1 to 5.
    type = (abs(type) % 5) + 1;

    // Build a parametric tone curve
    cmsToneCurve *curve = cmsBuildParametricToneCurve(ctx, type, params);
    if (curve != NULL) {
      // This is the function we want to fuzz
      cmsGetToneCurveParams(curve);
      cmsFreeToneCurve(curve);
    }
  }

  // Clean up the context
  cmsDeleteContext(ctx);
  return 0;
}