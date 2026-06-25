#include <stdint.h>
#include <string.h>
#include <stdlib.h>
#include "/src/lcms/include/lcms2.h"

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  cmsContext context = cmsCreateContext(NULL, NULL);

  /*
   * ANALYSIS: The function-level coverage report showed cmsCreateNULLProfileTHR in cmsvirt.c was uncovered.
   * IMPLEMENTATION: The following block calls cmsCreateNULLProfileTHR to exercise the
   *                 creation of a NULL profile.
   */
  cmsHPROFILE null_profile = cmsCreateNULLProfileTHR(context);
  if (null_profile) {
    cmsCloseProfile(null_profile);
  }

  /*
   * ANALYSIS: The function-level coverage report showed the cmsGBD* family of functions were uncovered.
   * IMPLEMENTATION: The following block calls cmsGBDAlloc, cmsGDBAddPoint, and cmsGBDFree to exercise
   *                 the gamut boundary description API.
   */
  cmsHANDLE gbd = cmsGBDAlloc(context);
  if (gbd) {
    cmsCIELab lab;
    if (size >= sizeof(cmsCIELab)) {
      memcpy(&lab, data, sizeof(cmsCIELab));
      cmsGDBAddPoint(gbd, &lab);
    }
    cmsGBDFree(gbd);
  }

  /*
   * ANALYSIS: The function-level coverage report showed cmsLab2LCh and cmsLCh2Lab were uncovered.
   * IMPLEMENTATION: The following block calls cmsLab2LCh and cmsLCh2Lab to exercise the
   *                 Lab/LCh color conversion functions.
   */
  if (size >= sizeof(cmsCIELab)) {
    cmsCIELab lab_in, lab_out;
    cmsCIELCh lch;
    memcpy(&lab_in, data, sizeof(cmsCIELab));
    cmsLab2LCh(&lch, &lab_in);
    cmsLCh2Lab(&lab_out, &lch);
  }

  // Clean up.
  cmsDeleteContext(context);

  return 0;
}