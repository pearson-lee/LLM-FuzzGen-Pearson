#include <stdint.h>
#include <string.h>
#include <stdlib.h>
#include "/src/lcms/include/lcms2.h"

// Helper to get data from the fuzz input
static size_t get_data(const uint8_t **data, size_t *size, void *dest, size_t dest_size) {
  if (*size < dest_size) {
    return 0;
  }
  memcpy(dest, *data, dest_size);
  *data += dest_size;
  *size -= dest_size;
  return dest_size;
}

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

  /*
   * ANALYSIS: The function-level coverage report showed the cmsDeltaE family of functions in cmspcs.c were uncovered.
   * IMPLEMENTATION: The following block calls cmsDeltaE, cmsCIE94DeltaE, cmsBFDdeltaE, cmsCMCdeltaE, and cmsCIE2000DeltaE
   *                 to exercise various color difference calculations.
   */
  if (size >= sizeof(cmsCIELab) * 2 + sizeof(double) * 5) {
    cmsCIELab lab1, lab2;
    double l, c, Kl, Kc, Kh;

    const uint8_t* current_data = data;
    size_t current_size = size;

    get_data(&current_data, &current_size, &lab1, sizeof(cmsCIELab));
    get_data(&current_data, &current_size, &lab2, sizeof(cmsCIELab));
    get_data(&current_data, &current_size, &l, sizeof(double));
    get_data(&current_data, &current_size, &c, sizeof(double));
    get_data(&current_data, &current_size, &Kl, sizeof(double));
    get_data(&current_data, &current_size, &Kc, sizeof(double));
    get_data(&current_data, &current_size, &Kh, sizeof(double));

    cmsDeltaE(&lab1, &lab2);
    cmsCIE94DeltaE(&lab1, &lab2);
    cmsBFDdeltaE(&lab1, &lab2);
    cmsCMCdeltaE(&lab1, &lab2, l, c);
    cmsCIE2000DeltaE(&lab1, &lab2, Kl, Kc, Kh);
  }

  /*
   * ANALYSIS: The function-level coverage report showed the cmsNamedColor* family of functions in cmsnamed.c were uncovered.
   * IMPLEMENTATION: The following block calls cmsAllocNamedColorList, cmsAppendNamedColor, cmsNamedColorCount,
   *                 cmsNamedColorInfo, and cmsNamedColorIndex to exercise the named color API.
   * MEMORY: cmsFreeNamedColorList is called to prevent memory leaks.
   */
  if (size > (sizeof(cmsUInt32Number) + sizeof(cmsUInt16Number) * 3 + sizeof(cmsUInt16Number) * 16 + 32)) {
    cmsUInt32Number nColorant;
    cmsUInt16Number PCS[3];
    cmsUInt16Number Device[16];
    char Name[33];

    const uint8_t* current_data = data;
    size_t current_size = size;

    get_data(&current_data, &current_size, &nColorant, sizeof(cmsUInt32Number));
    nColorant %= 16; // Keep it reasonable

    cmsNAMEDCOLORLIST* named_color_list = cmsAllocNamedColorList(context, 1, nColorant, "prefix", "suffix");
    if (named_color_list) {
      if (current_size > sizeof(PCS) + sizeof(Device) + 32) {
          get_data(&current_data, &current_size, PCS, sizeof(PCS));
          get_data(&current_data, &current_size, Device, sizeof(Device));
          size_t name_len = get_data(&current_data, &current_size, Name, 32);
          Name[name_len] = '\0';

          cmsAppendNamedColor(named_color_list, Name, PCS, Device);
          cmsNamedColorCount(named_color_list);
          cmsNamedColorIndex(named_color_list, Name);

          char name_buf[33], prefix_buf[33], suffix_buf[33];
          cmsNamedColorInfo(named_color_list, 0, name_buf, prefix_buf, suffix_buf, NULL, NULL);
      }
      cmsFreeNamedColorList(named_color_list);
    }
  }


  // Clean up.
  cmsDeleteContext(context);

  return 0;
}