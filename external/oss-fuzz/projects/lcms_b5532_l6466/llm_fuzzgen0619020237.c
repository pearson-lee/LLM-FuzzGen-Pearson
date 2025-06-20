#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include "lcms2.h"
#include "lcms2_plugin.h"
#include <stdio.h>

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  if (size == 0) {
    return 0;
  }

  // --- Block 1: Fuzz cmsCreateDeviceLinkFromCubeFile ---
  char filename1[L_tmpnam];
  if (tmpnam(filename1) != NULL) {
    FILE* f = fopen(filename1, "wb");
    if (f) {
      if (fwrite(data, 1, size, f) == size) {
        fclose(f);
        cmsHPROFILE hProfile = cmsCreateDeviceLinkFromCubeFile(filename1);
        if (hProfile) {
          cmsMD5computeID(hProfile);
          cmsCloseProfile(hProfile);
        }
      } else {
        fclose(f);
      }
    }
    remove(filename1);
  }

  // --- Block 2: Fuzz memory and stream functions ---
  cmsHPROFILE h_srgb = cmsCreate_sRGBProfile();
  if (h_srgb) {
    cmsUInt32Number profileSize = 0;
    if (cmsSaveProfileToMem(h_srgb, NULL, &profileSize)) {
      void *memProfile = malloc(profileSize);
      if (memProfile) {
        if (cmsSaveProfileToMem(h_srgb, memProfile, &profileSize)) {
          cmsHPROFILE hMemProfile = cmsOpenProfileFromMem(memProfile, profileSize);
          if (hMemProfile) {
            char filename2[L_tmpnam];
            if (tmpnam(filename2) != NULL) {
              FILE *f_out = fopen(filename2, "wb");
              if (f_out) {
                // Based on ASan reports, cmsSaveProfileToStream likely closes
                // the file handle it is given. Calling fclose(f_out) here
                // would result in a double-free.
                cmsSaveProfileToStream(hMemProfile, f_out);
              }
              remove(filename2);
            }
            cmsCloseProfile(hMemProfile);
          }
        }
        free(memProfile);
      }
    }
    cmsCloseProfile(h_srgb);
  }

  // --- Block 3: Fuzz IT8 functions ---
  // Added a valid IT8 file to improve coverage of cmsIT8SetTableByLabel
  const char* it8_data =
    "ORIGINATOR \"lcms\"\n"
    "DESCRIPTOR \"a test file\"\n"
    "SAMPLE_ID \"1\"\n"
    "LABEL \"My Label 1 MYTYPE\"\n";
  char filename3[L_tmpnam];
  if (tmpnam(filename3) != NULL) {
    FILE* f = fopen(filename3, "wb");
    if (f) {
      fwrite(it8_data, 1, strlen(it8_data), f);
      fclose(f);
      cmsHANDLE hIT8 = cmsIT8LoadFromFile(NULL, filename3);
      if (hIT8) {
        cmsIT8SetTableByLabel(hIT8, "SAMPLE_ID", "My Label", "MYTYPE");
        const char **propertyNames;
        cmsUInt32Number propertyCount = cmsIT8EnumPropertyMulti(hIT8, "DESCRIPTOR", &propertyNames);
        if (propertyCount > 0 && propertyNames != NULL) {}
        cmsIT8GetDataRowColDbl(hIT8, 0, 0);
        char patchName[256];
        const char* patchNamePtr = cmsIT8GetPatchName(hIT8, 0, patchName);
        if (patchNamePtr) {}
        cmsIT8Free(hIT8);
      }
    }
    remove(filename3);
  }

  // --- Block 4: Fuzz cmsMD5 functions ---
  cmsHANDLE hMD5 = cmsMD5alloc(NULL);
  if (hMD5) {
    cmsMD5add(hMD5, data, size);
    cmsProfileID profileID;
    cmsMD5finish(&profileID, hMD5);
  }

  // --- Block 5: Fuzz cmsOpenProfileFromStream ---
  // Added to cover cmsOpenProfileFromStream, which was previously uncovered.
  // A profile is saved to a file, then reopened from the stream.
  // Memory safety is maintained by ensuring the file is properly closed.
  cmsHPROFILE h_srgb_stream = cmsCreate_sRGBProfile();
  if (h_srgb_stream) {
    char filename4[L_tmpnam];
    if (tmpnam(filename4) != NULL) {
        FILE* f = fopen(filename4, "wb");
        if (f) {
            if (cmsSaveProfileToStream(h_srgb_stream, f)) {
                // cmsSaveProfileToStream closes the file handle, so we need to reopen it.
                f = fopen(filename4, "rb");
                if (f) {
                    cmsHPROFILE hProfile = cmsOpenProfileFromStream(f, "r");
                    if (hProfile) {
                        cmsCloseProfile(hProfile);
                    }
                }
            }
        }
        remove(filename4);
    }
    cmsCloseProfile(h_srgb_stream);
  }

  return 0;
}