#include "/src/lcms/include/lcms2.h"
#include "/src/lcms/src/lcms2_internal.h"
#include <stdint.h>
#include <string.h>
#include <stdlib.h>

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  if (size < sizeof(int) * 2 + 2) {
    return 0;
  }

  // cmsIT8 calls
  cmsHANDLE hIT8 = cmsIT8Alloc(NULL);
  if (hIT8) {
    int row = *(int *)data;
    data += sizeof(int);
    size -= sizeof(int);
    int col = *(int *)data;
    data += sizeof(int);
    size -= sizeof(int);

    char *val = (char *)malloc(size + 1);
    if (val) {
      memcpy(val, data, size);
      val[size] = '\0';
      cmsIT8SetDataRowCol(hIT8, row, col, val);
      free(val);
    }

    if (size > 2) {
      size_t key_len = data[0];
      data++;
      size--;
      if (size > key_len) {
        char *key = (char *)malloc(key_len + 1);
        if (key) {
          memcpy(key, data, key_len);
          key[key_len] = '\0';
          data += key_len;
          size -= key_len;

          if (size > 0) {
            char *buffer = (char *)malloc(size + 1);
            if (buffer) {
              memcpy(buffer, data, size);
              buffer[size] = '\0';
              cmsIT8SetPropertyUncooked(hIT8, key, buffer);
              free(buffer);
            }
          }
          free(key);
        }
      }
    }
    cmsIT8Free(hIT8);
  }

  // Profile sequence calls
  cmsHPROFILE hProfile = cmsCreateProfilePlaceholder(NULL);
  if (hProfile) {
    cmsSEQ *seq = _cmsReadProfileSequence(hProfile);
    if (seq) {
      cmsFreeProfileSequenceDescription(seq);
    }
    // Added call to cmsMD5computeID to improve coverage of cmsmd5.c
    cmsMD5computeID(hProfile);
    cmsCloseProfile(hProfile);
  }

  // Added calls to MD5 functions to improve coverage of cmsmd5.c
  cmsHANDLE hMD5 = cmsMD5alloc(NULL);
  if (hMD5) {
    cmsMD5add(hMD5, data, (cmsUInt32Number)size);
    cmsProfileID profileID;
    cmsMD5finish(&profileID, hMD5);
  }

  // Added calls to GDB functions to improve coverage of cmssm.c
  cmsHANDLE hGDB = cmsGBDAlloc(NULL);
  if (hGDB) {
    if (size >= sizeof(cmsCIELab)) {
      cmsCIELab lab;
      memcpy(&lab, data, sizeof(cmsCIELab));
      cmsGDBCheckPoint(hGDB, &lab);
    }
    cmsGBDFree(hGDB);
  }

  // Added calls to create a profile with a parametric curve tag to improve coverage of cmsgamma.c and cmstypes.c
  if (size > sizeof(int) + 7 * sizeof(double)) {
    cmsHPROFILE hProfileWrite = cmsCreateProfilePlaceholder(NULL);
    if (hProfileWrite) {
      int type = (*(int *)data) % 5 + 1; // Types 1-5
      const uint8_t *params_data = data + sizeof(int);

      double params[7];
      memcpy(params, params_data, 7 * sizeof(double));

      cmsToneCurve *curve = cmsBuildParametricToneCurve(NULL, type, params);
      if (curve) {
        if (cmsWriteTag(hProfileWrite, cmsSigCurveType, curve)) {
          cmsUInt32Number profile_len = 0;
          // Save profile to memory to exercise write handlers.
          if (cmsSaveProfileToMem(hProfileWrite, NULL, &profile_len) && profile_len > 0) {
            char *profile_buf = (char *)malloc(profile_len);
            if (profile_buf) {
              if (cmsSaveProfileToMem(hProfileWrite, profile_buf, &profile_len)) {
                // Read the profile from memory to exercise read handlers.
                cmsHPROFILE hProfileRead = cmsOpenProfileFromMem(profile_buf, profile_len);
                if (hProfileRead) {
                  // This will trigger Type_Curve_Read or Type_ParametricCurve_Read
                  cmsReadTag(hProfileRead, cmsSigCurveType);
                  cmsCloseProfile(hProfileRead);
                }
              }
              free(profile_buf);
            }
          }
        }
        cmsFreeToneCurve(curve);
      }
      cmsCloseProfile(hProfileWrite);
    }
  }

  // Added calls to CIECAM02 functions to improve coverage of cmscam02.c
  if (size >= sizeof(cmsViewingConditions) + sizeof(cmsCIEXYZ)) {
    cmsViewingConditions vc;
    memcpy(&vc, data, sizeof(cmsViewingConditions));
    const uint8_t *xyz_data = data + sizeof(cmsViewingConditions);

    cmsHANDLE hCIECAM02 = cmsCIECAM02Init(NULL, &vc);
    if (hCIECAM02) {
      cmsCIEXYZ In;
      cmsJCh Out;
      memcpy(&In, xyz_data, sizeof(cmsCIEXYZ));
      cmsCIECAM02Forward(hCIECAM02, &In, &Out);
      cmsCIECAM02Reverse(hCIECAM02, &Out, &In);
      cmsCIECAM02Done(hCIECAM02); // Frees the hCIECAM02 handle
    }
  }

  // Added calls to cmsCreateRGBProfileTHR to improve coverage of cmsvirt.c
  if (size >= sizeof(cmsCIExyY) + sizeof(cmsCIExyYTRIPLE)) {
      cmsCIExyY WhitePoint;
      memcpy(&WhitePoint, data, sizeof(cmsCIExyY));
      const uint8_t* primaries_data = data + sizeof(cmsCIExyY);

      cmsCIExyYTRIPLE Primaries;
      memcpy(&Primaries, primaries_data, sizeof(cmsCIExyYTRIPLE));

      cmsToneCurve* curves[3];
      curves[0] = cmsBuildGamma(NULL, 2.2);
      curves[1] = cmsBuildGamma(NULL, 2.2);
      curves[2] = cmsBuildGamma(NULL, 2.2);

      // This call aims to improve coverage in cmsvirt.c
      cmsHPROFILE hProfileRGB = cmsCreateRGBProfileTHR(NULL, &WhitePoint, &Primaries, curves);
      if (hProfileRGB) {
          cmsCloseProfile(hProfileRGB);
      }

      // All allocated tone curves are freed to prevent memory leaks.
      cmsFreeToneCurve(curves[0]);
      cmsFreeToneCurve(curves[1]);
      cmsFreeToneCurve(curves[2]);
  }

  // Added calls to cover LUT8 read/write operations based on coverage report.
  if (size > 24 * sizeof(cmsUInt16Number)) {
    cmsHPROFILE hProfileWrite = cmsCreateProfilePlaceholder(NULL);
    if (hProfileWrite) {
      cmsPipeline *lut = cmsPipelineAlloc(NULL, 3, 3);
      if (lut) {
        cmsStage *clut = cmsStageAllocCLut16bit(NULL, 2, 3, 3, (const cmsUInt16Number *)data);
        if (clut) {
          cmsPipelineInsertStage(lut, cmsAT_END, clut);
          if (cmsWriteTag(hProfileWrite, cmsSigLut8Type, lut)) {
            cmsUInt32Number profile_len = 0;
            if (cmsSaveProfileToMem(hProfileWrite, NULL, &profile_len) && profile_len > 0) {
              char *profile_buf = (char *)malloc(profile_len);
              if (profile_buf) {
                if (cmsSaveProfileToMem(hProfileWrite, profile_buf, &profile_len)) {
                  cmsHPROFILE hProfileRead = cmsOpenProfileFromMem(profile_buf, profile_len);
                  if (hProfileRead) {
                    // This will trigger Type_LUT8_Read
                    cmsReadTag(hProfileRead, cmsSigLut8Type);
                    cmsCloseProfile(hProfileRead);
                  }
                }
                free(profile_buf);
              }
            }
          }
        }
        cmsPipelineFree(lut); // This also frees the clut stage.
      }
      cmsCloseProfile(hProfileWrite);
    }
  }

  // Added calls to cover ColorantTable read/write operations based on coverage report.
  if (size > sizeof(cmsUInt16Number) * 3 + sizeof(cmsUInt16Number) * 16) {
    cmsHPROFILE hProfileWrite = cmsCreateProfilePlaceholder(NULL);
    if (hProfileWrite) {
      cmsNAMEDCOLORLIST *nc = cmsAllocNamedColorList(NULL, 1, 4, "p", "s");
      if (nc) {
        cmsUInt16Number pcs[3];
        cmsUInt16Number colorant[16];
        memcpy(pcs, data, sizeof(pcs));
        memcpy(colorant, data + sizeof(pcs), sizeof(colorant));

        if (cmsAppendNamedColor(nc, "name", pcs, colorant)) {
          if (cmsWriteTag(hProfileWrite, cmsSigColorantTableType, nc)) {
            cmsUInt32Number profile_len = 0;
            if (cmsSaveProfileToMem(hProfileWrite, NULL, &profile_len) && profile_len > 0) {
              char *profile_buf = (char *)malloc(profile_len);
              if (profile_buf) {
                if (cmsSaveProfileToMem(hProfileWrite, profile_buf, &profile_len)) {
                  cmsHPROFILE hProfileRead = cmsOpenProfileFromMem(profile_buf, profile_len);
                  if (hProfileRead) {
                    // This will trigger Type_ColorantTable_Read
                    cmsReadTag(hProfileRead, cmsSigColorantTableType);
                    cmsCloseProfile(hProfileRead);
                  }
                }
                free(profile_buf);
              }
            }
          }
        }
        cmsFreeNamedColorList(nc);
      }
      cmsCloseProfile(hProfileWrite);
    }
  }

  // Added calls to cover Text read/write operations based on coverage report.
  if (size > 10) {
    cmsHPROFILE hProfileWrite = cmsCreateProfilePlaceholder(NULL);
    if (hProfileWrite) {
      cmsMLU *mlu = cmsMLUalloc(NULL, 1);
      if (mlu) {
        char text[11];
        memcpy(text, data, 10);
        text[10] = '\0';
        // This call aims to improve coverage in cmsnamed.c
        if (cmsMLUsetASCII(mlu, "en", "US", text)) {
          if (cmsWriteTag(hProfileWrite, cmsSigTextType, mlu)) {
            cmsUInt32Number profile_len = 0;
            if (cmsSaveProfileToMem(hProfileWrite, NULL, &profile_len) && profile_len > 0) {
              char *profile_buf = (char *)malloc(profile_len);
              if (profile_buf) {
                if (cmsSaveProfileToMem(hProfileWrite, profile_buf, &profile_len)) {
                  cmsHPROFILE hProfileRead = cmsOpenProfileFromMem(profile_buf, profile_len);
                  if (hProfileRead) {
                    // This will trigger Type_Text_Read
                    cmsReadTag(hProfileRead, cmsSigTextType);
                    cmsCloseProfile(hProfileRead);
                  }
                }
                free(profile_buf);
              }
            }
          }
        }
        cmsMLUfree(mlu);
      }
      cmsCloseProfile(hProfileWrite);
    }
  }

  return 0;
}