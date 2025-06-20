#include "/src/lcms/include/lcms2.h"
#include "/src/lcms/src/lcms2_internal.h"
#include <stdint.h>
#include <string.h>

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

  return 0;
}