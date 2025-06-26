#include "lcms2.h"
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

// Fuzzer-driven wchar_t string creation.
// The first byte of the data is used as the length of the string.
static wchar_t *CreateWideString(const uint8_t **data, size_t *size) {
  if (*size < 1) {
    return NULL;
  }
  uint8_t len = *(*data);
  (*data)++;
  (*size)--;

  if (*size < len) {
    len = *size;
  }

  wchar_t *ws = (wchar_t *)malloc(sizeof(wchar_t) * (len + 1));
  if (!ws) {
    return NULL;
  }

  for (uint8_t i = 0; i < len; i++) {
    ws[i] = (wchar_t)((*data)[i]);
  }
  ws[len] = 0;

  *data += len;
  *size -= len;
  return ws;
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  if (size < 1) {
    return 0;
  }

  cmsContext ctx = cmsCreateContext(NULL, NULL);
  if (!ctx) {
    return 0;
  }

  // --- Create and populate a dictionary object ---
  // This will be used to exercise Type_Dictionary_* functions.
  cmsHANDLE dict = cmsDictAlloc(ctx);
  if (dict) {
    uint8_t num_dict_entries = data[0] % 8; // Limit entries to avoid timeouts
    data++;
    size--;

    for (uint8_t i = 0; i < num_dict_entries; i++) {
      wchar_t *name = CreateWideString(&data, &size);
      wchar_t *value = CreateWideString(&data, &size);

      if (name && value) {
        cmsDictAddEntry(dict, name, value, NULL, NULL);
      }

      free(name);
      free(value);
    }
  }

  // --- Create and populate a profile sequence description ---
  // This will be used to exercise Type_ProfileSequenceId_* functions.
  cmsSEQ *seq = NULL;
  if (size > 0) {
    uint8_t num_seq_entries = data[0] % 5;
    data++;
    size--;
    seq = cmsAllocProfileSequenceDescription(ctx, num_seq_entries);
    if (seq) {
      for (uint8_t i = 0; i < num_seq_entries && size > sizeof(cmsProfileID); i++) {
        memcpy(&seq->seq[i].ProfileID, data, sizeof(cmsProfileID));
        data += sizeof(cmsProfileID);
        size -= sizeof(cmsProfileID);

        wchar_t *desc_str = CreateWideString(&data, &size);
        if (desc_str) {
          seq->seq[i].Description = cmsMLUalloc(ctx, 1);
          if (seq->seq[i].Description) {
            cmsMLUsetWide(seq->seq[i].Description, "en", "US", desc_str);
          }
          free(desc_str);
        }
      }
    }
  }

  // --- Create and populate a colorant table ---
  // This will be used to exercise Type_ColorantTable_* functions.
  cmsNAMEDCOLORLIST *colorant_table = NULL;
  if (size > 0) {
    uint8_t num_colors = data[0] % 10;
    data++;
    size--;
    colorant_table = cmsAllocNamedColorList(ctx, num_colors, 3, "p", "s");
    if (colorant_table) {
      for (uint8_t i = 0; i < num_colors && size >= 7 + sizeof(uint16_t) * 3; i++) {
        uint16_t PCS[3];
        char name[8];

        memcpy(PCS, data, sizeof(PCS));
        data += sizeof(PCS);
        size -= sizeof(PCS);

        memcpy(name, data, 7);
        name[7] = '\0';
        data += 7;
        size -= 7;

        cmsAppendNamedColor(colorant_table, name, PCS, NULL);
      }
    }
  }

  // --- Create a profile and write the objects as tags ---
  // This exercises the Type_*_Write functions.
  cmsHPROFILE hProfile = cmsCreateProfilePlaceholder(ctx);
  if (!hProfile) {
    if (dict)
      cmsDictFree(dict);
    if (seq)
      cmsFreeProfileSequenceDescription(seq);
    if (colorant_table)
      cmsFreeNamedColorList(colorant_table);
    cmsDeleteContext(ctx);
    return 0;
  }

  if (dict) {
    cmsWriteTag(hProfile, cmsSigMetaTag, dict);
    cmsDictFree(dict); // cmsWriteTag dups the object, so we free the original.
  }
  if (seq) {
    cmsWriteTag(hProfile, cmsSigProfileSequenceIdTag, seq);
    cmsFreeProfileSequenceDescription(seq);
  }
  if (colorant_table) {
    cmsWriteTag(hProfile, cmsSigColorantTableTag, colorant_table);
    cmsFreeNamedColorList(colorant_table);
  }

  // --- Save profile to memory and reload it ---
  // This is the core of the test. It writes the data to a buffer and then
  // reads it back, forcing the Type_*_Read handlers to be called.
  char *buffer = NULL;
  cmsUInt32Number profile_size = 0;
  if (cmsSaveProfileToMem(hProfile, NULL, &profile_size)) {
    buffer = (char *)malloc(profile_size);
    if (buffer) {
      if (cmsSaveProfileToMem(hProfile, buffer, &profile_size)) {
        cmsHPROFILE hProfile2 = cmsOpenProfileFromMem(buffer, profile_size);
        if (hProfile2) {
          // Read the dictionary tag and duplicate it to test Type_Dictionary_Dup
          cmsHANDLE read_dict = (cmsHANDLE)cmsReadTag(hProfile2, cmsSigMetaTag);
          if (read_dict) {
            cmsHANDLE dup_dict = cmsDictDup(read_dict);
            if (dup_dict) {
              cmsDictFree(dup_dict); // Free the duplicated object.
            }
          }

          // Read the sequence tag and duplicate it to test Type_ProfileSequenceId_Dup
          cmsSEQ *read_seq = (cmsSEQ *)cmsReadTag(hProfile2, cmsSigProfileSequenceIdTag);
          if (read_seq) {
            cmsSEQ *dup_seq = cmsDupProfileSequenceDescription(read_seq);
            if (dup_seq) {
              cmsFreeProfileSequenceDescription(dup_seq);
            }
          }

          // Read the colorant table tag and duplicate it to test Type_ColorantTable_Dup
          cmsNAMEDCOLORLIST *read_colors = (cmsNAMEDCOLORLIST *)cmsReadTag(hProfile2, cmsSigColorantTableTag);
          if (read_colors) {
            cmsNAMEDCOLORLIST *dup_colors = cmsDupNamedColorList(read_colors);
            if (dup_colors) {
              cmsFreeNamedColorList(dup_colors);
            }
          }

          // Closing the profile frees the original read tags.
          cmsCloseProfile(hProfile2);
        }
      }
      free(buffer);
    }
  }

  cmsCloseProfile(hProfile);
  cmsDeleteContext(ctx);

  return 0;
}