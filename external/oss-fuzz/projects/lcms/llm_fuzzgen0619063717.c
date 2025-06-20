#include "lcms2.h"
#include <stdint.h>
#include <stdlib.h>

// --- Fuzzer-generated data ---
struct FuzzerData {
  uint8_t *data;
  size_t size;
  size_t offset;
};

static uint16_t consume_word(struct FuzzerData *data) {
  uint16_t value = 0;
  if (data->offset + 1 < data->size) {
    value |= (uint16_t)data->data[data->offset++] << 8;
    value |= (uint16_t)data->data[data->offset++];
  }
  return value;
}

static uint32_t consume_dword(struct FuzzerData *data) {
  uint32_t value = 0;
  if (data->offset + 3 < data->size) {
    value |= (uint32_t)data->data[data->offset++] << 24;
    value |= (uint32_t)data->data[data->offset++] << 16;
    value |= (uint32_t)data->data[data->offset++] << 8;
    value |= (uint32_t)data->data[data->offset++];
  }
  return value;
}

// --- End of fuzzer-generated data ---

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  if (size < 1) {
    return 0;
  }

  struct FuzzerData fuzzer_data;
  fuzzer_data.data = (uint8_t *)data;
  fuzzer_data.size = size;
  fuzzer_data.offset = 0;

  cmsContext null_context = NULL;
  cmsHPROFILE profile = cmsCreateProfilePlaceholder(null_context);
  if (!profile) {
    return 0;
  }

  // Create a memory-based IO handler
  cmsIOHANDLER *io = cmsOpenIOhandlerFromNULL(null_context);
  if (!io) {
    cmsCloseProfile(profile);
    return 0;
  }

  // Fuzz Type_LUTB2A_Write
  cmsPipeline *lut = cmsPipelineAlloc(null_context, 3, 3);
  if (lut) {
    cmsStage *stage = cmsStageAllocCLut16bit(null_context, consume_word(&fuzzer_data) % 17, 3, 3, NULL);
    if (stage) {
      cmsPipelineInsertStage(lut, cmsAT_BEGIN, stage);
      cmsWriteTag(profile, cmsSigBToA0Tag, lut);
    }
    cmsPipelineFree(lut);
  }

  // Fuzz Type_MPE_Write
  cmsPipeline *mpe = cmsPipelineAlloc(null_context, 3, 3);
  if (mpe) {
    cmsFloat64Number matrix[9] = {1.0, 0.0, 0.0, 0.0, 1.0, 0.0, 0.0, 0.0, 1.0};
    cmsFloat64Number offset[3] = {0.0, 0.0, 0.0};
    cmsStage *stage = cmsStageAllocMatrix(null_context, 3, 3, matrix, offset);
    if (stage) {
      cmsPipelineInsertStage(mpe, cmsAT_BEGIN, stage);
      cmsWriteTag(profile, cmsSigDToB0Tag, mpe);
    }
    cmsPipelineFree(mpe);
  }

  // Fuzz Type_ProfileSequenceDesc_Write
  cmsSEQ *seq = cmsAllocProfileSequenceDescription(null_context, 1);
  if (seq) {
    seq->seq[0].deviceMfg = consume_dword(&fuzzer_data);
    seq->seq[0].deviceModel = consume_dword(&fuzzer_data);
    seq->seq[0].attributes = consume_dword(&fuzzer_data);
    seq->seq[0].technology = (cmsTechnologySignature)consume_dword(&fuzzer_data);
    cmsWriteTag(profile, cmsSigProfileSequenceDescTag, seq);
    cmsFreeProfileSequenceDescription(seq);
  }

  // Fuzz Type_UcrBg_Write
  cmsUcrBg *ucrbg = (cmsUcrBg *)malloc(sizeof(cmsUcrBg));
  if (ucrbg) {
    ucrbg->Ucr = cmsBuildTabulatedToneCurve16(null_context, 2, NULL);
    ucrbg->Bg = cmsBuildTabulatedToneCurve16(null_context, 2, NULL);
    ucrbg->Desc = cmsMLUalloc(null_context, 1);
    if (ucrbg->Ucr && ucrbg->Bg && ucrbg->Desc) {
      cmsMLUsetASCII(ucrbg->Desc, "en", "US", "ucrbg");
      cmsWriteTag(profile, cmsSigUcrBgTag, ucrbg);
    }
    if (ucrbg->Ucr)
      cmsFreeToneCurve(ucrbg->Ucr);
    if (ucrbg->Bg)
      cmsFreeToneCurve(ucrbg->Bg);
    if (ucrbg->Desc)
      cmsMLUfree(ucrbg->Desc);
    free(ucrbg);
  }

  // Fuzz Type_CrdInfo_Write
  cmsMLU *crd_info = cmsMLUalloc(null_context, 5);
  if (crd_info) {
    cmsMLUsetASCII(crd_info, "PS", "nm", "name");
    cmsMLUsetASCII(crd_info, "PS", "#0", "crd0");
    cmsMLUsetASCII(crd_info, "PS", "#1", "crd1");
    cmsMLUsetASCII(crd_info, "PS", "#2", "crd2");
    cmsMLUsetASCII(crd_info, "PS", "#3", "crd3");
    cmsWriteTag(profile, cmsSigCrdInfoTag, crd_info);
    cmsMLUfree(crd_info);
  }

  // Save the profile to the memory IO handler
  cmsSaveProfileToIOhandler(profile, io);

  // Clean up
  cmsCloseIOhandler(io);
  cmsCloseProfile(profile);

  return 0;
}