#include "/src/lcms/include/lcms2.h"
#include "/src/lcms/include/lcms2_plugin.h"
#include "/src/lcms/src/lcms2_internal.h"
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

  // Added call to uncovered function Type_vcgt_Write based on coverage report
  cmsToneCurve *vcgt_curves[3];
  vcgt_curves[0] = cmsBuildTabulatedToneCurve16(null_context, 2, NULL);
  vcgt_curves[1] = cmsBuildTabulatedToneCurve16(null_context, 2, NULL);
  vcgt_curves[2] = cmsBuildTabulatedToneCurve16(null_context, 2, NULL);
  if (vcgt_curves[0] && vcgt_curves[1] && vcgt_curves[2]) {
    cmsWriteTag(profile, cmsSigVcgtTag, vcgt_curves);
  }
  if (vcgt_curves[0])
    cmsFreeToneCurve(vcgt_curves[0]);
  if (vcgt_curves[1])
    cmsFreeToneCurve(vcgt_curves[1]);
  if (vcgt_curves[2])
    cmsFreeToneCurve(vcgt_curves[2]);

  // Added call to uncovered function Type_LUT8_Write based on coverage report
  cmsPipeline *lut8 = cmsPipelineAlloc(null_context, 3, 3);
  if (lut8) {
    cmsStage *stage = cmsStageAllocCLut16bit(null_context, consume_word(&fuzzer_data) % 17, 3, 3, NULL);
    if (stage) {
      cmsPipelineInsertStage(lut8, cmsAT_BEGIN, stage);
      cmsWriteTag(profile, (cmsTagSignature)cmsSigLutAtoBType, lut8);
    }
    cmsPipelineFree(lut8);
  }

  // Added call to uncovered function Type_ProfileSequenceId_Write based on coverage report
  cmsSEQ *seqId = cmsAllocProfileSequenceDescription(null_context, 1);
  if (seqId) {
    seqId->seq[0].deviceMfg = consume_dword(&fuzzer_data);
    seqId->seq[0].deviceModel = consume_dword(&fuzzer_data);
    seqId->seq[0].attributes = consume_dword(&fuzzer_data);
    seqId->seq[0].technology = (cmsTechnologySignature)consume_dword(&fuzzer_data);
    cmsWriteTag(profile, cmsSigProfileSequenceIdTag, seqId);
    cmsFreeProfileSequenceDescription(seqId);
  }

  // Added call to uncovered function Type_NamedColor_Write based on coverage report
  cmsNAMEDCOLORLIST *named_color_list = cmsAllocNamedColorList(null_context, 1, 3, "prefix", "suffix");
  if (named_color_list) {
    uint16_t pcs[3] = {0};
    uint16_t device[3] = {0};
    char name[256] = "a name";
    cmsAppendNamedColor(named_color_list, name, pcs, device);
    cmsWriteTag(profile, cmsSigNamedColor2Tag, named_color_list);
    cmsFreeNamedColorList(named_color_list);
  }

  // Added call to uncovered function Type_Screening_Write based on coverage report
  cmsScreening *screening = (cmsScreening *)malloc(sizeof(cmsScreening));
  if (screening) {
    screening->Flag = 0;
    screening->nChannels = 1;
    screening->Channels[0].Frequency = 1.0;
    screening->Channels[0].ScreenAngle = 45.0;
    screening->Channels[0].SpotShape = 0;
    cmsWriteTag(profile, cmsSigScreeningTag, screening);
    free(screening);
  }

  // Added call to uncovered function Type_MHC2_Write based on coverage report
  cmsMHC2Type *mhc2_data = (cmsMHC2Type *)malloc(sizeof(cmsMHC2Type));
  if (mhc2_data) {
    mhc2_data->CurveEntries = 2;
    mhc2_data->RedCurve = (cmsFloat64Number *)malloc(2 * sizeof(cmsFloat64Number));
    mhc2_data->GreenCurve = (cmsFloat64Number *)malloc(2 * sizeof(cmsFloat64Number));
    mhc2_data->BlueCurve = (cmsFloat64Number *)malloc(2 * sizeof(cmsFloat64Number));

    if (mhc2_data->RedCurve && mhc2_data->GreenCurve && mhc2_data->BlueCurve) {
      mhc2_data->RedCurve[0] = 0.0;
      mhc2_data->RedCurve[1] = 1.0;
      mhc2_data->GreenCurve[0] = 0.0;
      mhc2_data->GreenCurve[1] = 1.0;
      mhc2_data->BlueCurve[0] = 0.0;
      mhc2_data->BlueCurve[1] = 1.0;
      cmsWriteTag(profile, (cmsTagSignature)0x4D484332, mhc2_data);
    }

    if (mhc2_data->RedCurve)
      free(mhc2_data->RedCurve);
    if (mhc2_data->GreenCurve)
      free(mhc2_data->GreenCurve);
    if (mhc2_data->BlueCurve)
      free(mhc2_data->BlueCurve);
    free(mhc2_data);
  }

  // Save the profile to the memory IO handler
  cmsSaveProfileToIOhandler(profile, io);

  // Clean up
  cmsCloseIOhandler(io);
  cmsCloseProfile(profile);

  return 0;
}