#include "lcms2.h"
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

// Manually define missing tag/signature constants to avoid internal headers
#define cmsSigVideoSignalType ((cmsTagTypeSignature)0x76696473)
#define cmsSigLittleCMS ((cmsSignature)0x4C434D53)

// Helper function to create a simple pipeline for testing the MPE tag handler.
// A pipeline is a complex structure, and creating one exercises many other
// lcms functions.
static cmsPipeline *CreateTestPipeline(cmsContext ctx, const uint8_t *data, size_t size) {
  if (size < 2) {
    return NULL;
  }

  // Use fuzz data to determine input and output channels.
  cmsUInt32Number input_channels = (data[0] % 15) + 1;  // 1-16
  cmsUInt32Number output_channels = (data[1] % 15) + 1; // 1-16

  cmsPipeline *p = cmsPipelineAlloc(ctx, input_channels, output_channels);
  if (p == NULL) {
    return NULL;
  }

  // Add a matrix stage to the pipeline if there is enough data.
  size_t matrix_elements = (size_t)input_channels * output_channels;
  size_t offset_elements = output_channels;
  size_t required_data_size = (matrix_elements + offset_elements) * sizeof(cmsFloat64Number);

  if (size >= (2 + required_data_size)) {
    cmsFloat64Number *matrix = (cmsFloat64Number *)malloc(matrix_elements * sizeof(cmsFloat64Number));
    cmsFloat64Number *offset = (cmsFloat64Number *)malloc(offset_elements * sizeof(cmsFloat64Number));

    if (matrix && offset) {
      memcpy(matrix, data + 2, matrix_elements * sizeof(cmsFloat64Number));
      memcpy(offset, data + 2 + (matrix_elements * sizeof(cmsFloat64Number)), offset_elements * sizeof(cmsFloat64Number));

      cmsStage *matrix_stage = cmsStageAllocMatrix(ctx, output_channels, input_channels, matrix, offset);
      if (matrix_stage) {
        cmsPipelineInsertStage(p, cmsAT_END, matrix_stage);
      }
    }

    if (matrix)
      free(matrix);
    if (offset)
      free(offset);
  }
  return p;
}

// Fuzzer entry point
int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  if (size < 1) {
    return 0;
  }

  // Create a context. NULL is used for default memory management and logging.
  cmsContext ctx = cmsCreateContext(NULL, NULL);
  if (ctx == NULL) {
    return 0;
  }

  // Create a placeholder profile to write tags to.
  cmsHPROFILE hProfile = cmsCreateProfilePlaceholder(ctx);
  if (hProfile == NULL) {
    cmsDeleteContext(ctx);
    return 0;
  }

  // Use a byte from the input data as a control flag to decide which tags to
  // write. This allows the fuzzer to explore different combinations.
  uint8_t control = data[0];
  const uint8_t *current_data = data + 1;
  size_t remaining_size = size - 1;

  // Tag 1: Video Signal Tag (cmsSigVideoSignalType)
  if ((control & 0x01) && remaining_size >= sizeof(cmsVideoSignalType)) {
    cmsVideoSignalType videoSignal;
    memcpy(&videoSignal, current_data, sizeof(cmsVideoSignalType));
    cmsWriteTag(hProfile, cmsSigVideoSignalType, &videoSignal);
    current_data += sizeof(cmsVideoSignalType);
    remaining_size -= sizeof(cmsVideoSignalType);
  }

  // Tag 2: Data Tag (cmsSigDataTag)
  if ((control & 0x02) && remaining_size > sizeof(cmsICCData)) {
    size_t data_len = remaining_size / 4; // Use a portion of the data
    if (data_len > 0) {
      // The cmsICCData struct has a flexible array member.
      cmsICCData *icc_data = (cmsICCData *)malloc(sizeof(cmsICCData) + data_len - 1);
      if (icc_data) {
        icc_data->len = (cmsUInt32Number)data_len;
        icc_data->flag = 0; // Must be 0
        memcpy(icc_data->data, current_data, data_len);
        cmsWriteTag(hProfile, cmsSigDataTag, icc_data);
        free(icc_data); // Clean up the allocated data structure.
        current_data += data_len;
        remaining_size -= data_len;
      }
    }
  }

  // Tag 3: Signature Tag (cmsSigSignatureType)
  if ((control & 0x04) && remaining_size >= sizeof(cmsTagSignature)) {
    cmsTagSignature sig;
    memcpy(&sig, current_data, sizeof(cmsTagSignature));
    cmsWriteTag(hProfile, cmsSigSignatureType, &sig);
    current_data += sizeof(cmsTagSignature);
    remaining_size -= sizeof(cmsTagSignature);
  }

  // Tag 4: Multi-Process Element Tag (e.g., cmsSigDToB0Tag)
  if ((control & 0x08) && remaining_size > 2) {
    cmsPipeline *p = CreateTestPipeline(ctx, current_data, remaining_size);
    if (p) {
      cmsWriteTag(hProfile, cmsSigDToB0Tag, p);
      cmsPipelineFree(p); // Clean up the pipeline.
    }
  }

  // Tag 5: Profile Sequence Description Tag (cmsSigProfileSequenceDescTag)
  if ((control & 0x10) && remaining_size > 1) {
    cmsUInt32Number n_seq = (current_data[0] % 3) + 1; // 1 to 4 sequences
    current_data++;
    remaining_size--;

    cmsSEQ *seq = cmsAllocProfileSequenceDescription(ctx, n_seq);
    if (seq) {
      // Fill the sequence with some valid-ish data. The MLU objects must be
      // allocated to avoid writing NULL pointers, which would crash.
      for (cmsUInt32Number i = 0; i < n_seq; i++) {
        seq->seq[i].deviceMfg = cmsSigLittleCMS;
        seq->seq[i].deviceModel = cmsSigLittleCMS;
        seq->seq[i].technology = cmsSigDigitalCamera;
        seq->seq[i].Manufacturer = cmsMLUalloc(ctx, 1);
        seq->seq[i].Model = cmsMLUalloc(ctx, 1);
        seq->seq[i].Description = cmsMLUalloc(ctx, 1);
      }
      cmsWriteTag(hProfile, cmsSigProfileSequenceDescTag, seq);
      cmsFreeProfileSequenceDescription(seq); // Clean up the sequence object.
    }
  }

  // Save the profile with all its new tags to a memory buffer.
  cmsUInt32Number profile_size = 0;
  cmsSaveProfileToMem(hProfile, NULL, &profile_size);

  if (profile_size > 0) {
    void *profile_mem = malloc(profile_size);
    if (profile_mem) {
      if (cmsSaveProfileToMem(hProfile, profile_mem, &profile_size)) {
        // Open the profile from the memory buffer we just created.
        cmsHPROFILE hProfileRead = cmsOpenProfileFromMem(profile_mem, profile_size);
        if (hProfileRead) {
          // Read back the tags to exercise the Type_*_Read handlers.
          // For most tags, cmsReadTag returns a pointer to internal data that
          // should not be freed. However, for cmsSigDToB0Tag (pipeline) and
          // cmsSigProfileSequenceDescTag, it returns an allocated object that
          // MUST be freed.
          if (control & 0x01)
            cmsReadTag(hProfileRead, cmsSigVideoSignalType);
          if (control & 0x02)
            cmsReadTag(hProfileRead, cmsSigDataTag);
          if (control & 0x04)
            cmsReadTag(hProfileRead, cmsSigSignatureType);

          if (control & 0x08) {
            // The pointer returned by cmsReadTag is owned by the profile
            // and will be freed by cmsCloseProfile. Do not free it here.
            cmsReadTag(hProfileRead, cmsSigDToB0Tag);
          }
          if (control & 0x10) {
            // The pointer returned by cmsReadTag is owned by the profile
            // and will be freed by cmsCloseProfile. Do not free it here.
            cmsReadTag(hProfileRead, cmsSigProfileSequenceDescTag);
          }
          // Close the read profile, which frees its internal resources.
          cmsCloseProfile(hProfileRead);
        }
      }
      // Free the memory buffer for the profile.
      free(profile_mem);
    }
  }

  // Final cleanup.
  cmsCloseProfile(hProfile);
  cmsDeleteContext(ctx);
  return 0;
}