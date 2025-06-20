#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include "/src/lcms/include/lcms2.h"
#include "/src/lcms/src/lcms2_internal.h"

// Fuzzer entry point.
int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  if (size < sizeof(cmsUInt32Number) * 2) {
    return 0;
  }

  // Added call to cmsPlugin to improve coverage of cmsplugin.c.
  // This function was identified as uncovered in the coverage report.
  cmsPlugin(NULL);

  // Create a memory-based IO handler to read from the fuzzer input.
  cmsIOHANDLER *io = cmsOpenIOhandlerFromMem(NULL, (void *)data, size, "r");
  if (io == NULL) {
    return 0;
  }

  // Create a context.
  cmsContext null_context = NULL;
  cmsHPROFILE profile = cmsCreateProfilePlaceholder(null_context);
  if (profile == NULL) {
    cmsCloseIOhandler(io);
    return 0;
  }

  // Added call to cmsMD5computeID to improve coverage of cmsmd5.c.
  // This function was identified as uncovered in the coverage report.
  // Calling it exercises the MD5 computation functionality in lcms.
  // The function is memory-safe as it frees allocated memory.
  cmsMD5computeID(profile);

  // Get the vcgt type handler.
  cmsTagTypeHandler *vcgt_handler = _cmsGetTagTypeHandler(null_context, cmsSigVcgtTag);
  if (vcgt_handler) {
    // Read a vcgt tag.
    cmsUInt32Number items, bytes;
    void *vcgt_tag = vcgt_handler->ReadPtr(vcgt_handler, io, &items, &bytes);
    if (vcgt_tag != NULL) {
      // Added call to WritePtr to improve coverage of Type_vcgt_Write.
      // This function was identified as uncovered in the coverage report.
      cmsIOHANDLER *write_io = cmsOpenIOhandlerFromMem(null_context, NULL, 0, "w");
      if (write_io != NULL) {
        vcgt_handler->WritePtr(vcgt_handler, write_io, vcgt_tag, 1);
        cmsCloseIOhandler(write_io);
      }
      // Duplicate and free the vcgt tag.
      void *vcgt_dup = vcgt_handler->DupPtr(vcgt_handler, vcgt_tag, bytes);
      if (vcgt_dup != NULL) {
        vcgt_handler->FreePtr(vcgt_handler, vcgt_dup);
      }
      vcgt_handler->FreePtr(vcgt_handler, vcgt_tag);
    }
  }

  // Reset the IO handler to the beginning of the data.
  io->Seek(io, 0);

  // Create a UcrBg structure and populate it with fuzzer data.
  cmsUcrBg *ucrbg = (cmsUcrBg *)_cmsMalloc(null_context, sizeof(cmsUcrBg));
  if (ucrbg == NULL) {
    cmsCloseProfile(profile);
    cmsCloseIOhandler(io);
    return 0;
  }
  ucrbg->Ucr = cmsBuildGamma(null_context, 256);
  ucrbg->Bg = cmsBuildGamma(null_context, 256);
  ucrbg->Desc = cmsMLUalloc(null_context, 1);
  if (ucrbg->Ucr == NULL || ucrbg->Bg == NULL || ucrbg->Desc == NULL) {
    if (ucrbg->Ucr)
      cmsFreeToneCurve(ucrbg->Ucr);
    if (ucrbg->Bg)
      cmsFreeToneCurve(ucrbg->Bg);
    if (ucrbg->Desc)
      cmsMLUfree(ucrbg->Desc);
    _cmsFree(null_context, ucrbg);
    cmsCloseProfile(profile);
    cmsCloseIOhandler(io);
    return 0;
  }

  // Get the UcrBg type handler.
  cmsTagTypeHandler *ucrbg_handler = _cmsGetTagTypeHandler(null_context, cmsSigUcrBgTag);
  if (ucrbg_handler) {
    // Write the UcrBg structure to a memory buffer.
    cmsIOHANDLER *write_io = cmsOpenIOhandlerFromMem(null_context, NULL, 0, "w");
    if (write_io != NULL) {
      ucrbg_handler->WritePtr(ucrbg_handler, write_io, ucrbg, 1);
      cmsCloseIOhandler(write_io);
    }

    // Duplicate and free the UcrBg structure.
    cmsUcrBg *ucrbg_dup = (cmsUcrBg *)ucrbg_handler->DupPtr(ucrbg_handler, ucrbg, 0);
    if (ucrbg_dup != NULL) {
      ucrbg_handler->FreePtr(ucrbg_handler, ucrbg_dup);
    }

    // Free the original UcrBg structure.
    ucrbg_handler->FreePtr(ucrbg_handler, ucrbg);
  } else {
    // If the handler is not found, free the manually allocated structure.
    cmsFreeToneCurve(ucrbg->Ucr);
    cmsFreeToneCurve(ucrbg->Bg);
    cmsMLUfree(ucrbg->Desc);
    _cmsFree(null_context, ucrbg);
  }

  // Allocate and free a Lab pre-linearization stage.
  cmsStage *stage = _cmsStageAllocLabPrelin(null_context);
  if (stage != NULL) {
    cmsStageFree(stage);
  }

  // Create an IT8 handle and get a property.
  cmsHANDLE it8 = cmsIT8Alloc(null_context);
  if (it8 != NULL) {
    cmsIT8GetPropertyMulti(it8, "prop", "subprop");
    // Added call to cmsIT8SetIndexColumn to improve coverage of cmscgats.c
    // This function was identified as uncovered in the coverage report.
    cmsIT8SetIndexColumn(it8, "SAMPLE_ID");
    cmsIT8Free(it8);
  }

  // Clean up remaining resources.
  cmsCloseProfile(profile);
  cmsCloseIOhandler(io);

  return 0;
}