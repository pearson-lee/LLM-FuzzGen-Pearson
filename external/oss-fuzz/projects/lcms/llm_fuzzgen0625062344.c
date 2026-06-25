#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include "/src/lcms/include/lcms2.h"

#ifndef _FUZZ_TARGET_NAME
#define _FUZZ_TARGET_NAME "fuzz_target"
#endif

// Helper function to create a temporary file with the given content
static char *create_temp_file(const uint8_t *data, size_t size) {
  char *path = (char *)malloc(256);
  if (!path) {
    return NULL;
  }
  snprintf(path, 256, "/tmp/%s.cube", _FUZZ_TARGET_NAME);

  FILE *file = fopen(path, "wb");
  if (!file) {
    free(path);
    return NULL;
  }

  fwrite(data, 1, size, file);
  fclose(file);
  return path;
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  if (size < 20) {
    return 0;
  }

  // Create a context
  cmsContext context = cmsCreateContext(NULL, NULL);
  if (!context) {
    return 0;
  }

  /*
   * ANALYSIS: The function-level coverage report showed
   * cmsCreateDeviceLinkFromCubeFileTHR had many missed branches. The line-level
   * report confirmed this was due to the fuzzer not providing a valid CUBE
   * file.
   * IMPLEMENTATION: The following code block creates a temporary CUBE file
   * from the fuzzer data and passes it to
   * cmsCreateDeviceLinkFromCubeFileTHR to exercise the file parsing and
   * device link creation logic.
   */
  char *temp_file_path = create_temp_file(data, size);
  if (temp_file_path) {
    cmsHPROFILE profile = cmsCreateDeviceLinkFromCubeFileTHR(context, temp_file_path);
    if (profile) {
      cmsCloseProfile(profile);
    }
    unlink(temp_file_path);
    free(temp_file_path);
  }

  /*
   * ANALYSIS: The function-level coverage report showed cmsIT8SetData had low
   * coverage. The line-level report showed that the function often returned
   * early because the IT8 object was not set up correctly.
   * IMPLEMENTATION: The following code block creates an IT8 object, sets some
   * properties, and then uses cmsIT8SetData to populate it with data from the
   * fuzzer input. This should exercise the data setting logic.
   */
  cmsHANDLE it8 = cmsIT8Alloc(context);
  if (it8) {
    cmsIT8SetSheetType(it8, "LCMS_TEST");
    cmsIT8SetPropertyStr(it8, "ORIGINATOR", "LCMS");
    cmsIT8SetPropertyStr(it8, "DESCRIPTOR", "Test IT8");

    if (size > 10) {
      char patch[5];
      char sample[7];
      char value[6];
      memcpy(patch, data, 4);
      patch[4] = '\0';
      memcpy(sample, data + 4, 6);
      sample[6] = '\0';
      memcpy(value, data + 10, 5);
      value[5] = '\0';
      cmsIT8SetData(it8, patch, sample, value);
    }
    cmsIT8Free(it8);
  }

  /*
   * ANALYSIS: The function-level coverage report showed
   * cmsDetectDestinationBlackPoint had low coverage. The line-level report
   * showed that many branches related to different intents were not being
   * taken.
   * IMPLEMENTATION: The following code block creates a profile and then calls
   * cmsDetectDestinationBlackPoint with different intents to exercise the
   * complex logic within the function.
   */
  cmsHPROFILE srgb_profile = cmsCreate_sRGBProfileTHR(context);
  if (srgb_profile) {
    cmsCIEXYZ black_point;
    for (int i = 0; i < 4; i++) {
      cmsDetectDestinationBlackPoint(&black_point, srgb_profile, i, 0);
    }

    /*
     * ANALYSIS: The function-level coverage report showed cmsGetPostScriptCRD and
     * cmsGetPostScriptCSA have low coverage. The line-level reports for
     * WriteNamedColorCRD and WriteNamedColorCSA show that the code paths for
     * handling named color profiles are not being exercised.
     * IMPLEMENTATION: The following code block creates a named color profile,
     * appends a color, and then calls cmsGetPostScriptCRD and cmsGetPostScriptCSA
     * to generate PostScript output, targeting the uncovered named color logic.
     */
    cmsHPROFILE named_color_profile = cmsCreateNULLProfileTHR(context);
    if (named_color_profile) {
      cmsNAMEDCOLORLIST* nc_list = cmsAllocNamedColorList(context, 1, 3, "Prefix", "Suffix");
      if (nc_list) {
        uint16_t pcs[3] = {0};
        uint16_t colorant[3] = {0};
        if (size >= 6) {
            memcpy(pcs, data, 6);
        }
        if (size >= 12) {
            memcpy(colorant, data + 6, 6);
        }
        cmsAppendNamedColor(nc_list, "FuzzyColor", pcs, colorant);
        cmsWriteTag(named_color_profile, cmsSigNamedColor2Tag, nc_list);
        cmsFreeNamedColorList(nc_list);

        char ps_buffer[1024];
        cmsGetPostScriptCSA(context, named_color_profile, 0, 0, ps_buffer, sizeof(ps_buffer));
        cmsGetPostScriptCRD(context, named_color_profile, 0, 0, ps_buffer, sizeof(ps_buffer));
      }
      cmsCloseProfile(named_color_profile);
    }

    cmsCloseProfile(srgb_profile);
  }

  /*
   * ANALYSIS: The function-level coverage report showed
   * cmsGetToneCurveEstimatedTable and cmsGetToneCurveEstimatedTableEntries had
   * 0% coverage.
   * IMPLEMENTATION: The following code block creates a tone curve and then
   * calls these two functions to get data from it.
   */
  if (size > 2) {
    cmsToneCurve *tone_curve = cmsBuildTabulatedToneCurve16(context, data[0], NULL);
    if (tone_curve) {
      cmsGetToneCurveEstimatedTableEntries(tone_curve);
      cmsGetToneCurveEstimatedTable(tone_curve);
      cmsFreeToneCurve(tone_curve);
    }
  }

  cmsDeleteContext(context);
  return 0;
}