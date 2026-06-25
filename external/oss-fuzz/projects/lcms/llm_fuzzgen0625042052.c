#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include "lcms2.h"
#include "lcms2_plugin.h"

// Dummy transform plugin
static void* MyTransform(struct _cms_trans_form_pipeline_st* pipeline, void* Cargo) {
  return Cargo;
}

static void MyFree(void* ptr) {
  // Do nothing
}

static cmsPluginTransform MyTransformPlugin = {
    {cmsPluginMagicNumber, 2060, cmsPluginTransformSig, NULL},
    MyTransform,
    MyTransform,
    MyTransform,
    MyFree
};

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    if (size < 1) {
        return 0;
    }

    cmsContext context = cmsCreateContext(NULL, NULL);
    if (!context) {
        return 0;
    }

    /*
     * ANALYSIS: The function-level coverage report showed _cmsRegisterTransformPlugin had low branch
     *           coverage.
     * IMPLEMENTATION: The following code block registers and unregisters a dummy transform plugin to
     *                 exercise the uncovered branches.
     */
    cmsPlugin(&MyTransformPlugin);
    cmsUnregisterPlugins();

    /*
     * ANALYSIS: The function-level coverage report showed cmsCIECAM02Init had low coverage.
     * IMPLEMENTATION: The following code block creates and then frees a CIECAM02 view conditions
     *                 object to exercise the uncovered code paths.
     */
    cmsViewingConditions vc;
    vc.whitePoint.X = 0.9642;
    vc.whitePoint.Y = 1.0;
    vc.whitePoint.Z = 0.8249;
    vc.La = 64;
    vc.Yb = 18;
    vc.D_value = 1.0;
    vc.surround = 2;
    cmsHANDLE cam = cmsCIECAM02Init(context, &vc);
    if (cam) {
        cmsCIECAM02Done(cam);
    }

    /*
     * ANALYSIS: The function-level coverage report showed cmsDetectDestinationBlackPoint had very low coverage.
     * IMPLEMENTATION: The following code block creates a transform between an RGB and a CMYK profile and then
     *                 calls cmsDetectDestinationBlackPoint to exercise the uncovered code paths.
     */
    cmsHPROFILE hRgb = cmsCreate_sRGBProfileTHR(context);
    cmsHPROFILE hCmyk = cmsCreateInkLimitingDeviceLinkTHR(context, cmsSigCmykData, 150);
    if (hRgb && hCmyk) {
        cmsHTRANSFORM hTransform = cmsCreateTransformTHR(context, hRgb, TYPE_RGB_8, hCmyk, TYPE_CMYK_8, INTENT_PERCEPTUAL, cmsFLAGS_BLACKPOINTCOMPENSATION);
        if (hTransform) {
            cmsCIEXYZ black_point;
            cmsDetectDestinationBlackPoint(&black_point, hCmyk, INTENT_PERCEPTUAL, cmsFLAGS_BLACKPOINTCOMPENSATION);
            cmsDeleteTransform(hTransform);
        }
    }
    if (hRgb) {
        cmsCloseProfile(hRgb);
    }
    if (hCmyk) {
        cmsCloseProfile(hCmyk);
    }

    /*
     * ANALYSIS: The function-level coverage report showed _cmsReadCHAD had low coverage.
     * IMPLEMENTATION: The following code block creates a profile, writes a 'chad' tag to it,
     *                 and then reads the tag to exercise the uncovered code paths.
     */
    cmsHPROFILE hProfile = cmsCreateProfilePlaceholder(context);
    if (hProfile) {
        double r = (double)data[0] / 255.0;
        cmsFloat64Number chad[] = {r, r, r, r, r, r, r, r, r};
        if (cmsWriteTag(hProfile, cmsSigChromaticAdaptationTag, chad)) {
            cmsFloat64Number* read_chad = (cmsFloat64Number*)cmsReadTag(hProfile, cmsSigChromaticAdaptationTag);
        }
        cmsCloseProfile(hProfile);
    }

    /*
     * ANALYSIS: The function-level coverage report showed cmsIT8SetTable had low coverage.
     * IMPLEMENTATION: The following code block creates an IT8 object and then sets a table in it
     *                 to exercise the uncovered code paths.
     */
    cmsHANDLE hIT8 = cmsIT8Alloc(context);
    if (hIT8) {
        cmsIT8SetTable(hIT8, 1);
        cmsIT8Free(hIT8);
    }

    cmsDeleteContext(context);
    return 0;
}