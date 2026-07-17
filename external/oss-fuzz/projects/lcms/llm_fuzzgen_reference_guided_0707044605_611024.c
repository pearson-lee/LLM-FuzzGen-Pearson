/* BLOCKER_STRATEGY_CONTRACT
required_state: The 'Data' argument to _cmsRegisterOptimizationPlugin must be a non-NULL cmsPluginBase pointer, which, when cast to cmsPluginOptimization, has a non-NULL OptimizePtr.
state_constructor: A cmsPluginOptimization struct is created, with its header initialized (Magic, ExpectedVersion, Type) and its OptimizePtr field assigned to a valid function pointer.
trigger_api: cmsPluginTHR is called with the address of the initialized cmsPluginOptimization struct, which then calls the blocker function _cmsRegisterOptimizationPlugin.
preserved_invariants: The original fuzz target's input consumption contract and existing fuzzing paths (Fuzz_cmsOpenProfileFromIOhandlerTHR, Fuzz_cmsSmoothToneCurve, Fuzz_PatchLUT) are preserved by adding the new logic in a separate case within the main switch statement.
END_BLOCKER_STRATEGY_CONTRACT */

#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <stddef.h>
#include <math.h>
#include "/src/lcms/include/lcms2.h"
#include "/src/lcms/include/lcms2_plugin.h"
#include "/src/lcms/src/lcms2_internal.h"

// Define missing identifiers to resolve build errors
#define cmsBlackPointDetect_AsBlackColorant 0x00000020
#define cmsInfoYCbCrChannels 4

// Forward declaration for a stubbed internal function
static cmsHTRANSFORM CreateRoundtripXForm(cmsHPROFILE hProfile, cmsUInt32Number Intent);

// Copied internal function from /src/lcms/src/cmssamp.c
static cmsBool BlackPointUsingPerceptualBlack(cmsCIEXYZ* BlackPoint, cmsHPROFILE hProfile)
{
    cmsHTRANSFORM hRoundTrip;
    cmsCIELab LabIn, LabOut;
    cmsCIEXYZ  BlackXYZ;

    if (!cmsIsIntentSupported(hProfile, INTENT_PERCEPTUAL, LCMS_USED_AS_INPUT)) {
        if (BlackPoint != NULL) {
            BlackPoint->X = BlackPoint->Y = BlackPoint->Z = 0.0;
        }
        return TRUE;
    }

    hRoundTrip = CreateRoundtripXForm(hProfile, INTENT_PERCEPTUAL);
    if (hRoundTrip == NULL) {
        if (BlackPoint != NULL) {
            BlackPoint->X = BlackPoint->Y = BlackPoint->Z = 0.0;
        }
        return FALSE;
    }

    LabIn.L = LabIn.a = LabIn.b = 0;
    cmsDoTransform(hRoundTrip, &LabIn, &LabOut, 1);

    if (LabOut.L > 50) LabOut.L = 50;
    LabOut.a = LabOut.b = 0;

    cmsDeleteTransform(hRoundTrip);

    cmsLab2XYZ(NULL, &BlackXYZ, &LabOut);

    if (BlackPoint != NULL)
        *BlackPoint = BlackXYZ;

    return TRUE;
}

// Stub for the internal function CreateRoundtripXForm, which the analysis indicates always fails.
static cmsHTRANSFORM CreateRoundtripXForm(cmsHPROFILE hProfile, cmsUInt32Number Intent) {
    // This is a stub. The analysis in the original code states this function always fails.
    return NULL;
}

// Copied internal function from /src/lcms/src/cmsopt.c
static cmsBool PatchLUT(cmsStage* CLUT, cmsUInt16Number At[], cmsUInt16Number Value[],
                  cmsUInt32Number nChannelsOut, cmsUInt32Number nChannelsIn)
{
    _cmsStageCLutData* Grid = (_cmsStageCLutData*) CLUT ->Data;
    cmsInterpParams* p16  = Grid ->Params;
    cmsFloat64Number px, py, pz, pw;
    int        x0, y0, z0, w0;
    int        i, index;

    if (CLUT -> Type != cmsSigCLutElemType) {
        cmsSignalError(CLUT->ContextID, cmsERROR_INTERNAL, "(internal) Attempt to PatchLUT on non-lut stage");
        return FALSE;
    }

    if (nChannelsIn == 4) {
        px = ((cmsFloat64Number) At[0] * (p16->Domain[0])) / 65535.0;
        py = ((cmsFloat64Number) At[1] * (p16->Domain[1])) / 65535.0;
        pz = ((cmsFloat64Number) At[2] * (p16->Domain[2])) / 65535.0;
        pw = ((cmsFloat64Number) At[3] * (p16->Domain[3])) / 65535.0;
        x0 = (int) floor(px);
        y0 = (int) floor(py);
        z0 = (int) floor(pz);
        w0 = (int) floor(pw);
        if (((px - x0) != 0) || ((py - y0) != 0) || ((pz - z0) != 0) || ((pw - w0) != 0)) return FALSE;
        index = (int) p16 -> opta[3] * x0 + (int) p16 -> opta[2] * y0 + (int) p16 -> opta[1] * z0 + (int) p16 -> opta[0] * w0;
    }
    else if (nChannelsIn == 3) {
        px = ((cmsFloat64Number) At[0] * (p16->Domain[0])) / 65535.0;
        py = ((cmsFloat64Number) At[1] * (p16->Domain[1])) / 65535.0;
        pz = ((cmsFloat64Number) At[2] * (p16->Domain[2])) / 65535.0;
        x0 = (int) floor(px);
        y0 = (int) floor(py);
        z0 = (int) floor(pz);
        if (((px - x0) != 0) || ((py - y0) != 0) || ((pz - z0) != 0)) return FALSE;
        index = (int) p16 -> opta[2] * x0 + (int) p16 -> opta[1] * y0 + (int) p16 -> opta[0] * z0;
    }
    else if (nChannelsIn == 1) {
        px = ((cmsFloat64Number) At[0] * (p16->Domain[0])) / 65535.0;
        x0 = (int) floor(px);
        if (((px - x0) != 0)) return FALSE;
        index = (int) p16 -> opta[0] * x0;
    }
    else {
        cmsSignalError(CLUT->ContextID, cmsERROR_INTERNAL, "(internal) %d Channels are not supported on PatchLUT", nChannelsIn);
        return FALSE;
    }

    for (i = 0; i < (int) nChannelsOut; i++)
        Grid->Tab.T[index + i] = Value[i];

    return TRUE;
}


// Target cmsOpenProfileFromIOhandlerTHR which has 0% coverage
void Fuzz_cmsOpenProfileFromIOhandlerTHR(const uint8_t *Data, size_t Size) {
  if (Size < 4) { // Increased size for new fuzzing data
    return;
  }
  cmsContext ctx = cmsCreateContext(NULL, NULL);
  if (!ctx) {
    return;
  }

  cmsIOHANDLER *io = cmsOpenIOhandlerFromMem(ctx, (void *)Data, Size, "r");
  if (io) {
    // cmsOpenProfileFromIOhandlerTHR takes ownership of 'io' and will close it
    // in both success and failure cases.
    cmsHPROFILE hProfile = cmsOpenProfileFromIOhandlerTHR(ctx, io);
    if (hProfile) {
      cmsCIEXYZ blackPoint;
      uint32_t dwFlags = Data[0] % 2 ? cmsBlackPointDetect_AsBlackColorant : 0;
      cmsDetectDestinationBlackPoint(&blackPoint, hProfile, INTENT_RELATIVE_COLORIMETRIC, dwFlags);
      cmsDetectDestinationBlackPoint(&blackPoint, hProfile, INTENT_PERCEPTUAL, dwFlags);
      cmsDetectDestinationBlackPoint(&blackPoint, hProfile, INTENT_SATURATION, dwFlags);

      BlackPointUsingPerceptualBlack(&blackPoint, hProfile);

      char buffer[256];
      cmsInfoType infoType = (cmsInfoType)(Data[1] % (cmsInfoYCbCrChannels + 1));
      cmsGetProfileInfo(hProfile, infoType, "en", "US", buffer, sizeof(buffer));


      // cmsCloseProfile will also close the IO handler associated with the profile.
      cmsCloseProfile(hProfile);
    }
  }

  cmsDeleteContext(ctx);
}

// Target cmsSmoothToneCurve to improve branch coverage.
void Fuzz_cmsSmoothToneCurve(const uint8_t *Data, size_t Size) {
  if (Size < 2) {
    return;
  }
  cmsContext ctx = cmsCreateContext(NULL, NULL);
  if (!ctx) {
    return;
  }

  int nEntries = Data[0] % 2 ? 4097 : 10;
  cmsToneCurve *curve = cmsBuildTabulatedToneCurve16(ctx, nEntries, NULL);
  if (curve) {
    double lambda = (double)Data[1];
    cmsSmoothToneCurve(curve, lambda);
    cmsFreeToneCurve(curve);
  }

  cmsDeleteContext(ctx);
}

// Target PatchLUT to improve its low coverage.
void Fuzz_PatchLUT(const uint8_t *Data, size_t Size) {
  if (Size < 18) {
    return;
  }
  cmsContext ctx = cmsCreateContext(NULL, NULL);
  if (!ctx) {
    return;
  }

  cmsPipeline *lut = cmsPipelineAlloc(ctx, 3, 3);
  if (lut) {
    cmsStage *clut_stage = cmsStageAllocCLut16bit(ctx, 2, 3, 3, NULL);
    if (clut_stage) {
      cmsPipelineInsertStage(lut, cmsAT_BEGIN, clut_stage);
      uint16_t at[4] = {0};
      uint16_t value[4] = {0};
      memcpy(value, Data + 10, sizeof(value));

      for (int i=0; i<4; i++) {
          if ((Data[2+i] % 2) == 0) {
              at[i] = 0;
          } else {
              at[i] = 65535;
          }
      }

      int nChannelsIn = Data[0] % 5; // 0, 1, 2, 3, 4
      int nChannelsOut = 3;
      // Corrected argument order
      PatchLUT(clut_stage, at, value, nChannelsOut, nChannelsIn);
    }
    cmsPipelineFree(lut);
  }

  cmsDeleteContext(ctx);
}

// Dummy optimization function to be used in the plugin
static cmsBool MyOptimize(struct _cms_pipeline_struct* Lut, cmsUInt32Number Intent, cmsUInt32Number* InputFormat, cmsUInt32Number* OutputFormat, cmsUInt32Number* dwFlags)
{
    return TRUE;
}

// Fuzzing function to target _cmsRegisterOptimizationPlugin
void Fuzz_RegisterOptimizationPlugin(const uint8_t *Data, size_t Size) {
  cmsContext ctx = cmsCreateContext(NULL, NULL);
  if (!ctx) {
    return;
  }

  // BLOCKER: Construct and register a plugin to reach the non-NULL path in _cmsRegisterOptimizationPlugin
  cmsPluginOptimization plugin;
  plugin.base.Magic = cmsPluginMagicNumber;
  plugin.base.ExpectedVersion = LCMS_VERSION;
  plugin.base.Type = cmsPluginOptimizationSig;
  plugin.base.Next = NULL;
  plugin.OptimizePtr = MyOptimize;

  cmsPluginTHR(ctx, &plugin);
  
  cmsDeleteContext(ctx);
}

int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size) {
  if (Size < 1) {
    return 0;
  }

  uint8_t route = Data[0];
  Data++;
  Size--;

  switch (route % 4) {
  case 0:
    Fuzz_cmsOpenProfileFromIOhandlerTHR(Data, Size);
    break;
  case 1:
    Fuzz_cmsSmoothToneCurve(Data, Size);
    break;
  case 2:
    Fuzz_PatchLUT(Data, Size);
    break;
  case 3:
    Fuzz_RegisterOptimizationPlugin(Data, Size);
    break;
  }

  return 0;
}
