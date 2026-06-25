#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <stddef.h>
#include "/src/lcms/include/lcms2.h"

int LLVMFuzzerTestOneInput(const uint8_t *fuzz_data, size_t fuzz_size) {
    cmsContext context = cmsCreateContext(NULL, NULL);
    if (!context) {
        return 0;
    }

    cmsHPROFILE ps_profile = cmsOpenProfileFromMemTHR(context, fuzz_data, fuzz_size);
    if (ps_profile) {
        char ps_buffer[1024];
        cmsGetPostScriptCRD(context, ps_profile, 0, 0, ps_buffer, sizeof(ps_buffer));
        cmsCloseProfile(ps_profile);
    }

    /*
     * FUZZING BLOCK 6: Test cmsDoTransform with alpha channels.
     */
    /*
     * ANALYSIS: The coverage report for cmsalpha.c showed that many formatters
     *           for alpha channels (e.g., from8to16, from16toHLF) were at 0% coverage.
     * IMPLEMENTATION: This block creates a transform between two profiles using
     *                 pixel formats that include an alpha channel (TYPE_RGBA_8 and
     *                 TYPE_BGRA_8) and calls cmsDoTransform to exercise this logic.
     */
    cmsHPROFILE srgb_profile_xform = cmsCreate_sRGBProfileTHR(context);
    cmsHPROFILE gray_profile_xform = cmsCreateGrayProfileTHR(context, NULL, NULL);
    if (srgb_profile_xform && gray_profile_xform) {
        cmsHTRANSFORM hTransform = cmsCreateTransform(srgb_profile_xform, TYPE_RGBA_8,
                                                      gray_profile_xform, TYPE_BGRA_8,
                                                      0, 0);
        if (hTransform) {
            uint8_t input[4] = { 0x11, 0x22, 0x33, 0x44 };
            uint8_t output[4];
            cmsDoTransform(hTransform, input, output, 1);
            cmsDeleteTransform(hTransform);
        }
    }
    if (srgb_profile_xform) cmsCloseProfile(srgb_profile_xform);
    if (gray_profile_xform) cmsCloseProfile(gray_profile_xform);

    /*
     * FUZZING BLOCK 7: Test named color read/write functionality.
     */
    /*
     * ANALYSIS: The coverage report for cmstypes.c showed that Type_NamedColor_Read
     *           was uncovered. This indicates that profiles containing named color
     *           tags were not being parsed.
     * IMPLEMENTATION: This block creates a named color list, adds it to a profile,
     *                 saves the profile to memory, and then re-loads it. This
     *                 save/load cycle is designed to trigger both the writing and
     *                 the uncovered reading logic for named color tags.
     */
    cmsHPROFILE named_color_profile = cmsCreateProfilePlaceholder(context);
    if (named_color_profile) {
        cmsNAMEDCOLORLIST* nc = cmsAllocNamedColorList(context, 1, 3, "p", "s");
        if (nc) {
            uint16_t pcs[3] = {0, 0, 0};
            uint16_t device[3] = {0, 0, 0};
            char name[17];
            memset(name, 0, sizeof(name));
            size_t name_len = fuzz_size > 16 ? 16 : fuzz_size;
            if (name_len > 0) {
                memcpy(name, fuzz_data, name_len);
            }

            if (cmsAppendNamedColor(nc, name, pcs, device)) {
                if (cmsWriteTag(named_color_profile, cmsSigNamedColor2Tag, nc)) {
                    unsigned char* buffer = NULL;
                    cmsUInt32Number len = 0;
                    if (cmsSaveProfileToMem(named_color_profile, NULL, &len)) {
                        buffer = (unsigned char*)malloc(len);
                        if (buffer) {
                            if (cmsSaveProfileToMem(named_color_profile, buffer, &len)) {
                                cmsHPROFILE hRead = cmsOpenProfileFromMemTHR(context, buffer, len);
                                if (hRead) {
                                    cmsCloseProfile(hRead);
                                }
                            }
                            free(buffer);
                        }
                    }
                }
            }
            cmsFreeNamedColorList(nc);
        }
        cmsCloseProfile(named_color_profile);
    }


    cmsDeleteContext(context);
    return 0;
}