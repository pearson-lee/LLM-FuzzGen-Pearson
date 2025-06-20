#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include "/src/lcms/include/lcms2.h"
#include <unistd.h>

// Fuzzer entry point.
int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    if (size < 1) {
        return 0;
    }

    // Create a context.
    cmsContext context = cmsCreateContext(NULL, NULL);
    if (context == NULL) {
        return 0;
    }

    // Create a memory-based I/O handler from the fuzzer input.
    cmsIOHANDLER *io = cmsOpenIOhandlerFromMem(context, (void *)data, size, "r");
    if (io == NULL) {
        cmsDeleteContext(context);
        return 0;
    }

    // Attempt to open a profile from the I/O handler.
    // The second argument (1) is to exercise the cmsOpenProfileFromIOhandler2THR code path.
    cmsHPROFILE profile = cmsOpenProfileFromIOhandler2THR(context, io, 1);
    if (profile != NULL) {
        // If a profile is successfully opened, try to get PostScript data from it.
        char buffer[1024];
        cmsGetPostScriptCSA(context, profile, 0, 0, buffer, sizeof(buffer));
        cmsGetPostScriptCRD(context, profile, 0, 0, buffer, sizeof(buffer));

        // Test reading a tag from the profile.
        cmsPipeline *pipeline = (cmsPipeline *)cmsReadTag(profile, cmsSigBToA0Tag);
        if (pipeline != NULL) {
            cmsPipelineFree(pipeline);
        }

        // Close the profile handle. This also closes the underlying IO handler.
        cmsCloseProfile(profile);
    } else {
        // If the profile could not be opened, we must close the IO handler ourselves.
        cmsCloseIOhandler(io);
    }

    // Attempt to load an IT8 object from the fuzzer input.
    cmsHANDLE it8 = cmsIT8LoadFromMem(context, data, size);
    if (it8 != NULL) {
        // Free the IT8 handle.
        cmsIT8Free(it8);
    }

    // Create a temporary file with the fuzzer data to test file-based API.
    char filename[256];
    sprintf(filename, "/tmp/lcms_fuzz_%d", getpid());
    FILE *fp = fopen(filename, "wb");
    if (fp != NULL) {
        fwrite(data, 1, size, fp);
        fclose(fp);

        // Attempt to create a device link from the temporary cube file.
        cmsHPROFILE devicelink = cmsCreateDeviceLinkFromCubeFileTHR(context, filename);
        if (devicelink != NULL) {
            cmsCloseProfile(devicelink);
        }

        // Clean up the temporary file.
        remove(filename);
    }

    // Delete the context and free all associated resources.
    cmsDeleteContext(context);

    return 0;
}