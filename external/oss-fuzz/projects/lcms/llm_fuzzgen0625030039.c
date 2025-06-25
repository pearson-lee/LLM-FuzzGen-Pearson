#include <stdint.h>
#include <stddef.h>
#include <stdio.h>
#include <string.h>

#include "/src/lcms/include/lcms2.h"
#include "/src/lcms/include/lcms2_plugin.h"
#include "/src/lcms/src/lcms2_internal.h"

// Define a custom IO handler for in-memory operations
typedef struct {
    const uint8_t *Data;
    size_t Size;
    size_t Pos;
} MemIO;

static cmsUInt32Number MemRead(cmsIOHANDLER* io, void* Buffer, cmsUInt32Number Size, cmsUInt32Number Count) {
    MemIO* mem_io = (MemIO*)io->ContextID; // Correctly cast ContextID to MemIO*
    size_t bytes_to_read = (size_t)Size * Count;
    if (mem_io->Pos + bytes_to_read > mem_io->Size) {
        bytes_to_read = mem_io->Size - mem_io->Pos;
    }
    memcpy(Buffer, mem_io->Data + mem_io->Pos, bytes_to_read);
    mem_io->Pos += bytes_to_read;
    return (cmsUInt32Number)(bytes_to_read / Size);
}

static cmsBool MemSeek(cmsIOHANDLER* io, cmsUInt32Number Offset) {
    MemIO* mem_io = (MemIO*)io->ContextID; // Correctly cast ContextID to MemIO*
    if (Offset > mem_io->Size) {
        return FALSE;
    }
    mem_io->Pos = Offset;
    return TRUE;
}

static cmsUInt32Number MemTell(cmsIOHANDLER* io) {
    MemIO* mem_io = (MemIO*)io->ContextID; // Correctly cast ContextID to MemIO*
    return (cmsUInt32Number)mem_io->Pos;
}

static cmsBool MemClose(cmsIOHANDLER* io) {
    // No allocation to free for this simple in-memory handler
    // The IO handler itself is stack-allocated in LLVMFuzzerTestOneInput,
    // so no need to free it here.
    return TRUE;
}

// Fuzz target for cmsOpenProfileFromIOhandlerTHR and cmsCreateProofingTransformTHR
int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size) {
    // Ensure there's enough data for basic operations
    if (Size < 100) {
        return 0;
    }

    cmsContext ContextID = cmsCreateContext(NULL, NULL);
    if (!ContextID) {
        return 0;
    }

    // Fuzzing cmsOpenProfileFromIOhandlerTHR
    // We'll simulate a file stream using a memory-backed IO handler.
    MemIO mem_io = {Data, Size, 0};
    cmsIOHANDLER io_handler; // Declare on stack
    memset(&io_handler, 0, sizeof(cmsIOHANDLER)); // Initialize to zeros

    // IMPORTANT FIX: ContextID in cmsIOHANDLER should point to our custom data (MemIO), not the cmsContext.
    io_handler.ContextID = &mem_io; // Associate with the custom MemIO data
    io_handler.Read = MemRead;
    io_handler.Seek = MemSeek;
    io_handler.Tell = MemTell;
    io_handler.Close = MemClose;
    io_handler.UsedSpace = 0; // Not used for read-only memory handler

    // cmsOpenProfileFromIOhandlerTHR expects a pointer to cmsIOHANDLER
    cmsHPROFILE hProfile = cmsOpenProfileFromIOhandlerTHR(ContextID, &io_handler);
    if (hProfile) {
        cmsCloseProfile(hProfile);
    }
    // The cmsOpenProfileFromIOhandlerTHR function does not close the IO handler internally.
    // Since io_handler is stack-allocated, it will be cleaned up when the function returns.


    // Fuzzing cmsCreateProofingTransformTHR
    // This function requires multiple profiles and intents.
    // We'll create some dummy profiles for testing.
    cmsHPROFILE hInputProfile = NULL;
    cmsHPROFILE hOutputProfile = NULL;
    cmsHPROFILE hProofingProfile = NULL;

    // Create dummy sRGB profile for input and output
    hInputProfile = cmsCreate_sRGBProfileTHR(ContextID);
    hOutputProfile = cmsCreate_sRGBProfileTHR(ContextID);
    hProofingProfile = cmsCreate_sRGBProfileTHR(ContextID);

    if (hInputProfile && hOutputProfile && hProofingProfile) {
        cmsUInt32Number InputFormat = TYPE_RGB_8;
        cmsUInt32Number OutputFormat = TYPE_RGB_8;
        cmsUInt32Number nIntent = INTENT_PERCEPTUAL;
        cmsUInt32Number ProofingIntent = INTENT_RELATIVE_COLORIMETRIC;
        cmsUInt32Number dwFlags = cmsFLAGS_BLACKPOINTCOMPENSATION | cmsFLAGS_SOFTPROOFING;

        cmsHTRANSFORM hTransform = cmsCreateProofingTransformTHR(
            ContextID,
            hInputProfile,
            InputFormat,
            hOutputProfile,
            OutputFormat,
            hProofingProfile,
            ProofingIntent,
            nIntent,
            dwFlags
        );

        if (hTransform) {
            cmsDeleteTransform(hTransform);
        }
    }

    // Clean up profiles
    if (hInputProfile) {
        cmsCloseProfile(hInputProfile);
    }
    if (hOutputProfile) {
        cmsCloseProfile(hOutputProfile);
    }
    if (hProofingProfile) {
        cmsCloseProfile(hProofingProfile);
    }

    cmsDeleteContext(ContextID);

    return 0;
}