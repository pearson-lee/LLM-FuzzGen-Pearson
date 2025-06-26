#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include "lcms2.h"

// Fuzzer data provider structure to help consume input data safely.
typedef struct {
    const uint8_t *Data;
    size_t Size;
    size_t Offset;
} FuzzDataProvider;

// Checks if 'count' bytes can be safely consumed from the provider.
static int CanConsume(FuzzDataProvider *provider, size_t count) {
    return provider->Offset + count <= provider->Size;
}

// Consumes a block of bytes into 'dest'. Returns 1 on success, 0 on failure.
static int ConsumeBytes(FuzzDataProvider *provider, void *dest, size_t count) {
    if (!CanConsume(provider, count)) {
        return 0;
    }
    memcpy(dest, provider->Data + provider->Offset, count);
    provider->Offset += count;
    return 1;
}

// Consumes a value of any type. Returns 1 on success, 0 on failure.
#define ConsumeValue(provider, dest) ConsumeBytes(provider, dest, sizeof(*(dest)))

// Consumes a single byte to be used for making choices in the fuzzer.
static uint8_t ConsumeChoice(FuzzDataProvider *provider) {
    uint8_t choice = 0;
    if (CanConsume(provider, 1)) {
        ConsumeValue(provider, &choice);
    }
    return choice;
}

// Fuzzes the creation of gray profiles with different parameters.
void FuzzGrayProfile(cmsContext ctx, FuzzDataProvider *provider) {
    cmsCIExyY white_point;
    cmsToneCurve *gamma = NULL;
    cmsHPROFILE gray_profile = NULL;

    uint8_t choice = ConsumeChoice(provider);

    // Based on fuzzer input, decide whether to use a custom white point and gamma curve.
    if ((choice & 1) && ConsumeValue(provider, &white_point)) {
        if ((choice & 2)) {
            uint16_t num_entries = 0;
            if (ConsumeValue(provider, &num_entries)) {
                // Keep table size reasonable to avoid excessive memory allocation.
                num_entries = (num_entries % 4096) + 2;
                if (CanConsume(provider, num_entries * sizeof(uint16_t))) {
                    // Create a tone curve from fuzzer data.
                    uint16_t *table = (uint16_t *)(provider->Data + provider->Offset);
                    provider->Offset += num_entries * sizeof(uint16_t);
                    gamma = cmsBuildTabulatedToneCurve16(ctx, num_entries, table);
                }
            }
        }
        gray_profile = cmsCreateGrayProfile(&white_point, gamma);
    } else {
        // Call with default parameters.
        gray_profile = cmsCreateGrayProfile(NULL, NULL);
    }

    // Cleanup resources.
    if (gray_profile) {
        cmsCloseProfile(gray_profile);
    }
    if (gamma) {
        cmsFreeToneCurve(gamma);
    }
}

// Fuzzes profile tag handling and Gamut Boundary Description (GBD).
void FuzzProfileTagsAndGDB(cmsContext ctx, FuzzDataProvider *provider) {
    // Create a placeholder profile to which we can write tags.
    cmsHPROFILE profile = cmsCreateProfilePlaceholder(ctx);
    if (!profile) {
        return;
    }

    // --- Test Profile Sequence Description Tag ---
    cmsSEQ *seq = cmsAllocProfileSequenceDescription(ctx, 1);
    if (seq) {
        // Populate the sequence description fields with fuzzer data.
        if (CanConsume(provider, sizeof(cmsSignature) * 2 + sizeof(cmsUInt64Number) + sizeof(cmsTechnologySignature))) {
            ConsumeValue(provider, &seq->seq[0].deviceMfg);
            ConsumeValue(provider, &seq->seq[0].deviceModel);
            ConsumeValue(provider, &seq->seq[0].attributes);
            ConsumeValue(provider, &seq->seq[0].technology);
        }
        
        // Allocate and set MLU (Multi-Localized Unicode) data for text fields.
        seq->seq[0].Description = cmsMLUalloc(ctx, 1);
        if (seq->seq[0].Description) {
            cmsMLUsetASCII(seq->seq[0].Description, "en", "US", "Fuzzer Profile");
        }
        seq->seq[0].Manufacturer = cmsMLUalloc(ctx, 1);
        if (seq->seq[0].Manufacturer) {
            cmsMLUsetASCII(seq->seq[0].Manufacturer, "en", "US", "Fuzzer Inc.");
        }
        seq->seq[0].Model = cmsMLUalloc(ctx, 1);
        if (seq->seq[0].Model) {
            cmsMLUsetASCII(seq->seq[0].Model, "en", "US", "Fuzz-o-matic");
        }

        // Write the sequence tag to the profile. This creates a copy of the data.
        cmsWriteTag(profile, cmsSigProfileSequenceDescTag, seq);
        
        // Read the tag back to test the reading logic. The returned pointer
        // is owned by the profile and MUST NOT be freed.
        cmsReadTag(profile, cmsSigProfileSequenceDescTag);

        // Free the original sequence object, as the profile now has its own copy.
        cmsFreeProfileSequenceDescription(seq);
    }

    // --- Test Total Area Coverage detection ---
    cmsDetectTAC(profile);

    // --- Test Gamut Boundary Description (GBD) API ---
    cmsHANDLE gbd = cmsGBDAlloc(ctx);
    if (gbd) {
        // Add a variable number of points to the GBD.
        uint8_t num_points = ConsumeChoice(provider) & 0x0F; // Limit points
        for (int i = 0; i < num_points; ++i) {
            cmsCIELab lab;
            if (ConsumeValue(provider, &lab)) {
                cmsGDBAddPoint(gbd, &lab);
            }
        }
        // Compute the gamut boundary.
        cmsGDBCompute(gbd, 0);
        
        // Check a point against the computed gamut.
        cmsCIELab lab_check;
        if (ConsumeValue(provider, &lab_check)) {
            cmsGDBCheckPoint(gbd, &lab_check);
        }
        cmsGBDFree(gbd);
    }

    cmsCloseProfile(profile);
}

int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size) {
    if (Size < 1) {
        return 0;
    }

    FuzzDataProvider provider = {Data, Size, 0};

    // A single context is used for all operations.
    cmsContext ctx = cmsCreateContext(NULL, NULL);
    if (!ctx) {
        return 0;
    }

    // --- Test NULL Profile Creation ---
    cmsHPROFILE null_profile = cmsCreateNULLProfile();
    if (null_profile) {
        cmsCloseProfile(null_profile);
    }

    // --- Test Gray Profile Creation ---
    FuzzGrayProfile(ctx, &provider);

    // --- Test Profile Tags and GBD ---
    FuzzProfileTagsAndGDB(ctx, &provider);

    // Final cleanup of the context.
    cmsDeleteContext(ctx);
    return 0;
}