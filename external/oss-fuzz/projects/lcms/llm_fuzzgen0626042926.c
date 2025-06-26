#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include "lcms2.h"
#include "lcms2_plugin.h"

// This fuzzer targets the cmsPlugin API, which has very low coverage.
// It creates various plugin types with fuzzed data and attempts to register them.
// This approach helps uncover vulnerabilities in the plugin registration and
// handling logic. The fuzzer also calls cmsCreateContext and cmsDeleteContext
// to test context management under the influence of fuzzed plugins.

// Wrapper functions to safely handle memory operations for the fuzzed plugin.
static void* MallocWrapper(cmsContext ContextID, cmsUInt32Number size) {
    (void)ContextID;
    return malloc(size);
}

static void FreeWrapper(cmsContext ContextID, void* Ptr) {
    (void)ContextID;
    free(Ptr);
}

static void* ReallocWrapper(cmsContext ContextID, void* Ptr, cmsUInt32Number NewSize) {
    (void)ContextID;
    return realloc(Ptr, NewSize);
}

static void* MallocZeroWrapper(cmsContext ContextID, cmsUInt32Number size) {
    (void)ContextID;
    return calloc(size, 1);
}


int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    if (size < 1) {
        return 0;
    }

    // Unregister all plugins to ensure a clean state for each fuzzing iteration.
    cmsUnregisterPlugins();

    // Use the first byte of the input to select which plugin type to fuzz.
    uint8_t choice = data[0];
    const uint8_t *plugin_data = data + 1;
    size_t plugin_size = size - 1;

    void* plugin_ptr = NULL;

    // Allocate and populate a plugin structure based on the 'choice'.
    // The plugin data is copied from the fuzzer input.
    switch (choice % 10) {
        case 0: {
            // A cmsPluginMemHandler with invalid pointers will crash immediately
            // in cmsCreateContext. So we provide valid ones and let the fuzzer
            // test context management with a custom memory handler.
            cmsPluginMemHandler* plugin = (cmsPluginMemHandler*)malloc(sizeof(cmsPluginMemHandler));
            if (!plugin) break;
            
            plugin->MallocPtr = MallocWrapper;
            plugin->MallocZeroPtr = MallocZeroWrapper;
            plugin->ReallocPtr = ReallocWrapper;
            plugin->FreePtr = FreeWrapper;

            plugin->base.Type = cmsPluginMemHandlerSig;
            plugin_ptr = plugin;
            break;
        }
        case 1: {
            if (plugin_size < sizeof(cmsPluginInterpolation)) break;
            cmsPluginInterpolation* plugin = (cmsPluginInterpolation*)malloc(sizeof(cmsPluginInterpolation));
            if (!plugin) break;
            memcpy(plugin, plugin_data, sizeof(cmsPluginInterpolation));
            plugin->base.Type = cmsPluginInterpolationSig;
            plugin_ptr = plugin;
            break;
        }
        case 2: {
            if (plugin_size < sizeof(cmsPluginParametricCurves)) break;
            cmsPluginParametricCurves* plugin = (cmsPluginParametricCurves*)malloc(sizeof(cmsPluginParametricCurves));
            if (!plugin) break;
            memcpy(plugin, plugin_data, sizeof(cmsPluginParametricCurves));
            plugin->base.Type = cmsPluginParametricCurveSig;
            plugin_ptr = plugin;
            break;
        }
        case 3: {
            if (plugin_size < sizeof(cmsPluginFormatters)) break;
            cmsPluginFormatters* plugin = (cmsPluginFormatters*)malloc(sizeof(cmsPluginFormatters));
            if (!plugin) break;
            memcpy(plugin, plugin_data, sizeof(cmsPluginFormatters));
            plugin->base.Type = cmsPluginFormattersSig;
            plugin_ptr = plugin;
            break;
        }
        case 4: {
            if (plugin_size < sizeof(cmsPluginTagType)) break;
            cmsPluginTagType* plugin = (cmsPluginTagType*)malloc(sizeof(cmsPluginTagType));
            if (!plugin) break;
            memcpy(plugin, plugin_data, sizeof(cmsPluginTagType));
            plugin->base.Type = cmsPluginTagTypeSig;
            plugin_ptr = plugin;
            break;
        }
        case 5: {
            if (plugin_size < sizeof(cmsPluginTag)) break;
            cmsPluginTag* plugin = (cmsPluginTag*)malloc(sizeof(cmsPluginTag));
            if (!plugin) break;
            memcpy(plugin, plugin_data, sizeof(cmsPluginTag));
            plugin->base.Type = cmsPluginTagSig;
            plugin_ptr = plugin;
            break;
        }
        case 6: {
            if (plugin_size < sizeof(cmsPluginRenderingIntent)) break;
            cmsPluginRenderingIntent* plugin = (cmsPluginRenderingIntent*)malloc(sizeof(cmsPluginRenderingIntent));
            if (!plugin) break;
            memcpy(plugin, plugin_data, sizeof(cmsPluginRenderingIntent));
            plugin->base.Type = cmsPluginRenderingIntentSig;
            plugin_ptr = plugin;
            break;
        }
        case 7: {
            if (plugin_size < sizeof(cmsPluginMultiProcessElement)) break;
            cmsPluginMultiProcessElement* plugin = (cmsPluginMultiProcessElement*)malloc(sizeof(cmsPluginMultiProcessElement));
            if (!plugin) break;
            memcpy(plugin, plugin_data, sizeof(cmsPluginMultiProcessElement));
            plugin->base.Type = cmsPluginMultiProcessElementSig;
            plugin_ptr = plugin;
            break;
        }
        case 8: {
            if (plugin_size < sizeof(cmsPluginOptimization)) break;
            cmsPluginOptimization* plugin = (cmsPluginOptimization*)malloc(sizeof(cmsPluginOptimization));
            if (!plugin) break;
            memcpy(plugin, plugin_data, sizeof(cmsPluginOptimization));
            plugin->base.Type = cmsPluginOptimizationSig;
            plugin_ptr = plugin;
            break;
        }
        case 9: {
            if (plugin_size < sizeof(cmsPluginTransform)) break;
            cmsPluginTransform* plugin = (cmsPluginTransform*)malloc(sizeof(cmsPluginTransform));
            if (!plugin) break;
            memcpy(plugin, plugin_data, sizeof(cmsPluginTransform));
            plugin->base.Type = cmsPluginTransformSig;
            plugin_ptr = plugin;
            break;
        }
    }

    if (plugin_ptr) {
        // Set required fields to pass initial validation.
        cmsPluginBase* base = (cmsPluginBase*)plugin_ptr;
        base->Magic = cmsPluginMagicNumber;
        base->ExpectedVersion = 2000;
        base->Next = NULL;

        // Register the plugin. If registration succeeds, the memory is now owned by lcms.
        // If it fails, we must free it ourselves to prevent a memory leak.
        if (!cmsPlugin(plugin_ptr)) {
            free(plugin_ptr);
        }
    }

    // Fuzz context creation with the (potentially registered) plugin.
    // The user data pointer is also fuzzed.
    cmsContext ctx = cmsCreateContext(NULL, (void*)data);
    if (ctx) {
        cmsDeleteContext(ctx);
    }

    // Unregistering plugins will free the memory allocated for any successfully registered plugin.
    cmsUnregisterPlugins();

    return 0;
}