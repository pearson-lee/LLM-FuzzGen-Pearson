#include <stdint.h>
#include <stddef.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <wchar.h> // For wchar_t

// Include necessary lcms2 headers
#include "/src/lcms/include/lcms2.h"
#include "/src/lcms/include/lcms2_plugin.h"

// Define a maximum size for allocated buffers to prevent excessive memory usage
// #define MAX_ALLOC_SIZE 4096 // This define was not used in the original code, removing it.

// Define a maximum number of points for GBD to prevent excessive loop iterations
#define MAX_GBD_POINTS 100

// Define a maximum number of MLU translations to prevent excessive memory usage
#define MAX_MLU_TRANSLATIONS 10

// Define a maximum buffer size for MLU translations
#define MAX_MLU_BUFFER_SIZE 256

// Define a maximum number of GBD points to add
#define MAX_GBD_ADD_POINTS 10

// Define a maximum size for profile data
#define MAX_PROFILE_SIZE 1024 * 1024 // 1MB

// Define a maximum size for IT8 data
#define MAX_IT8_SIZE 1024 * 1024 // 1MB


// Helper function to consume an integral type (uint8_t)
uint8_t ConsumeIntegral_u8(const uint8_t** DataPos, size_t* RemainingSize) {
    uint8_t value = 0;
    if (*RemainingSize >= sizeof(uint8_t)) {
        memcpy(&value, *DataPos, sizeof(uint8_t));
        *DataPos += sizeof(uint8_t);
        *RemainingSize -= sizeof(uint8_t);
    } else if (*RemainingSize > 0) {
        memcpy(&value, *DataPos, *RemainingSize);
        *DataPos += *RemainingSize;
        *RemainingSize = 0;
    }
    return value;
}

// Helper function to consume an integral type (uint16_t)
uint16_t ConsumeIntegral_u16(const uint8_t** DataPos, size_t* RemainingSize) {
    uint16_t value = 0;
    if (*RemainingSize >= sizeof(uint16_t)) {
        memcpy(&value, *DataPos, sizeof(uint16_t));
        *DataPos += sizeof(uint16_t);
        *RemainingSize -= sizeof(uint16_t);
    } else if (*RemainingSize > 0) {
        memcpy(&value, *DataPos, *RemainingSize);
        *DataPos += *RemainingSize;
        *RemainingSize = 0;
    }
    return value;
}

// Helper function to consume an integral type (uint32_t)
uint32_t ConsumeIntegral_u32(const uint8_t** DataPos, size_t* RemainingSize) {
    uint32_t value = 0;
    if (*RemainingSize >= sizeof(uint32_t)) {
        memcpy(&value, *DataPos, sizeof(uint32_t));
        *DataPos += sizeof(uint32_t);
        *RemainingSize -= sizeof(uint32_t);
    } else if (*RemainingSize > 0) {
        memcpy(&value, *DataPos, *RemainingSize);
        *DataPos += *RemainingSize;
        *RemainingSize = 0;
    }
    return value;
}

// Helper function to consume an integral type (double)
double ConsumeIntegral_double(const uint8_t** DataPos, size_t* RemainingSize) {
    double value = 0;
    if (*RemainingSize >= sizeof(double)) {
        memcpy(&value, *DataPos, sizeof(double));
        *DataPos += sizeof(double);
        *RemainingSize -= sizeof(double);
    } else if (*RemainingSize > 0) {
        memcpy(&value, *DataPos, *RemainingSize);
        *DataPos += *RemainingSize;
        *RemainingSize = 0;
    }
    return value;
}


// Helper function to consume a string
// Returns a malloc'd string, must be freed by the caller
char* ConsumeString(const uint8_t** DataPos, size_t* RemainingSize, size_t max_len, size_t min_len) {
    size_t len_byte_size = sizeof(uint8_t); // Use a byte to determine length
    if (*RemainingSize < len_byte_size) {
        // Not enough data for length byte, return a string of min_len (or 0 if min_len > 0)
        size_t actual_len = (min_len > 0) ? min_len : 0;
        char* terminated_string = (char*)calloc(actual_len + 1, 1);
        return terminated_string ? terminated_string : strdup("");
    }
    uint8_t len = ConsumeIntegral_u8(DataPos, RemainingSize) % (max_len + 1);

    // Ensure minimum length
    if (len < min_len) {
        len = min_len;
    }

    if (*RemainingSize < len) {
        len = *RemainingSize;
    }

    char* terminated_string = (char*)malloc(len + 1);
    if (terminated_string) {
        memcpy(terminated_string, *DataPos, len);
        terminated_string[len] = '\0';
        *DataPos += len;
        *RemainingSize -= len;
    } else {
        // Handle malloc failure, return a string of min_len (or 0 if min_len > 0)
        size_t actual_len = (min_len > 0) ? min_len : 0;
        terminated_string = (char*)calloc(actual_len + 1, 1);
        return terminated_string ? terminated_string : strdup("");
    }
    return terminated_string;
}

// Helper function to consume a chunk of data
// Returns a pointer into the original Data buffer, no need to free
const uint8_t* ConsumeBytes(const uint8_t** DataPos, size_t* RemainingSize, size_t size, size_t* actual_size) {
    size_t bytes_to_consume = size;
    if (*RemainingSize < bytes_to_consume) {
        bytes_to_consume = *RemainingSize;
    }
    const uint8_t* result = *DataPos;
    *DataPos += bytes_to_consume;
    *RemainingSize -= bytes_to_consume;
    if (actual_size) {
        *actual_size = bytes_to_consume;
    }
    return result;
}


// Entry point for the fuzzer.
// This function receives a byte array of fuzzer-generated data.
int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size) {
  // Create a FuzzedDataProvider to consume the input data.
  // This is a C++ feature, but the fuzzer harness provides it.
  // We will simulate consuming data using pointer arithmetic and size checks
  // as if we were using FuzzedDataProvider in C.
  const uint8_t *DataPos = Data;
  size_t RemainingSize = Size;

  // Initialize lcms2 context (optional, but good practice for thread safety)
  cmsContext context = cmsCreateContext(NULL, NULL);
  if (!context) {
      return 0; // Unable to create context, nothing to do
  }

  // --- Fuzzing cmsCreateNULLProfile ---
  // The original code used cmsCreateNULLProfile() which does not take a context.
  // The API info shows cmsCreateNULLProfileTHR(cmsContext) which does.
  // Let's use the THR version for consistency with context usage.
  cmsHPROFILE null_profile = cmsCreateNULLProfileTHR(context);
  if (null_profile) {
      // Profile created successfully, close it to free memory
      cmsCloseProfile(null_profile);
  }

  // --- Fuzzing cmsOpenProfileFromMem ---
  size_t profile_size;
  const uint8_t* profile_data = ConsumeBytes(&DataPos, &RemainingSize, MAX_PROFILE_SIZE, &profile_size);
  if (profile_data && profile_size > 0) {
      // The original code used cmsOpenProfileFromMem which does not take a context.
      // Let's use cmsOpenProfileFromMemTHR for consistency.
      cmsHPROFILE mem_profile = cmsOpenProfileFromMemTHR(context, profile_data, profile_size);
      if (mem_profile) {
          // Profile opened successfully, close it to free memory
          cmsCloseProfile(mem_profile);
      }
  }

  // --- Fuzzing cmsIT8LoadFromMem ---
  size_t it8_size;
  const uint8_t* it8_data = ConsumeBytes(&DataPos, &RemainingSize, MAX_IT8_SIZE, &it8_size);
  if (it8_data && it8_size > 0) {
      cmsHANDLE it8_handle = cmsIT8LoadFromMem(context, it8_data, it8_size);
      if (it8_handle) {
          // IT8 data loaded successfully, free the handle
          cmsIT8Free(it8_handle);
      }
  }

  // --- Fuzzing cmsMLUgetTranslation ---
  // Use ConsumeIntegral_u32 and pass DataPos and RemainingSize
  cmsMLU *mlu = cmsMLUalloc(context, ConsumeIntegral_u32(&DataPos, &RemainingSize) % MAX_MLU_TRANSLATIONS);
  if (mlu) {
      // Add some translations to the MLU
      // Use ConsumeIntegral_u8 and pass DataPos and RemainingSize
      size_t num_translations = ConsumeIntegral_u8(&DataPos, &RemainingSize) % MAX_MLU_TRANSLATIONS;
      for (size_t i = 0; i < num_translations; ++i) {
          // Use ConsumeString and pass DataPos and RemainingSize, min_len=2 for lang/country
          char* lang = ConsumeString(&DataPos, &RemainingSize, 10, 2); // Max language code length, min 2
          char* country = ConsumeString(&DataPos, &RemainingSize, 10, 2); // Max country code length, min 2
          char* text = ConsumeString(&DataPos, &RemainingSize, 50, 0); // Max text length, min 0
          if (lang && country && text) {
              cmsMLUsetASCII(mlu, lang, country, text);
          }
          free(lang);
          free(country);
          free(text);
      }

      // Get a translation
      // Use ConsumeString and pass DataPos and RemainingSize, min_len=2 for lang/country
      char* get_lang = ConsumeString(&DataPos, &RemainingSize, 10, 2);
      char* get_country = ConsumeString(&DataPos, &RemainingSize, 10, 2);
      // Use ConsumeIntegral_u16 and pass DataPos and RemainingSize
      cmsUInt32Number buffer_size = ConsumeIntegral_u16(&DataPos, &RemainingSize) % MAX_MLU_BUFFER_SIZE;
      wchar_t* buffer = (wchar_t*)calloc(buffer_size, sizeof(wchar_t));

      if (get_lang && get_country && buffer) {
          // Correct function call: use cmsMLUgetWide instead of cmsMLUgetTranslation
          // cmsMLUgetWide signature: cmsUInt32Number cmsMLUgetWide(cmsMLU* mlu, const char* Lang, const char* Country, wchar_t* Buffer, cmsUInt32Number BufferSize)
          cmsMLUgetWide(mlu, get_lang, get_country, buffer, buffer_size);
      }

      free(get_lang);
      free(get_country);
      free(buffer);

      // Free the MLU
      cmsMLUfree(mlu);
  }

  // --- Fuzzing cmsGBDAlloc and cmsGDBAddPoint ---
  // Use ConsumeIntegral_u8 and pass DataPos and RemainingSize
  // cmsUInt32Number num_gbd_points = ConsumeIntegral_u8(&DataPos, &RemainingSize) % MAX_GBD_POINTS; // This is not needed for cmsGBDAlloc
  // Corrected cmsGBDAlloc call: only takes context
  cmsHANDLE gbd_handle = cmsGBDAlloc(context);
  if (gbd_handle) {
      // Use ConsumeIntegral_u8 and pass DataPos and RemainingSize
      size_t points_to_add = ConsumeIntegral_u8(&DataPos, &RemainingSize) % MAX_GBD_ADD_POINTS;
      for (size_t i = 0; i < points_to_add; ++i) {
          cmsCIELab lab;
          // Use ConsumeIntegral_double and pass DataPos and RemainingSize
          lab.L = ConsumeIntegral_double(&DataPos, &RemainingSize);
          lab.a = ConsumeIntegral_double(&DataPos, &RemainingSize);
          lab.b = ConsumeIntegral_double(&DataPos, &RemainingSize);
          cmsGDBAddPoint(gbd_handle, &lab);
      }
      // Attempt to compute, even if not enough points were added
      cmsGDBCompute(gbd_handle, 0); // 0 for default behavior or fuzzer value

      // Free the GBD handle
      // Corrected cmsGBDFree call: only takes the handle
      cmsGBDFree(gbd_handle);
  }


  // Delete the lcms2 context
  cmsDeleteContext(context);

  return 0;
}