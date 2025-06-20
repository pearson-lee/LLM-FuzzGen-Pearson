#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include "lcms2.h"

// --- Fuzzer-generated temporary file management ---
// To handle APIs that expect file paths, we create a temporary
// file with the fuzzer's data and pass its path to the API.
// This allows fuzzing of file-based I/O operations.
#include <stdio.h>
#include <unistd.h>

// Helper function to create a temporary file with the given data.
// Returns the file path, or NULL on error. The caller is responsible
// for deleting the file.
static char *create_temp_file(const uint8_t *data, size_t size) {
  char *tmp_filename = strdup("/tmp/lcms_fuzzer_temp_file-XXXXXX");
  if (!tmp_filename) {
    return NULL;
  }

  int fd = mkstemp(tmp_filename);
  if (fd == -1) {
    free(tmp_filename);
    return NULL;
  }

  // Write the data to the file.
  if (write(fd, data, size) != (ssize_t)size) {
    close(fd);
    unlink(tmp_filename);
    free(tmp_filename);
    return NULL;
  }

  close(fd);
  return tmp_filename;
}

// --- Fuzz Target ---
// This fuzz target is designed to exercise a variety of lcms APIs
// for creating, manipulating, and saving color profiles. It covers
// both memory-based and file-based profile operations, with a
// focus on dictionary and tag handling.

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  if (size < 1) {
    return 0;
  }

  // Create a context.
  cmsContext ctx = cmsCreateContext(NULL, NULL);
  if (!ctx) {
    return 0;
  }

  // --- Test 1: Create a device link from a .cube file ---
  // We create a temporary file with the fuzzer data and pass its
  // path to cmsCreateDeviceLinkFromCubeFileTHR. This tests the
  // parsing of .cube files.
  char *tmp_filename = create_temp_file(data, size);
  if (tmp_filename) {
    cmsHPROFILE profile_from_cube =
        cmsCreateDeviceLinkFromCubeFileTHR(ctx, tmp_filename);
    if (profile_from_cube) {
      cmsCloseProfile(profile_from_cube);
    }
    unlink(tmp_filename);
    free(tmp_filename);
  }

  // --- Test 2: Open a profile from a memory buffer ---
  // This tests the parsing of profiles directly from memory, a common
  // use case for fuzzing.
  cmsHPROFILE profile_from_mem = cmsOpenProfileFromMemTHR(ctx, data, size);
  if (profile_from_mem) {
    cmsCloseProfile(profile_from_mem);
  }

  // --- Test 3: Create a profile, add a dictionary, and save it ---
  // This section tests the creation of a new profile, the addition
  // of a dictionary tag, and the process of saving the profile to
  // memory. This exercises the dictionary writing logic.
  cmsHPROFILE profile_to_write = cmsCreateProfilePlaceholder(ctx);
  if (profile_to_write) {
    // Create a dictionary and add some entries.
    cmsHANDLE dict = cmsDictAlloc(ctx);
    if (dict) {
      cmsMLU *mlu_display_name = cmsMLUalloc(ctx, 1);
      cmsMLU *mlu_value = cmsMLUalloc(ctx, 1);

      if (mlu_display_name && mlu_value) {
        cmsMLUsetASCII(mlu_display_name, "en", "US", "Test Name");
        cmsMLUsetASCII(mlu_value, "en", "US", "Test Value");
        cmsDictAddEntry(dict, L"Name", L"Value", mlu_display_name, mlu_value);
      }

      if (mlu_display_name) {
        cmsMLUfree(mlu_display_name);
      }
      if (mlu_value) {
        cmsMLUfree(mlu_value);
      }

      // Write the dictionary to the profile.
      cmsWriteTag(profile_to_write, cmsSigMetaTag, dict);
      cmsDictFree(dict);
    }

    // Save the profile to a memory buffer.
    uint8_t *out_buf = NULL;
    cmsUInt32Number out_size = 0;
    if (cmsSaveProfileToMem(profile_to_write, NULL, &out_size)) {
      out_buf = (uint8_t *)malloc(out_size);
      if (out_buf) {
        if (cmsSaveProfileToMem(profile_to_write, out_buf, &out_size)) {
          // --- Test 4: Read the dictionary back from the saved profile ---
          // This tests the dictionary reading logic.
          cmsHPROFILE profile_to_read =
              cmsOpenProfileFromMemTHR(ctx, out_buf, out_size);
          if (profile_to_read) {
            cmsHANDLE read_dict =
                cmsReadTag(profile_to_read, cmsSigMetaTag);
            if (read_dict) {
              // The dictionary is read but not used further.
              // The purpose is to exercise the reading code path.
            }
            cmsCloseProfile(profile_to_read);
          }
        }
        free(out_buf);
      }
    }
    cmsCloseProfile(profile_to_write);
  }

  // Clean up the context.
  cmsDeleteContext(ctx);

  return 0;
}