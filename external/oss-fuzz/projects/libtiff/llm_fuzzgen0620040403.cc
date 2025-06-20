#include <cstddef>
#include <cstdint>
#include <string>
#include <vector>
#include <fuzzer/FuzzedDataProvider.h>
#include <cstdio>   // For mkstemp, unlink
#include <fcntl.h>  // For open, O_RDWR, O_CREAT
#include <unistd.h> // For close

// Include libtiff headers with full project-relative paths
#include "/src/libtiff/libtiff/tiffio.h"
#include "/src/libtiff/libtiff/tiffiop.h" // Required for internal TIFF memory management functions

// Custom error and warning handlers for TIFFSetErrorHandler and TIFFSetWarningHandler.
// These handlers simply absorb the messages, allowing the fuzzer to continue
// exploring code paths even when errors or warnings occur within libtiff.
static void custom_error_handler(const char* module, const char* fmt, va_list ap) {
    // Suppress error messages to prevent fuzzer from exiting.
    // In a real fuzzing setup, you might log these to a separate file for analysis.
    (void)module;
    (void)fmt;
    (void)ap;
}

static void custom_warning_handler(const char* module, const char* fmt, va_list ap) {
    // Suppress warning messages.
    (void)module;
    (void)fmt;
    (void)ap;
}

// Custom error and warning handlers for TIFFOpenOptionsSetErrorHandlerExtR and TIFFOpenOptionsSetWarningHandlerExtR.
// These handlers have a different signature (TIFFErrorHandlerExtR) and are used with extended options.
static int custom_error_handler_ext(TIFF *tif, void *clientdata, const char* module, const char* fmt, va_list ap) {
    (void)tif;
    (void)clientdata;
    (void)module;
    (void)fmt;
    (void)ap;
    return 0; // Return 0 to indicate that the error was handled.
}

static int custom_warning_handler_ext(TIFF *tif, void *clientdata, const char* module, const char* fmt, va_list ap) {
    (void)tif;
    (void)clientdata;
    (void)module;
    (void)fmt;
    (void)ap;
    return 0; // Return 0 to indicate that the warning was handled.
}

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size) {
  FuzzedDataProvider fdp(Data, Size);

  // Set global custom error and warning handlers for libtiff.
  // This ensures that any errors or warnings encountered during TIFF operations
  // do not terminate the fuzzer prematurely.
  TIFFSetErrorHandler(custom_error_handler);
  TIFFSetWarningHandler(custom_warning_handler);

  // --- Fuzzing TIFFOpenExt ---
  {
    // Generate a random filename and open mode string.
    // The filename length is fuzzed to explore various path lengths.
    // The mode string length is kept small as typical modes are short (e.g., "r", "w", "r+").
    std::string filename = fdp.ConsumeRandomLengthString(fdp.ConsumeIntegralInRange(0, 256));
    std::string mode = fdp.ConsumeRandomLengthString(fdp.ConsumeIntegralInRange(1, 5));

    TIFFOpenOptions *opts = nullptr;
    // Introduce randomness to decide whether to use TIFFOpenOptions.
    if (fdp.ConsumeBool()) {
      // Allocate TIFFOpenOptions. This memory is managed by libtiff's internal
      // allocation functions, but we are responsible for calling TIFFOpenOptionsFree.
      opts = TIFFOpenOptionsAlloc();
      if (opts) {
        // Fuzz various options within TIFFOpenOptions to explore different configurations.
        // These values can influence memory allocations and error handling behavior.
        TIFFOpenOptionsSetMaxSingleMemAlloc(opts, fdp.ConsumeIntegral<tmsize_t>());
        TIFFOpenOptionsSetMaxCumulatedMemAlloc(opts, fdp.ConsumeIntegral<tmsize_t>());
        TIFFOpenOptionsSetWarnAboutUnknownTags(opts, fdp.ConsumeBool());

        // Set custom error/warning handlers specifically for this TIFFOpenOptions instance.
        // This provides an additional layer of robustness for the fuzzer.
        TIFFOpenOptionsSetErrorHandlerExtR(opts, custom_error_handler_ext, nullptr);
        TIFFOpenOptionsSetWarningHandlerExtR(opts, custom_warning_handler_ext, nullptr);
      }
    }

    // Call the target API: TIFFOpenExt.
    // This function attempts to open a TIFF file with the fuzzed filename, mode, and options.
    TIFF *tif = TIFFOpenExt(filename.c_str(), mode.c_str(), opts);

    // Memory management: If a TIFF object was successfully opened, it must be closed.
    // TIFFClose deallocates all resources associated with the TIFF handle.
    if (tif) {
      TIFFClose(tif);
    }

    // Memory management: If TIFFOpenOptions were allocated, they must be freed.
    // This prevents memory leaks from the TIFFOpenOptions object itself.
    if (opts) {
      TIFFOpenOptionsFree(opts);
    }
  }

  // --- Fuzzing TIFFFdOpenExt ---
  {
    // Create a temporary file to obtain a valid file descriptor.
    // mkstemp is used for safer temporary file creation compared to tmpfile.
    std::string temp_filename_template = "/tmp/fuzz_libtiff_XXXXXX";
    std::vector<char> temp_filename_buffer(temp_filename_template.begin(), temp_filename_template.end());
    temp_filename_buffer.push_back('\0'); // Null-terminate the string for mkstemp

    // Create a unique temporary file and get its file descriptor.
    int fd = mkstemp(temp_filename_buffer.data());

    // Proceed only if the temporary file was successfully created.
    if (fd != -1) {
      // Get the actual filename generated by mkstemp.
      std::string filename = temp_filename_buffer.data();
      // Generate a random mode string for opening the file descriptor.
      std::string mode = fdp.ConsumeRandomLengthString(fdp.ConsumeIntegralInRange(1, 5));

      TIFFOpenOptions *opts = nullptr;
      // Introduce randomness to decide whether to use TIFFOpenOptions.
      if (fdp.ConsumeBool()) {
        opts = TIFFOpenOptionsAlloc();
        if (opts) {
          TIFFOpenOptionsSetMaxSingleMemAlloc(opts, fdp.ConsumeIntegral<tmsize_t>());
          TIFFOpenOptionsSetMaxCumulatedMemAlloc(opts, fdp.ConsumeIntegral<tmsize_t>());
          TIFFOpenOptionsSetWarnAboutUnknownTags(opts, fdp.ConsumeBool());
          TIFFOpenOptionsSetErrorHandlerExtR(opts, custom_error_handler_ext, nullptr);
          TIFFOpenOptionsSetWarningHandlerExtR(opts, custom_warning_handler_ext, nullptr);
        }
      }

      // Call the target API: TIFFFdOpenExt.
      // This function attempts to open a TIFF file using an existing file descriptor.
      TIFF *tif = TIFFFdOpenExt(fd, filename.c_str(), mode.c_str(), opts);

      // Memory management: Close TIFF file if opened.
      if (tif) {
        TIFFClose(tif);
      }

      // Memory management: Free TIFFOpenOptions if allocated.
      if (opts) {
        TIFFOpenOptionsFree(opts);
      }

      // Cleanup: Close the file descriptor and delete the temporary file.
      // It's crucial to close the file descriptor obtained from mkstemp.
      close(fd);
      // Remove the temporary file from the filesystem.
      unlink(filename.c_str());
    }
  }

  return 0;
}