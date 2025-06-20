#include <cstddef>
#include <cstdint>
#include <string>
#include <vector>
#include <memory> // For std::unique_ptr
#include <cstring> // For memcpy
#include <cstdio>  // For va_list, vfprintf (if logging is enabled)

#include <fuzzer/FuzzedDataProvider.h>

// libtiff headers
#include "/src/libtiff/libtiff/tiffio.h"
#include "/src/libtiff/libtiff/tiff.h"

// Custom error and warning handlers to prevent libtiff from calling exit() or abort()
// on malformed inputs. This allows the fuzzer to continue exploring code paths
// even when errors or warnings occur within the library.
// The TIFFErrorHandlerExt and TIFFWarningHandlerExt functions expect a clientdata
// parameter as the first argument.
static void custom_warning_handler(thandle_t clientdata, const char *module, const char *fmt, va_list ap) {
  (void)clientdata; // Unused parameter, added to match libtiff's expected signature
  (void)module; // Unused parameter
  (void)fmt;    // Unused parameter
  (void)ap;     // Unused parameter
  // Suppress warnings by doing nothing.
  // For debugging, uncomment the following line:
  // vfprintf(stderr, fmt, ap); fprintf(stderr, "\n");
}

static void custom_error_handler(thandle_t clientdata, const char *module, const char *fmt, va_list ap) {
  (void)clientdata; // Unused parameter, added to match libtiff's expected signature
  (void)module; // Unused parameter
  (void)fmt;    // Unused parameter
  (void)ap;     // Unused parameter
  // Suppress errors by doing nothing.
  // For debugging, uncomment the following line:
  // vfprintf(stderr, fmt, ap); fprintf(stderr, "\n");
}

// Structure to hold the in-memory file data and current offset.
// This simulates a file system in memory for libtiff's custom I/O functions.
struct InMemoryFile {
    std::vector<uint8_t> data; // Stores the file content
    tmsize_t offset;           // Current read/write offset within the data

    // Constructor to initialize with fuzzer-provided data.
    InMemoryFile(const std::vector<uint8_t>& initial_data) : data(initial_data), offset(0) {}
};

// Custom read function for TIFFClientOpen.
// Reads 'size' bytes from the in-memory file into 'buf'.
static tmsize_t read_proc(thandle_t fd, void *buf, tmsize_t size) {
    InMemoryFile* f = static_cast<InMemoryFile*>(fd);
    if (!f) return (tmsize_t)-1; // Invalid file handle

    tmsize_t bytes_to_read = size;
    // Limit read to available data
    if (f->offset + bytes_to_read > f->data.size()) {
        bytes_to_read = f->data.size() - f->offset;
    }

    if (bytes_to_read < 0) bytes_to_read = 0; // Ensure non-negative bytes to read

    // Copy data from our in-memory buffer to libtiff's buffer
    memcpy(buf, f->data.data() + f->offset, bytes_to_read);
    f->offset += bytes_to_read; // Advance offset
    return bytes_to_read;
}

// Custom write function for TIFFClientOpen.
// Writes 'size' bytes from 'buf' into the in-memory file.
static tmsize_t write_proc(thandle_t fd, void *buf, tmsize_t size) {
    InMemoryFile* f = static_cast<InMemoryFile*>(fd);
    if (!f) return (tmsize_t)-1; // Invalid file handle

    // Resize the in-memory buffer if necessary to accommodate the write
    if (f->offset + size > f->data.size()) {
        f->data.resize(f->offset + size);
    }

    // Copy data from libtiff's buffer to our in-memory buffer
    memcpy(f->data.data() + f->offset, buf, size);
    f->offset += size; // Advance offset
    return size;
}

// Custom seek function for TIFFClientOpen.
// Moves the current offset within the in-memory file.
static uint64_t seek_proc(thandle_t fd, uint64_t off, int whence) {
    InMemoryFile* f = static_cast<InMemoryFile*>(fd);
    if (!f) return (uint64_t)-1; // Invalid file handle

    uint64_t new_offset = 0;
    switch (whence) {
        case SEEK_SET: // Seek from beginning of file
            new_offset = off;
            break;
        case SEEK_CUR: // Seek from current position
            new_offset = f->offset + off;
            break;
        case SEEK_END: // Seek from end of file
            new_offset = f->data.size() + off;
            break;
        default:
            return (uint64_t)-1; // Invalid whence value
    }

    // Cap the new offset to prevent excessive memory allocation if seeking far beyond current size.
    // This is a common fuzzing practice to avoid OOM issues.
    const uint64_t MAX_FUZZ_FILE_SIZE = 10 * 1024 * 1024; // Limit in-memory file size to 10 MB
    if (new_offset > MAX_FUZZ_FILE_SIZE) {
        new_offset = MAX_FUZZ_FILE_SIZE;
    }

    f->offset = new_offset; // Update current offset
    return f->offset;
}

// Custom close function for TIFFClientOpen.
// No explicit action needed here as InMemoryFile is managed by std::unique_ptr.
static int close_proc(thandle_t fd) {
    (void)fd; // Unused parameter
    return 0;
}

// Custom size function for TIFFClientOpen.
// Returns the current size of the in-memory file.
static uint64_t size_proc(thandle_t fd) {
    InMemoryFile* f = static_cast<InMemoryFile*>(fd);
    if (!f) return 0; // Invalid file handle
    return f->data.size();
}

// Custom map function for TIFFClientOpen.
// Not typically used for basic fuzzing, so we indicate failure.
static int map_proc(thandle_t fd, void **pbase, toff_t *psize) {
    (void)fd; (void)pbase; (void)psize; // Unused parameters
    return 0; // Indicate failure (0 for failure in libtiff's map_proc)
}

// Custom unmap function for TIFFClientOpen.
// Not typically used for basic fuzzing.
static void unmap_proc(thandle_t fd, void *base, toff_t size) {
    (void)fd; (void)base; (void)size; // Unused parameters
}

// Entry point for the fuzzer.
extern "C" int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size) {
    FuzzedDataProvider fdp(Data, Size);

    // Set custom error and warning handlers. This is crucial for fuzzing
    // to prevent libtiff from terminating the process on internal errors,
    // allowing the fuzzer to discover more bugs.
    TIFFSetWarningHandlerExt(custom_warning_handler);
    TIFFSetErrorHandlerExt(custom_error_handler);

    // Consume all remaining fuzzer data to be used as the initial content
    // for our in-memory TIFF file.
    std::vector<uint8_t> initial_tiff_data = fdp.ConsumeRemainingBytes<uint8_t>();

    // Create an InMemoryFile object. std::unique_ptr ensures that the
    // InMemoryFile object is automatically cleaned up when it goes out of scope,
    // preventing memory leaks.
    // Replaced std::make_unique with direct new and std::unique_ptr construction
    // for broader compiler compatibility (e.g., C++11 environments).
    std::unique_ptr<InMemoryFile> in_memory_file(new InMemoryFile(initial_tiff_data));

    // Fuzz the mode string for TIFFClientOpen (e.g., "r", "w", "r+", "w+").
    // Limiting the length to prevent excessively long or invalid mode strings.
    std::string mode_str = fdp.ConsumeRandomLengthString(4);

    // 1. Fuzz TIFFClientOpen: This function is used to open a TIFF file
    // with custom I/O routines. By using our in-memory file, we can fuzz
    // file opening and initial parsing without actual disk I/O.
    // This effectively covers the functionality of TIFFOpen and TIFFFdOpen
    // in an in-memory context.
    TIFF* tif = TIFFClientOpen(
        "fuzz.tif", // A dummy filename, not used by our custom I/O
        mode_str.c_str(), // Fuzzed mode string
        in_memory_file.get(), // Our InMemoryFile object passed as thandle_t (void*)
        read_proc,
        write_proc,
        seek_proc,
        close_proc,
        size_proc,
        map_proc,
        unmap_proc
    );

    // Proceed only if the TIFF file was successfully opened.
    if (tif) {
        // Set some essential TIFF tags. These are often required for libtiff's
        // read/write functions to operate correctly and to define the image structure.
        // Fuzzing these values within reasonable ranges helps explore diverse image configurations.
        uint32_t width = fdp.ConsumeIntegralInRange<uint32_t>(1, 1024);
        uint32_t length = fdp.ConsumeIntegralInRange<uint32_t>(1, 1024);
        uint16_t samples_per_pixel = fdp.ConsumeIntegralInRange<uint16_t>(1, 4);
        uint16_t bits_per_sample = fdp.PickValueInArray<uint16_t>({1, 2, 4, 8, 16, 32});
        uint16_t photometric = fdp.PickValueInArray<uint16_t>({PHOTOMETRIC_MINISWHITE, PHOTOMETRIC_MINISBLACK, PHOTOMETRIC_RGB, PHOTOMETRIC_PALETTE});
        uint16_t planar_config = fdp.PickValueInArray<uint16_t>({PLANARCONFIG_CONTIG, PLANARCONFIG_SEPARATE});
        uint16_t compression = fdp.PickValueInArray<uint16_t>({COMPRESSION_NONE, COMPRESSION_LZW, COMPRESSION_DEFLATE, COMPRESSION_JPEG});
        uint32_t rows_per_strip = fdp.ConsumeIntegralInRange<uint32_t>(1, length);

        TIFFSetField(tif, TIFFTAG_IMAGEWIDTH, width);
        TIFFSetField(tif, TIFFTAG_IMAGELENGTH, length);
        TIFFSetField(tif, TIFFTAG_SAMPLESPERPIXEL, samples_per_pixel);
        TIFFSetField(tif, TIFFTAG_BITSPERSAMPLE, bits_per_sample);
        TIFFSetField(tif, TIFFTAG_PHOTOMETRIC, photometric);
        TIFFSetField(tif, TIFFTAG_PLANARCONFIG, planar_config);
        TIFFSetField(tif, TIFFTAG_COMPRESSION, compression);
        TIFFSetField(tif, TIFFTAG_ROWSPERSTRIP, rows_per_strip);

        // 2. Fuzz TIFFSetDirectory: Attempts to change the active directory within the TIFF file.
        // Fuzzing with various directory numbers can expose issues in directory parsing and navigation,
        // especially with malformed directory structures.
        if (fdp.remaining_bytes() >= sizeof(tdir_t)) {
            tdir_t dir_num = fdp.ConsumeIntegral<tdir_t>();
            TIFFSetDirectory(tif, dir_num);
        }

        // 3. Fuzz TIFFReadRGBAStrip: Reads a strip of RGBA data from the TIFF file.
        // This targets image decoding, pixel format conversion, and strip-based reading logic.
        // Allocate a buffer large enough for a strip of RGBA data.
        // TIFFReadRGBAStrip expects a buffer of uint32_t (RGBA pixels).
        tmsize_t strip_size_bytes = TIFFStripSize(tif);
        if (strip_size_bytes > 0) {
            // Calculate the number of uint32_t elements needed for the buffer.
            tmsize_t rgba_buffer_elements = strip_size_bytes / sizeof(uint32_t);
            if (rgba_buffer_elements > 0) {
                // std::vector manages memory for rgba_buffer, ensuring no leaks.
                std::vector<uint32_t> rgba_buffer(rgba_buffer_elements);
                if (fdp.remaining_bytes() >= sizeof(uint32_t)) {
                    // Fuzz the row number to read, keeping it within image bounds.
                    uint32_t row_to_read = fdp.ConsumeIntegralInRange<uint32_t>(0, length > 0 ? length - 1 : 0);
                    TIFFReadRGBAStrip(tif, row_to_read, rgba_buffer.data());
                }
            }
        }

        // 4. Fuzz TIFFWriteScanline: Writes a single scanline of image data to the TIFF file.
        // This targets image encoding and data serialization for scanline-based writing.
        tmsize_t scanline_size_bytes = TIFFScanlineSize(tif);
        if (scanline_size_bytes > 0) {
            // Ensure enough fuzzer data is available for the scanline buffer.
            if (fdp.remaining_bytes() >= scanline_size_bytes) {
                // std::vector manages memory for scanline_data, ensuring no leaks.
                std::vector<uint8_t> scanline_data = fdp.ConsumeBytes<uint8_t>(scanline_size_bytes);
                // Fuzz the row and sample numbers for writing, keeping them within image bounds.
                uint32_t row_to_write = fdp.ConsumeIntegralInRange<uint32_t>(0, length > 0 ? length - 1 : 0);
                uint16_t sample_to_write = fdp.ConsumeIntegralInRange<uint16_t>(0, samples_per_pixel > 0 ? samples_per_pixel - 1 : 0);
                TIFFWriteScanline(tif, scanline_data.data(), row_to_write, sample_to_write);
            }
        }

        // 5. Fuzz TIFFWriteEncodedStrip: Writes an entire encoded strip of data to the TIFF file.
        // This function is a good complement to TIFFWriteScanline, covering different write paths,
        // especially those involving compression and strip management.
        tmsize_t encoded_strip_size_bytes = TIFFStripSize(tif);
        if (encoded_strip_size_bytes > 0) {
            // Ensure enough fuzzer data is available for the encoded strip buffer.
            if (fdp.remaining_bytes() >= encoded_strip_size_bytes) {
                // std::vector manages memory for encoded_strip_data, ensuring no leaks.
                std::vector<uint8_t> encoded_strip_data = fdp.ConsumeBytes<uint8_t>(encoded_strip_size_bytes);
                // Fuzz the strip number, ensuring it's within valid bounds.
                uint32_t num_strips = TIFFNumberOfStrips(tif);
                uint32_t strip_num = fdp.ConsumeIntegralInRange<uint32_t>(0, num_strips > 0 ? num_strips - 1 : 0);
                TIFFWriteEncodedStrip(tif, strip_num, encoded_strip_data.data(), encoded_strip_data.size());
            }
        }

        // Clean up the TIFF object. This is absolutely critical for memory safety.
        // TIFFClose deallocates all resources associated with the TIFF handle.
        TIFFClose(tif);
    }

    return 0; // Fuzzer always returns 0 unless a crash is found.
}