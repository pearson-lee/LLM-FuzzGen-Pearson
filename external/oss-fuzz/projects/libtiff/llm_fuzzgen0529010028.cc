#include <cstddef>
#include <cstdint>
#include <string>
#include <vector>
#include <fuzzer/FuzzedDataProvider.h>
#include <cstring> // For memcpy
#include <limits> // For std::numeric_limits

// Include necessary libtiff headers
#include "/work/include/tiffio.h"
#include "/src/libtiff/libtiff/tiffiop.h" // For _TIFFmalloc and _TIFFfree

// Custom error and warning handlers to suppress output during fuzzing
// These handlers prevent libtiff from printing messages to stderr, which can
// pollute fuzzer output and potentially slow down fuzzing.
static void custom_warning_handler(thandle_t fd, const char *module, const char *fmt, va_list ap) {
  (void)fd;     // Unused parameter
  (void)module; // Unused parameter
  (void)fmt;    // Unused parameter
  (void)ap;     // Unused parameter
}

static void custom_error_handler(thandle_t fd, const char *module, const char *fmt, va_list ap) {
  (void)fd;     // Unused parameter
  (void)module; // Unused parameter
  (void)fmt;    // Unused parameter
  (void)ap;     // Unused parameter
}

// In-memory file representation for TIFF I/O.
// This class simulates a file in memory, allowing libtiff to read from
// the fuzzer's input data as if it were a file on disk.
class InMemoryFile {
public:
    std::vector<uint8_t> data; // Stores the fuzzer input data
    tmsize_t offset;           // Current read/write offset within the data

    // Constructor: Initializes with fuzzer data and sets offset to 0.
    InMemoryFile(const std::vector<uint8_t>& fuzzer_data) : data(fuzzer_data), offset(0) {}

    // Read function: Reads 'size' bytes into 'buf'.
    // Returns the number of bytes actually read.
    tmsize_t read(void* buf, tmsize_t size) {
        if (offset >= data.size()) {
            return 0; // End of file
        }
        tmsize_t bytes_to_read = size;
        // Ensure we don't read past the end of the data
        if (offset + bytes_to_read > data.size()) {
            bytes_to_read = data.size() - offset;
        }
        // Copy data from our in-memory buffer to the provided buffer
        memcpy(buf, data.data() + offset, bytes_to_read);
        offset += bytes_to_read; // Advance the offset
        return bytes_to_read;
    }

    // Write function: Not strictly needed for read-only fuzzing, but required by TIFFClientOpen.
    // Returns 0 as we don't support writing in this fuzz target.
    tmsize_t write(void* buf, tmsize_t size) {
        // Added to support write operations for fuzzing write-related functions.
        // This minimal implementation grows the buffer if needed and copies data.
        if (offset + size > data.size()) {
            data.resize(offset + size); // Grow the buffer if needed
        }
        memcpy(data.data() + offset, buf, size);
        offset += size;
        return size;
    }

    // Seek function: Moves the current offset within the data.
    // Supports SEEK_SET, SEEK_CUR, SEEK_END.
    // Returns the new offset.
    uint64_t seek(uint64_t off, int whence) {
        if (whence == SEEK_SET) {
            offset = off;
        } else if (whence == SEEK_CUR) {
            offset += off;
        } else if (whence == SEEK_END) {
            offset = data.size() + off;
        }
        // Ensure offset stays within valid bounds
        if (offset < 0) offset = 0;
        if (offset > data.size()) offset = data.size();
        return offset;
    }

    // Close function: No-op for in-memory files, as there's no file handle to close.
    // Returns 0 for success.
    int close() {
        return 0;
    }

    // Size function: Returns the total size of the in-memory data.
    uint64_t size() {
        return data.size();
    }

    // Map function: Provides a direct pointer to the data.
    // Required for memory-mapped I/O by libtiff, though not always used.
    // Returns 0 for success.
    int map(void** base, toff_t* size) {
        *base = data.data();
        *size = data.size();
        return 0;
    }

    // Unmap function: Cleans up resources from map. No-op for this implementation.
    void unmap(void* base, toff_t size) {
        (void)base; // Unused parameter
        (void)size; // Unused parameter
    }
};

// Static wrapper functions for TIFFClientOpen.
// These functions bridge the C++ InMemoryFile class methods to the C-style
// function pointers expected by libtiff's TIFFClientOpen.
static tmsize_t read_proc(thandle_t handle, void* buf, tmsize_t size) {
    return static_cast<InMemoryFile*>(handle)->read(buf, size);
}

static tmsize_t write_proc(thandle_t handle, void* buf, tmsize_t size) {
    return static_cast<InMemoryFile*>(handle)->write(buf, size);
}

static uint64_t seek_proc(thandle_t handle, uint64_t off, int whence) {
    return static_cast<InMemoryFile*>(handle)->seek(off, whence);
}

static int close_proc(thandle_t handle) {
    // The InMemoryFile object is managed by the fuzzer, so we don't delete it here.
    return static_cast<InMemoryFile*>(handle)->close();
}

static uint64_t size_proc(thandle_t handle) {
    return static_cast<InMemoryFile*>(handle)->size();
}

static int map_proc(thandle_t handle, void** base, toff_t* size) {
    return static_cast<InMemoryFile*>(handle)->map(base, size);
}

static void unmap_proc(thandle_t handle, void* base, toff_t size) {
    static_cast<InMemoryFile*>(handle)->unmap(base, size);
}

// Entry point for the fuzzer. LLVMFuzzerTestOneInput is called with each new fuzzer input.
extern "C" int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size) {
    // FuzzedDataProvider helps consume bytes from the input data in a structured way.
    FuzzedDataProvider fdp(Data, Size);

    // Suppress TIFF error and warning output during fuzzing.
    // This prevents excessive console output from malformed TIFF files.
    TIFFSetWarningHandlerExt((TIFFErrorHandlerExt)custom_warning_handler);
    TIFFSetErrorHandlerExt((TIFFErrorHandlerExt)custom_error_handler);

    // Consume all remaining bytes to form the TIFF file content.
    std::vector<uint8_t> tiff_data = fdp.ConsumeRemainingBytes<uint8_t>();
    // Create an in-memory file object to simulate a file on disk.
    InMemoryFile in_memory_file(tiff_data);

    // API Call 1: TIFFOpen
    // Open the TIFF file using custom I/O functions.
    // The "fuzz.tif" filename is arbitrary for in-memory files.
    // Modified: Changed "r" to "r+" to enable read-write mode, covering TIFFFlush branches.
    TIFF* tiff = TIFFClientOpen(
        "fuzz.tif", "r+",
        static_cast<thandle_t>(&in_memory_file), // Pass the InMemoryFile object as a handle
        read_proc, write_proc, seek_proc, close_proc, size_proc,
        map_proc, unmap_proc
    );

    // If TIFFOpen fails, there's nothing more to do with this input.
    if (!tiff) {
        return 0;
    }

    // API Call 2: TIFFReadDirectory
    // Attempt to read the first directory in the TIFF file.
    // This exercises the directory parsing logic.
    TIFFReadDirectory(tiff);

    // Get image dimensions and strip information for subsequent API calls.
    uint32_t image_width = 0, image_height = 0;
    TIFFGetField(tiff, TIFFTAG_IMAGEWIDTH, &image_width);
    TIFFGetField(tiff, TIFFTAG_IMAGELENGTH, &image_height);

    // Added: Set TIFFTAG_MINSAMPLEVALUE and TIFFTAG_MAXSAMPLEVALUE.
    // This aims to increase coverage in the _TIFFVSetField function by exercising more tag-specific branches.
    TIFFSetField(tiff, TIFFTAG_MINSAMPLEVALUE, fdp.ConsumeIntegral<uint16_t>());
    TIFFSetField(tiff, TIFFTAG_MAXSAMPLEVALUE, fdp.ConsumeIntegral<uint16_t>());

    // Added: Attempt to trigger _TIFFMultiplySSize integer overflow.
    // This aims to cover the `if (first > TIFF_TMSIZE_T_MAX / second)` branch in `_TIFFMultiplySSize`.
    // We use TIFF_LONG8 (tag ID 34374) which has an element size of 8 bytes.
    // We set the count to a value that, when multiplied by 8, will exceed TIFF_TMSIZE_T_MAX.
    // TIFF_TMSIZE_T_MAX is typically INT_MAX (2147483647).
    // So, count = INT_MAX / 8 + 1 will cause an overflow.
    uint32_t overflow_count = std::numeric_limits<int32_t>::max() / 8 + 1;
    uint64_t dummy_value = 0; // Dummy value, as memory won't actually be allocated due to overflow check
    TIFFSetField(tiff, TIFF_LONG8, overflow_count, &dummy_value);
    // Memory safety: The overflow check happens before allocation, so no large memory is allocated.

    // Added: Attempt to trigger _TIFFMultiplySSize error path for zero count.
    // This covers the `if (first <= 0 || second <= 0)` branch in `_TIFFMultiplySSize`.
    uint32_t custom_tag_value = fdp.ConsumeIntegral<uint32_t>();
    TIFFSetField(tiff, 65535, 0, custom_tag_value); // 65535 is an arbitrary custom tag ID

    // Added: Calls to TIFFGetFieldDefaulted for uncovered tags.
    // This aims to increase coverage in the TIFFVGetFieldDefaulted function by exercising more case branches.
    uint32_t subfiletype;
    TIFFGetFieldDefaulted(tiff, TIFFTAG_SUBFILETYPE, &subfiletype);
    uint16_t threshholding;
    TIFFGetFieldDefaulted(tiff, TIFFTAG_THRESHHOLDING, &threshholding);
    uint16_t fillorder;
    TIFFGetFieldDefaulted(tiff, TIFFTAG_FILLORDER, &fillorder);
    uint32_t rowsperstrip;
    TIFFGetFieldDefaulted(tiff, TIFFTAG_ROWSPERSTRIP, &rowsperstrip);
    // Memory safety: These are read operations and do not allocate memory.

    // API Call 3: TIFFReadEncodedStrip
    // Read an encoded strip of image data. This tests decompression and decoding.
    if (image_width > 0 && image_height > 0) {
        uint32_t strips_per_image = TIFFNumberOfStrips(tiff);
        if (strips_per_image > 0) {
            // Select a random strip to read from the available strips.
            uint32_t strip_to_read = fdp.ConsumeIntegralInRange<uint32_t>(0, strips_per_image - 1);
            // Determine the size of the strip.
            tmsize_t strip_size = TIFFRawStripSize(tiff, strip_to_read);

            if (strip_size > 0) {
                // Limit the buffer size to prevent excessive memory allocation and potential OOM issues.
                // A 10MB limit is chosen as a reasonable upper bound for fuzzer inputs.
                const tmsize_t MAX_STRIP_BUFFER_SIZE = 1024 * 1024 * 10; // 10 MB
                if (strip_size > MAX_STRIP_BUFFER_SIZE) {
                    strip_size = MAX_STRIP_BUFFER_SIZE;
                }
                // Allocate a buffer to hold the decoded strip data.
                // std::vector handles memory allocation and deallocation automatically (RAII).
                std::vector<uint8_t> strip_buffer(strip_size);
                // Read the encoded strip into the buffer.
                TIFFReadEncodedStrip(tiff, strip_to_read, strip_buffer.data(), strip_size);
            }
        }
    }

    // API Call 4: TIFFRGBAImageBegin and TIFFRGBAImageGet
    // Initialize and read RGBA image data. This tests color space conversion and image processing.
    TIFFRGBAImage img;
    char emsg[1024]; // Buffer for error messages from TIFFRGBAImageBegin

    // Attempt to initialize the RGBA image structure.
    // The last parameter '0' indicates no special flags.
    if (TIFFRGBAImageBegin(&img, tiff, 0, emsg)) {
        // If initialization is successful, try to read the image raster.
        // Allocate memory for the raster data.
        // Use _TIFFmalloc for consistency with libtiff's internal memory management.
        uint32_t* raster = (uint32_t*) _TIFFmalloc(image_width * image_height * sizeof(uint32_t));
        if (raster) {
            // Read the RGBA image data into the allocated raster buffer.
            TIFFRGBAImageGet(&img, raster, image_width, image_height);
            // Free the allocated raster buffer.
            _TIFFfree(raster);
        }
        // Clean up resources associated with the TIFFRGBAImage structure.
        // This is crucial as TIFFRGBAImageBegin allocates internal resources.
        TIFFRGBAImageEnd(&img);
    }

    // API Call 5: TIFFFlush
    // Flush any pending writes to the TIFF file.
    // Even in read mode, this can exercise internal state and resource management.
    // This call will now hit the `if (tif->tif_mode != O_RDONLY)` branch in TIFFCleanup due to "r+" mode.
    TIFFFlush(tiff);

    // Clean up: Close the TIFF file. This is crucial for memory safety,
    // as TIFFClose frees all resources associated with the TIFF handle.
    TIFFClose(tiff);

    return 0; // Indicate successful fuzzing iteration
}