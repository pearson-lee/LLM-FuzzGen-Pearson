#include <cstddef>
#include <cstdint>
#include <string>
#include <vector>
#include <fuzzer/FuzzedDataProvider.h>
#include <memory> // For std::unique_ptr
#include <algorithm> // For std::min, std::max

// libtiff public API header
#include "/src/libtiff/libtiff/tiffio.h"

// Custom in-memory file structure to simulate file I/O for libtiff.
// This allows the fuzzer to operate on a memory buffer instead of actual files,
// making it self-contained, faster, and avoiding file system side effects.
struct InMemoryFile {
    std::vector<uint8_t> data; // Stores the TIFF file content in memory.
    uint64_t offset = 0;        // Current read/write offset within the data.
};

// --- Custom I/O Callbacks for libtiff (TIFFClientOpen) ---

// Callback for reading data from the in-memory file.
static tmsize_t read_proc(thandle_t fd, void* buf, tmsize_t size) {
    InMemoryFile* f = static_cast<InMemoryFile*>(fd);
    if (f->offset >= f->data.size()) {
        return 0; // Reached end of file.
    }
    // Calculate bytes to read, ensuring we don't read beyond the buffer's end.
    tmsize_t bytes_to_read = std::min(size, (tmsize_t)(f->data.size() - f->offset));
    memcpy(buf, f->data.data() + f->offset, bytes_to_read);
    f->offset += bytes_to_read; // Advance the offset.
    return bytes_to_read;
}

// Callback for writing data to the in-memory file.
static tmsize_t write_proc(thandle_t fd, void* buf, tmsize_t size) {
    InMemoryFile* f = static_cast<InMemoryFile*>(fd);
    // Resize the data vector if the write operation extends beyond its current size.
    if (f->offset + size > f->data.size()) {
        f->data.resize(f->offset + size);
    }
    memcpy(f->data.data() + f->offset, buf, size);
    f->offset += size; // Advance the offset.
    return size;
}

// Callback for seeking within the in-memory file.
static uint64_t seek_proc(thandle_t fd, uint64_t off, int whence) {
    InMemoryFile* f = static_cast<InMemoryFile*>(fd);
    uint64_t new_offset;
    switch (whence) {
        case SEEK_SET:
            new_offset = off;
            break;
        case SEEK_CUR:
            new_offset = f->offset + off;
            break;
        case SEEK_END:
            new_offset = f->data.size() + off;
            break;
        default:
            return (uint64_t)-1; // Indicate an error for unsupported whence.
    }
    // Ensure the new offset is not negative.
    f->offset = std::max((uint64_t)0, new_offset);
    return f->offset;
}

// Callback for closing the in-memory file.
// The InMemoryFile object is managed by std::unique_ptr in LLVMFuzzerTestOneInput,
// so no explicit deletion or resource release is needed here.
static int close_proc(thandle_t fd) {
    (void)fd; // Suppress unused parameter warning.
    return 0;
}

// Callback for getting the size of the in-memory file.
static uint64_t size_proc(thandle_t fd) {
    InMemoryFile* f = static_cast<InMemoryFile*>(fd);
    return f->data.size();
}

// Dummy callback for memory mapping.
// Since we're operating on a std::vector, actual memory mapping is not performed.
// This function is required by TIFFClientOpen.
static int map_proc(thandle_t fd, void** pbase, toff_t* psize) {
    InMemoryFile* f = static_cast<InMemoryFile*>(fd);
    *pbase = f->data.data();
    *psize = f->data.size();
    return 0;
}

// Dummy callback for unmapping memory.
// Required by TIFFClientOpen, but no action is needed.
static void unmap_proc(thandle_t fd, void* base, toff_t size) {
    (void)fd; (void)base; (void)size; // Suppress unused parameter warnings.
}

// --- Custom Error and Warning Handlers ---

// Custom error handler to prevent libtiff from printing to stderr or exiting.
// This is crucial for continuous fuzzing, as libtiff might call error handlers
// for malformed inputs that would otherwise terminate the fuzzer.
static int custom_error_handler_r(TIFF* tif, void* clientdata, const char* module, const char* fmt, va_list ap) {
    (void)tif; (void)clientdata; (void)module; (void)fmt; (void)ap; // Suppress unused parameter warnings.
    return 0; // Return 0 as per TIFFErrorHandlerExtR signature
}

// Custom warning handler, similar to the error handler, to suppress output.
static int custom_warning_handler_r(TIFF* tif, void* clientdata, const char* module, const char* fmt, va_list ap) {
    (void)tif; (void)clientdata; (void)module; (void)fmt; (void)ap; // Suppress unused parameter warnings.
    return 0; // Return 0 as per TIFFErrorHandlerExtR signature
}

// --- Fuzz Target Entry Point ---

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size) {
    FuzzedDataProvider fdp(Data, Size);

    // Create an in-memory file object to hold the fuzzer's input data.
    // std::unique_ptr ensures that InMemoryFile is automatically deallocated
    // when it goes out of scope, preventing memory leaks.
    std::unique_ptr<InMemoryFile> in_memory_file(new InMemoryFile());
    in_memory_file->data = fdp.ConsumeRemainingBytes<uint8_t>();

    // Allocate TIFFOpenOptions and set custom error/warning handlers.
    TIFFOpenOptions *open_options = TIFFOpenOptionsAlloc();
    if (!open_options) {
        return 0; // Failed to allocate options, gracefully exit.
    }
    TIFFOpenOptionsSetErrorHandlerExtR(open_options, custom_error_handler_r, nullptr);
    TIFFOpenOptionsSetWarningHandlerExtR(open_options, custom_warning_handler_r, nullptr);

    // 1. Exercise TIFFOpen: Open the in-memory file using libtiff's custom I/O interface.
    // A dummy filename is provided as the actual file system is not accessed.
    std::string filename = fdp.ConsumeRandomLengthString(10);
    // Select a random file open mode ("r" for read, "w" for write, "a" for append).
    // Modified: Prioritize write/append modes to hit more write-related code paths.
    std::string mode_str = fdp.PickValueInArray<std::string>({"r", "w", "w", "a", "a"}); 

    TIFF* tif = TIFFClientOpenExt(filename.c_str(), mode_str.c_str(),
                               in_memory_file.get(), // Pass our InMemoryFile instance as client data.
                               read_proc, write_proc, seek_proc, close_proc,
                               size_proc, map_proc, unmap_proc,
                               open_options); // Pass the configured options.

    // Free the TIFFOpenOptions object as it's no longer needed after TIFFClientOpenExt.
    TIFFOpenOptionsFree(open_options);

    // Only proceed with further operations if TIFFOpen successfully returned a TIFF handle.
    if (tif) {
        // Determine if the opened mode allows read or write operations.
        bool can_read = (mode_str == "r" || mode_str == "a");
        bool can_write = (mode_str == "w" || mode_str == "a");

        // 2. Exercise TIFFSetDirectory: Attempt to set the current directory within the TIFF file.
        // This tests libtiff's ability to parse and navigate directory structures,
        // which can be complex and prone to issues with malformed inputs.
        // Modified: Removed the fdp.remaining_bytes() check to ensure it's always called, improving coverage for TIFFSetDirectory.
        tdir_t dir_index = fdp.ConsumeIntegral<tdir_t>();
        TIFFSetDirectory(tif, dir_index); 

        // Added: If in write mode, attempt to write/rewrite directory to increase coverage for tif_dirwrite.c.
        if (can_write) {
            if (fdp.ConsumeBool()) {
                TIFFWriteDirectory(tif); // Added: Call TIFFWriteDirectory
            } else {
                TIFFRewriteDirectory(tif); // Added: Call TIFFRewriteDirectory
            }
        }

        // Retrieve image dimensions (width and height). These might be zero for invalid or empty TIFFs.
        uint32_t image_width = 0;
        uint32_t image_height = 0;
        TIFFGetField(tif, TIFFTAG_IMAGEWIDTH, &image_width);
        TIFFGetField(tif, TIFFTAG_IMAGELENGTH, &image_height);

        // Calculate a reasonable scanline size for buffer allocation.
        // TIFFScanlineSize can return 0 for malformed TIFFs, so a fallback is provided.
        tmsize_t scanline_size = TIFFScanlineSize(tif);
        if (scanline_size == 0) {
            // Heuristic fallback: assume 4 bytes per pixel (RGBA) if width is available, otherwise a default size.
            scanline_size = (image_width > 0) ? (tmsize_t)image_width * 4 : 1024;
        }
        // Cap the scanline size to prevent excessive memory allocations during fuzzing.
        scanline_size = std::min((tmsize_t)65536, scanline_size); // Max 64KB per scanline.

        // Proceed with scanline operations only if a valid scanline size is determined.
        if (scanline_size > 0) {
            // 3. Exercise TIFFReadScanline: Attempt to read a scanline of image data.
            // This targets the core image decoding logic, which is a common area for vulnerabilities.
            if (can_read && fdp.remaining_bytes() > 0) {
                std::vector<uint8_t> read_buffer(scanline_size); // Buffer to store read data.
                // Consume a row index, ensuring it's within valid bounds (0 to image_height - 1).
                // If image_height is 0, the upper bound becomes 0, so row will be 0.
                uint32_t row = fdp.ConsumeIntegralInRange<uint32_t>(0, image_height > 0 ? image_height - 1 : 0);
                uint16_t sample = fdp.ConsumeIntegral<uint16_t>(); // Sample index (often 0 for non-planar data).
                TIFFReadScanline(tif, read_buffer.data(), row, sample);
            }

            // 4. Exercise TIFFWriteScanline: Attempt to write a scanline of image data.
            // This targets the core image encoding logic, complementing the read operations.
            if (can_write && fdp.remaining_bytes() > 0) {
                // Consume bytes from the fuzzer input for the write buffer.
                // If not enough bytes are available, resize and pad with zeros.
                std::vector<uint8_t> write_buffer = fdp.ConsumeBytes<uint8_t>(scanline_size);
                if (write_buffer.size() < scanline_size) {
                    write_buffer.resize(scanline_size, 0);
                }
                // Consume a row index, ensuring it's within valid bounds.
                uint32_t row = fdp.ConsumeIntegralInRange<uint32_t>(0, image_height > 0 ? image_height - 1 : 0);
                uint16_t sample = fdp.ConsumeIntegral<uint16_t>(); // Sample index.
                TIFFWriteScanline(tif, write_buffer.data(), row, sample);
            }
        }

        // Added: Exercise TIFFFlush: Flush any pending writes to the underlying file.
        // This is important for ensuring data integrity and hitting relevant code paths, especially the tif_mode != O_RDONLY branch in TIFFCleanup.
        if (can_write) {
            TIFFFlush(tif); 
        }

        // 6. Exercise TIFFClose: Close the TIFF handle.
        // This is a critical step to ensure all allocated resources by libtiff
        // are properly released, preventing memory leaks.
        TIFFClose(tif);
    }

    // The unique_ptr for InMemoryFile automatically handles the deallocation
    // of the in-memory data buffer when LLVMFuzzerTestOneInput returns.
    return 0;
}