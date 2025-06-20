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

    // Added: TIFFOpenOptions to trigger error paths in _TIFFmallocExt, _TIFFcallocExt, _TIFFreallocExt
    // and TIFFClientOpenExt. Also set warn_about_unknown_tags to true.
    TIFFOpenOptions *opts = TIFFOpenOptionsAlloc();
    // Memory safety: opts is allocated and freed.
    if (opts) {
        opts->max_single_mem_alloc = 1; // Set to a small value to trigger allocation errors
        opts->max_cumulated_mem_alloc = 1; // Set to a small value to trigger allocation errors
        opts->warn_about_unknown_tags = 1; // Cover TIFFReadDirectory warning branch (lines 4408-4414)
    }

    // API Call 1: TIFFOpen
    // Open the TIFF file using custom I/O functions.
    // The "fuzz.tif" filename is arbitrary for in-memory files.
    // Modified: Changed "r" to "r+" to enable read-write mode, covering TIFFFlush branches.
    TIFF* tiff = TIFFClientOpenExt(
        "fuzz.tif", "r+",
        static_cast<thandle_t>(&in_memory_file), // Pass the InMemoryFile object as a handle
        read_proc, write_proc, seek_proc, close_proc, size_proc,
        map_proc, unmap_proc, opts
    );

    if (opts) {
        TIFFOpenOptionsFree(opts);
    }

    // If TIFFOpen fails, there's nothing more to do with this input.
    if (!tiff) {
        // Added: Attempt to open in read-only mode to cover TIFFFlush O_RDONLY branch (line 32).
        // This will also cover TIFFClientOpenExt error paths if the first open failed due to memory limits.
        InMemoryFile in_memory_file_read_only(tiff_data);
        TIFF* tiff_read_only = TIFFClientOpen(
            "fuzz_ro.tif", "r",
            static_cast<thandle_t>(&in_memory_file_read_only),
            read_proc, write_proc, seek_proc, close_proc, size_proc,
            map_proc, unmap_proc
        );
        if (tiff_read_only) {
            TIFFFlush(tiff_read_only); // Covers TIFFFlush O_RDONLY branch
            TIFFClose(tiff_read_only);
        }
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

    // Added: Attempt to trigger _TIFFMultiplySSize error path for zero count and non-NULL tif/where.
    // This covers the `if (first <= 0 || second <= 0)` branch in `_TIFFMultiplySSize` (lines 65-69).
    // Also covers `countInkNamesString` (line 197) and `_TIFFsetNString` (line 581) branches.
    std::string long_string = fdp.ConsumeRandomLengthString(1024);
    TIFFSetField(tiff, TIFFTAG_INKNAMES, 0, long_string.c_str()); // 0 count to trigger error

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

    // Added: More TIFFGetFieldDefaulted calls for uncovered branches.
    uint16_t resolutionunit;
    TIFFGetFieldDefaulted(tiff, TIFFTAG_RESOLUTIONUNIT, &resolutionunit); // Covers TIFFTAG_RESOLUTIONUNIT
    uint16_t predictor;
    TIFFGetFieldDefaulted(tiff, TIFFTAG_PREDICTOR, &predictor); // Covers TIFFTAG_PREDICTOR
    uint16_t dotrange[2];
    TIFFGetFieldDefaulted(tiff, TIFFTAG_DOTRANGE, &dotrange[0], &dotrange[1]); // Covers TIFFTAG_DOTRANGE
    uint16_t numberofinks;
    TIFFGetFieldDefaulted(tiff, TIFFTAG_NUMBEROFINKS, &numberofinks); // Covers TIFFTAG_NUMBEROFINKS
    uint16_t tiledepth;
    TIFFGetFieldDefaulted(tiff, TIFFTAG_TILEDEPTH, &tiledepth); // Covers TIFFTAG_TILEDEPTH
    uint16_t datatype;
    TIFFGetFieldDefaulted(tiff, TIFFTAG_DATATYPE, &datatype); // Covers TIFFTAG_DATATYPE
    uint16_t sampleformat;
    TIFFGetFieldDefaulted(tiff, TIFFTAG_SAMPLEFORMAT, &sampleformat); // Covers TIFFTAG_SAMPLEFORMAT
    uint32_t imagedepth;
    TIFFGetFieldDefaulted(tiff, TIFFTAG_IMAGEDEPTH, &imagedepth); // Covers TIFFTAG_IMAGEDEPTH
    float ycbcrcoeffs[3];
    TIFFGetFieldDefaulted(tiff, TIFFTAG_YCBCRCOEFFICIENTS, &ycbcrcoeffs[0]); // Covers TIFFTAG_YCBCRCOEFFICIENTS
    uint16_t ycbcrsubsampling[2];
    TIFFGetFieldDefaulted(tiff, TIFFTAG_YCBCRSUBSAMPLING, &ycbcrsubsampling[0], &ycbcrsubsampling[1]); // Covers TIFFTAG_YCBCRSUBSAMPLING
    uint16_t ycbcrpositioning;
    TIFFGetFieldDefaulted(tiff, TIFFTAG_YCBCRPOSITIONING, &ycbcrpositioning); // Covers TIFFTAG_YCBCRPOSITIONING
    float whitepoint[2];
    TIFFGetFieldDefaulted(tiff, TIFFTAG_WHITEPOINT, &whitepoint[0]); // Covers TIFFTAG_WHITEPOINT
    uint16_t *transferfunction[3];
    TIFFGetFieldDefaulted(tiff, TIFFTAG_TRANSFERFUNCTION, &transferfunction[0]); // Covers TIFFTAG_TRANSFERFUNCTION
    float refblackwhite[6];
    TIFFGetFieldDefaulted(tiff, TIFFTAG_REFERENCEBLACKWHITE, &refblackwhite[0]); // Covers TIFFTAG_REFERENCEBLACKWHITE

    // Added: More TIFFSetField calls for uncovered branches in _TIFFVSetField.
    TIFFSetField(tiff, TIFFTAG_SUBFILETYPE, fdp.ConsumeIntegral<uint32_t>()); // Covers TIFFTAG_SUBFILETYPE
    TIFFSetField(tiff, TIFFTAG_ORIENTATION, fdp.ConsumeIntegralInRange<uint16_t>(1, 8)); // Covers TIFFTAG_ORIENTATION
    TIFFSetField(tiff, TIFFTAG_XRESOLUTION, fdp.ConsumeFloatingPoint<double>()); // Covers TIFFTAG_XRESOLUTION
    TIFFSetField(tiff, TIFFTAG_YPOSITION, fdp.ConsumeFloatingPoint<double>()); // Covers TIFFTAG_YPOSITION
    TIFFSetField(tiff, TIFFTAG_RESOLUTIONUNIT, fdp.ConsumeIntegralInRange<uint16_t>(1, 3)); // Covers TIFFTAG_RESOLUTIONUNIT
    TIFFSetField(tiff, TIFFTAG_PAGENUMBER, fdp.ConsumeIntegral<uint16_t>(), fdp.ConsumeIntegral<uint16_t>()); // Covers TIFFTAG_PAGENUMBER
    TIFFSetField(tiff, TIFFTAG_HALFTONEHINTS, fdp.ConsumeIntegral<uint16_t>(), fdp.ConsumeIntegral<uint16_t>()); // Covers TIFFTAG_HALFTONEHINTS
    // For TIFFTAG_COLORMAP, it requires a colormap. Let's try to set it with some dummy data.
    uint16_t colormap_data[256];
    fdp.ConsumeData(colormap_data, sizeof(colormap_data));
    TIFFSetField(tiff, TIFFTAG_COLORMAP, colormap_data, colormap_data, colormap_data); // Covers TIFFTAG_COLORMAP
    TIFFSetField(tiff, TIFFTAG_MATTEING, fdp.ConsumeBool()); // Covers TIFFTAG_MATTEING
    TIFFSetField(tiff, TIFFTAG_TILEWIDTH, fdp.ConsumeIntegral<uint32_t>()); // Covers TIFFTAG_TILEWIDTH
    TIFFSetField(tiff, TIFFTAG_TILELENGTH, fdp.ConsumeIntegral<uint32_t>()); // Covers TIFFTAG_TILELENGTH
    TIFFSetField(tiff, TIFFTAG_TILEDEPTH, fdp.ConsumeIntegral<uint32_t>()); // Covers TIFFTAG_TILEDEPTH
    TIFFSetField(tiff, TIFFTAG_DATATYPE, fdp.ConsumeIntegralInRange<uint16_t>(0, 3)); // Covers TIFFTAG_DATATYPE
    TIFFSetField(tiff, TIFFTAG_SAMPLEFORMAT, fdp.ConsumeIntegralInRange<uint16_t>(1, 5)); // Covers TIFFTAG_SAMPLEFORMAT
    TIFFSetField(tiff, TIFFTAG_IMAGEDEPTH, fdp.ConsumeIntegral<uint32_t>()); // Covers TIFFTAG_IMAGEDEPTH
    TIFFSetField(tiff, TIFFTAG_SUBIFD, fdp.ConsumeIntegral<uint16_t>(), (uint64_t*)nullptr); // Covers TIFFTAG_SUBIFD
    TIFFSetField(tiff, TIFFTAG_YCBCRPOSITIONING, fdp.ConsumeIntegralInRange<uint16_t>(1, 2)); // Covers TIFFTAG_YCBCRPOSITIONING
    TIFFSetField(tiff, TIFFTAG_TRANSFERFUNCTION, colormap_data, colormap_data, colormap_data); // Covers TIFFTAG_TRANSFERFUNCTION
    float ref_bw_data[6];
    fdp.ConsumeData(ref_bw_data, sizeof(ref_bw_data));
    TIFFSetField(tiff, TIFFTAG_REFERENCEBLACKWHITE, ref_bw_data); // Covers TIFFTAG_REFERENCEBLACKWHITE
    TIFFSetField(tiff, TIFFTAG_NUMBEROFINKS, fdp.ConsumeIntegral<uint16_t>()); // Covers TIFFTAG_NUMBEROFINKS
    TIFFSetField(tiff, TIFFTAG_PERSAMPLE, fdp.ConsumeIntegralInRange<uint16_t>(1, 2)); // Covers TIFFTAG_PERSAMPLE

    // Added: Trigger _TIFFMultiply64 and _TIFFCastUInt64ToSSize overflow by setting large image dimensions.
    // This will affect TIFFScanlineSize64 and TIFFStripSize64.
    TIFFSetField(tiff, TIFFTAG_IMAGEWIDTH, std::numeric_limits<uint32_t>::max());
    TIFFSetField(tiff, TIFFTAG_IMAGELENGTH, std::numeric_limits<uint32_t>::max());

    // Added: Trigger TIFFReadDirectory error paths.
    // Set BitsPerSample > 24 to cover line 4672 in TIFFReadDirectory.
    TIFFSetField(tiff, TIFFTAG_BITSPERSAMPLE, fdp.ConsumeIntegralInRange<uint16_t>(25, 32));

    // Added: Set image dimensions to 0 to cover zero scanline/tile/strip size errors.
    TIFFSetField(tiff, TIFFTAG_IMAGEWIDTH, 0);
    TIFFSetField(tiff, TIFFTAG_IMAGELENGTH, 0);

    // Added: Set compression to OJPEG and planarconfig to separate to cover OJPEG hack in TIFFReadDirectory.
    TIFFSetField(tiff, TIFFTAG_COMPRESSION, COMPRESSION_OJPEG);
    TIFFSetField(tiff, TIFFTAG_PLANARCONFIG, PLANARCONFIG_SEPARATE);

    // Added: Trigger TIFFInitLZW and TIFFInitZIP error paths by setting compression.
    // This will call TIFFSetCompressionScheme which will call TIFFInitLZW or TIFFInitZIP.
    // The TIFFOpenOptions above should trigger memory allocation failures in these init functions.
    TIFFSetField(tiff, TIFFTAG_COMPRESSION, COMPRESSION_LZW);
    TIFFSetField(tiff, TIFFTAG_COMPRESSION, COMPRESSION_ADOBE_DEFLATE);

    // Added: Trigger TIFFNumberOfStrips and TIFFNumberOfTiles branches.
    TIFFSetField(tiff, TIFFTAG_ROWSPERSTRIP, 0); // Covers TIFFNumberOfStrips line 69
    TIFFSetField(tiff, TIFFTAG_TILEWIDTH, 0); // Covers TIFFNumberOfTiles line 111
    TIFFSetField(tiff, TIFFTAG_TILELENGTH, 0); // Covers TIFFNumberOfTiles line 112
    TIFFSetField(tiff, TIFFTAG_TILEDEPTH, 0); // Covers TIFFNumberOfTiles line 113

    // Added: Create multiple directories to trigger _TIFFCheckDirNumberAndOffset hash set operations.
    // This will also cover TIFFWriteDirectorySec branches.
    for (int i = 0; i < fdp.ConsumeIntegralInRange<int>(0, 5); ++i) {
        TIFFCreateDirectory(tiff);
        TIFFWriteDirectory(tiff);
    }

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
    // Added: Manipulate photometric and bitspersample to cover more TIFFRGBAImageOK/Begin branches.
    uint16_t photometric_val = fdp.ConsumeIntegralInRange<uint16_t>(0, 10); // Fuzz photometric
    uint16_t bits_per_sample_val = fdp.ConsumeIntegralInRange<uint16_t>(1, 16); // Fuzz bits per sample
    TIFFSetField(tiff, TIFFTAG_PHOTOMETRIC, photometric_val);
    TIFFSetField(tiff, TIFFTAG_BITSPERSAMPLE, bits_per_sample_val);

    if (TIFFRGBAImageBegin(&img, tiff, 0, emsg)) {
        // If initialization is successful, try to read the image raster.
        // Allocate memory for the raster data.
        // Use _TIFFmalloc for consistency with libtiff's internal memory management.
        uint32_t* raster = (uint32_t*) _TIFFmalloc(image_width * image_height * sizeof(uint32_t));
        // Memory safety: raster is allocated using _TIFFmalloc and freed using _TIFFfree.
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