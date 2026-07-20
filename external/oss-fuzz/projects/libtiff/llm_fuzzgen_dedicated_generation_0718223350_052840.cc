/* BLOCKER_STRATEGY_CONTRACT
required_state: The `_TIFFmallocExt` function must return `NULL` when invoked by `makebwmap`. This is achieved when the memory allocation requested by `makebwmap` exceeds the `max_single_mem_alloc` limit configured on the `TIFF` handle.
state_constructor: A TIFF file is first created with `PHOTOMETRIC_MINISBLACK` or `PHOTOMETRIC_MINISWHITE` and a `BITSPERSAMPLE` value of 1, 2, 4, or 8. This file is then re-opened using `TIFFOpenExt` along with a `TIFFOpenOptions` structure where `max_single_mem_alloc` is set to a small value (e.g., under 3072 bytes), which is less than the amount `makebwmap` will attempt to allocate.
trigger_api: The `TIFFReadRGBAImage` function is called to process the image. This triggers a call chain through `TIFFRGBAImageBegin`, `setupMap`, and finally to `makebwmap`, causing the controlled memory allocation failure.
preserved_invariants: The fuzzer maintains the standard workflow of creating, writing, closing, and then re-opening a TIFF file for reading. The key modification is the introduction of memory allocation limits via `TIFFOpenExt` to induce the desired failure state.
END_BLOCKER_STRATEGY_CONTRACT */

#include <fuzzer/FuzzedDataProvider.h>
#include <tiffio.h>
#include <tiff.h>
#include <unistd.h>
#include <string>
#include <vector>

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size) {
    if (Size < 20) {
        return 0;
    }
    FuzzedDataProvider fdp(Data, Size);

    const std::string path = "/tmp/makebwmap_fuzz.tif";

    // Create a TIFF file with properties that lead to makebwmap being called.
    TIFF* tif_write = TIFFOpen(path.c_str(), "w");
    if (!tif_write) {
        return 0;
    }

    uint32_t width = fdp.ConsumeIntegralInRange<uint32_t>(1, 100);
    uint32_t height = fdp.ConsumeIntegralInRange<uint32_t>(1, 100);
    uint16_t bitspersample = fdp.PickValueInArray<uint16_t>({1, 2, 4, 8});
    uint16_t photometric = fdp.PickValueInArray<uint16_t>({PHOTOMETRIC_MINISBLACK, PHOTOMETRIC_MINISWHITE});

    TIFFSetField(tif_write, TIFFTAG_IMAGEWIDTH, width);
    TIFFSetField(tif_write, TIFFTAG_IMAGELENGTH, height);
    TIFFSetField(tif_write, TIFFTAG_BITSPERSAMPLE, bitspersample);
    TIFFSetField(tif_write, TIFFTAG_SAMPLESPERPIXEL, (uint16_t)1);
    TIFFSetField(tif_write, TIFFTAG_PHOTOMETRIC, photometric);
    TIFFSetField(tif_write, TIFFTAG_PLANARCONFIG, PLANARCONFIG_CONTIG);
    TIFFSetField(tif_write, TIFFTAG_COMPRESSION, COMPRESSION_NONE);

    tsize_t scanline_size = TIFFScanlineSize(tif_write);
    if (scanline_size > 0) {
        std::vector<char> scanline(scanline_size, 0);
        for (uint32_t row = 0; row < height; ++row) {
            if (TIFFWriteScanline(tif_write, scanline.data(), row, 0) < 0) {
                break;
            }
        }
    }

    TIFFClose(tif_write);

    // Re-open the file with a memory allocation limit to cause _TIFFmallocExt to fail.
    TIFFOpenOptions* opts = TIFFOpenOptionsAlloc();
    if (!opts) {
        unlink(path.c_str());
        return 0;
    }
    
    // The allocation in makebwmap is at least 3072 bytes. Set a smaller limit.
    TIFFOpenOptionsSetMaxSingleMemAlloc(opts, fdp.ConsumeIntegralInRange<tmsize_t>(1, 3000));
    
    TIFF* tif_read = TIFFOpenExt(path.c_str(), "r", opts);
    TIFFOpenOptionsFree(opts);

    if (!tif_read) {
        unlink(path.c_str());
        return 0;
    }

    // Trigger the call to makebwmap via TIFFReadRGBAImage.
    uint32_t read_width = 0, read_height = 0;
    TIFFGetField(tif_read, TIFFTAG_IMAGEWIDTH, &read_width);
    TIFFGetField(tif_read, TIFFTAG_IMAGELENGTH, &read_height);

    if (read_width > 0 && read_height > 0 && read_width < 2048 && read_height < 2048) {
        uint32_t* raster = (uint32_t*)_TIFFmalloc(read_width * read_height * sizeof(uint32_t));
        if (raster) {
            // This call will trigger the blocker.
            TIFFReadRGBAImage(tif_read, read_width, read_height, raster, 0);
            _TIFFfree(raster);
        }
    }
    
    TIFFClose(tif_read);
    unlink(path.c_str());

    return 0;
}
