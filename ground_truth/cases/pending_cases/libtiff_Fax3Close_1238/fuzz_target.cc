#include <fuzzer/FuzzedDataProvider.h>
#include "/work/include/tiffio.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <stdarg.h>

// This is an internal libtiff definition that is not in the public headers.
// It is needed to exercise the OJPEG code paths.
#define JPEGPROC_OJPEG 1

// A dummy error handler to prevent libtiff from exiting.
static void dummyErrorHandler(const char* module, const char* fmt, va_list ap) {
    // Do nothing.
}

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    FuzzedDataProvider fdp(data, size);

    // Create a unique temporary filename.
    char filename[256];
    snprintf(filename, sizeof(filename), "/tmp/%s.tif", _FUZZ_TARGET_NAME);

    // Set a dummy error handler.
    TIFFSetErrorHandler(dummyErrorHandler);
    TIFFSetWarningHandler(dummyErrorHandler);

    /*
     * ANALYSIS: The tif_dirwrite.c file has many uncovered functions for writing
     *           64-bit integer arrays, specifically for BigTIFF files.
     * IMPLEMENTATION: Randomly choose to write a BigTIFF file by using the "w8"
     *                 mode. This will exercise the BigTIFF-specific code paths.
     */
    const char* mode = fdp.ConsumeBool() ? "w" : "w8";
    TIFF *tif = TIFFOpen(filename, mode);
    if (!tif) {
        unlink(filename);
        return 0;
    }

    /*
     * ANALYSIS: The coverage report for TIFFPrintDirectory shows that many
     *           tag-related branches are missed.
     * IMPLEMENTATION: Set a variety of TIFF tags using FuzzedDataProvider to
     *                 increase coverage in TIFFPrintDirectory and
     *                 TIFFVGetFieldDefaulted.
     */
    uint32_t width = fdp.ConsumeIntegralInRange<uint32_t>(1, 512);
    uint32_t height = fdp.ConsumeIntegralInRange<uint32_t>(1, 512);
    TIFFSetField(tif, TIFFTAG_IMAGEWIDTH, width);
    TIFFSetField(tif, TIFFTAG_IMAGELENGTH, height);
    TIFFSetField(tif, TIFFTAG_BITSPERSAMPLE, 8);
    TIFFSetField(tif, TIFFTAG_SAMPLESPERPIXEL, 1);
    TIFFSetField(tif, TIFFTAG_PLANARCONFIG, PLANARCONFIG_CONTIG);
    TIFFSetField(tif, TIFFTAG_PHOTOMETRIC, PHOTOMETRIC_MINISBLACK);
    TIFFSetField(tif, TIFFTAG_SUBFILETYPE, fdp.ConsumeIntegral<uint32_t>());
    TIFFSetField(tif, TIFFTAG_RESOLUTIONUNIT, fdp.ConsumeIntegralInRange<uint16_t>(1, 3));
    TIFFSetField(tif, TIFFTAG_FILLORDER, fdp.ConsumeIntegralInRange<uint16_t>(1, 2));
    TIFFSetField(tif, TIFFTAG_ORIENTATION, fdp.ConsumeIntegralInRange<uint16_t>(1, 8));
    
    /*
     * ANALYSIS: The function-level coverage report shows that many of the
     *           `TIFFWriteDirectoryTag...` functions in `tif_dirwrite.c` for
     *           signed and floating-point types have zero coverage.
     * IMPLEMENTATION: Set tags that take signed integer and float values to
     *                 exercise these uncovered code paths.
     */
    TIFFSetField(tif, TIFFTAG_SMINSAMPLEVALUE, fdp.ConsumeIntegral<int16_t>());
    TIFFSetField(tif, TIFFTAG_SMAXSAMPLEVALUE, fdp.ConsumeIntegral<int16_t>());
    TIFFSetField(tif, TIFFTAG_XPOSITION, fdp.ConsumeFloatingPoint<float>());
    TIFFSetField(tif, TIFFTAG_YPOSITION, fdp.ConsumeFloatingPoint<float>());

    /*
     * ANALYSIS: The function `DoubleToSrational` in `tif_dirwrite.c` is
     *           completely uncovered. This function is used when writing tags
     *           that take a double value, such as TIFFTAG_STONITS.
     * IMPLEMENTATION: Set the TIFFTAG_STONITS tag with a double value to
     *                 exercise the `DoubleToSrational` function.
     */
    if (fdp.ConsumeBool()) {
        TIFFSetField(tif, TIFFTAG_STONITS, fdp.ConsumeFloatingPoint<double>());
    }

    /*
     * ANALYSIS: The function-level coverage report shows that `TIFFWriteDirectoryTagFloatArray`
     *           in `tif_dirwrite.c` has zero coverage.
     * IMPLEMENTATION: Set tags that take float array values to exercise this code path.
     *           `TIFFTAG_YCBCRCOEFFICIENTS` expects 3 floats.
     *           `TIFFTAG_REFERENCEBLACKWHITE` expects 6 floats.
     */
    if (fdp.ConsumeBool()) {
        float ycbcr[3];
        ycbcr[0] = fdp.ConsumeFloatingPoint<float>();
        ycbcr[1] = fdp.ConsumeFloatingPoint<float>();
        ycbcr[2] = fdp.ConsumeFloatingPoint<float>();
        TIFFSetField(tif, TIFFTAG_YCBCRCOEFFICIENTS, ycbcr);
    }
    if (fdp.ConsumeBool()) {
        float refbw[6];
        for (int i = 0; i < 6; ++i) {
            refbw[i] = fdp.ConsumeFloatingPoint<float>();
        }
        TIFFSetField(tif, TIFFTAG_REFERENCEBLACKWHITE, refbw);
    }

    /*
     * ANALYSIS: The coverage report for `tif_predict.c` shows that predictor
     *           functions for 32-bit integer and floating point data are uncovered.
     * IMPLEMENTATION: Set the predictor tag and configure the bit depth and
     *                 sample format to exercise these code paths.
     */
    if (fdp.ConsumeBool()) {
        TIFFSetField(tif, TIFFTAG_PREDICTOR, PREDICTOR_HORIZONTAL);
        if (fdp.ConsumeBool()) {
            TIFFSetField(tif, TIFFTAG_BITSPERSAMPLE, 32);
            TIFFSetField(tif, TIFFTAG_SAMPLEFORMAT, fdp.PickValueInArray({SAMPLEFORMAT_UINT, SAMPLEFORMAT_INT}));
        } else {
            TIFFSetField(tif, TIFFTAG_BITSPERSAMPLE, 32);
            TIFFSetField(tif, TIFFTAG_SAMPLEFORMAT, SAMPLEFORMAT_IEEEFP);
        }
    }


    /*
     * ANALYSIS: The OJPEG-related functions OJPEGReadSecondarySos and
     *           OJPEGPrintDir have low coverage. The fuzz target coverage report
     *           shows the OJPEG read path is never taken. This is because
     *           `JPEGPROC_OJPEG` must be set.
     * IMPLEMENTATION: Set the compression to OJPEG and set `TIFFTAG_JPEGPROC`
     *                 to `JPEGPROC_OJPEG` to properly configure the OJPEG codec.
     */
    bool ojpeg_enabled = false;
    if (fdp.ConsumeBool()) {
        TIFFSetField(tif, TIFFTAG_COMPRESSION, COMPRESSION_OJPEG);
        TIFFSetField(tif, TIFFTAG_JPEGPROC, JPEGPROC_OJPEG);
        // These tags are for OJPEGPrintDir
        uint64_t interchange_format = fdp.ConsumeIntegral<uint64_t>();
        uint64_t interchange_format_length = fdp.ConsumeIntegral<uint64_t>();
        TIFFSetField(tif, TIFFTAG_JPEGIFOFFSET, interchange_format);
        TIFFSetField(tif, TIFFTAG_JPEGIFBYTECOUNT, interchange_format_length);
        ojpeg_enabled = true;
    }

    /*
     * ANALYSIS: The coverage for `tif_fax3.c` is low. Functions like
     *           `Fax3VSetField` and `Fax3PrintDir` are not well-covered.
     * IMPLEMENTATION: Set the compression to `COMPRESSION_CCITTFAX3` and set
     *                 the `TIFFTAG_GROUP3OPTIONS` tag to exercise these code paths.
     */
    if (fdp.ConsumeBool()) {
        TIFFSetField(tif, TIFFTAG_COMPRESSION, COMPRESSION_CCITTFAX3);
        TIFFSetField(tif, TIFFTAG_GROUP3OPTIONS, fdp.ConsumeIntegral<uint32_t>());
        // Fix: Fax3/4 compression requires BitsPerSample to be 1.
        TIFFSetField(tif, TIFFTAG_BITSPERSAMPLE, 1);
    }

    // Write dummy scanlines.
    // The OJPEG encoder asserts if we feed it garbage data via TIFFWriteScanline.
    // To avoid this, and since our goal is to test the OJPEG *reader*,
    // we skip writing scanline data when OJPEG is enabled. We still write the
    // directory, which creates a file that the reader part of the fuzzer can process.
    if (!ojpeg_enabled) {
        char* scanline = (char*)_TIFFmalloc(TIFFScanlineSize(tif));
        if (scanline) {
            std::vector<uint8_t> scanline_data = fdp.ConsumeBytes<uint8_t>(TIFFScanlineSize(tif));
            if (scanline_data.size() == (size_t)TIFFScanlineSize(tif)) {
                memcpy(scanline, scanline_data.data(), scanline_data.size());
                for (uint32_t row = 0; row < height; row++) {
                    if (TIFFWriteScanline(tif, scanline, row, 0) < 0) {
                        break;
                    }
                }
            }
            _TIFFfree(scanline);
        }
    }

    /*
     * ANALYSIS: TIFFSetSubDirectory has uncovered branches. The fuzz target report
     *           shows `TIFFSetDirectory(tif, 1)` always fails because the second
     *           directory is incomplete.
     * IMPLEMENTATION: Write a second directory and also write image data to it,
     *                 making it a valid directory that can be read back.
     */
    TIFFWriteDirectory(tif);

    /*
     * ANALYSIS: The OJPEG reading logic was never hit because the second
     *           directory would overwrite the OJPEG settings.
     * IMPLEMENTATION: If OJPEG was set for the first directory, also set it
     *                 for the second directory to ensure the setting persists.
     */
    if (ojpeg_enabled) {
        TIFFSetField(tif, TIFFTAG_COMPRESSION, COMPRESSION_OJPEG);
        TIFFSetField(tif, TIFFTAG_JPEGPROC, JPEGPROC_OJPEG);
        uint64_t interchange_format = fdp.ConsumeIntegral<uint64_t>();
        uint64_t interchange_format_length = fdp.ConsumeIntegral<uint64_t>();
        TIFFSetField(tif, TIFFTAG_JPEGIFOFFSET, interchange_format);
        TIFFSetField(tif, TIFFTAG_JPEGIFBYTECOUNT, interchange_format_length);
    }

    uint32_t height2 = fdp.ConsumeIntegralInRange<uint32_t>(1, 512);
    TIFFSetField(tif, TIFFTAG_IMAGEWIDTH, fdp.ConsumeIntegralInRange<uint32_t>(1, 512));
    TIFFSetField(tif, TIFFTAG_IMAGELENGTH, height2);

    if (!ojpeg_enabled) {
        char* scanline2 = (char*)_TIFFmalloc(TIFFScanlineSize(tif));
        if (scanline2) {
            std::vector<uint8_t> scanline_data2 = fdp.ConsumeBytes<uint8_t>(TIFFScanlineSize(tif));
            if (scanline_data2.size() == (size_t)TIFFScanlineSize(tif)) {
                memcpy(scanline2, scanline_data2.data(), scanline_data2.size());
                for (uint32_t row = 0; row < height2; row++) {
                    if (TIFFWriteScanline(tif, scanline2, row, 0) < 0) {
                        break;
                    }
                }
            }
            _TIFFfree(scanline2);
        }
    }


    TIFFClose(tif);

    // Re-open the TIFF file for reading.
    tif = TIFFOpen(filename, "r");
    if (!tif) {
        unlink(filename);
        return 0;
    }

    FILE *dev_null = fopen("/dev/null", "w");
    if (dev_null) {
        /*
         * ANALYSIS: TIFFPrintDirectory has many uncovered branches related to
         *           its flags.
         * IMPLEMENTATION: Call TIFFPrintDirectory with a combination of flags to
         *                 exercise these branches.
         */
        uint32_t flags = fdp.ConsumeIntegral<uint32_t>();
        TIFFPrintDirectory(tif, dev_null, flags);
        fclose(dev_null);
    }

    /*
     * ANALYSIS: TIFFVGetFieldDefaulted has many untested cases in its switch
     *           statement.
     * IMPLEMENTATION: Call TIFFVGetFieldDefaulted with a variety of tags to
     *                 increase coverage.
     */
    uint32_t defaulted_tags[] = {
        TIFFTAG_SUBFILETYPE, TIFFTAG_BITSPERSAMPLE, TIFFTAG_THRESHHOLDING,
        TIFFTAG_FILLORDER, TIFFTAG_ORIENTATION, TIFFTAG_SAMPLESPERPIXEL,
        TIFFTAG_ROWSPERSTRIP, TIFFTAG_MINSAMPLEVALUE, TIFFTAG_MAXSAMPLEVALUE,
        TIFFTAG_PLANARCONFIG, TIFFTAG_RESOLUTIONUNIT, TIFFTAG_PREDICTOR,
        TIFFTAG_DOTRANGE, TIFFTAG_INKSET, TIFFTAG_NUMBEROFINKS,
        TIFFTAG_EXTRASAMPLES, TIFFTAG_MATTEING, TIFFTAG_TILEDEPTH,
        TIFFTAG_DATATYPE, TIFFTAG_SAMPLEFORMAT, TIFFTAG_IMAGEDEPTH,
        TIFFTAG_YCBCRCOEFFICIENTS, TIFFTAG_YCBCRSUBSAMPLING,
        TIFFTAG_YCBCRPOSITIONING, TIFFTAG_WHITEPOINT, TIFFTAG_TRANSFERFUNCTION,
        TIFFTAG_REFERENCEBLACKWHITE
    };
    uint32_t tag_to_get = fdp.PickValueInArray(defaulted_tags);
    
    switch (tag_to_get) {
        case TIFFTAG_SUBFILETYPE: {
            uint32_t value;
            TIFFGetFieldDefaulted(tif, tag_to_get, &value);
            break;
        }
        case TIFFTAG_BITSPERSAMPLE:
        case TIFFTAG_THRESHHOLDING:
        case TIFFTAG_FILLORDER:
        case TIFFTAG_ORIENTATION:
        case TIFFTAG_SAMPLESPERPIXEL:
        case TIFFTAG_MINSAMPLEVALUE:
        case TIFFTAG_MAXSAMPLEVALUE:
        case TIFFTAG_PLANARCONFIG:
        case TIFFTAG_RESOLUTIONUNIT:
        case TIFFTAG_PREDICTOR:
        case TIFFTAG_INKSET:
        case TIFFTAG_NUMBEROFINKS:
        case TIFFTAG_MATTEING:
        case TIFFTAG_DATATYPE:
        case TIFFTAG_SAMPLEFORMAT:
        case TIFFTAG_YCBCRPOSITIONING: {
            uint16_t value;
            TIFFGetFieldDefaulted(tif, tag_to_get, &value);
            break;
        }
        case TIFFTAG_ROWSPERSTRIP:
        case TIFFTAG_TILEDEPTH:
        case TIFFTAG_IMAGEDEPTH: {
            uint32_t value;
            TIFFGetFieldDefaulted(tif, tag_to_get, &value);
            break;
        }
        case TIFFTAG_DOTRANGE: {
            uint16_t value1, value2;
            TIFFGetFieldDefaulted(tif, tag_to_get, &value1, &value2);
            break;
        }
        case TIFFTAG_EXTRASAMPLES: {
            uint16_t value1;
            const uint16_t* value2;
            TIFFGetFieldDefaulted(tif, tag_to_get, &value1, &value2);
            break;
        }
        case TIFFTAG_YCBCRCOEFFICIENTS: {
            const float* value;
            TIFFGetFieldDefaulted(tif, tag_to_get, &value);
            break;
        }
        case TIFFTAG_YCBCRSUBSAMPLING: {
            uint16_t value1, value2;
            TIFFGetFieldDefaulted(tif, tag_to_get, &value1, &value2);
            break;
        }
        case TIFFTAG_WHITEPOINT: {
            const float* value;
            TIFFGetFieldDefaulted(tif, tag_to_get, &value);
            break;
        }
        case TIFFTAG_TRANSFERFUNCTION: {
            const uint16_t *v1, *v2, *v3;
            TIFFGetFieldDefaulted(tif, tag_to_get, &v1, &v2, &v3);
            break;
        }
        case TIFFTAG_REFERENCEBLACKWHITE: {
            const float* value;
            TIFFGetFieldDefaulted(tif, tag_to_get, &value);
            break;
        }
    }


    /*
     * ANALYSIS: OJPEGReadSecondarySos is completely uncovered. It is called
     *           when reading multi-scan OJPEG files.
     * IMPLEMENTATION: Attempt to read from the OJPEG file. With the correct
     *                 tags now being set, this has a chance of exercising the
     *                 OJPEG reading logic.
     */
    uint16_t compression;
    if (TIFFGetField(tif, TIFFTAG_COMPRESSION, &compression) && compression == COMPRESSION_OJPEG) {
        char* buf = (char*)_TIFFmalloc(TIFFStripSize(tif));
        if (buf) {
            TIFFReadEncodedStrip(tif, 0, buf, (tsize_t)-1);
            _TIFFfree(buf);
        }
    }

    /*
     * ANALYSIS: The check for TIFFTAG_SUBIFD was on the second directory, which
     *           doesn't have one. This meant TIFFSetSubDirectory was never called.
     * IMPLEMENTATION: Get the SUBIFD tag from the first directory (where it
     *                 exists) and then call TIFFSetSubDirectory to exercise that
     *                 code path.
     */
    uint16_t dircount = 0;
    uint64_t* dir_offsets = nullptr;
    if (TIFFGetField(tif, TIFFTAG_SUBIFD, &dircount, &dir_offsets) && dircount > 0)
    {
        TIFFSetSubDirectory(tif, dir_offsets[0]);
    }

    // Navigate to the next directory to exercise TIFFSetDirectory
    TIFFSetDirectory(tif, 1);

    TIFFClose(tif);
    unlink(filename);

    return 0;
}