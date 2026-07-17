#include <fuzzer/FuzzedDataProvider.h>
#include "/work/include/tiffio.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <stdarg.h>

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

    // Create a TIFF file for writing.
    TIFF *tif = TIFFOpen(filename, "w");
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
     * ANALYSIS: The OJPEG-related functions OJPEGReadSecondarySos and
     *           OJPEGPrintDir have low coverage.
     * IMPLEMENTATION: Set the compression to OJPEG to exercise the OJPEG codec
     *                 and related functions.
     */
    if (fdp.ConsumeBool()) {
        TIFFSetField(tif, TIFFTAG_COMPRESSION, COMPRESSION_OJPEG);
        // These tags are for OJPEGPrintDir
        uint64_t interchange_format = fdp.ConsumeIntegral<uint64_t>();
        uint64_t interchange_format_length = fdp.ConsumeIntegral<uint64_t>();
        TIFFSetField(tif, TIFFTAG_JPEGIFOFFSET, interchange_format);
        TIFFSetField(tif, TIFFTAG_JPEGIFBYTECOUNT, interchange_format_length);
    }

    // Write dummy scanlines.
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

    /*
     * ANALYSIS: TIFFSetSubDirectory has uncovered branches related to handling
     *           of sub-IFDs.
     * IMPLEMENTATION: Write a second directory to the TIFF file. This allows
     *                 testing of directory navigation functions like
     *                 TIFFSetSubDirectory.
     */
    TIFFWriteDirectory(tif);
    TIFFSetField(tif, TIFFTAG_IMAGEWIDTH, fdp.ConsumeIntegralInRange<uint32_t>(1, 512));
    TIFFSetField(tif, TIFFTAG_IMAGELENGTH, fdp.ConsumeIntegralInRange<uint32_t>(1, 512));

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
     * IMPLEMENTATION: Attempt to read from the OJPEG file. While not guaranteed
     *                 to trigger OJPEGReadSecondarySos without a specially
     *                 crafted file, this provides a foundation for future
     *                 improvements.
     */
    uint16_t compression;
    if (TIFFGetField(tif, TIFFTAG_COMPRESSION, &compression) && compression == COMPRESSION_OJPEG) {
        char* buf = (char*)_TIFFmalloc(TIFFStripSize(tif));
        if (buf) {
            TIFFReadEncodedStrip(tif, 0, buf, (tsize_t)-1);
            _TIFFfree(buf);
        }
    }

    // Navigate directories to exercise TIFFSetSubDirectory
    if (TIFFSetDirectory(tif, 1)) {
        uint64_t dir_offset;
        if (TIFFGetField(tif, TIFFTAG_SUBIFD, &dir_offset))
        {
            TIFFSetSubDirectory(tif, dir_offset);
        }
    }

    TIFFClose(tif);
    unlink(filename);

    return 0;
}