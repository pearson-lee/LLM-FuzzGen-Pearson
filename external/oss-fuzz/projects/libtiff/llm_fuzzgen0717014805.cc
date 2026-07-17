#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <string>
#include <vector>
#include <unistd.h>

#include "/src/libtiff/libtiff/tiffio.h"
#include "/src/libtiff/libtiff/tif_hash_set.h"
#include <fuzzer/FuzzedDataProvider.h>

// Define a dummy hash function for the hash set
static unsigned long
hash_ptr(const void *p)
{
    return (unsigned long)(uintptr_t)p;
}

// Define a dummy equality function for the hash set
static bool
equal_ptr(const void *p1, const void *p2)
{
    return p1 == p2;
}


extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    FuzzedDataProvider fdp(data, size);

    // --- Part 1: Fuzz TIFFHashSet ---
    /*
     * ANALYSIS: The coverage report for TIFFHashSetInsert shows that branches for
     *           handling element collisions and rehashing are never taken.
     * IMPLEMENTATION: This block creates a TIFFHashSet and inserts multiple
     *                 elements. It inserts a duplicate pointer to test the collision
     *                 handling path. It also inserts a variable number of elements
     *                 to increase the probability of triggering a rehash.
     */
    if (fdp.ConsumeBool()) {
        TIFFHashSet *hash_set = TIFFHashSetNew(hash_ptr, equal_ptr, nullptr);
        if (hash_set) {
            const int num_insertions = fdp.ConsumeIntegralInRange<int>(5, 50);
            std::vector<void*> pointers;
            for (int i = 0; i < num_insertions; ++i) {
                // Use integer values as pointers for deterministic fuzzing
                void* p = reinterpret_cast<void*>(fdp.ConsumeIntegral<uintptr_t>());
                pointers.push_back(p);
                TIFFHashSetInsert(hash_set, p);
            }
            // Insert a duplicate to test collision handling
            if (!pointers.empty()) {
                TIFFHashSetInsert(hash_set, pointers[0]);
            }
            TIFFHashSetDestroy(hash_set);
        }
    }

    // --- Part 2: Fuzz TIFF Directory and Tag Writing ---
    std::string base_name = "fuzz_";
    // Use a compile-time macro to ensure unique filenames in parallel fuzzing
    #ifdef _FUZZ_TARGET_NAME
        base_name += _FUZZ_TARGET_NAME;
    #endif
    std::string filename = "/tmp/" + base_name + ".tif";

    TIFF *tif = TIFFOpen(filename.c_str(), "w");
    if (!tif) {
        unlink(filename.c_str());
        return 0;
    }

    // Set mandatory fields
    uint32_t width = fdp.ConsumeIntegralInRange<uint32_t>(1, 512);
    uint32_t height = fdp.ConsumeIntegralInRange<uint32_t>(1, 512);
    TIFFSetField(tif, TIFFTAG_IMAGEWIDTH, width);
    TIFFSetField(tif, TIFFTAG_IMAGELENGTH, height);
    TIFFSetField(tif, TIFFTAG_BITSPERSAMPLE, 8);
    TIFFSetField(tif, TIFFTAG_SAMPLESPERPIXEL, 3);
    TIFFSetField(tif, TIFFTAG_PLANARCONFIG, PLANARCONFIG_CONTIG);
    TIFFSetField(tif, TIFFTAG_PHOTOMETRIC, PHOTOMETRIC_RGB);

    // --- Coverage-guided fuzzing for specific compression codecs ---
    if (fdp.ConsumeBool()) {
        /*
         * ANALYSIS: The line-coverage report for LogLuvVSetField shows that the
         *           branches for TIFFTAG_SGILOGDATAFMT and TIFFTAG_SGILOGENCODE
         *           are never executed.
         * IMPLEMENTATION: Set the compression to COMPRESSION_SGILOG and then
         *                 call TIFFSetField with the uncovered tags and fuzzed values
         *                 to exercise these specific code paths.
         */
        TIFFSetField(tif, TIFFTAG_COMPRESSION, COMPRESSION_SGILOG);
        TIFFSetField(tif, TIFFTAG_SGILOGDATAFMT, fdp.ConsumeIntegralInRange<int>(0, 4));
        TIFFSetField(tif, TIFFTAG_SGILOGENCODE, fdp.ConsumeIntegralInRange<int>(0, 2));

    } else if (fdp.ConsumeBool()) {
        /*
         * ANALYSIS: The line-coverage report for PixarLogVSetField shows that the
         *           branches for TIFFTAG_PIXARLOGQUALITY and TIFFTAG_PIXARLOGDATAFMT
         *           are never executed.
         * IMPLEMENTATION: Set the compression to COMPRESSION_PIXARLOG and then
         *                 call TIFFSetField with the uncovered tags and fuzzed values
         *                 to exercise these specific code paths.
         */
        TIFFSetField(tif, TIFFTAG_COMPRESSION, COMPRESSION_PIXARLOG);
        TIFFSetField(tif, TIFFTAG_PIXARLOGQUALITY, fdp.ConsumeIntegralInRange<int>(-128, 127));
        TIFFSetField(tif, TIFFTAG_PIXARLOGDATAFMT, fdp.ConsumeIntegralInRange<int>(0, 6));
    } else if (fdp.ConsumeBool()) {
        /*
         * ANALYSIS: The function-level coverage report shows OJPEGPrintDir and
         *           other OJPEG-related functions have zero or low coverage.
         * IMPLEMENTATION: Set the compression to COMPRESSION_OJPEG. This,
         *                 combined with the later call to TIFFPrintDirectory,
         *                 will exercise the OJPEG-specific print logic.
         *                 Also setting JPEGPROC and PHOTOMETRIC as they are
         *                 often required for JPEG-based compression.
         */
        TIFFSetField(tif, TIFFTAG_COMPRESSION, COMPRESSION_OJPEG);
        TIFFSetField(tif, TIFFTAG_JPEGPROC, JPEGPROC_BASELINE);
        TIFFSetField(tif, TIFFTAG_PHOTOMETRIC, PHOTOMETRIC_YCBCR);
    } else if (fdp.ConsumeBool()) {
        /*
         * ANALYSIS: The function-level coverage report for tif_packbits.c shows that
         *           the PackBitsEncode function is completely uncovered (0%).
         * IMPLEMENTATION: Set the compression to COMPRESSION_PACKBITS. When
         *                 TIFFWriteScanline is called later, it will invoke the
         *                 PackBits encoder, covering this previously unreached code.
         */
        TIFFSetField(tif, TIFFTAG_COMPRESSION, COMPRESSION_PACKBITS);
    } else if (fdp.ConsumeBool()) {
        /*
         * ANALYSIS: The function-level coverage report for tif_dirwrite.c shows that
         *           many specific tag writing functions like TIFFWriteDirectoryTagTransferfunction
         *           are completely uncovered.
         * IMPLEMENTATION: Call TIFFSetField with TIFFTAG_TRANSFERFUNCTION and
         *                 TIFFTAG_INKNAMES to exercise their specific directory writing logic
         *                 within the later call to TIFFWriteDirectory.
         */
        std::string ink_names_str = fdp.ConsumeRandomLengthString(100);
        if (!ink_names_str.empty()) {
            std::string ink_names_data = ink_names_str;
            // The INKNAMES tag requires a list of names separated by a null
            // character, with the list terminated by a double null.
            ink_names_data.push_back('\0');
            ink_names_data.push_back('\0');
            // By providing the length explicitly, we avoid a buggy code path
            // in the library that tries to calculate it.
            TIFFSetField(tif, TIFFTAG_INKNAMES, ink_names_data.length(), ink_names_data.c_str());
        }

        // The transfer function requires 3 arrays of 256 shorts for 8-bit RGB
        std::vector<uint16_t> tf(256 * 3);
        for(size_t i = 0; i < tf.size(); ++i) {
            tf[i] = fdp.ConsumeIntegral<uint16_t>();
        }
        TIFFSetField(tif, TIFFTAG_TRANSFERFUNCTION, tf.data(), tf.data() + 256, tf.data() + 512);
    } else if (fdp.ConsumeBool()) {
        /*
         * ANALYSIS: The function-level coverage report for tif_jpeg.c shows that
         *           the JPEG encoding functions (JPEGSetupEncode, JPEGEncode, etc.)
         *           are completely uncovered (0%).
         * IMPLEMENTATION: Set the compression to COMPRESSION_JPEG. This will
         *                 trigger the JPEG encoding pipeline when TIFFWriteScanline
         *                 is called, exercising this uncovered codec.
         */
        TIFFSetField(tif, TIFFTAG_COMPRESSION, COMPRESSION_JPEG);
        TIFFSetField(tif, TIFFTAG_PHOTOMETRIC, PHOTOMETRIC_YCBCR);
        TIFFSetField(tif, TIFFTAG_JPEGCOLORMODE, JPEGCOLORMODE_RGB);
    } else if (fdp.ConsumeBool()) {
        /*
         * ANALYSIS: The function-level coverage report for tif_lzw.c shows that
         *           the LZW encoding functions (LZWSetupEncode, LZWEncode, etc.)
         *           are completely uncovered (0%).
         * IMPLEMENTATION: Set the compression to COMPRESSION_LZW. This will
         *                 trigger the LZW encoding pipeline when TIFFWriteScanline
         *                 is called, covering this widely-used codec.
         */
        TIFFSetField(tif, TIFFTAG_COMPRESSION, COMPRESSION_LZW);
    } else if (fdp.ConsumeBool()) {
        /*
         * ANALYSIS: The function-level coverage report for tif_zip.c shows that
         *           the ZIP encoding functions (ZIPSetupEncode, ZIPEncode, etc.)
         *           are completely uncovered (0%).
         * IMPLEMENTATION: Set the compression to COMPRESSION_ADOBE_DEFLATE. This will
         *                 trigger the ZIP encoding pipeline when TIFFWriteScanline
         *                 is called, exercising this uncovered codec.
         */
        TIFFSetField(tif, TIFFTAG_COMPRESSION, COMPRESSION_ADOBE_DEFLATE);
    } else if (fdp.ConsumeBool()) {
        /*
         * ANALYSIS: The function-level coverage report for tif_lzma.c shows that
         *           the LZMA encoding functions (LZMASetupEncode, LZMAEncode, etc.)
         *           are completely uncovered (0%).
         * IMPLEMENTATION: Set the compression to COMPRESSION_LZMA. This will
         *                 trigger the LZMA encoding pipeline when TIFFWriteScanline
         *                 is called, exercising this uncovered codec.
         */
        TIFFSetField(tif, TIFFTAG_COMPRESSION, COMPRESSION_LZMA);
    } else if (fdp.ConsumeBool()) {
        /*
         * ANALYSIS: The function-level coverage report for tif_fax3.c shows that
         *           the Fax3 encoding functions are completely uncovered (0%).
         * IMPLEMENTATION: Set the compression to COMPRESSION_CCITTFAX3. This
         *                 requires a bilevel image, so we override the default color
         *                 image tags, setting BitsPerSample and SamplesPerPixel to 1
         *                 and the photometric to MINISWHITE. This allows the
         *                 TIFFWriteScanline call to trigger the FAX3 encoder.
         */
        TIFFSetField(tif, TIFFTAG_COMPRESSION, COMPRESSION_CCITTFAX3);
        TIFFSetField(tif, TIFFTAG_BITSPERSAMPLE, 1);
        TIFFSetField(tif, TIFFTAG_SAMPLESPERPIXEL, 1);
        TIFFSetField(tif, TIFFTAG_PHOTOMETRIC, PHOTOMETRIC_MINISWHITE);
        TIFFSetField(tif, TIFFTAG_GROUP3OPTIONS, fdp.ConsumeIntegral<uint32_t>());
    } else if (fdp.ConsumeBool()) {
        /*
         * ANALYSIS: The function-level coverage report shows that many tile-related
         *           functions in tif_tile.c and tif_getimage.c (e.g., TIFFCheckTile,
         *           gtTileContig) have low or zero coverage.
         * IMPLEMENTATION: Set the TILEWIDTH and TILELENGTH tags to create a
         *                 tiled image instead of the default stripped layout. The
         *                 subsequent write and read operations will then exercise the
         *                 tiled image processing pathways. Tile dimensions must be
         *                 a multiple of 16.
         */
        uint32_t tile_width = fdp.PickValueInArray<uint32_t>({16, 32, 64, 128, 256, 512});
        uint32_t tile_height = fdp.PickValueInArray<uint32_t>({16, 32, 64, 128, 256, 512});
        TIFFSetField(tif, TIFFTAG_TILEWIDTH, tile_width);
        TIFFSetField(tif, TIFFTAG_TILELENGTH, tile_height);
    } else if (fdp.ConsumeBool()) {
        /*
         * ANALYSIS: The function-level coverage report for tif_dir.c shows that
         *           TIFFUnsetField is completely uncovered (0%).
         * IMPLEMENTATION: Call TIFFSetField for a simple tag (ARTIST) and
         *                 then immediately call TIFFUnsetField to cover this
         *                 unexercised API function.
         */
        const char* artist = "Fuzzer";
        TIFFSetField(tif, TIFFTAG_ARTIST, artist);
        TIFFUnsetField(tif, TIFFTAG_ARTIST);
    } else if (fdp.ConsumeBool()) {
        /*
         * ANALYSIS: The function-level coverage report for tif_dirwrite.c shows that
         *           TIFFWriteDirectoryTagColormap is completely uncovered (0%).
         * IMPLEMENTATION: Create a palette-color image by setting the photometric to
         *                 PALETTE and providing a colormap via TIFFTAG_COLORMAP. This
         *                 exercises the specific tag writing logic for colormaps.
         */
        TIFFSetField(tif, TIFFTAG_PHOTOMETRIC, PHOTOMETRIC_PALETTE);
        TIFFSetField(tif, TIFFTAG_SAMPLESPERPIXEL, 1);
        uint16_t bps = fdp.PickValueInArray<uint16_t>({1, 2, 4, 8});
        TIFFSetField(tif, TIFFTAG_BITSPERSAMPLE, bps);

        const int cmap_size = 1 << bps;
        std::vector<uint16_t> r(cmap_size), g(cmap_size), b(cmap_size);
        for (int i = 0; i < cmap_size; ++i) {
            r[i] = fdp.ConsumeIntegral<uint16_t>();
            g[i] = fdp.ConsumeIntegral<uint16_t>();
            b[i] = fdp.ConsumeIntegral<uint16_t>();
        }
        TIFFSetField(tif, TIFFTAG_COLORMAP, r.data(), g.data(), b.data());
    }


    if (TIFFIsTiled(tif)) {
        /*
         * ANALYSIS: With a tiled image configured, TIFFWriteScanline cannot be used.
         *           The tile-writing APIs must be used instead. TIFFWriteEncodedTile
         *           is a direct way to exercise the tile encoding pipeline.
         * IMPLEMENTATION: Write a single fuzzer-data-filled tile to the image. This
         *                 complements setting the tile tags and ensures the tile-writing
         *                 code paths are actually executed.
         */
        tmsize_t tile_size = TIFFTileSize(tif);
        if (tile_size > 0 && tile_size < 1000000) { // Avoid huge allocations
            std::vector<uint8_t> tile_buffer(tile_size);
            size_t consumed_bytes = fdp.ConsumeData(tile_buffer.data(), tile_size);
            /*
             * ANALYSIS: The detailed fuzz target coverage report showed that the branch
             *           checking `consumed_bytes == tile_size` was never taken, because
             *           the fuzzer rarely provides the exact amount of data.
             * IMPLEMENTATION: Relax the check to `consumed_bytes > 0` to allow writing
             *                 partially-filled tiles, which exercises the TIFFWriteEncodedTile
             *                 function that was previously uncovered.
             */
            if (consumed_bytes > 0) {
                TIFFWriteEncodedTile(tif, 0, tile_buffer.data(), consumed_bytes);
            }
        }
    } else {
        // Write dummy scanline to make the image valid for directory writing
        tmsize_t scanline_size = TIFFScanlineSize(tif);
        if (scanline_size > 0) {
            std::vector<uint8_t> scanline(scanline_size);
            // Ensure the buffer is fully populated to avoid using uninitialized data
            size_t consumed_bytes = fdp.ConsumeData(scanline.data(), scanline.size());
            if (consumed_bytes == (size_t)scanline_size) {
                TIFFWriteScanline(tif, scanline.data(), 0, 0);
            }
        }
    }

    /*
     * ANALYSIS: The function TIFFWriteDirectory and its underlying implementation
     *           TIFFWriteDirectorySec are completely uncovered (0% coverage).
     * IMPLEMENTATION: Call TIFFWriteDirectory() after setting various fields.
     *                 This single call will exercise the extensive, uncovered logic
     *                 for writing IFD (Image File Directory) entries to the file.
     */
    TIFFWriteDirectory(tif);

    /*
     * ANALYSIS: The function-level coverage report shows that functions for handling
     *           multiple directories (IFDs) like TIFFSetSubDirectory and TIFFUnlinkDirectory
     *           are completely uncovered.
     * IMPLEMENTATION: After writing the first directory, this block will sometimes
     *                 write a second directory to the same TIFF file. This exercises
     *                 the library's logic for creating and linking multiple IFDs,
     *                 improving coverage in tif_dir.c and tif_dirwrite.c. It also
     *                 sometimes calls the uncovered TIFFUnlinkDirectory function.
     */
    if (fdp.ConsumeBool()) {
        // Set mandatory fields for the second directory
        TIFFSetField(tif, TIFFTAG_IMAGEWIDTH, width);
        TIFFSetField(tif, TIFFTAG_IMAGELENGTH, height);
        TIFFSetField(tif, TIFFTAG_BITSPERSAMPLE, 8);
        TIFFSetField(tif, TIFFTAG_SAMPLESPERPIXEL, 3);
        TIFFSetField(tif, TIFFTAG_PLANARCONFIG, PLANARCONFIG_CONTIG);
        TIFFSetField(tif, TIFFTAG_PHOTOMETRIC, PHOTOMETRIC_RGB);
        TIFFSetField(tif, TIFFTAG_SUBFILETYPE, FILETYPE_PAGE); // Mark as a page in a multi-page doc
        TIFFWriteDirectory(tif);

        /*
         * ANALYSIS: The function-level coverage report shows that TIFFUnlinkDirectory
         *           is completely uncovered (0%).
         * IMPLEMENTATION: After writing a second directory, call TIFFUnlinkDirectory
         *                 to exercise this unreached API function. This requires at
         *                 least two directories to be present.
         */
        if (fdp.ConsumeBool()) {
            TIFFUnlinkDirectory(tif, 2);
        }
    }

    /*
     * ANALYSIS: The function-level coverage report shows that TIFFPrintDirectory
     *           and related functions in tif_print.c are completely uncovered (0%).
     *           Calling this function exercises a large amount of unreached code.
     * IMPLEMENTATION: Open /dev/null to provide a valid FILE* handle without
     *                 creating actual file output, then call TIFFPrintDirectory.
     *                 This will also call codec-specific print handlers like
     *                 OJPEGPrintDir if that compression was selected.
     */
    if (fdp.ConsumeBool()) {
        FILE* dev_null = fopen("/dev/null", "w");
        if (dev_null) {
            TIFFPrintDirectory(tif, dev_null, 0);
            fclose(dev_null);
        }
    }

    /*
     * ANALYSIS: The function-level coverage report shows that TIFFSetClientInfo
     *           and TIFFGetClientInfo in tif_extension.c are completely
     *           uncovered (0%).
     * IMPLEMENTATION: Call TIFFSetClientInfo to associate some fuzzer-driven
     *                 data with the TIFF handle, and then immediately retrieve it
     *                 with TIFFGetClientInfo to cover both functions.
     */
    if (fdp.ConsumeBool()) {
        std::string client_name = fdp.ConsumeRandomLengthString(16);
        std::vector<uint8_t> client_data = fdp.ConsumeBytes<uint8_t>(fdp.ConsumeIntegralInRange<size_t>(1, 32));
        // The TIFF handle does not take ownership of the data, so it must
        // remain valid for as long as it's needed. Since we call GetClientInfo
        // immediately after, the vector's scope is sufficient.
        TIFFSetClientInfo(tif, client_data.data(), client_name.c_str());
        (void)TIFFGetClientInfo(tif, client_name.c_str());
    }

    // Close the TIFF file to flush all writes and release resources.
    TIFFClose(tif);

    /*
     * ANALYSIS: The function-level coverage report shows that the TIFFReadRGBAImage
     *           API and its related functions in tif_getimage.c are completely uncovered.
     * IMPLEMENTATION: After writing and closing the TIFF file, this block re-opens it
     *                 for reading. It then allocates a buffer and calls TIFFReadRGBAImage
     *                 to exercise the entire image reading and color space conversion pipeline.
     *                 The buffer is allocated with _TIFFmalloc and freed with _TIFFfree
     *                 to use the library's own memory management.
     */
    if (fdp.ConsumeBool()) {
        TIFF* read_tif = TIFFOpen(filename.c_str(), "r");
        if (read_tif) {
            do {
                uint32_t read_w, read_h;
                TIFFGetField(read_tif, TIFFTAG_IMAGEWIDTH, &read_w);
                TIFFGetField(read_tif, TIFFTAG_IMAGELENGTH, &read_h);

                // Check for potential huge allocation
                if (read_w > 0 && read_h > 0 && read_w < 4096 && read_h < 4096) {
                    if ((uint64_t)read_w * read_h * sizeof(uint32_t) < 100000000) {
                        uint32_t* raster = (uint32_t*) _TIFFmalloc(read_w * read_h * sizeof(uint32_t));
                        if (raster) {
                            TIFFReadRGBAImage(read_tif, read_w, read_h, raster, 0);
                            _TIFFfree(raster);
                        }
                    }
                }
            } while (TIFFReadDirectory(read_tif)); // Loop to read all directories
            TIFFClose(read_tif);
        }
    }


    // Clean up the temporary file.
    unlink(filename.c_str());

    return 0;
}