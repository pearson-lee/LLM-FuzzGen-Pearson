#include <fuzzer/FuzzedDataProvider.h>
#include "tiffio.h"
#include "zlib.h"
#include <vector>
#include <string>

// TIFF client data structure for in-memory fuzzing
struct TiffClientData {
    const uint8_t* data;
    tmsize_t size;
    tmsize_t offset;
};

// TIFF read function for in-memory fuzzing
static tmsize_t read_proc(thandle_t handle, void* buf, tmsize_t size) {
    TiffClientData* client_data = reinterpret_cast<TiffClientData*>(handle);
    tmsize_t to_read = size;
    if (client_data->offset + size > client_data->size) {
        to_read = client_data->size - client_data->offset;
    }
    if (to_read > 0) {
        memcpy(buf, client_data->data + client_data->offset, to_read);
        client_data->offset += to_read;
    }
    return to_read;
}

// TIFF write function for in-memory fuzzing (not used in this fuzzer)
static tmsize_t write_proc(thandle_t, void*, tmsize_t) {
    return 0;
}

// TIFF seek function for in-memory fuzzing
static toff_t seek_proc(thandle_t handle, toff_t offset, int whence) {
    TiffClientData* client_data = reinterpret_cast<TiffClientData*>(handle);
    toff_t new_offset = client_data->offset;
    if (whence == SEEK_SET) {
        new_offset = offset;
    } else if (whence == SEEK_CUR) {
        new_offset += offset;
    } else if (whence == SEEK_END) {
        new_offset = client_data->size + offset;
    }

    if (new_offset < 0) {
        client_data->offset = 0;
    } else if (new_offset > client_data->size) {
        client_data->offset = client_data->size;
    } else {
        client_data->offset = new_offset;
    }
    return client_data->offset;
}

// TIFF close function for in-memory fuzzing
static int close_proc(thandle_t) {
    return 0;
}

// TIFF size function for in-memory fuzzing
static toff_t size_proc(thandle_t handle) {
    TiffClientData* client_data = reinterpret_cast<TiffClientData*>(handle);
    return client_data->size;
}

// The main fuzzing function
extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
    FuzzedDataProvider provider(data, size);

    // Prepare the in-memory TIFF file
    TiffClientData client_data;
    client_data.data = data;
    client_data.size = size;
    client_data.offset = 0;

    // Open the TIFF file from memory
    TIFF* tif = TIFFClientOpen("fuzz", "r", reinterpret_cast<thandle_t>(&client_data), read_proc, write_proc, seek_proc, close_proc, size_proc, nullptr, nullptr);
    if (!tif) {
        return 0;
    }

    // Loop through all directories in the TIFF file
    do {
        // Exercise TIFFVTileSize
        uint32_t tile_rows = provider.ConsumeIntegralInRange<uint32_t>(0, 1000);
        (void)TIFFVTileSize(tif, tile_rows);

        // Exercise TIFFRawStripSize
        uint32_t strip_index = provider.ConsumeIntegralInRange<uint32_t>(0, TIFFNumberOfStrips(tif));
        (void)TIFFRawStripSize(tif, strip_index);

    } while (TIFFReadDirectory(tif));

    // Exercise deflateParams from zlib
    z_stream strm;
    strm.zalloc = Z_NULL;
    strm.zfree = Z_NULL;
    strm.opaque = Z_NULL;
    if (deflateInit(&strm, Z_DEFAULT_COMPRESSION) == Z_OK) {
        int level = provider.ConsumeIntegralInRange<int>(-1, 9);
        int strategy = provider.ConsumeIntegralInRange<int>(0, 4);
        deflateParams(&strm, level, strategy);
        deflateEnd(&strm);
    }

    // Clean up and close the TIFF file
    if (tif) {
        TIFFClose(tif);
    }

    return 0;
}