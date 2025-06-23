#include <cstddef>
#include <cstdint>
#include <vector>
#include <string>
#include <fuzzer/FuzzedDataProvider.h>
#include "tiffio.h"
#include "/src/libtiff/libtiff/tiffiop.h"
#include "/src/libtiff/libtiff/tif_dir.h"

// Define a custom client data structure to hold the fuzzed data.
struct TiffClientData {
    FuzzedDataProvider* fdp;
    std::vector<uint8_t> data;
    tmsize_t offset;
};

// Custom read function for libtiff.
tmsize_t read_proc(thandle_t handle, void* buffer, tmsize_t size) {
    TiffClientData* client_data = reinterpret_cast<TiffClientData*>(handle);
    if (client_data->offset + size > client_data->data.size()) {
        size = client_data->data.size() - client_data->offset;
    }
    if (size > 0) {
        memcpy(buffer, client_data->data.data() + client_data->offset, size);
        client_data->offset += size;
    }
    return size;
}

// Custom write function for libtiff.
tmsize_t write_proc(thandle_t handle, void* buffer, tmsize_t size) {
    TiffClientData* client_data = reinterpret_cast<TiffClientData*>(handle);
    client_data->data.insert(client_data->data.end(),
                             reinterpret_cast<uint8_t*>(buffer),
                             reinterpret_cast<uint8_t*>(buffer) + size);
    client_data->offset += size;
    return size;
}

// Custom seek function for libtiff.
toff_t seek_proc(thandle_t handle, toff_t offset, int whence) {
    TiffClientData* client_data = reinterpret_cast<TiffClientData*>(handle);
    toff_t new_offset = client_data->offset;
    if (whence == SEEK_SET) {
        new_offset = offset;
    } else if (whence == SEEK_CUR) {
        new_offset += offset;
    } else if (whence == SEEK_END) {
        new_offset = client_data->data.size() + offset;
    }
    if (new_offset > client_data->data.size()) {
        return -1;
    }
    client_data->offset = new_offset;
    return new_offset;
}

// Custom close function for libtiff.
int close_proc(thandle_t) {
    return 0;
}

// Custom size function for libtiff.
toff_t size_proc(thandle_t handle) {
    TiffClientData* client_data = reinterpret_cast<TiffClientData*>(handle);
    return client_data->data.size();
}

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
    FuzzedDataProvider fdp(data, size);

    TiffClientData client_data;
    client_data.fdp = &fdp;
    client_data.offset = 0;

    // Create a TIFF file in memory for writing.
    TIFF* tiff_write = TIFFClientOpen("in-memory-write", "w",
                                      reinterpret_cast<thandle_t>(&client_data),
                                      read_proc, write_proc, seek_proc,
                                      close_proc, size_proc, nullptr, nullptr);
    if (!tiff_write) {
        return 0;
    }

    // Write some basic tags to the TIFF file.
    TIFFSetField(tiff_write, TIFFTAG_IMAGEWIDTH, fdp.ConsumeIntegralInRange<uint32_t>(1, 1024));
    TIFFSetField(tiff_write, TIFFTAG_IMAGELENGTH, fdp.ConsumeIntegralInRange<uint32_t>(1, 1024));
    TIFFSetField(tiff_write, TIFFTAG_BITSPERSAMPLE, 8);
    TIFFSetField(tiff_write, TIFFTAG_SAMPLESPERPIXEL, 1);
    TIFFSetField(tiff_write, TIFFTAG_PLANARCONFIG, PLANARCONFIG_CONTIG);
    TIFFSetField(tiff_write, TIFFTAG_COMPRESSION, COMPRESSION_NONE);
    TIFFSetField(tiff_write, TIFFTAG_PHOTOMETRIC, PHOTOMETRIC_MINISBLACK);

    // Write a custom directory.
    uint64_t dir_offset = 0;
    TIFFWriteCustomDirectory(tiff_write, &dir_offset);
    TIFFCheckpointDirectory(tiff_write);

    // Create an EXIF directory
    TIFFCreateEXIFDirectory(tiff_write);
    uint64_t exif_dir_offset = 0;
    TIFFWriteCustomDirectory(tiff_write, &exif_dir_offset);
    TIFFCheckpointDirectory(tiff_write);

    // Create a GPS directory
    TIFFCreateGPSDirectory(tiff_write);
    uint64_t gps_dir_offset = 0;
    TIFFWriteCustomDirectory(tiff_write, &gps_dir_offset);
    TIFFCheckpointDirectory(tiff_write);

    TIFFClose(tiff_write);

    // Now, open the in-memory TIFF for reading.
    client_data.offset = 0; // Reset offset for reading
    TIFF* tiff_read = TIFFClientOpen("in-memory-read", "r",
                                     reinterpret_cast<thandle_t>(&client_data),
                                     read_proc, write_proc, seek_proc,
                                     close_proc, size_proc, nullptr, nullptr);
    if (!tiff_read) {
        return 0;
    }

    // Try to read the custom directory.
    if (dir_offset > 0) {
        TIFFSetSubDirectory(tiff_read, dir_offset);
    }

    // Try to read the EXIF directory.
    if (exif_dir_offset > 0) {
        TIFFReadEXIFDirectory(tiff_read, exif_dir_offset);
    }

    // Try to read the GPS directory.
    if (gps_dir_offset > 0) {
        TIFFReadGPSDirectory(tiff_read, gps_dir_offset);
    }

    // Fuzz TIFFReadCustomDirectory with a fuzzed TIFFFieldArray
    if (dir_offset > 0 && fdp.ConsumeBool()) {
        const size_t field_count = fdp.ConsumeIntegralInRange<size_t>(1, 10);
        std::vector<TIFFField> fields(field_count);
        std::vector<std::string> field_names(field_count);
        for (size_t i = 0; i < field_count; ++i) {
            field_names[i] = fdp.ConsumeRandomLengthString(10);
            fields[i].field_tag = fdp.ConsumeIntegral<uint32_t>();
            fields[i].field_readcount = fdp.ConsumeIntegral<int>();
            fields[i].field_writecount = fdp.ConsumeIntegral<int>();
            fields[i].field_type = static_cast<TIFFDataType>(fdp.ConsumeIntegralInRange<int>(0, TIFF_IFD8));
            fields[i].field_bit = fdp.ConsumeIntegralInRange<int>(0, FIELD_LAST);
            fields[i].field_oktochange = fdp.ConsumeBool();
            fields[i].field_passcount = fdp.ConsumeBool();
            fields[i].field_name = const_cast<char*>(field_names[i].c_str());
        }
        TIFFFieldArray fuzzed_fields;
        fuzzed_fields.fields = fields.data();
        fuzzed_fields.count = field_count;
        TIFFReadCustomDirectory(tiff_read, dir_offset, &fuzzed_fields);
    }

    TIFFClose(tiff_read);

    return 0;
}