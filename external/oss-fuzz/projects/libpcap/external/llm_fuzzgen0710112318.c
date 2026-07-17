#include <pcap/pcap.h>
#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

#define _FUZZ_TARGET_NAME "fuzz_pcap_findalldevs"

// Helper function to create a temporary file with the given content
static char* create_temp_file(const uint8_t* data, size_t size) {
    char* path = (char*)malloc(256);
    if (!path) {
        return NULL;
    }
    snprintf(path, 256, "/tmp/%s.pcap", _FUZZ_TARGET_NAME);

    FILE* fp = fopen(path, "wb");
    if (!fp) {
        free(path);
        return NULL;
    }
    fwrite(data, 1, size, fp);
    fclose(fp);
    return path;
}

int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
    pcap_if_t* alldevs;
    char errbuf[PCAP_ERRBUF_SIZE];
    char* source = NULL;
    char* temp_file_path = NULL;

    if (size < 1) {
        return 0;
    }

    // One byte to decide the source type
    uint8_t source_type = data[0];
    data++;
    size--;

    if (source_type % 3 == 0) {
        // Use a fuzzer-generated string as the source
        size_t source_len = size > 255 ? 255 : size;
        source = (char*)malloc(source_len + 1);
        if (!source) {
            return 0;
        }
        memcpy(source, data, source_len);
        source[source_len] = '\0';

        // Reject sources that look like file paths, as we can't clean them up
        // and they can cause crashes if malformed (e.g. "file://").
        if (strncmp(source, "file://", 7) == 0) {
            free(source);
            return 0;
        }
    } else if (source_type % 3 == 1) {
        // Use a file source
        temp_file_path = create_temp_file(data, size);
        if (temp_file_path) {
            // +8 for "file://" and null terminator.
            source = (char*)malloc(strlen(temp_file_path) + 8);
            if (source) {
                snprintf(source, strlen(temp_file_path) + 8, "file://%s", temp_file_path);
            }
        }
    } else {
        // Use a local interface source
        source = strdup("rpcap://");
    }

    if (!source) {
        if (temp_file_path) {
            unlink(temp_file_path);
            free(temp_file_path);
        }
        return 0;
    }

    if (pcap_findalldevs_ex(source, NULL, &alldevs, errbuf) == 0 && alldevs) {
        pcap_if_t* dev;
        for (dev = alldevs; dev != NULL; dev = dev->next) {
            pcap_t* handle = pcap_open_dead_with_tstamp_precision(DLT_NULL, 65535, PCAP_TSTAMP_PRECISION_MICRO);
            if (handle) {
                struct bpf_program fp;
                if (size > 1) {
                    char* filter = (char*)malloc(size);
                    if (filter) {
                        memcpy(filter, data, size - 1);
                        filter[size - 1] = '\0';
                        if (pcap_compile(handle, &fp, filter, 1, PCAP_NETMASK_UNKNOWN) == 0) {
                            pcap_freecode(&fp);
                        }
                        free(filter);
                    }
                }
                pcap_close(handle);
            }
        }
        pcap_freealldevs(alldevs);
    }

    free(source);
    if (temp_file_path) {
        unlink(temp_file_path);
        free(temp_file_path);
    }

    return 0;
}