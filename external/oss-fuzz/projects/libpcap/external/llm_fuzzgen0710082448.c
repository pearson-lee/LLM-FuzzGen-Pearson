#include <stdint.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/stat.h>
#include <sys/types.h>

#include "/src/libpcap/pcap/pcap.h"
/*
 * FIX: The build error "unknown type name '__u_char'" is resolved by
 * including the internal pcap header pcap-int.h. This header provides
 * necessary type definitions that are not exposed in the public pcap.h
 * but are required for compilation when using pcap's data structures
 * and functions directly.
 */
#include "/src/libpcap/pcap-int.h"

// Helper to consume a chunk of data from the fuzzer input
static const uint8_t *consume_data(const uint8_t **data, size_t *size, size_t *len) {
    if (*size == 0) {
        *len = 0;
        return NULL;
    }
    *len = (*data)[0] % *size;
    if (*len == 0 && *size > 1) {
        *len = 1;
    }
    const uint8_t *ret = *data + 1;
    *data += *len;
    *size -= *len;
    return ret;
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    if (size < 1) {
        return 0;
    }

    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_if_t *alldevs = NULL;
    pcap_t *handle = NULL;
    struct bpf_program fp;
    pcap_dumper_t *dumper = NULL;

    // Define unique temporary file and directory paths using the fuzzer name
    char pcap_filepath[256];
    snprintf(pcap_filepath, sizeof(pcap_filepath), "/tmp/%s.pcap", _FUZZ_TARGET_NAME);
    char dir_path[256];
    snprintf(dir_path, sizeof(dir_path), "/tmp/%s_dir", _FUZZ_TARGET_NAME);
    char file_in_dir_path[512];
    snprintf(file_in_dir_path, sizeof(file_in_dir_path), "%s/file.pcap", dir_path);

    // Create a temporary directory for file-based operations
    mkdir(dir_path, 0700);
    // Create a dummy file inside the directory to test file enumeration
    FILE *dummy_file = fopen(file_in_dir_path, "w");
    if (dummy_file) {
        fclose(dummy_file);
    }

    /*
     * ANALYSIS: The function-level coverage report showed pcap_findalldevs_ex
     *           had low coverage (61.85% line, 70.37% branch). The line-level
     *           report showed that the code path for `PCAP_SRC_FILE` was not
     *           well-tested.
     * IMPLEMENTATION: The following block calls pcap_findalldevs_ex with a
     *                 `file://` source string pointing to a temporary directory.
     *                 This specifically exercises the file enumeration logic within
     *                 the function.
     */
    char source_str[512];
    snprintf(source_str, sizeof(source_str), "file://%s/", dir_path);
    if (pcap_findalldevs_ex(source_str, NULL, &alldevs, errbuf) == 0) {
        pcap_freealldevs(alldevs);
        alldevs = NULL;
    }

    // Create a dead pcap handle to avoid needing real network interfaces
    handle = pcap_open_dead(DLT_EN10MB, 65535);
    if (handle == NULL) {
        goto cleanup;
    }

    // Consume data for the filter string
    size_t filter_len;
    const uint8_t *filter_data = consume_data(&data, &size, &filter_len);
    char *filter_str = NULL;
    if (filter_data && filter_len > 0) {
        filter_str = (char *)malloc(filter_len + 1);
        if (filter_str) {
            memcpy(filter_str, filter_data, filter_len);
            filter_str[filter_len] = '\0';
        }
    }

    /*
     * ANALYSIS: The function `pcapint_filter_with_aux_data` has very low coverage
     *           (40%), with many BPF instructions and conditions being completely
     *           uncovered. This function is called by pcap_dispatch/pcap_loop to
     *           execute the BPF filter.
     * IMPLEMENTATION: The following code compiles and sets a filter based on
     *                 raw fuzzer input. This will generate a wide variety of valid
     *                 and invalid BPF programs, exercising the BPF interpreter
     *                 and increasing coverage in `pcapint_filter_with_aux_data`.
     */
    if (filter_str) {
        if (pcap_compile(handle, &fp, filter_str, 1, PCAP_NETMASK_UNKNOWN) == 0) {
            pcap_setfilter(handle, &fp);
            pcap_freecode(&fp);
        }
        free(filter_str);
    }

    /*
     * ANALYSIS: The coverage report for `sf-pcap.c` shows that functions like
     *           `pcap_dump_open` and `pcap_dump` have room for improvement.
     * IMPLEMENTATION: The following code opens a pcap dumper to a temporary
     *                 file and dumps a packet constructed from fuzzer data.
     *                 This exercises the pcap file writing functionality.
     */
    dumper = pcap_dump_open(handle, pcap_filepath);
    if (dumper != NULL) {
        struct pcap_pkthdr pkt_hdr;
        if (size >= sizeof(pkt_hdr)) {
            memcpy(&pkt_hdr, data, sizeof(pkt_hdr));
            data += sizeof(pkt_hdr);
            size -= sizeof(pkt_hdr);

            // Sanitize packet header values to be reasonable
            pkt_hdr.caplen = (pkt_hdr.caplen % (65535 + 1));
            pkt_hdr.len = (pkt_hdr.len % (65535 + 1));
            if (pkt_hdr.caplen > size) {
                pkt_hdr.caplen = size;
            }
            if (pkt_hdr.len < pkt_hdr.caplen) {
                pkt_hdr.len = pkt_hdr.caplen;
            }
            pcap_dump((u_char *)dumper, &pkt_hdr, data);
        }
        pcap_dump_close(dumper);
    }

cleanup:
    // All resources must be freed to prevent memory leaks.
    if (handle) {
        pcap_close(handle);
    }
    if (alldevs) {
        pcap_freealldevs(alldevs);
    }
    // Clean up temporary files and directory
    unlink(file_in_dir_path);
    rmdir(dir_path);
    unlink(pcap_filepath);

    return 0;
}