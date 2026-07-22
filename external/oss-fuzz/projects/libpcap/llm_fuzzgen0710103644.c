#include <stdint.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include "pcap/pcap.h"

#ifndef _FUZZ_TARGET_NAME
#define _FUZZ_TARGET_NAME "llm_fuzzgen0710101422"
#endif

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    if (size < 1) {
        return 0;
    }

    char *filter_string = (char *)malloc(size);
    if (filter_string == NULL) {
        return 0;
    }
    memcpy(filter_string, data, size - 1);
    filter_string[size - 1] = '\0';

    pcap_t *p;
    struct bpf_program prog;
    char errbuf[PCAP_ERRBUF_SIZE];

    /*
     * ANALYSIS: The function-level coverage report showed pcap_findalldevs and
     *           pcap_freealldevs had low coverage.
     * IMPLEMENTATION: The following code block calls pcap_findalldevs to get a
     *                 list of devices and pcap_freealldevs to free the list,
     *                 improving coverage in these functions.
     */
    pcap_if_t *alldevs;
    if (pcap_findalldevs(&alldevs, errbuf) == 0) {
        pcap_freealldevs(alldevs);
    }

    /*
     * ANALYSIS: The function-level coverage report showed pcap_list_tstamp_types
     *           had low coverage.
     * IMPLEMENTATION: The following code block calls pcap_list_tstamp_types to
     *                 get the list of supported timestamp types and then frees
     *                 it, improving coverage.
     */
    p = pcap_open_dead(DLT_EN10MB, 65535);
    if (p != NULL) {
        int *tstamp_types;
        int n = pcap_list_tstamp_types(p, &tstamp_types);
        if (n >= 0) {
            if (n > 0) {
                pcap_free_tstamp_types(tstamp_types);
            }
        }
        pcap_close(p);
    }

    /*
     * ANALYSIS: The function-level coverage report showed several pcap_set_*
     *           functions had missed branches, likely related to being called on
     *           a non-activated pcap_t handle.
     * IMPLEMENTATION: The following code block calls these functions on a
     *                 non-activated handle to exercise these error paths.
     */
    if (data[0] % 2 == 0) {
        p = pcap_open_dead(DLT_EN10MB, 65535);
        if (p != NULL) {
            pcap_set_snaplen(p, 200);
            pcap_set_promisc(p, 1);
            pcap_set_timeout(p, 500);
            pcap_set_tstamp_type(p, PCAP_TSTAMP_HOST);
            pcap_set_immediate_mode(p, 1);
            pcap_set_buffer_size(p, 2 * 1024 * 1024);
            pcap_set_tstamp_precision(p, PCAP_TSTAMP_PRECISION_NANO);
            if (pcap_compile(p, &prog, filter_string, 0, PCAP_NETMASK_UNKNOWN) == 0) {
                pcap_freecode(&prog);
            }
            pcap_close(p);
        }
    }

    /*
     * ANALYSIS: The function-level coverage report showed pcap_dump_open_append
     *           had 0% coverage. This function is used to append to an existing
     *           pcap file.
     * IMPLEMENTATION: The following code creates a temporary pcap file, writes a
     *                 packet to it, and then re-opens it in append mode to write
     *                 another packet. This exercises pcap_dump_open, pcap_dump,
     *                 and pcap_dump_open_append.
     */
    char path[256];
    snprintf(path, sizeof(path), "/tmp/%s.pcap", _FUZZ_TARGET_NAME);
    p = pcap_open_dead(DLT_EN10MB, 65535);
    if (p != NULL) {
        pcap_dumper_t *dumper = pcap_dump_open(p, path);
        if (dumper != NULL) {
            struct pcap_pkthdr hdr;
            hdr.caplen = size;
            hdr.len = size;
            pcap_dump((u_char *)dumper, &hdr, data);
            pcap_dump_close(dumper);

            dumper = pcap_dump_open_append(p, path);
            if (dumper != NULL) {
                pcap_dump((u_char *)dumper, &hdr, data);
                pcap_dump_close(dumper);
            }
        }
        pcap_close(p);
        unlink(path);
    }


    const char *filters[] = {
        "wlan src host 11:22:33:44:55:66",
        "wlan dst host 11:22:33:44:55:66",
        "wlan addr1 11:22:33:44:55:66",
        "wlan addr2 11:22:33:44:55:66",
        "wlan addr3 11:22:33:44:55:66",
        "wlan addr4 11:22:33:44:55:66",
        "wlan ra 11:22:33:44:55:66",
        "wlan ta 11:22:33:44:55:66",
        filter_string
    };
    int num_filters = sizeof(filters) / sizeof(filters[0]);

    for (int i = 0; i < num_filters; i++) {
        p = pcap_open_dead(DLT_EN10MB, 65535);
        if (p == NULL) {
            continue;
        }
        if (pcap_compile(p, &prog, filters[i], 0, PCAP_NETMASK_UNKNOWN) == 0) {
            pcap_freecode(&prog);
        }
        pcap_close(p);
    }

    /*
     * ANALYSIS: The function-level coverage report showed gen_atmtype_abbrev
     *           had very low coverage. This is because the filter compiler
     *           only parses ATM-specific keywords when the link-layer type is
     *           set to an ATM type. The fuzzer was using DLT_EN10MB.
     * IMPLEMENTATION: This loop compiles ATM-specific filters with the
     *                 DLT_ATM_RFC1483 link-layer type to improve coverage in
     *                 ATM-related filter parsing code.
     */
    const char *atm_filters[] = {
        "atm metac",
        "atm bcc",
        "atm oam4sc",
        "atm oam4ec",
        "atm sc",
        "atm ilmic",
        "atm lane",
        "atm llc",
    };
    int num_atm_filters = sizeof(atm_filters) / sizeof(atm_filters[0]);
    for (int i = 0; i < num_atm_filters; i++) {
        p = pcap_open_dead(DLT_ATM_RFC1483, 65535);
        if (p == NULL) {
            continue;
        }
        if (pcap_compile(p, &prog, atm_filters[i], 0, PCAP_NETMASK_UNKNOWN) == 0) {
            pcap_freecode(&prog);
        }
        pcap_close(p);
    }


    free(filter_string);
    return 0;
}