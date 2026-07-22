#include <stdint.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>
#include "pcap/pcap.h"

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

    const char *filters[] = {
        "wlan src host 11:22:33:44:55:66",
        "wlan dst host 11:22:33:44:55:66",
        "wlan addr1 11:22:33:44:55:66",
        "wlan addr2 11:22:33:44:55:66",
        "wlan addr3 11:22:33:44:55:66",
        "wlan addr4 11:22:33:44:55:66",
        "wlan ra 11:22:33:44:55:66",
        "wlan ta 11:22:33:44:55:66",
        "atm metac",
        "atm bcc",
        "atm oam4sc",
        "atm oam4ec",
        "atm sc",
        "atm ilmic",
        "atm lane",
        "atm llc",
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

    free(filter_string);
    return 0;
}