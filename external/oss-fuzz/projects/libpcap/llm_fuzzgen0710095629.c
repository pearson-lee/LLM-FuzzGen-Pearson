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

    /*
     * ANALYSIS: The function-level coverage report showed pcap_compile had a branch
     *           with zero hits. The line-level report confirmed this was at line 880,
     *           in the `if (!p->activated)` check.
     * IMPLEMENTATION: The following code block sometimes creates a pcap_t that is not
     *                 activated and passes it to pcap_compile to specifically
     *                 exercise this uncovered error-handling path.
     */
    if (data[0] % 2 == 0) {
        p = pcap_open_dead(DLT_EN10MB, 65535);
        if (p != NULL) {
            if (pcap_compile(p, &prog, filter_string, 0, PCAP_NETMASK_UNKNOWN) == 0) {
                pcap_freecode(&prog);
            }
            pcap_close(p);
        }
    }

    /*
     * ANALYSIS: The function-level coverage report showed gen_wlanhostop and
     *           gen_atmtype_abbrev had very low branch coverage. The line-level
     *           reports confirmed that only one case in the switch statements
     *           was being exercised.
     * IMPLEMENTATION: The following code calls pcap_compile with a variety of
     *                 filter strings designed to exercise the different cases
     *                 in the switch statements in gen_wlanhostop and
     *                 gen_atmtype_abbrev.
     */
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