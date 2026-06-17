#include <stdint.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>

// Internal libpcap header that includes other necessary internal headers
// like gencode.h and optimize.h, as well as public headers like pcap/pcap.h and pcap/bpf.h.
// This ensures all required definitions for the BPF instruction structures and macros are available.
#include <pcap-int.h>

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    // We need at least some data for a filter string.
    if (size == 0) {
        return 0;
    }

    // Create a null-terminated string from the input data.
    // This mimics how filter strings are typically handled by libpcap.
    char *filter_str = (char *)malloc(size + 1);
    if (filter_str == NULL) {
        return 0;
    }
    memcpy(filter_str, data, size);
    filter_str[size] = '\0';

    // Create a "dead" pcap handle. This is a common practice in fuzzing
    // to test pcap_compile without needing a live network interface.
    pcap_t *p = pcap_open_dead(DLT_EN10MB, 65535);
    if (p == NULL) {
        free(filter_str);
        return 0;
    }

    struct bpf_program fcode;
    // Attempt to compile the filter string. The 'optimize' flag is set to 1
    // to ensure the BPF optimization path, which contains the blocker, is exercised.
    // PCAP_NETMASK_UNKNOWN is a standard value for the netmask when it's not relevant.
    if (pcap_compile(p, &fcode, filter_str, 1, PCAP_NETMASK_UNKNOWN) == 0) {
        // If compilation was successful, free the allocated BPF program.
        pcap_freecode(&fcode);
    }

    // Clean up allocated resources.
    free(filter_str);
    pcap_close(p);

    return 0;
}