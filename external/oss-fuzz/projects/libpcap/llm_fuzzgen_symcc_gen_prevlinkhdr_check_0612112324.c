#include <stdint.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>
#include <pcap-int.h>

int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size) {
    // A minimal filter string to trigger the 'geneve' branch is "geneve" (6 chars) + null terminator.
    // The hint suggests "udp port 6081 and ip proto geneve" which is longer.
    // We need at least enough size for a minimal filter string like "geneve" plus null terminator.
    if (Size < 7) {
        return 0;
    }

    // Create a "dead" pcap handle, as in the original fuzz target.
    // This allows calling pcap_compile without a live network interface.
    pcap_t *p = pcap_open_dead(DLT_EN10MB, 65535);
    if (p == NULL) {
        return 0;
    }

    // Allocate memory for the filter string and null-terminate it.
    // This preserves the original native input format.
    char *filter_str = (char *)malloc(Size + 1);
    if (filter_str == NULL) {
        pcap_close(p);
        return 0;
    }
    memcpy(filter_str, Data, Size);
    filter_str[Size] = '\0';

    struct bpf_program fcode;
    // Attempt to compile the filter string.
    // This call will internally lead to `gen_prevlinkhdr_check`.
    // The `optimize` flag is set to 1, consistent with the original fuzz target.
    // PCAP_NETMASK_UNKNOWN is used for the netmask.
    if (pcap_compile(p, &fcode, filter_str, 1, PCAP_NETMASK_UNKNOWN) == 0) {
        // If compilation was successful, free the compiled BPF program to prevent memory leaks.
        pcap_freecode(&fcode);
    }

    // Clean up allocated resources.
    free(filter_str);
    pcap_close(p);

    return 0;
}