#include <stdint.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>

// Include libpcap internal headers to get access to necessary structs and functions.
// The original fuzz target uses "/src/libpcap/pcap-int.h".
// Following the rule: strip "/src/libpcap/", keep the rest as-is, and use angle brackets.
#include <pcap-int.h>

// The main fuzzing entry point
int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size) {
    // We need at least 1 byte for the null terminator.
    if (Size < 1) {
        return 0;
    }

    // Create a "dead" pcap handle. This is essential for fuzzing because it
    // allows us to call pcap_compile and other functions without needing a
    // live network interface.
    pcap_t *p = pcap_open_dead(DLT_EN10MB, 65535);
    if (p == NULL) {
        // This should not happen with pcap_open_dead, but check just in case
        return 0;
    }

    // Allocate memory for the filter string and null-terminate it.
    // This is the input to pcap_compile.
    char *filter_str = (char *)malloc(Size + 1);
    if (filter_str == NULL) {
        pcap_close(p);
        return 0;
    }
    memcpy(filter_str, Data, Size);
    filter_str[Size] = '\0';

    struct bpf_program fcode;
    // Initialize fcode.bf_insns to NULL to safely check if it was populated later.
    fcode.bf_insns = NULL;

    // Attempt to compile the filter string.
    // The 'optimize' flag is set to 1, which will trigger the bpf_optimize call
    // and subsequently the number_blks_r function where the blocker resides.
    // PCAP_NETMASK_UNKNOWN is used as in the original fuzzer.
    pcap_compile(p, &fcode, filter_str, 1, PCAP_NETMASK_UNKNOWN);

    // Clean up the allocated string and the pcap handle.
    // pcap_freecode needs to be called only if pcap_compile was successful
    // and allocated instructions (fcode.bf_insns is not NULL).
    if (fcode.bf_insns != NULL) {
        pcap_freecode(&fcode);
    }
    free(filter_str);
    pcap_close(p);

    return 0;
}
