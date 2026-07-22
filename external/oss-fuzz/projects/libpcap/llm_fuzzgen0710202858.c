#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include "/src/libpcap/pcap/pcap.h"

// The pcap_compile() function and its subcomponents (like the gen_* functions)
// are the primary targets for this fuzzer.

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    if (size < 3) {
        return 0;
    }

    /*
     * ANALYSIS: The function-level coverage report showed that many functions
     *           within gencode.c have very low coverage, including gen_wlanhostop (8.81%),
     *           gen_atmtype_abbrev (15.38%), gen_host6 (17.02%), gen_inbound_outbound (37.68%),
     *           and gen_multicast (42.17%). A detailed line-level analysis using
     *           get_line_coverage_report revealed that most of the uncovered branches
     *           in these functions are dependent on the link-layer type of the pcap
     *           handle and the specific filter string provided. For example, gen_atmtype_abbrev
     *           requires an ATM linktype (e.g., DLT_ATM_RFC1483) to be active, and
     *           gen_wlanhostop requires specific "wlan" keywords in the filter.
     *
     * IMPLEMENTATION: This fuzzer targets pcap_compile() to exercise the filter
     *                 generation engine.
     *                 1. The first byte of the fuzzing data is used to select a link-layer
     *                    type for pcap_open_dead(). This allows the fuzzer to explore
     *                    code paths specific to dozens of different link types.
     *                 2. The second byte determines if the BPF optimizer is enabled,
     *                    targeting optimizer-specific code paths.
     *                 3. The remainder of the data is used as the filter string itself.
     *                    This allows the fuzzer's mutation engine to discover the complex
     *                    filter syntax and trigger the various logic paths in the targeted
     *                    gen_* functions.
     */

    // Use the first byte of the input data to select a link-layer type.
    // This is crucial for exploring linktype-dependent code paths.
    int linktype = data[0];

    // Use the second byte to toggle the BPF optimizer.
    int optimize = data[1] % 2;

    // The rest of the data is treated as the filter expression.
    // We copy it to a new buffer to ensure it's a null-terminated C-string.
    char *filter_string = (char *)malloc(size - 1);
    if (filter_string == NULL) {
        return 0;
    }
    memcpy(filter_string, data + 2, size - 2);
    filter_string[size - 2] = '\0';

    // Create a dead pcap handle with the selected linktype.
    // Using pcap_open_dead is ideal for fuzzing the compiler because it
    // avoids any platform-specific, privileged, or stateful operations.
    pcap_t *p = pcap_open_dead(linktype, 65535 /* snaplen */);
    if (p == NULL) {
        free(filter_string);
        return 0;
    }

    struct bpf_program fcode;
    // Call pcap_compile to trigger the filter generation logic.
    // This is the main entry point for the functions we want to cover.
    if (pcap_compile(p, &fcode, filter_string, optimize, PCAP_NETMASK_UNKNOWN) == 0) {
        // If compilation is successful, free the allocated resources.
        pcap_freecode(&fcode);
    }

    // Clean up all resources.
    pcap_close(p);
    free(filter_string);

    return 0;
}