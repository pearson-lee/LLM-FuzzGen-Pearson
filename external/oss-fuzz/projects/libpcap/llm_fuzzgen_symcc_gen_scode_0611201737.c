#include <stdint.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>

// Corrected angle-bracket include for libpcap header
#include <pcap/pcap.h>

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    // Minimum size for a filter string that can trigger the blocker.
    // An example filter like "link host 00:11:22:33:44:55" is 27 characters.
    // A smaller size might be valid for other filter expressions, but for the
    // specific blocker path, we need enough data for an Ethernet address.
    // Let's set a reasonable minimum to avoid trivial inputs.
    if (size < 10) { // "link host X" is at least 10 chars
        return 0;
    }

    pcap_t *p = NULL;
    struct bpf_program fcode;
    char *filter_string = NULL;
    int compile_result = -1;

    // 1. Create a dummy pcap_t handle with a specific link type.
    // This ensures that cstate->linktype inside pcap_compile's internal
    // compiler_state_t will be set to a value that matches the blocker's
    // switch case (e.g., DLT_EN10MB).
    // DLT_EN10MB (1) is a common Ethernet link type and is one of the cases
    // that leads to the blocker at gencode.c:6704.
    p = pcap_open_dead(DLT_EN10MB, 65535); // DLT_EN10MB, snaplen
    if (p == NULL) {
        // pcap_open_dead can fail due to memory allocation issues.
        return 0;
    }

    // 2. Prepare the filter string from fuzzer input.
    // The filter string needs to be null-terminated as expected by pcap_compile.
    filter_string = (char *)malloc(size + 1);
    if (filter_string == NULL) {
        pcap_close(p); // Clean up pcap_t handle
        return 0;
    }
    memcpy(filter_string, data, size);
    filter_string[size] = '\0';

    // 3. Call pcap_compile. This function will parse the filter_string,
    // and if the string contains an expression like "link host <ether_addr>",
    // it will eventually call gen_scode with proto == Q_LINK, leading to the blocker.
    compile_result = pcap_compile(p, &fcode, filter_string, 1, PCAP_NETMASK_UNKNOWN);

    // 4. Clean up resources.
    if (compile_result == 0) {
        // If compilation was successful, free the compiled BPF program.
        pcap_freecode(&fcode);
    }
    // Close the pcap_t handle, which also frees its internal resources.
    pcap_close(p);
    // Free the dynamically allocated filter string.
    free(filter_string);

    return 0;
}
