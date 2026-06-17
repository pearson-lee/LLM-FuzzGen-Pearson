#include <stdint.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h> // For PCAP_ERRBUF_SIZE and potential snprintf in pcap_t error handling

// libpcap headers
#include <pcap/pcap.h> // Main libpcap header

// The blocker is in newchunk, which is called during pcap_compile.
// The original fuzzer calls pcap_compile with a filter string.
// This harness focuses on providing a filter string to pcap_compile
// to trigger the memory allocation exhaustion.

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    // A minimum size is required for a meaningful filter string.
    // If size is 0, there's no filter string to compile.
    if (size == 0) {
        return 0;
    }

    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t *p = NULL;
    struct bpf_program program;
    char *filter_string = NULL;

    // 1. Create a pcap_t handle.
    // Using pcap_open_dead to create an activated handle without needing a real device or file.
    // DLT_EN10MB (Ethernet) is a common and safe default link type.
    // 65535 is a typical maximum snapshot length.
    p = pcap_open_dead(DLT_EN10MB, 65535);
    if (!p) {
        // If pcap_open_dead fails, it's likely due to memory exhaustion,
        // which is a valid fuzzer outcome but not the target blocker.
        return 0;
    }

    // 2. Prepare the filter string from fuzzer input.
    // The entire input data is treated as the BPF filter expression.
    // It must be null-terminated for pcap_compile.
    filter_string = (char *)malloc(size + 1);
    if (!filter_string) {
        pcap_close(p); // Clean up the pcap_t handle.
        return 0; // Allocation failure for filter string.
    }
    memcpy(filter_string, data, size);
    filter_string[size] = '\0'; // Null-terminate the string.

    // 3. Call pcap_compile.
    // This is the public API function that leads to the 'newchunk' blocker.
    // 'optimize=1' and 'PCAP_NETMASK_UNKNOWN' are used, consistent with the original fuzzer's approach.
    if (pcap_compile(p, &program, filter_string, 1, PCAP_NETMASK_UNKNOWN) == 0) {
        // If compilation succeeds, the BPF program is generated.
        // It must be freed to prevent memory leaks.
        pcap_freecode(&program);
    }
    // Note: pcap_compile can return non-zero on error, which is expected for invalid filter strings.
    // We don't need to handle the error specifically here, as the goal is to reach the blocker.

    // 4. Clean up resources.
    free(filter_string); // Free the allocated filter string.
    pcap_close(p);       // Close the pcap_t handle, which also frees its associated resources.

    return 0; // Indicate successful execution of the fuzzer.
}