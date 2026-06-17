#include <stdint.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>

// Use angle-bracket includes and preserve subdirectory structure
#include <pcap/pcap.h>

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    // Return early for empty input to avoid unnecessary allocations and processing.
    if (size == 0) {
        return 0;
    }

    // Allocate memory for the filter string, including space for the null terminator.
    char *filter_str = (char *)malloc(size + 1);
    if (filter_str == NULL) {
        // Handle allocation failure gracefully.
        return 0;
    }

    // Copy the fuzzed data and null-terminate the string.
    memcpy(filter_str, data, size);
    filter_str[size] = '\0';

    pcap_t *pcap_handle_compile = NULL;
    struct bpf_program fp;
    char errbuf[PCAP_ERRBUF_SIZE]; // Required by pcap_create, pcap_open_live etc.

    // Create a dummy pcap_t for compilation. pcap_open_dead is suitable as it doesn't require a real device.
    // DLT_EN10MB (Ethernet) and a typical snaplen are used, consistent with common pcap usage.
    pcap_handle_compile = pcap_open_dead(DLT_EN10MB, 65535);
    if (pcap_handle_compile == NULL) {
        free(filter_str);
        return 0; // Handle allocation failure or internal pcap error
    }

    // Call pcap_compile with the fuzzed filter string.
    // The '1' for optimize and PCAP_NETMASK_UNKNOWN are standard parameters.
    if (pcap_compile(pcap_handle_compile, &fp, filter_str, 1, PCAP_NETMASK_UNKNOWN) == 0) {
        // If compilation is successful, free the compiled code.
        pcap_freecode(&fp);
    }

    // Clean up resources.
    pcap_close(pcap_handle_compile);
    free(filter_str);

    return 0;
}