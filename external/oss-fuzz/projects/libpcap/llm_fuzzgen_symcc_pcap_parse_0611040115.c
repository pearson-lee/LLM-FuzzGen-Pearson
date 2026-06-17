#include <stdint.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>

// Include the main libpcap header using its project-relative path.
// This provides definitions for pcap_t, pcap_compile, pcap_open_dead, etc.
#include <pcap/pcap.h>

// The entry point for the fuzzer.
// This harness targets the pcap_parse function, which is internally called by pcap_compile.
// The fuzzer input `data` is treated as the filter expression string.
int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
    // We need at least 1 byte for a null terminator if size is 0, or size + 1 otherwise.
    // If size is 0, we'll just have a null terminator.
    char* filter_string = (char*)malloc(size + 1);
    if (!filter_string) {
        return 0; // Allocation failure
    }

    // Copy the fuzzer input data and null-terminate it.
    memcpy(filter_string, data, size);
    filter_string[size] = '\0';

    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t *p = NULL;
    struct bpf_program fcode;

    // Create a "dead" pcap handle. This is a valid pcap_t object that doesn't
    // actually capture from a device or read from a file. It's suitable for
    // functions like pcap_compile that only need the handle for context.
    // DLT_EN10MB (Ethernet) and 65535 (maximum snapshot length) are common defaults.
    p = pcap_open_dead(DLT_EN10MB, 65535);
    if (!p) {
        free(filter_string);
        return 0; // Failed to create dead pcap handle
    }

    // Call pcap_compile. This function internally calls pcap_parse with the
    // provided filter string. The 'optimize' flag is set to 1, and
    // PCAP_NETMASK_UNKNOWN is used, mirroring the original fuzzer's usage.
    int result = pcap_compile(p, &fcode, filter_string, 1, PCAP_NETMASK_UNKNOWN);

    // Cleanup resources.
    // If pcap_compile succeeded (result == 0), fcode.bf_insns was allocated and needs to be freed.
    if (result == 0) {
        pcap_freecode(&fcode);
    }
    // Close the pcap handle.
    pcap_close(p);
    // Free the filter string buffer.
    free(filter_string);

    return 0; // Fuzzer should always return 0 unless there's an unrecoverable error.
}