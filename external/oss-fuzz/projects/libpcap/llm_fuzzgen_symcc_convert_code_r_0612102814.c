#include <stdint.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>
#include <pcap/pcap.h>
#include <pcap/bpf.h>

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    if (size < 2) {
        return 0;
    }

    // Extract linktype and optimize flag from the first two bytes of the input.
    const int linktype = data[0];
    const int optimize = data[1] & 1;

    // The rest of the data constitutes the BPF filter string.
    const uint8_t *filter_data = data + 2;
    size_t filter_len = size - 2;

    // Allocate memory for the filter string and ensure it is null-terminated.
    char *filter_string = (char *)malloc(filter_len + 1);
    if (!filter_string) {
        return 0; // Out of memory, gracefully exit.
    }
    memcpy(filter_string, filter_data, filter_len);
    filter_string[filter_len] = '\0';

    struct bpf_program program;
    // Initialize program.bf_insns to NULL to safely check if it was allocated later.
    program.bf_insns = NULL;

    // Call pcap_compile_nopcap, which is a public API that leads to convert_code_r.
    // The snaplen_arg (65535) and mask (PCAP_NETMASK_UNKNOWN) are taken from the original fuzzer.
    pcap_compile_nopcap(65535, linktype, &program, filter_string, optimize, PCAP_NETMASK_UNKNOWN);

    // If pcap_compile_nopcap was successful (returned 0), free the compiled BPF program.
    // If it failed, program.bf_insns would not have been allocated or would be NULL.
    if (program.bf_insns != NULL) {
        pcap_freecode(&program);
    }

    // Free the allocated filter string.
    free(filter_string);

    return 0;
}