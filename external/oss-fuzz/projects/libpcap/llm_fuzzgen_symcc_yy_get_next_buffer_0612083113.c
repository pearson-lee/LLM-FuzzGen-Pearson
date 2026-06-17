#include <stdint.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>
#include <pcap/pcap.h> // Corrected include path for libpcap

// The entry point for the fuzzer.
// This harness focuses on exercising the BPF filter compilation path
// to reach the yy_get_next_buffer function, which is part of the
// Flex-generated scanner for filter expressions.
int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    // A filter string must have at least one character to be meaningful.
    if (size == 0) {
        return 0;
    }

    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t *p = NULL;
    struct bpf_program fcode;
    char *filter_string = NULL;

    // Allocate memory for the filter string and null-terminate it.
    // pcap_compile expects a null-terminated C string.
    filter_string = (char *)malloc(size + 1);
    if (!filter_string) {
        return 0; // Allocation failure
    }
    memcpy(filter_string, data, size);
    filter_string[size] = '\0'; // Null-terminate the string

    // Create a "dead" pcap handle. This is the simplest way to get a
    // valid pcap_t structure for pcap_compile without requiring live
    // capture setup or file operations. The DLT_EN10MB (Ethernet)
    // and 65535 (max snapshot length) are common and reasonable defaults.
    p = pcap_open_dead(DLT_EN10MB, 65535);
    if (!p) {
        free(filter_string);
        return 0; // pcap_open_dead failed
    }

    // Call pcap_compile to trigger the BPF filter parsing and scanning logic.
    // The '1' enables optimization, and PCAP_NETMASK_UNKNOWN is a standard value.
    // This function internally calls pcap_lex (the scanner) which then calls
    // yy_get_next_buffer.
    if (pcap_compile(p, &fcode, filter_string, 1, PCAP_NETMASK_UNKNOWN) == 0) {
        // If compilation succeeds, free the compiled BPF program.
        pcap_freecode(&fcode);
    }

    // Clean up allocated resources.
    if (p) {
        pcap_close(p);
    }
    free(filter_string);

    return 0;
}