#include <pcap.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <unistd.h>
#include <stdint.h> // For uint8_t

// Include pcap-int.h to get the full definition of 'struct pcap'
// and access to internal members like bpf_codegen_flags.
#include "pcap-int.h"

// Maximum length for the dynamically constructed filter string.
// This ensures we don't overflow the buffer when concatenating prefixes and fuzzer data.
#define MAX_FILTER_LEN 2048

int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size) {
    // A minimum size is required to make meaningful choices and have data to append.
    if (Size < 1) {
        return 0;
    }

    pcap_t *pcap_handle = NULL;
    struct bpf_program fp;
    char errbuf[PCAP_ERRBUF_SIZE];
    // Use a byte from the input for the optimization flag to vary behavior.
    int optimize = (Data[0] % 2);
    // A common netmask for filter compilation.
    bpf_u_int32 netmask = 0xFFFFFF00;

    /*
     * ANALYSIS: pcap_open_dead is used to create a pcap_t handle without
     *           requiring a real network interface or file. This is crucial
     *           for a deterministic and stateless fuzzer.
     * IMPLEMENTATION: Call pcap_open_dead with DLT_EN10MB (Ethernet) and a
     *                 standard snaplen.
     */
    pcap_handle = pcap_open_dead(DLT_EN10MB, 65535);
    if (pcap_handle == NULL) {
        // If the handle cannot be created, there's nothing further to fuzz.
        return 0;
    }

    // Allocate memory for the filter string.
    // MAX_FILTER_LEN is chosen to be large enough for prefixes and fuzzer data.
    char *filter_string = (char *)malloc(MAX_FILTER_LEN);
    if (filter_string == NULL) {
        pcap_close(pcap_handle);
        return 0;
    }
    filter_string[0] = '\0'; // Initialize as an empty string.

    // Use the first byte of the fuzzer input to select a specific filter pattern.
    // This helps guide the fuzzer towards specific, often unhit, grammar rules.
    uint8_t choice = Data[0] % 5; // Selects one of 5 different patterns.

    // The rest of the fuzzer input will be appended to the chosen pattern.
    const uint8_t *remaining_data = Data + 1;
    size_t remaining_size = Size - 1;

    // Ensure the remaining data doesn't exceed the buffer capacity after adding a prefix.
    // A buffer of 64 bytes is reserved for the prefix.
    if (remaining_size >= MAX_FILTER_LEN - 64) {
        remaining_size = MAX_FILTER_LEN - 64 - 1; // -1 for null terminator
    }

    /*
     * ANALYSIS: The function-level coverage report highlighted many unhit grammar
     *           rules and functions within pcap_parse and gencode.c. To specifically
     *           target these, the fuzzer input is used to select a predefined
     *           filter expression prefix, followed by fuzzer-generated data.
     * IMPLEMENTATION: A switch statement uses Data[0] to pick one of five diverse
     *                 filter expression types, aiming to hit specific zero-coverage
     *                 branches related to PF logs, comparisons, LLC, WLAN, and generic
     *                 complex expressions.
     */
    switch (choice) {
        case 0:
            /*
             * ANALYSIS: grammar.c:pfreason_to_num and grammar.c:pfaction_to_num had 0% coverage.
             *           These are called when parsing "pflog reason <ID>" or "pflog action <ID>".
             * IMPLEMENTATION: Generate either "pflog reason " or "pflog action " as a prefix.
             */
            if (Data[0] % 2 == 0) {
                snprintf(filter_string, MAX_FILTER_LEN, "pflog reason ");
            } else {
                snprintf(filter_string, MAX_FILTER_LEN, "pflog action ");
            }
            break;
        case 1:
            /*
             * ANALYSIS: gencode.c:gen_less, gencode.c:gen_greater, and gencode.c:gen_byteop
             *           had 0% coverage. These correspond to filter expressions like
             *           "len < X", "len > X", and "ip[offset:size] & 0xff = value".
             * IMPLEMENTATION: Generate prefixes for these comparison and byte operations.
             */
            if (Data[0] % 3 == 0) {
                snprintf(filter_string, MAX_FILTER_LEN, "len < ");
            } else if (Data[0] % 3 == 1) {
                snprintf(filter_string, MAX_FILTER_LEN, "len > ");
            } else {
                snprintf(filter_string, MAX_FILTER_LEN, "ip[0:1] & 0xff = ");
            }
            break;
        case 2:
            /*
             * ANALYSIS: Functions like gencode.c:gen_llc_i, gen_llc_s, gen_llc_u,
             *           gen_llc_s_subtype, and gen_llc_u_subtype had 0% coverage.
             *           These are hit by "llc i", "llc s", "llc u", or specific LLC subtype names.
             * IMPLEMENTATION: Generate various LLC type and subtype prefixes.
             */
            if (Data[0] % 5 == 0) {
                snprintf(filter_string, MAX_FILTER_LEN, "llc i ");
            } else if (Data[0] % 5 == 1) {
                snprintf(filter_string, MAX_FILTER_LEN, "llc s ");
            } else if (Data[0] % 5 == 2) {
                snprintf(filter_string, MAX_FILTER_LEN, "llc u ");
            } else if (Data[0] % 5 == 3) {
                snprintf(filter_string, MAX_FILTER_LEN, "llc s_cmd "); // Example subtype
            } else {
                snprintf(filter_string, MAX_FILTER_LEN, "llc u_xid "); // Example subtype
            }
            break;
        case 3:
            /*
             * ANALYSIS: gencode.c:gen_p80211_fcdir had 0% coverage. This function
             *           is called when parsing 802.11 frame control direction filters
             *           like "wlan fcdir tods".
             * IMPLEMENTATION: Generate prefixes for different WLAN frame control directions.
             */
            if (Data[0] % 4 == 0) {
                snprintf(filter_string, MAX_FILTER_LEN, "wlan fcdir tods ");
            } else if (Data[0] % 4 == 1) {
                snprintf(filter_string, MAX_FILTER_LEN, "wlan fcdir fromds ");
            } else if (Data[0] % 4 == 2) {
                snprintf(filter_string, MAX_FILTER_LEN, "wlan fcdir nods ");
            } else {
                snprintf(filter_string, MAX_FILTER_LEN, "wlan fcdir dstods ");
            }
            break;
        case 4:
            /*
             * ANALYSIS: Many other grammar rules in pcap_parse related to technologies
             *           like VLAN, MPLS, and Geneve also showed low or zero coverage.
             * IMPLEMENTATION: Generate a more complex, generic filter expression
             *                 combining various keywords to explore these paths.
             */
            snprintf(filter_string, MAX_FILTER_LEN, "vlan and mpls and geneve and host ");
            break;
    }

    // Append the rest of the fuzzer data to the chosen prefix.
    // strncat is used for safety to prevent buffer overflows.
    strncat(filter_string, (const char *)remaining_data, remaining_size);
    // Ensure null termination, as strncat might not null-terminate if source size is exactly n.
    filter_string[MAX_FILTER_LEN - 1] = '\0';

    // Blocker-specific logic: Force BPF_SPECIAL_VLAN_HANDLING flag.
    // This flag is part of the pcap_t structure, specifically bpf_codegen_flags.
    // To hit the blocked branch, we need this flag to be set.
    // The existing target uses pcap_open_dead, which returns a pcap_t handle.
    // We can modify this handle directly to set the flag.
    // NOTE: This directly manipulates an internal pcap_t field to satisfy the blocker.
    // This is done because there is no public API to set this flag directly.
    // The BPF_SPECIAL_VLAN_HANDLING flag is defined in pcap-int.h.
    // We ensure that the pcap_handle is not NULL before dereferencing.
    if (pcap_handle != NULL) {
        // We ensure the flag is set. If the original pcap_t already has other flags,
        // we preserve them by using a bitwise OR.
        pcap_handle->bpf_codegen_flags |= BPF_SPECIAL_VLAN_HANDLING;
    }


    /*
     * ANALYSIS: pcap_compile is the primary API being fuzzed, responsible for parsing
     *           and compiling filter expressions. Its internal logic relies heavily
     *           on pcap_parse and pcap_lex.
     * IMPLEMENTATION: Call pcap_compile with the constructed filter string and other parameters.
     */
    int ret = pcap_compile(pcap_handle, &fp, filter_string, optimize, netmask);

    if (ret == 0) {
        /*
         * ANALYSIS: pcap_setfilter was identified as a related API to exercise,
         *           and its internal logic for applying filters should be tested.
         * IMPLEMENTATION: If compilation is successful, pcap_setfilter is called
         *                 to exercise the path where a valid filter program is applied.
         *                 This also implicitly tests pcap_freecode if pcap_setfilter
         *                 replaces an existing filter.
         */
        pcap_setfilter(pcap_handle, &fp); // Apply the filter (even on a dead handle)

        /*
         * ANALYSIS: pcap_freecode is essential for proper memory management of
         *           the compiled filter program (struct bpf_program).
         * IMPLEMENTATION: Always call pcap_freecode after a successful pcap_compile
         *                 to prevent memory leaks.
         */
        pcap_freecode(&fp); // Free the compiled filter program
    }

    /*
     * ANALYSIS: The filter_string was dynamically allocated using malloc.
     * IMPLEMENTATION: Free the allocated memory to prevent memory leaks.
     */
    free(filter_string);

    /*
     * ANALYSIS: The pcap_handle was opened using pcap_open_dead.
     * IMPLEMENTATION: Close the pcap handle to release associated resources.
     */
    pcap_close(pcap_handle);

    return 0;
}