#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <unistd.h> // For unlink

#include "/src/libpcap/pcap/pcap.h"
#include "/src/libpcap/gencode.h" // For compiler_state_t, although not directly used, it's part of the internal compilation process
#include "/src/libpcap/build/scanner.h" // For yyscan_t, pcap_lex_init, pcap_lex_destroy, pcap__scan_string
#include "/src/libpcap/build/grammar.h" // For pcap_parse (yyparse)

// FuzzedDataProvider is a C++ library, but the prompt asks for a C fuzzer.
// We will simulate FuzzedDataProvider functionality for C by directly using Data and Size.
// For structured input, we'll manually parse the Data buffer.

// Helper function to create a null-terminated string from fuzzer data
static char* create_fuzzed_string(const uint8_t *Data, size_t Size) {
    if (Size == 0) {
        return strdup("");
    }
    char *str = (char *)malloc(Size + 1);
    if (str == NULL) {
        return NULL;
    }
    memcpy(str, Data, Size);
    str[Size] = '\0';
    return str;
}

// Fuzzer entry point
int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size) {
    // We'll divide the input data to simulate different fuzzed parameters.
    // This is a simple way to get structured input in C without FuzzedDataProvider.
    size_t offset = 0;

    // --- Fuzzing pcap_compile ---
    pcap_t *p = NULL;
    char errbuf[PCAP_ERRBUF_SIZE];
    struct bpf_program program;
    char *filter_string = NULL;

    // Initialize program struct to avoid issues if pcap_compile fails early
    program.bf_len = 0;
    program.bf_insns = NULL;

    // Fuzz parameters for pcap_open_dead
    int linktype = 0;
    if (Size >= offset + sizeof(int)) {
        memcpy(&linktype, Data + offset, sizeof(int));
        offset += sizeof(int);
    }
    // Limit linktype to a reasonable range if necessary, or let libpcap handle invalid ones.

    int snaplen = 0;
    if (Size >= offset + sizeof(int)) {
        memcpy(&snaplen, Data + offset, sizeof(int));
        offset += sizeof(int);
    }
    /*
     * ANALYSIS: The line-level coverage report for `pcap_compile` showed that
     *           the branch `if (cstate.snaplen == 0)` at line 781 was taken
     *           but not always.
     * IMPLEMENTATION: Sometimes set snaplen to 0 to explicitly exercise this path.
     */
    if (snaplen < 0 || (Size > offset && Data[offset] % 2 == 0)) { // Use a byte from Data to decide
        snaplen = 0;
    }
    if (Size > offset) offset++; // Consume the byte used for decision

    p = pcap_open_dead(linktype, snaplen);
    if (p == NULL) {
        // pcap_open_dead failing usually means malloc failed, which is out of fuzzer's scope.
        return 0;
    }

    // Fuzz the filter string
    int use_null_filter = 0;
    if (Size >= offset + sizeof(char)) { // Use a byte to decide if filter_string should be NULL
        use_null_filter = (Data[offset] % 2 == 0);
        offset += sizeof(char);
    }

    /*
     * ANALYSIS: The line-level coverage report for `pcap_compile` showed that
     *           the `False` branch of `xbuf ? xbuf : ""` at line 791 (which means
     *           `xbuf` is NULL) was never taken.
     * IMPLEMENTATION: Sometimes pass NULL for the filter string to `pcap_compile`
     *                 to ensure the `xbuf == NULL` path is exercised.
     */
    if (use_null_filter) {
        filter_string = NULL;
    } else {
        filter_string = create_fuzzed_string(Data + offset, Size - offset);
        if (filter_string == NULL) {
            pcap_close(p);
            return 0;
        }
    }

    // Fuzz optimize and netmask
    int optimize = 0;
    if (Size >= offset + sizeof(char)) {
        optimize = (Data[offset] % 2 != 0); // Use a byte to decide if optimize is true
        offset += sizeof(char);
    }

    bpf_u_int32 netmask = 0;
    if (Size >= offset + sizeof(bpf_u_int32)) {
        memcpy(&netmask, Data + offset, sizeof(bpf_u_int32));
        offset += sizeof(bpf_u_int32);
    }

    // Call pcap_compile
    pcap_compile(p, &program, filter_string, optimize, netmask);

    /*
     * ANALYSIS: The line-level coverage report for `pcap_compile` showed that
     *           `if (cstate.e != NULL)` at line 808 had `True: 0`. This means
     *           `cstate.e` was always NULL when an error occurred in `pcap_parse`.
     *           `bpf_set_error` (called by `pcap_parse` on error) sets `cstate->e`
     *           using `sdup`. To hit this, we need `pcap_parse` to error AND `sdup`
     *           to succeed. Generating diverse filter strings is the best way to
     *           trigger various error conditions within `pcap_parse`.
     * IMPLEMENTATION: The diverse `filter_string` input aims to trigger various
     *                 error paths in `pcap_parse` that might set `cstate.e`.
     */

    // Cleanup for pcap_compile
    if (program.bf_insns != NULL) {
        pcap_freecode(&program);
    }
    if (filter_string != NULL) {
        free(filter_string);
    }
    pcap_close(p);

    // --- Fuzzing pcap_lex_init and pcap_lex_destroy ---
    yyscan_t scanner_for_lex_fns = NULL;

    /*
     * ANALYSIS: The line-level coverage report for `pcap_lex_init` showed that
     *           `if (ptr_yy_globals == NULL)` at line 5446 had `True: 0`.
     * IMPLEMENTATION: Explicitly call `pcap_lex_init` with a `NULL` pointer
     *                 to exercise this error handling path.
     */
    if (Size > offset && Data[offset] % 2 == 0) { // Use a byte from Data to decide
        pcap_lex_init(NULL);
    }
    if (Size > offset) offset++; // Consume the byte used for decision

    // Test normal initialization and destruction
    if (pcap_lex_init(&scanner_for_lex_fns) == 0 && scanner_for_lex_fns != NULL) {
        /*
         * ANALYSIS: The line-level coverage report for `pcap_lex_destroy` showed that
         *           the `while(YY_CURRENT_BUFFER)` loop (lines 5537-5541) had 0 hits.
         *           This means the buffer stack was always empty. `pcap__scan_string`
         *           pushes a buffer onto this stack.
         * IMPLEMENTATION: Call `pcap__scan_string` to push a buffer before calling
         *                 `pcap_lex_destroy` to ensure the buffer cleanup loop is exercised.
         */
        char *scan_data_str = NULL;
        if (Size > offset) {
            scan_data_str = create_fuzzed_string(Data + offset, Size - offset);
        } else {
            scan_data_str = strdup(""); // Empty string if no more data
        }

        if (scan_data_str != NULL) {
            YY_BUFFER_STATE temp_buffer = pcap__scan_string(scan_data_str, scanner_for_lex_fns);
            // We don't need to explicitly delete temp_buffer, as pcap_lex_destroy will handle it.
            free(scan_data_str); // Free the fuzzed string
        }

        pcap_lex_destroy(scanner_for_lex_fns);
    }

    return 0;
}