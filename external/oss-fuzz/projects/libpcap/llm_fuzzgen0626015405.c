#include <stdint.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>

/*
 * Include the main internal pcap header. This is often necessary for
 * fuzzing, as it provides access to all internal type definitions and
 * function prototypes that may not be in the public headers.
 */
#include "/src/libpcap/pcap-int.h"

/*
 * A simple callback function for pcap_dispatch and pcap_loop.
 * It doesn't need to do anything for this fuzzer.
 */
static void dummy_callback(u_char *user, const struct pcap_pkthdr *h, const u_char *bytes) {
    /* Do nothing */
    (void)user;
    (void)h;
    (void)bytes;
}

#ifdef __cplusplus
extern "C"
#endif
/* The main fuzzing entry point */
int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size) {
    /*
     * We need at least enough data for a filter string, a bpf_insn,
     * and a pcap_pkthdr. This is a rough heuristic.
     */
    if (Size < sizeof(struct bpf_insn) + sizeof(struct pcap_pkthdr) + 1) {
        return 0;
    }

    /*
     * Create a "dead" pcap handle. This is essential for fuzzing because it
     * allows us to call pcap_compile and other functions without needing a
     * live network interface, which wouldn't be available in a typical
     * fuzzing environment.
     */
    pcap_t *p = pcap_open_dead(DLT_EN10MB, 65535);
    if (p == NULL) {
        /* This should not happen with pcap_open_dead, but check just in case */
        return 0;
    }

    // === ENHANCEMENT: Fuzz pcap_list_datalinks and pcap_set_datalink ===
    // Based on coverage report, pcap_list_datalinks and pcap_set_datalink
    // were not being called. This explores different link-layer header types.
    int *dlt_buf;
    int dlt_count = pcap_list_datalinks(p, &dlt_buf);
    if (dlt_count > 0) {
        // Use a byte from the input to select a datalink type to set.
        pcap_set_datalink(p, dlt_buf[Data[0] % dlt_count]);
        // Free the list allocated by pcap_list_datalinks to prevent leaks.
        pcap_free_datalinks(dlt_buf);
    }

    // === ENHANCEMENT: Fuzz pcap_inject ===
    // Based on coverage report, pcap_inject was not being called.
    // This tests the packet injection path, which may have different logic
    // on a dead handle compared to a live one.
    pcap_inject(p, Data, Size);

    // === ENHANCEMENT: Fuzz pcap_dump_open and pcap_dump ===
    // Based on coverage report, file dumping functions were not covered.
    // Using tmpfile() provides a safe, temporary file stream for the dumper
    // that is automatically cleaned up by the OS on process exit.
    FILE *temp_file = tmpfile();
    if (temp_file != NULL) {
        pcap_dumper_t *dumper = pcap_dump_fopen(p, temp_file);
        if (dumper != NULL) {
            struct pcap_pkthdr pkthdr;
            if (Size > sizeof(struct pcap_pkthdr)) {
                memcpy(&pkthdr, Data, sizeof(struct pcap_pkthdr));
                const u_char *pktdata = Data + sizeof(struct pcap_pkthdr);
                pkthdr.caplen = pkthdr.len = Size - sizeof(struct pcap_pkthdr);
                // Dump the packet to the temporary file.
                pcap_dump((u_char *)dumper, &pkthdr, pktdata);
            }
            // Close the dumper to free associated resources. This also closes
            // the underlying FILE* stream (temp_file).
            pcap_dump_close(dumper);
        }
        else {
            // If dumper is NULL, pcap_dump_close won't be called, so we
            // must close the file handle ourselves.
            fclose(temp_file);
        }
    }

    /*
     * Fuzz Target 1: bpf_validate()
     * This function checks a raw BPF program for validity.
     * The second argument to bpf_validate is the number of instructions,
     * not the size in bytes.
     */
    const struct bpf_insn *prog_insns = (const struct bpf_insn *)Data;
    size_t prog_len = Size / sizeof(struct bpf_insn);
    if (prog_len > 0) {
        bpf_validate(prog_insns, prog_len);
    }

    /*
     * Fuzz Target 2: pcap_compile()
     * This function compiles a user-supplied filter string into a BPF program.
     * The filter language is complex and a great candidate for fuzzing.
     * We create a null-terminated string from the input data.
     */
    char *filter_str = (char *)malloc(Size + 1);
    if (filter_str == NULL) {
        pcap_close(p);
        return 0;
    }
    memcpy(filter_str, Data, Size);
    filter_str[Size] = '\0';

    struct bpf_program fcode;
    /* Attempt to compile the filter string */
    if (pcap_compile(p, &fcode, filter_str, 1, PCAP_NETMASK_UNKNOWN) == 0) {
        /*
         * Fuzz Target 3: pcap_offline_filter()
         * If compilation was successful, we can now test the filter against a
         * packet. We'll construct a packet header and use the rest of the
         * input data as the packet itself.
         */
        if (Size > sizeof(struct pcap_pkthdr)) {
            struct pcap_pkthdr pkthdr;
            memcpy(&pkthdr, Data, sizeof(struct pcap_pkthdr));
            const u_char *pktdata = Data + sizeof(struct pcap_pkthdr);
            pkthdr.caplen = pkthdr.len = Size - sizeof(struct pcap_pkthdr);
            pcap_offline_filter(&fcode, &pkthdr, pktdata);
        }

        /*
         * Fuzz Target 4: pcap_setfilter()
         * Test setting the compiled filter on the handle.
         */
        pcap_setfilter(p, &fcode);

        /*
         * Fuzz Target 5: pcap_dispatch()
         * Although we don't have a live capture, calling dispatch can still
         * exercise some logic with the installed filter.
         */
        pcap_dispatch(p, 1, dummy_callback, NULL);

        /*
         * IMPORTANT: Free the memory allocated by pcap_compile to avoid leaks.
         */
        pcap_freecode(&fcode);
    }

    /* Clean up the allocated string and the pcap handle */
    free(filter_str);
    pcap_close(p);

    return 0;
}