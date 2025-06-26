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

    // === ENHANCEMENT: Fuzz pcap_create and related option-setting functions ===
    // Based on coverage reports, functions like pcap_set_tstamp_precision,
    // pcap_set_snaplen, etc., were not being called because they require a
    // non-activated pcap handle. pcap_open_dead returns an activated one.
    // This block creates a handle, calls the setters, and closes it without
    // activating to specifically target these uncovered functions.
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t *p_created = pcap_create("any", errbuf);
    if (p_created != NULL) {
        // Use bytes from the input to exercise various setters.
        if (Size > 6) {
            pcap_set_snaplen(p_created, Data[0] * 256);
            pcap_set_promisc(p_created, Data[1] % 2);
            pcap_set_timeout(p_created, Data[2]);
            pcap_set_tstamp_type(p_created, Data[3] % 3);
            pcap_set_immediate_mode(p_created, Data[4] % 2);
            pcap_set_buffer_size(p_created, Size * 10);
            pcap_set_tstamp_precision(p_created, Data[5] % 2);
        }
        // Close the handle to prevent memory leaks.
        pcap_close(p_created);
    }

    // === ENHANCEMENT: Fuzz pcap_findalldevs ===
    // Based on coverage report, device enumeration functions were not covered.
    // This exercises the logic for finding available devices.
    pcap_if_t *alldevs;
    if (pcap_findalldevs(&alldevs, errbuf) == 0) {
        // Free the device list allocated by pcap_findalldevs to prevent leaks.
        pcap_freealldevs(alldevs);
    }

    // === ENHANCEMENT: Fuzz pcap_statustostr ===
    // Based on coverage report, pcap_statustostr had many uncovered error codes.
    // This calls the function with a wider range of inputs to improve coverage.
    int error_codes[] = {
        PCAP_ERROR_ACTIVATED, PCAP_ERROR_NO_SUCH_DEVICE,
        PCAP_ERROR_RFMON_NOTSUP, PCAP_ERROR_NOT_RFMON,
        PCAP_ERROR_PERM_DENIED, PCAP_ERROR_IFACE_NOT_UP,
        PCAP_ERROR_CANTSET_TSTAMP_TYPE, PCAP_ERROR_PROMISC_PERM_DENIED,
        PCAP_ERROR_TSTAMP_PRECISION_NOTSUP
    };
    if (Size > 0) {
        pcap_statustostr(error_codes[Data[0] % (sizeof(error_codes)/sizeof(int))]);
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