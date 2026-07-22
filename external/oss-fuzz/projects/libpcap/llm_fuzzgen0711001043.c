#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <unistd.h>
#include "/src/libpcap/pcap/pcap.h"

// The pcap_compile() function and its subcomponents (like the gen_* functions)
// are the primary targets for this fuzzer.

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    if (size < 5) {
        return 0;
    }

    /*
     * ANALYSIS: The function-level coverage report shows pcap_findalldevs() (52.38%) and
     *           pcap_freealldevs() (95.65%) are not fully covered. These are core pcap
     *           functions for device enumeration.
     * IMPLEMENTATION: Call pcap_findalldevs() and pcap_freealldevs() to exercise
     *                 the device discovery and cleanup logic. This is done at the
     *                 start as it doesn't depend on other parts of the fuzzer.
     */
    pcap_if_t *alldevs;
    char errbuf[PCAP_ERRBUF_SIZE];
    if (pcap_findalldevs(&alldevs, errbuf) == 0) {
        pcap_freealldevs(alldevs);
    }

    /*
     * ANALYSIS: The function-level coverage report showed that many functions
     *           within gencode.c have very low coverage, including gen_wlanhostop (8.81%),
     *           gen_atmtype_abbrev (15.38%), gen_host6 (17.02%), gen_inbound_outbound (37.68%),
     *           and gen_multicast (42.17%). A detailed line-level analysis using
     *           get_line_coverage_report revealed that most of the uncovered branches
     *           in these functions are dependent on the link-layer type of the pcap
     *           handle and the specific filter string provided. For example, gen_atmtype_abbrev
     *           requires an ATM linktype (e.g., DLT_ATM_RFC1483) to be active, and
     *           gen_wlanhostop requires specific "wlan" keywords in the filter.
     *
     * IMPLEMENTATION: This fuzzer targets pcap_compile() to exercise the filter
     *                 generation engine.
     *                 1. The first byte of the fuzzing data is used to select a link-layer
     *                    type for pcap_open_dead(). This allows the fuzzer to explore
     *                    code paths specific to dozens of different link types.
     *                 2. The second byte determines if the BPF optimizer is enabled,
     *                    targeting optimizer-specific code paths.
     *                 3. The remainder of the data is used as the filter string itself.
     *                    This allows the fuzzer's mutation engine to discover the complex
     *                    filter syntax and trigger the various logic paths in the targeted
     *                    gen_* functions.
     */

    // Use the first byte of the input data to select a link-layer type.
    // This is crucial for exploring linktype-dependent code paths.
    int linktype = data[0];

    // Use the second byte to toggle the BPF optimizer.
    int optimize = data[1] % 2;

    // The rest of the data is treated as the filter expression.
    // We copy it to a new buffer to ensure it's a null-terminated C-string.
    char *filter_string = (char *)malloc(size - 3);
    if (filter_string == NULL) {
        return 0;
    }
    memcpy(filter_string, data + 4, size - 4);
    filter_string[size - 4] = '\0';

    // Create a dead pcap handle with the selected linktype.
    // Using pcap_open_dead is ideal for fuzzing the compiler because it
    // avoids any platform-specific, privileged, or stateful operations.
    pcap_t *p = pcap_open_dead(linktype, 65535 /* snaplen */);
    if (p == NULL) {
        free(filter_string);
        return 0;
    }

    /*
     * ANALYSIS: The coverage report shows pcapint_setnonblock_fd (47.37%) and
     *           pcapint_getnonblock_fd (0.00%) are poorly covered.
     * IMPLEMENTATION: Call pcap_setnonblock() and pcap_getnonblock() to exercise
     *                 the non-blocking mode logic on the pcap handle. A byte
     *                 from the input data is used to determine the mode.
     */
    if (size > 2) {
        pcap_setnonblock(p, data[2] % 2, errbuf);
        pcap_getnonblock(p, errbuf);
    }

    struct bpf_program fcode;
    // Call pcap_compile to trigger the filter generation logic.
    // This is the main entry point for the functions we want to cover.
    if (pcap_compile(p, &fcode, filter_string, optimize, PCAP_NETMASK_UNKNOWN) == 0) {
        /*
         * ANALYSIS: The function-level coverage report shows that bpf_filter() has 0%
         *           coverage, and its underlying implementation pcapint_filter_with_aux_data()
         *           is also poorly covered. These functions execute a compiled filter.
         * IMPLEMENTATION: After a successful compilation, we execute the compiled filter
         *                 against the raw input data to exercise this logic.
         */
        if (size > 4) {
            (void)bpf_filter(fcode.bf_insns, data + 4, size - 4, size - 4);
        }

        /*
         * ANALYSIS: The function pcapint_filter_with_aux_data() has low coverage (49.09%).
         *           While bpf_filter() is called, pcap_offline_filter() provides an
         *           alternative path to the same underlying filter logic.
         * IMPLEMENTATION: After a successful compilation, call pcap_offline_filter()
         *                 with a dummy packet header to exercise this alternative
         *                 filter execution path.
         */
        if (size > 4) {
            struct pcap_pkthdr hdr;
            hdr.ts.tv_sec = 0;
            hdr.ts.tv_usec = 0;
            hdr.caplen = size - 4;
            hdr.len = size - 4;
            (void)pcap_offline_filter(&fcode, &hdr, data + 4);
        }

        /*
         * ANALYSIS: The function-level coverage report shows bpf_image() has low coverage (57.66%).
         *           This function is responsible for generating a human-readable representation
         *           of the BPF bytecode.
         * IMPLEMENTATION: Call bpf_dump() after a successful compilation to exercise the
         *                 BPF-to-text conversion logic in bpf_image.c.
         */
        bpf_dump(&fcode, 1);

        /*
         * ANALYSIS: The function-level coverage report shows pcap_list_datalinks() (66.67%)
         *           and pcap_set_datalink() (86.49%) are not fully covered.
         * IMPLEMENTATION: Call pcap_list_datalinks() to get available link types, then use a
         *                 byte from the fuzzer input to select and set a new link type. This
         *                 exercises the datalink enumeration and selection logic.
         */
        int *dlt_buf;
        int dlt_count = pcap_list_datalinks(p, &dlt_buf);
        if (dlt_count > 0) {
            int dlt_index = data[2] % dlt_count;
            pcap_set_datalink(p, dlt_buf[dlt_index]);
            pcap_free_datalinks(dlt_buf);
        }

        /*
         * ANALYSIS: The function-level coverage report shows pcap_list_tstamp_types() (65.22%)
         *           and pcap_set_tstamp_type() (66.67%) are not fully covered.
         * IMPLEMENTATION: Call pcap_list_tstamp_types() to get available timestamp types,
         *                 then use a byte from the fuzzer input to select and set a new
         *                 timestamp type, exercising the timestamp configuration logic.
         */
        int *tstamp_buf;
        int tstamp_count = pcap_list_tstamp_types(p, &tstamp_buf);
        if (tstamp_count > 0) {
            int tstamp_index = data[3] % tstamp_count;
            pcap_set_tstamp_type(p, tstamp_buf[tstamp_index]);
            pcap_free_tstamp_types(tstamp_buf);
        }

        /*
         * ANALYSIS: The coverage report shows that savefile-related functions such as
         *           pcap_dump_open(), pcap_dump(), and pcap_dump_open_append() in
         *           sf-pcap.c are not covered.
         * IMPLEMENTATION: Create a temporary file and use the pcap_dump* APIs to write
         *                 a dummy packet to it. This exercises the file writing and
         *                 appending code paths. The temporary file is statelessly managed
         *                 and deleted before the fuzzer exits.
         */
        char path[256];
        snprintf(path, sizeof(path), "/tmp/%s.pcap", "llm_fuzzgen0710225617");

        pcap_dumper_t *dumper = pcap_dump_open(p, path);
        if (dumper != NULL) {
            struct pcap_pkthdr hdr;
            hdr.ts.tv_sec = 0;
            hdr.ts.tv_usec = 0;
            
            uint32_t caplen = (size > 4) ? size - 4 : 0;
            if (caplen > 128) { // Cap length to a reasonable size
                caplen = 128;
            }
            hdr.caplen = caplen;
            hdr.len = caplen;

            if (hdr.caplen > 0) {
                pcap_dump((u_char *)dumper, &hdr, data + 4);
            }
            pcap_dump_close(dumper);

            // Also exercise the append logic, which is uncovered.
            pcap_dumper_t *appender = pcap_dump_open_append(p, path);
            if (appender != NULL) {
                pcap_dump_close(appender);
            }
        }
        unlink(path);

        // If compilation is successful, free the allocated resources.
        pcap_freecode(&fcode);
    }

    // Clean up all resources.
    pcap_close(p);
    free(filter_string);

    return 0;
}