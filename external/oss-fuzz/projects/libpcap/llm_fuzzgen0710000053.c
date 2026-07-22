#include <stdint.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>
#include <pcap/pcap.h>
#include <pcap/bpf.h>
#include <unistd.h>
#include <stdio.h>

#ifndef _FUZZ_TARGET_NAME
#define _FUZZ_TARGET_NAME "llm_fuzzgen0709235318"
#endif

// Helper macro to safely consume data from the fuzzing input
#define CONSUME_DATA(type, data, size, dest) \
    do { \
        if (size < sizeof(type)) { \
            return 0; \
        } \
        dest = *(type*)data; \
        data += sizeof(type); \
        size -= sizeof(type); \
    } while (0)

int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size) {
    if (Size < 1) {
        return 0;
    }

    /*
     * ANALYSIS: The function pcap_init, which can be used to initialize the
     *           library, had 0% coverage.
     * IMPLEMENTATION: Call pcap_init at the beginning of the fuzz target.
     *                 We ignore the return value as the function is optional.
     */
    pcap_init(PCAP_CHAR_ENC_UTF_8, NULL);

    char errbuf[PCAP_ERRBUF_SIZE];

    pcap_if_t *alldevs;
    if (pcap_findalldevs(&alldevs, errbuf) == 0) {
        pcap_freealldevs(alldevs);
    }

    // Consume data for parameters
    int linktype;
    int snaplen;
    int optimize;
    int new_snaplen, promisc, timeout, buffer_size;
    CONSUME_DATA(int, Data, Size, linktype);
    CONSUME_DATA(int, Data, Size, snaplen);
    CONSUME_DATA(int, Data, Size, optimize);
    CONSUME_DATA(int, Data, Size, new_snaplen);
    CONSUME_DATA(int, Data, Size, promisc);
    CONSUME_DATA(int, Data, Size, timeout);
    CONSUME_DATA(int, Data, Size, buffer_size);
    
    if (snaplen < 0) {
        snaplen = -snaplen;
    }

    pcap_t *p = pcap_open_dead(linktype, snaplen);
    if (p == NULL) {
        return 0;
    }

    /*
     * ANALYSIS: The functions pcap_list_datalinks and pcap_free_datalinks
     *           had 0% or very low coverage. The detailed fuzzer report showed
     *           the call to pcap_list_datalinks on the unactivated "live" handle
     *           was always failing.
     * IMPLEMENTATION: This block now operates on the "dead" pcap_t handle
     *                 which is in a valid state for these calls. This allows the
     *                 enumeration and free functions to be exercised correctly.
     */
    int *dlt_buf;
    if (pcap_list_datalinks(p, &dlt_buf) >= 0) {
        pcap_free_datalinks(dlt_buf);
    }
    int *tstamp_buf;
    if (pcap_list_tstamp_types(p, &tstamp_buf) >= 0) {
        pcap_free_tstamp_types(tstamp_buf);
    }

    char *filter_str = (char *)malloc(Size + 1);
    if (filter_str == NULL) {
        pcap_close(p);
        return 0;
    }
    memcpy(filter_str, Data, Size);
    filter_str[Size] = '\0';

    struct bpf_program fp;
    if (pcap_compile(p, &fp, filter_str, optimize, PCAP_NETMASK_UNKNOWN) == 0) {
        pcap_setfilter(p, &fp);
        bpf_dump(&fp, 1);

        struct pcap_pkthdr header;
        header.ts.tv_sec = 0;
        header.ts.tv_usec = 0;
        header.caplen = Size;
        header.len = Size;

        /*
         * ANALYSIS: The function pcap_offline_filter had low coverage. It is
         *           used to test a filter against a single packet in memory.
         * IMPLEMENTATION: Create a dummy packet header and use the remaining
         *                 fuzzer data as the packet content. Call
         *                 pcap_offline_filter to test the newly compiled filter
         *                 against this packet.
         */
        pcap_offline_filter(&fp, &header, Data);

        /*
         * ANALYSIS: The suite of pcap_dump_* functions for writing to savefiles
         *           (pcap_dump_open, pcap_dump, pcap_dump_close) had 0% coverage.
         *           The function pcap_dump_open_append also had 0% coverage.
         * IMPLEMENTATION: Create a temporary file and use pcap_dump_open to
         *                 create a dumper. A single packet (the fuzzer input)
         *                 is written using pcap_dump. The dumper is closed.
         *                 Then, pcap_dump_open_append is called to reopen the
         *                 file and append another packet, exercising that code
         *                 path. The temporary file is then deleted.
         */
        char path[256];
        snprintf(path, sizeof(path), "/tmp/%s.pcap", _FUZZ_TARGET_NAME);
        pcap_dumper_t *dumper = pcap_dump_open(p, path);
        if (dumper != NULL) {
            pcap_dump((u_char *)dumper, &header, Data);
            pcap_dump_close(dumper);

            pcap_dumper_t *dumper_append = pcap_dump_open_append(p, path);
            if (dumper_append != NULL) {
                pcap_dump((u_char *)dumper_append, &header, Data);
                pcap_dump_close(dumper_append);
            }
        }
        unlink(path);

        pcap_freecode(&fp);
    }

    pcap_t *p_live = pcap_create(filter_str, errbuf);
    if (p_live != NULL) {
        pcap_set_snaplen(p_live, new_snaplen);
        pcap_set_promisc(p_live, promisc);
        pcap_set_timeout(p_live, timeout);
        pcap_set_buffer_size(p_live, buffer_size);

        /*
         * ANALYSIS: The function pcap_set_tstamp_precision had 0% coverage.
         *           It must be called before a capture is activated.
         * IMPLEMENTATION: Call pcap_set_tstamp_precision on the unactivated
         *                 handle, attempting to set nanosecond precision.
         */
        pcap_set_tstamp_precision(p_live, PCAP_TSTAMP_PRECISION_NANO);

        /*
         * ANALYSIS: The function pcap_set_rfmon, for setting monitor mode, had
         *           0% coverage. It must be called before a capture is activated.
         * IMPLEMENTATION: Call pcap_set_rfmon on the unactivated handle, using a
         *                 hardcoded value of 1 to request monitor mode.
         */
        pcap_set_rfmon(p_live, 1);

        if (pcap_activate(p_live) == 0) {
            /*
             * ANALYSIS: The function pcap_inject had 0% coverage. It is used
             *           to transmit a packet.
             * IMPLEMENTATION: After successfully activating a live handle,
             *                 call pcap_inject to attempt to send the raw
             *                 fuzzer input as a packet.
             */
            pcap_inject(p_live, Data, Size);
        }
        pcap_close(p_live);
    }

    // Cleanup
    free(filter_str);
    pcap_close(p);

    return 0;
}