#include <sys/types.h>
#include <stdint.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>
#include <pcap/pcap.h>
#include <pcap/bpf.h>
#include <unistd.h>
#include <stdio.h>

#ifndef _FUZZ_TARGET_NAME
#define _FUZZ_TARGET_NAME "llm_fuzzgen0710000053"
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

/*
 * ANALYSIS: The pcap_loop and pcap_dispatch functions require a callback
 *           function to handle packets.
 * IMPLEMENTATION: This is a dummy callback that does nothing. It is used
 *                 as an argument to pcap_loop and pcap_dispatch to allow
 *                 them to be fuzzed.
 */
void dummy_handler(u_char *user, const struct pcap_pkthdr *h, const u_char *bytes) {
    // Do nothing
}

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

    /*
     * ANALYSIS: The function pcap_lookupdev had 0% coverage.
     * IMPLEMENTATION: Call pcap_lookupdev to exercise its code path. We
     *                 ignore the return value as it's expected to fail in
     *                 a sandboxed environment.
     */
    pcap_lookupdev(errbuf);

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
     * ANALYSIS: The function pcap_set_datalink had 0% coverage. It can be
     *           called on a dead handle.
     * IMPLEMENTATION: Call pcap_set_datalink on the dead handle 'p' to
     *                 increase coverage.
     */
    pcap_set_datalink(p, linktype);

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

        pcap_offline_filter(&fp, &header, Data);

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

        /*
         * ANALYSIS: The core packet processing functions pcap_loop, pcap_dispatch,
         *           pcap_next_ex, and pcap_next all had 0% coverage because they
         *           require an activated handle. The functions pcap_setdirection,
         *           pcap_getnonblock and pcap_setnonblock were also uncovered.
         * IMPLEMENTATION: Open the pcap file we just created using pcap_open_offline.
         *                 This provides a valid, activated handle to use with these
         *                 functions, dramatically increasing coverage.
         */
        pcap_t *p_offline = pcap_open_offline(path, errbuf);
        if (p_offline != NULL) {
            pcap_setdirection(p_offline, PCAP_D_IN);
            pcap_loop(p_offline, -1, dummy_handler, NULL);
            pcap_dispatch(p_offline, -1, dummy_handler, NULL);
            struct pcap_pkthdr *pkt_header;
            const u_char *pkt_data;
            pcap_next_ex(p_offline, &pkt_header, &pkt_data);
            pcap_next(p_offline, &header);
            pcap_setnonblock(p_offline, 1, errbuf);
            pcap_getnonblock(p_offline, errbuf);
            pcap_close(p_offline);
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
        pcap_set_tstamp_precision(p_live, PCAP_TSTAMP_PRECISION_NANO);
        pcap_set_rfmon(p_live, 1);

        if (pcap_activate(p_live) == 0) {
            pcap_inject(p_live, Data, Size);
        }
        pcap_close(p_live);
    }

    /*
     * ANALYSIS: The function pcap_inject_dead, an error path for pcap_inject,
     *           had 0% coverage.
     * IMPLEMENTATION: Call pcap_inject on the "dead" handle 'p' to
     *                 trigger this specific error path.
     */
    pcap_inject(p, Data, Size);

    // Cleanup
    free(filter_str);
    pcap_close(p);

    return 0;
}