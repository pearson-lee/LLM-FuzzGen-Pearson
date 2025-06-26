#include <pcap/pcap.h>
#include <pcap/bpf.h>
#include <pcap/dlt.h>
#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>

// Dummy handler for pcap_loop, does nothing.
static void dummy_handler(u_char *user, const struct pcap_pkthdr *h, const u_char *bytes) {
    (void)user;
    (void)h;
    (void)bytes;
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    if (size < 3) { // Need at least 3 bytes for linktype, optimize, and filter choice
        return 0;
    }
    
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_init(PCAP_CHAR_ENC_LOCAL, errbuf);
    pcap_init(PCAP_CHAR_ENC_UTF_8, errbuf);

    // NEW: Call pcap_lib_version to cover this previously uncovered function.
    pcap_lib_version();

    // NEW: Call pcap_lookupdev to cover it (likely to fail, but that's OK).
    pcap_lookupdev(errbuf);

    // NEW: Call pcap_statustostr to cover its implementation.
    pcap_statustostr(0); // 0 is not a special value, but exercises the function
    pcap_statustostr(PCAP_ERROR);
    pcap_statustostr(PCAP_ERROR_BREAK);
    pcap_statustostr(PCAP_ERROR_NOT_ACTIVATED);
    // NEW: Add more status codes to improve coverage in pcap_statustostr.
    pcap_statustostr(PCAP_WARNING);
    pcap_statustostr(PCAP_WARNING_PROMISC_NOTSUP);
    pcap_statustostr(PCAP_WARNING_TSTAMP_TYPE_NOTSUP);
    pcap_statustostr(12345); // Hit default case

    // Call pcap_lookupnet to improve coverage in pcap.c, which was previously uncovered.
    bpf_u_int32 net, mask;
    pcap_lookupnet("any", &net, &mask, errbuf);

    pcap_if_t *alldevs;
    if (pcap_findalldevs(&alldevs, errbuf) == 0) {
        pcap_freealldevs(alldevs);
    }

    const int linktype = data[0];
    const int optimize = data[1] & 1;
    const uint8_t choice = data[2];
    data += 3;
    size -= 3;

    // NEW: Add more diverse filters to improve coverage in gencode.c.
    // These target previously uncovered functions like gen_ifindex, gen_inbound, etc.
    const char *filters[] = {
        "host 127.0.0.1", "net 192.168.0.0/24", "port 80", "proto tcp",
        "ether host 00:11:22:33:44:55", "vlan 100", "ip6 host ::1", "ip",
        "len > 100",
        "len < 50",
        "ether broadcast",
        "ip multicast",
        "mpls",
        "pppoes",
        "portrange 10-20",
        // NEW: Add more diverse filters to improve coverage in gencode.c.
        "ifindex 5",
        "inbound",
        "outbound",
        "llc",
        "pppoed",
        "geneve",
        // NEW: Add filters for uncovered functions in gencode.c based on coverage analysis.
        "ip[0] > 10",         // Targets gen_greater
        "ip[0] & 0xf != 0",   // Targets gen_byteop
        "type mgt",           // Targets gen_p80211_type (requires DLT_IEEE802_11)
        "dir nodstods",       // Targets gen_p80211_fcdir (requires DLT_IEEE802_11)
        "decnet host 1.2",    // Targets gen_dnhostop
        "radio",              // Targets radio keyword (requires DLT_IEEE802_11_RADIO)
        "lane"                // Targets lane keyword (for ATM linktypes)
    };
    const int num_filters = sizeof(filters) / sizeof(filters[0]);
    
    char *filter_string = NULL;
    size_t filter_len = 0;

    if (choice % (num_filters + 1) < num_filters) {
        // Use a predefined filter. strdup is used for easy memory management with free().
        filter_string = strdup(filters[choice % num_filters]);
        if (!filter_string) {
            return 0;
        }
    } else {
        // Fallback to original random filter logic
        if (size == 0) {
            // If we are using raw data and there is no data left, we can't proceed.
            // But we can still execute the rest of the fuzzer with an empty filter.
            filter_string = strdup("");
            if (!filter_string) return 0;
        } else {
            filter_len = size / 2;
            filter_string = (char *)malloc(filter_len + 1);
            if (!filter_string) {
                return 0;
            }
            memcpy(filter_string, data, filter_len);
            filter_string[filter_len] = '\0';
            data += filter_len;
            size -= filter_len;
        }
    }

    size_t packet_len = size;
    const uint8_t *packet_data = data;

    struct bpf_program program;
    if (pcap_compile_nopcap(65535, linktype, &program, filter_string, optimize, PCAP_NETMASK_UNKNOWN) == 0) {
        (void)bpf_filter(program.bf_insns, packet_data, packet_len, packet_len);
        bpf_dump(&program, 1);
        bpf_dump(&program, 2);
        bpf_dump(&program, 3);
        (void)pcap_validate_filter(program.bf_insns, program.bf_len);
        pcap_freecode(&program);
    }

    pcap_t *p = pcap_open_dead(linktype, 65535);
    if (p) {
        // NEW: Call pcap_set_datalink on the dead handle to cover pcap_set_datalink.
        pcap_set_datalink(p, DLT_EN10MB);

        const char *dump_filename = "/tmp/fuzz_dump.pcap";

        pcap_dumper_t *dumper = pcap_dump_open(p, dump_filename);
        if (dumper) {
            struct pcap_pkthdr hdr;
            hdr.ts.tv_sec = 0;
            hdr.ts.tv_usec = 0;
            hdr.caplen = packet_len;
            hdr.len = packet_len;
            pcap_dump((u_char *)dumper, &hdr, packet_data);
            pcap_dump_flush(dumper);
            pcap_dump_close(dumper);
        }
        
        // NEW: Add a call with a NULL filename to cover the error path in pcap_dump_open_append.
        pcap_dump_open_append(p, NULL);
        
        pcap_dumper_t *dumper_stdout = pcap_dump_open_append(p, "-");
        if (dumper_stdout) {
            pcap_dump_close(dumper_stdout);
        }

        pcap_dumper_t *dumper_append = pcap_dump_open_append(p, dump_filename);
        if (dumper_append) {
            pcap_dump_close(dumper_append);
        }

        // NEW: Test appending to an existing file with mismatched snapshot length to improve pcap_dump_open_append coverage.
        pcap_t *p_snap = pcap_open_dead(linktype, 1500);
        if (p_snap) {
            pcap_dumper_t *dumper_snap_mismatch = pcap_dump_open_append(p_snap, dump_filename);
            if (dumper_snap_mismatch) {
                pcap_dump_close(dumper_snap_mismatch);
            }
            pcap_close(p_snap);
        }

        // NEW: Test appending to an existing file with mismatched timestamp precision to improve pcap_dump_open_append coverage.
        pcap_t *p_nano = pcap_open_dead_with_tstamp_precision(linktype, 65535, PCAP_TSTAMP_PRECISION_NANO);
        if (p_nano) {
            pcap_dumper_t *dumper_prec_mismatch = pcap_dump_open_append(p_nano, dump_filename);
            if (dumper_prec_mismatch) {
                pcap_dump_close(dumper_prec_mismatch);
            }
            pcap_close(p_nano);
        }

        int *dlt_buf;
        int dlt_count = pcap_list_datalinks(p, &dlt_buf);
        if (dlt_count > 0) {
            pcap_free_datalinks(dlt_buf);
        }

        struct pcap_pkthdr *pkt_header;
        const u_char *pkt_data;
        pcap_next_ex(p, &pkt_header, &pkt_data);

        pcap_breakloop(p);
        pcap_loop(p, 5, dummy_handler, NULL);
        pcap_loop(p, -1, dummy_handler, NULL);
        
        pcap_t *p_offline = pcap_open_offline(dump_filename, errbuf);
        if (p_offline) {
            pcap_loop(p_offline, 5, dummy_handler, NULL);
            pcap_next_ex(p_offline, &pkt_header, &pkt_data);
            pcap_close(p_offline);
        }

        pcap_close(p);
        
        remove(dump_filename);
    }

    pcap_t *p_unactivated = pcap_create("any", errbuf);
    if (p_unactivated) {
        // Call various pcap_set_... functions on an unactivated handle
        // to improve coverage in pcap.c for previously uncovered functions.
        pcap_set_snaplen(p_unactivated, 1024);
        pcap_set_promisc(p_unactivated, 1);
        pcap_set_rfmon(p_unactivated, 1); // This will likely fail but exercises the code
        pcap_set_timeout(p_unactivated, 1000);
        pcap_set_tstamp_type(p_unactivated, PCAP_TSTAMP_HOST);
        pcap_set_immediate_mode(p_unactivated, 1);
        pcap_set_buffer_size(p_unactivated, 2 * 1024 * 1024);
        pcap_set_tstamp_precision(p_unactivated, PCAP_TSTAMP_PRECISION_NANO);
        
        // NEW: Call pcap_setdirection to cover this zero-coverage function.
        pcap_setdirection(p_unactivated, PCAP_D_IN);
        pcap_setdirection(p_unactivated, PCAP_D_OUT);

        // Attempt to activate the handle to cover pcap_activate, which was uncovered.
        // This is expected to fail on most systems without root privileges,
        // but it still provides coverage for the wrapper function and error paths.
        pcap_activate(p_unactivated);

        pcap_loop(p_unactivated, 5, dummy_handler, NULL);
        pcap_close(p_unactivated);
    }

    free(filter_string);

    return 0;
}