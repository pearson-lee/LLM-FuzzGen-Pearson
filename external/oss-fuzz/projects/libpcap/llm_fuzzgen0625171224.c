#include <pcap/pcap.h>
#include <pcap/bpf.h>
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
    if (size < 2) {
        return 0;
    }
    
    // NEW: Call pcap_init to cover it.
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_init(PCAP_CHAR_ENC_LOCAL, errbuf);
    pcap_init(PCAP_CHAR_ENC_UTF_8, errbuf);

    // NEW: Call pcap_findalldevs and pcap_freealldevs to cover them.
    pcap_if_t *alldevs;
    if (pcap_findalldevs(&alldevs, errbuf) == 0) {
        pcap_freealldevs(alldevs);
    }

    // ... existing code ...
    const int linktype = data[0];
    const int optimize = data[1] & 1;
    data += 2;
    size -= 2;

    if (size == 0) {
        return 0;
    }
    size_t filter_len = size / 2;
    size_t packet_len = size - filter_len;
    const uint8_t *packet_data = data + filter_len;

    char *filter_string = (char *)malloc(filter_len + 1);
    if (!filter_string) {
        return 0;
    }
    memcpy(filter_string, data, filter_len);
    filter_string[filter_len] = '\0';

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
        
        // NEW: Call pcap_dump_open_append with NULL and "-" to cover error paths.
        pcap_dumper_t *dumper_null = pcap_dump_open_append(p, NULL);
        if (dumper_null) {
            pcap_dump_close(dumper_null);
        }
        pcap_dumper_t *dumper_stdout = pcap_dump_open_append(p, "-");
        if (dumper_stdout) {
            pcap_dump_close(dumper_stdout);
        }

        pcap_dumper_t *dumper_append = pcap_dump_open_append(p, dump_filename);
        if (dumper_append) {
            pcap_dump_close(dumper_append);
        }

        // NEW: Call pcap_list_datalinks and pcap_free_datalinks to cover them.
        int *dlt_buf;
        int dlt_count = pcap_list_datalinks(p, &dlt_buf);
        if (dlt_count > 0) {
            pcap_free_datalinks(dlt_buf);
        }

        // NEW: Call pcap_next_ex on dead handle to cover "live" capture path.
        struct pcap_pkthdr *pkt_header;
        const u_char *pkt_data;
        pcap_next_ex(p, &pkt_header, &pkt_data);

        pcap_breakloop(p);
        pcap_loop(p, 5, dummy_handler, NULL);
        pcap_loop(p, -1, dummy_handler, NULL);
        
        // NEW: Open the created dump file to test offline reading paths.
        pcap_t *p_offline = pcap_open_offline(dump_filename, errbuf);
        if (p_offline) {
            // NEW: Call pcap_loop on an offline handle to cover savefile reading.
            pcap_loop(p_offline, 5, dummy_handler, NULL);
            // NEW: Call pcap_next_ex on an offline handle.
            pcap_next_ex(p_offline, &pkt_header, &pkt_data);
            pcap_close(p_offline);
        }

        pcap_close(p);
        
        remove(dump_filename);
    }

    pcap_t *p_unactivated = pcap_create("any", errbuf);
    if (p_unactivated) {
        pcap_loop(p_unactivated, 5, dummy_handler, NULL);
        pcap_close(p_unactivated);
    }

    free(filter_string);

    return 0;
}