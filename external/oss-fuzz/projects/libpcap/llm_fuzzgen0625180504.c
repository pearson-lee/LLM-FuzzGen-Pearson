#include <pcap/pcap.h>
#include <pcap/bpf.h>
#include <pcap/dlt.h>
#include <pcap/namedb.h>
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

    // NEW: Fuzz pcap_next_etherent which was previously uncovered (0% coverage).
    // This involves creating a temporary file with fuzzer data.
    const char *ethers_filename = "/tmp/fuzz_ethers.txt";
    FILE *ethers_file = fopen(ethers_filename, "wb");
    if (ethers_file) {
        // Use the input data for the ethers file content.
        fwrite(data, 1, size, ethers_file);
        fclose(ethers_file); // Close after writing.

        ethers_file = fopen(ethers_filename, "rb"); // Re-open for reading.
        if (ethers_file) {
            // Loop through the file to exercise the parsing logic.
            while (pcap_next_etherent(ethers_file) != NULL);
            fclose(ethers_file);
        }
        remove(ethers_filename); // Clean up the temporary file.
    }

    // NEW: Call various name-to-address functions to improve coverage in nametoaddr.c
    if (size > 20) {
        char name[21];
        int port, proto, port1, port2;
        memcpy(name, data, 20);
        name[20] = '\0';
        pcap_nametoport(name, &port, &proto);
        pcap_nametoportrange(name, &port1, &port2, &proto);
        pcap_nametoproto(name);
        pcap_ether_aton(name);
    }
    
    // NEW: Call previously uncovered functions from pcap.c
    pcap_datalink_name_to_val("EN10MB");
    pcap_tstamp_type_name_to_val("host");


    pcap_lib_version();
    pcap_lookupdev(errbuf);

    pcap_statustostr(0);
    pcap_statustostr(PCAP_ERROR);
    pcap_statustostr(PCAP_ERROR_BREAK);
    pcap_statustostr(PCAP_ERROR_NOT_ACTIVATED);
    pcap_statustostr(PCAP_WARNING);
    pcap_statustostr(PCAP_WARNING_PROMISC_NOTSUP);
    pcap_statustostr(PCAP_WARNING_TSTAMP_TYPE_NOTSUP);
    pcap_statustostr(12345);

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
        "ifindex 5",
        "inbound",
        "outbound",
        "llc",
        "pppoed",
        "geneve",
        "ip[0] > 10",
        "ip[0] & 0xf != 0",
        "type mgt",
        "dir nodstods",
        "decnet host 1.2",
        "radio",
        "lane"
    };
    const int num_filters = sizeof(filters) / sizeof(filters[0]);
    
    char *filter_string = NULL;
    size_t filter_len = 0;

    if (choice % (num_filters + 1) < num_filters) {
        filter_string = strdup(filters[choice % num_filters]);
        if (!filter_string) {
            return 0;
        }
    } else {
        if (size == 0) {
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

    // NEW: Compile specific filters with specific linktypes to target
    // uncovered functions in gencode.c like gen_p80211_fcdir and gen_atmfield_code.
    struct bpf_program specific_program;
    if (pcap_compile_nopcap(65535, DLT_IEEE802_11, &specific_program, "dir nodstods", 0, PCAP_NETMASK_UNKNOWN) == 0) {
        pcap_freecode(&specific_program);
    }
    if (pcap_compile_nopcap(65535, DLT_ATM_RFC1483, &specific_program, "lane", 0, PCAP_NETMASK_UNKNOWN) == 0) {
        pcap_freecode(&specific_program);
    }

    pcap_t *p = pcap_open_dead(linktype, 65535);
    if (p) {
        // NEW: Call pcap_get_tstamp_precision to cover this 0% coverage function.
        pcap_get_tstamp_precision(p);
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
        
        pcap_dump_open_append(p, NULL);
        
        pcap_dumper_t *dumper_stdout = pcap_dump_open_append(p, "-");
        if (dumper_stdout) {
            pcap_dump_close(dumper_stdout);
        }

        pcap_dumper_t *dumper_append = pcap_dump_open_append(p, dump_filename);
        if (dumper_append) {
            pcap_dump_close(dumper_append);
        }

        pcap_t *p_snap = pcap_open_dead(linktype, 1500);
        if (p_snap) {
            pcap_dumper_t *dumper_snap_mismatch = pcap_dump_open_append(p_snap, dump_filename);
            if (dumper_snap_mismatch) {
                pcap_dump_close(dumper_snap_mismatch);
            }
            pcap_close(p_snap);
        }

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
            // NEW: Call pcap_file to cover this 0% coverage function.
            pcap_file(p_offline);
            pcap_loop(p_offline, 5, dummy_handler, NULL);
            pcap_next_ex(p_offline, &pkt_header, &pkt_data);
            pcap_close(p_offline);
        }

        pcap_close(p);
        
        remove(dump_filename);
    }

    pcap_t *p_unactivated = pcap_create("any", errbuf);
    if (p_unactivated) {
        pcap_set_snaplen(p_unactivated, 1024);
        pcap_set_promisc(p_unactivated, 1);
        pcap_set_rfmon(p_unactivated, 1);
        pcap_set_timeout(p_unactivated, 1000);
        pcap_set_tstamp_type(p_unactivated, PCAP_TSTAMP_HOST);
        pcap_set_immediate_mode(p_unactivated, 1);
        pcap_set_buffer_size(p_unactivated, 2 * 1024 * 1024);
        pcap_set_tstamp_precision(p_unactivated, PCAP_TSTAMP_PRECISION_NANO);
        
        pcap_setdirection(p_unactivated, PCAP_D_IN);
        pcap_setdirection(p_unactivated, PCAP_D_OUT);

        pcap_activate(p_unactivated);

        pcap_loop(p_unactivated, 5, dummy_handler, NULL);
        pcap_close(p_unactivated);
    }

    free(filter_string);

    return 0;
}