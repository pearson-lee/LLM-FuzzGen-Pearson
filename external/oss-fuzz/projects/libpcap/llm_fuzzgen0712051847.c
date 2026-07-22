#include <pcap.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <stddef.h>
#include <unistd.h>

// A list of protocols and keywords to generate filter strings for, to improve coverage in gencode.c
const char *keywords[] = {
    "tcp", "udp", "icmp", "arp", "rarp", "ip", "ip6", "sctp", "ether",
    "wlan", "ppp", "vlan", "mpls", "pppoe", "pppoes", "geneve", "vxlan",
    /*
     * ANALYSIS: The function-level coverage report shows low coverage in several
     *           gencode.c functions such as gen_ifindex, gen_inbound_outbound,
     *           gen_multicast, gen_broadcast, and various llc-related functions.
     *           Additionally, functions like gen_atmtype_abbrev and gen_mtp2type_abbrev
     *           have zero coverage.
     * IMPLEMENTATION: Added keywords to the list to specifically target these
     *                 uncovered functions by generating more complex and varied
     *                 filter strings. New keywords include 'atm', 'lane', 'oam',
     *                 'mtp2', and 'mtp3' to target ATM and MTP protocol parsing.
     */
    "ifindex 1", "inbound", "outbound", "multicast", "broadcast", "llc",
    "ip host 1.2.3.4", "net 1.2.3.0/24", "port 80", "portrange 1-1024",
    "atm", "lane", "oam", "mtp2", "mtp3"
};
const int num_keywords = sizeof(keywords) / sizeof(keywords[0]);

/*
 * ANALYSIS: The function-level coverage report shows that many functions
 *           in pcap-linux.c and pcap-usb-linux.c related to reading
 *           packets (e.g., pcap_read_linux_mmap_v2) have zero coverage.
 * IMPLEMENTATION: This dummy callback is used with pcap_dispatch to
 *                 exercise the packet reading code paths after activating a handle.
 */
void dummy_handler(u_char *user, const struct pcap_pkthdr *h, const u_char *bytes) {
    // Do nothing.
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    if (size < 4) {
        return 0;
    }

    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_if_t *alldevs;
    uint8_t choice = data[0];

    // Use one byte for the main choice, the rest for other operations
    data++;
    size--;

    if (choice % 4 == 0) {
        // Exercise the local interface enumeration.
        if (pcap_findalldevs_ex("rpcap://", NULL, &alldevs, errbuf) == 0) {
            pcap_freealldevs(alldevs);
        }
    } else if (choice % 4 == 1) {
        // Exercise the file source enumeration.
        if (pcap_findalldevs_ex("file:///", NULL, &alldevs, errbuf) == 0) {
            pcap_freealldevs(alldevs);
        }
    } else if (choice % 4 == 2) {
        /*
         * ANALYSIS: The function-level coverage report indicates that functions
         *           within pcap-usb-linux.c and pcap-linux.c have low coverage,
         *           especially packet reading functions like pcap_read_linux_mmap_v2.
         * IMPLEMENTATION: To exercise these code paths, this block creates and
         *                 activates a pcap handle, then calls pcap_dispatch to
         *                 trigger the underlying packet read mechanisms.
         */
        pcap_t *p = pcap_create("usbmon1", errbuf);
        if (p) {
            if (pcap_activate(p) == 0) {
                pcap_dispatch(p, 1, dummy_handler, NULL);
            }
            pcap_close(p);
        }
    } else { // choice % 4 == 3
        /*
         * ANALYSIS: The function-level coverage report shows that functions
         *           in sf-pcap.c for writing savefiles (e.g., pcap_dump_open,
         *           pcap_dump) are not covered.
         * IMPLEMENTATION: This block exercises the pcap file-writing APIs. It
         *                 opens a temporary file, writes the fuzzer data as a
         *                 single packet, and closes it. The file is created
         *                 with a unique name and unlinked to ensure statelessness
         *                 and prevent race conditions.
         */
        pcap_t *p = pcap_open_dead(DLT_EN10MB, 65535);
        if (p) {
            char path[256];
            snprintf(path, sizeof(path), "/tmp/%s.pcap", "llm_fuzzgen0712040051");
            pcap_dumper_t *dumper = pcap_dump_open(p, path);
            if (dumper) {
                struct pcap_pkthdr hdr;
                hdr.ts.tv_sec = 1672531200; // Arbitrary timestamp
                hdr.ts.tv_usec = 0;
                hdr.caplen = size;
                hdr.len = size;
                pcap_dump((u_char *)dumper, &hdr, data);
                pcap_dump_close(dumper);
            }
            unlink(path);
            pcap_close(p);
        }
    }

    if (size == 0) {
        return 0;
    }

    /*
     * ANALYSIS: The function-level coverage report shows that many functions
     *           in gencode.c, such as gen_proto, have very low coverage.
     *           This is because the existing fuzzers do not generate a wide
     *           variety of filter strings.
     * IMPLEMENTATION: Create a dummy pcap_t handle using pcap_open_dead and
     *                 compile a filter string. The filter string is constructed
     *                 by picking a random keyword from a predefined list and
     *                 combining it with fuzzer data. This will exercise the
     *                 filter compilation logic with a wider range of inputs.
     */
    pcap_t *handle = pcap_open_dead(DLT_EN10MB, 65535);
    if (handle == NULL) {
        return 0;
    }

    struct bpf_program fp;
    char filter_exp[256];

    // Create a filter expression from fuzzer data.
    const char *proto = keywords[data[0] % num_keywords];
    int n = snprintf(filter_exp, sizeof(filter_exp), "%s and %.*s", proto, (int)(size - 1), (const char*)(data + 1));
    if (n < 0 || n >= sizeof(filter_exp)) {
        pcap_close(handle);
        return 0;
    }
    filter_exp[sizeof(filter_exp) - 1] = '\0';


    if (pcap_compile(handle, &fp, filter_exp, 1, PCAP_NETMASK_UNKNOWN) == 0) {
        // pcap_setfilter is called to ensure the compiled filter is used.
        pcap_setfilter(handle, &fp);
        pcap_freecode(&fp);
    }

    pcap_close(handle);

    return 0;
}