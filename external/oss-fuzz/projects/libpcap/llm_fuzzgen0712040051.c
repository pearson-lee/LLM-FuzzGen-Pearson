#include <pcap.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <stddef.h>

// A list of protocols and keywords to generate filter strings for, to improve coverage in gencode.c
const char *keywords[] = {
    "tcp", "udp", "icmp", "arp", "rarp", "ip", "ip6", "sctp", "ether",
    "wlan", "ppp", "vlan", "mpls", "pppoe", "pppoes", "geneve", "vxlan",
    /*
     * ANALYSIS: The function-level coverage report shows low coverage in several
     *           gencode.c functions such as gen_ifindex, gen_inbound_outbound,
     *           gen_multicast, gen_broadcast, and various llc-related functions.
     * IMPLEMENTATION: Added keywords to the list to specifically target these
     *                 uncovered functions by generating more complex and varied
     *                 filter strings.
     */
    "ifindex 1", "inbound", "outbound", "multicast", "broadcast", "llc",
    "ip host 1.2.3.4", "net 1.2.3.0/24", "port 80", "portrange 1-1024"
};
const int num_keywords = sizeof(keywords) / sizeof(keywords[0]);

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    if (size < 2) {
        return 0;
    }

    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_if_t *alldevs;
    uint8_t choice = data[0];

    // Use one byte for the main choice, the rest for the filter
    data++;
    size--;

    if (choice % 3 == 0) {
        // Exercise the local interface enumeration.
        if (pcap_findalldevs_ex("rpcap://", NULL, &alldevs, errbuf) == 0) {
            pcap_freealldevs(alldevs);
        }
    } else if (choice % 3 == 1) {
        // Exercise the file source enumeration. This path has many uncovered branches.
        // We use "/" as the directory to search for files.
        if (pcap_findalldevs_ex("file:///", NULL, &alldevs, errbuf) == 0) {
            pcap_freealldevs(alldevs);
        }
    } else {
        /*
         * ANALYSIS: The function-level coverage report indicates that functions
         *           within pcap-usb-linux.c (e.g., usb_activate, usb_create)
         *           have zero or very low coverage.
         * IMPLEMENTATION: To exercise these code paths, this block attempts to
         *                 create and activate a pcap handle for a USB device.
         *                 This specifically targets the USB-related functions.
         *                 The handle is closed regardless of activation success
         *                 to prevent memory leaks.
         */
        pcap_t *p = pcap_create("usbmon1", errbuf);
        if (p) {
            pcap_activate(p);
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