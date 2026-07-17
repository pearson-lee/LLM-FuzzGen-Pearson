#include <pcap.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <stddef.h>

// A list of protocols to generate filter strings for, to improve coverage in gencode.c
const char *protocols[] = {
    "tcp", "udp", "icmp", "arp", "rarp", "ip", "ip6", "sctp", "ether",
    "wlan", "ppp", "vlan", "mpls", "pppoe", "pppoes", "geneve", "vxlan"
};
const int num_protocols = sizeof(protocols) / sizeof(protocols[0]);

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    if (size < 2) {
        return 0;
    }

    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_if_t *alldevs;

    /*
     * ANALYSIS: pcap_findalldevs_ex has low coverage, especially in the
     *           code paths for handling different source types.
     * IMPLEMENTATION: Use the fuzzer input to choose between exercising the
     *                 local interface path ('rpcap://') and the file listing
     *                 path ('file:///').
     */
    if (data[0] % 2 == 0) {
        // Exercise the local interface enumeration.
        if (pcap_findalldevs_ex("rpcap://", NULL, &alldevs, errbuf) == 0) {
            pcap_freealldevs(alldevs);
        }
    } else {
        // Exercise the file source enumeration. This path has many uncovered branches.
        // We use "/" as the directory to search for files.
        if (pcap_findalldevs_ex("file:///", NULL, &alldevs, errbuf) == 0) {
            pcap_freealldevs(alldevs);
        }
    }

    // Remaining data will be used for filter compilation
    data++;
    size--;

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
     *                 by picking a random protocol from a predefined list and
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
    const char *proto = protocols[data[0] % num_protocols];
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