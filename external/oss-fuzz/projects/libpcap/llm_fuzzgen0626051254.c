#include <stdint.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>

#include "/src/libpcap/pcap.h"
#include "/src/libpcap/pcap-int.h"

// Forward declaration for pcap_set_protocol_linux
int pcap_set_protocol_linux(pcap_t *, int);

// Dummy callback function for pcap_dispatch
void dummy_handler(u_char *user, const struct pcap_pkthdr *h, const u_char *bytes) {
    // Do nothing
}

int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size) {
    if (Size < 40) {
        return 0;
    }

    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t *p;

    // Use a portion of the data for the device name
    size_t dev_name_len = Data[0] % 32; // Keep it reasonably small
    if (dev_name_len == 0) {
        dev_name_len = 1;
    }
    if (1 + dev_name_len > Size) { // Bounds check
        return 0;
    }
    char *dev_name = (char *)malloc(dev_name_len + 1);
    if (!dev_name) {
        return 0;
    }
    memcpy(dev_name, Data + 1, dev_name_len);
    dev_name[dev_name_len] = '\0';
    size_t data_offset = 1 + dev_name_len;

    // Consume data for pcap_open_live parameters
    int snaplen = 0;
    if (data_offset + sizeof(snaplen) > Size) { // Bounds check
        free(dev_name);
        return 0;
    }
    memcpy(&snaplen, Data + data_offset, sizeof(snaplen));
    data_offset += sizeof(snaplen);

    if (data_offset >= Size) { // Bounds check
        free(dev_name);
        return 0;
    }
    int promisc = Data[data_offset++] % 2;

    int to_ms = 0;
    if (data_offset + sizeof(to_ms) > Size) { // Bounds check
        free(dev_name);
        return 0;
    }
    memcpy(&to_ms, Data + data_offset, sizeof(to_ms));
    data_offset += sizeof(to_ms);

    // Since we can't create real devices, we use pcap_open_dead to get a pcap_t handle
    // This allows us to fuzz functions that operate on a pcap_t structure.
    p = pcap_open_dead(DLT_EN10MB, snaplen);
    if (p == NULL) {
        free(dev_name);
        return 0;
    }

    // Fuzz the pcap_create/pcap_activate code path to hit various pcap_set_* functions.
    // This was added to improve coverage in pcap.c for pre-activation configuration.
    pcap_t *p_create = pcap_create(dev_name, errbuf);
    if (p_create) {
        pcap_set_rfmon(p_create, 1);
        pcap_set_tstamp_type(p_create, PCAP_TSTAMP_HOST);
        pcap_set_immediate_mode(p_create, 1);
        pcap_set_buffer_size(p_create, 1024);
        pcap_set_tstamp_precision(p_create, PCAP_TSTAMP_PRECISION_NANO);
        pcap_activate(p_create); // This will likely fail, which is fine.
        pcap_close(p_create);
    }

    // Fuzz pcap_set_protocol_linux
    if (data_offset + sizeof(int) <= Size) {
        int protocol;
        memcpy(&protocol, Data + data_offset, sizeof(protocol));
        pcap_set_protocol_linux(p, protocol);
        data_offset += sizeof(int);
    }

    // Added to cover packet direction control logic in pcap.c
    pcap_setdirection(p, PCAP_D_IN);

    // Added to cover datalink enumeration in pcap.c
    int *dlt_buf;
    if (pcap_list_datalinks(p, &dlt_buf) >= 0) {
        pcap_free_datalinks(dlt_buf);
    }

    // Fuzz BPF filter compilation to improve coverage in gencode.c, optimize.c, and bpf_filter.c
    if (data_offset < Size) {
        struct bpf_program fp;
        char* filter_str = (char*)malloc(Size - data_offset + 1);
        if (filter_str) {
            memcpy(filter_str, Data + data_offset, Size - data_offset);
            filter_str[Size - data_offset] = '\0';
            if (pcap_compile(p, &fp, filter_str, 1, PCAP_NETMASK_UNKNOWN) == 0) {
                pcap_setfilter(p, &fp);
                pcap_freecode(&fp);
            }
            free(filter_str);
        }
    }

    // Fuzz pcap_dump functionality to improve coverage in sf-pcap.c
    pcap_dumper_t *dumper = pcap_dump_open(p, "/dev/null");
    if (dumper) {
        struct pcap_pkthdr hdr;
        // Create a header from the fuzz data
        if (data_offset + sizeof(hdr) <= Size) {
           memcpy(&hdr, Data + data_offset, sizeof(hdr));
           // Ensure timestamps are somewhat sane to avoid large values
           hdr.ts.tv_sec = hdr.ts.tv_sec % 2000000000;
           hdr.caplen = hdr.caplen % (1024*64);
           hdr.len = hdr.len % (1024*64);
        } else {
           hdr.ts.tv_sec = 123;
           hdr.ts.tv_usec = 456;
           hdr.caplen = Size > 100 ? 100 : Size;
           hdr.len = Size > 100 ? 100 : Size;
        }

        // FIX: The captured length cannot be greater than the total size of the
        // input buffer `Data`.
        if (hdr.caplen > Size) {
            hdr.caplen = Size;
        }
        // Also, the original packet length should be at least the captured length.
        if (hdr.len < hdr.caplen) {
            hdr.len = hdr.caplen;
        }

        pcap_dump((u_char *)dumper, &hdr, Data);
        pcap_dump_close(dumper);
    }

    // Fuzz pcap_dispatch with a dummy handler
    pcap_dispatch(p, 1, dummy_handler, NULL);

    // Clean up resources
    pcap_close(p);
    free(dev_name);

    return 0;
}