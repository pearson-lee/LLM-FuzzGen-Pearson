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
    if (Size < 10) {
        return 0;
    }

    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t *p;

    // Use a portion of the data for the device name
    size_t dev_name_len = Data[0] % (Size > 255 ? 255 : Size);
    if (dev_name_len == 0) {
        dev_name_len = 1;
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
    if (data_offset + sizeof(snaplen) <= Size) {
        memcpy(&snaplen, Data + data_offset, sizeof(snaplen));
        data_offset += sizeof(snaplen);
    }

    int promisc = 0;
    if (data_offset < Size) {
        promisc = Data[data_offset++] % 2;
    }

    int to_ms = 0;
    if (data_offset + sizeof(to_ms) <= Size) {
        memcpy(&to_ms, Data + data_offset, sizeof(to_ms));
        data_offset += sizeof(to_ms);
    }

    // Since we can't create real devices, we use pcap_open_dead to get a pcap_t handle
    // This allows us to fuzz functions that operate on a pcap_t structure.
    p = pcap_open_dead(DLT_EN10MB, snaplen);
    if (p == NULL) {
        free(dev_name);
        return 0;
    }

    // Although pcap_open_live will likely fail without a real device, 
    // we call it to exercise its internal logic.
    pcap_t *p_live = pcap_open_live(dev_name, snaplen, promisc, to_ms, errbuf);
    if (p_live) {
        pcap_close(p_live);
    }

    // Fuzz pcap_set_protocol_linux
    if (data_offset + sizeof(int) <= Size) {
        int protocol;
        memcpy(&protocol, Data + data_offset, sizeof(protocol));
        pcap_set_protocol_linux(p, protocol);
    }

    // Fuzz pcap_can_set_rfmon
    pcap_can_set_rfmon(p);

    // Fuzz pcap_dispatch with a dummy handler
    pcap_dispatch(p, 1, dummy_handler, NULL);

    // Clean up resources
    pcap_close(p);
    free(dev_name);

    return 0;
}