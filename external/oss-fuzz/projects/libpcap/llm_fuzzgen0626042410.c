#include <pcap.h>
#include <stdint.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>

// This fuzzer targets several currently uncovered functions in libpcap
// by creating a "dead" pcap handle and performing various operations on it.
int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    // We need at least 7 bytes for configuration values and to determine filter length.
    if (size < 7) {
        return 0;
    }

    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t *p;
    struct bpf_program fp;

    // Consume the first 7 bytes of fuzzer data for configuration.
    // This adds variability to the state of the pcap_t object.
    const int datalink = data[0];
    const int nonblock = data[1] % 2;
    pcap_direction_t direction;
    switch (data[2] % 3) {
        case 0:
            direction = PCAP_D_IN;
            break;
        case 1:
            direction = PCAP_D_OUT;
            break;
        default:
            direction = PCAP_D_INOUT;
            break;
    }
    size_t filter_len = data[3];
    // Added a byte to control whether we call pcap_can_set_rfmon.
    // This targets the previously uncovered pcap_can_set_rfmon_dead function.
    const int check_rfmon = data[4];
    // Added a byte to control whether we call pcap_breakloop.
    // This targets the pcap_breakloop_dead function.
    const int do_breakloop = data[5];
    // Added a byte to control whether we call pcap_set_buffer_size.
    // This targets the pcap_bufsize function which was uncovered.
    const int buffer_size = data[6];


    data += 7;
    size -= 7;

    // Create a dead pcap handle using pcap_open_dead. This allows us to fuzz
    // functions that operate on a pcap_t without needing a live network interface.
    // DLT_EN10MB is a common datalink type for Ethernet.
    p = pcap_open_dead(DLT_EN10MB, 65535);
    if (p == NULL) {
        // If handle creation fails, we cannot proceed.
        return 0;
    }

    // Added call to pcap_set_buffer_size based on coverage report showing
    // pcap_bufsize was uncovered. This must be called before activation.
    pcap_set_buffer_size(p, buffer_size);

    // Added call to pcap_can_set_rfmon based on coverage report showing
    // pcap_can_set_rfmon_dead was uncovered.
    if (check_rfmon) {
        pcap_can_set_rfmon(p);
    }

    // Target: pcap_set_datalink (via pcap_set_datalink_dead).
    pcap_set_datalink(p, datalink);

    // Target: pcap_setnonblock/pcap_getnonblock (via _dead versions).
    pcap_setnonblock(p, nonblock, errbuf);
    pcap_getnonblock(p, errbuf);

    // Target: pcap_setdirection (via pcap_setdirection_dead).
    pcap_setdirection(p, direction);

    // Use a portion of the remaining data as a BPF filter string.
    // The filter string must be null-terminated, so we manage the memory carefully.
    if (filter_len >= size) {
        filter_len = size > 0 ? size - 1 : 0;
    }
    
    char *filter_str = (char *)malloc(filter_len + 1);
    if (filter_str == NULL) {
        pcap_close(p);
        return 0;
    }
    memcpy(filter_str, data, filter_len);
    filter_str[filter_len] = '\0';

    data += filter_len;
    size -= filter_len;

    // Target: pcap_compile and pcap_setfilter on the dead handle.
    // This robustly tests the BPF filter compilation logic.
    if (pcap_compile(p, &fp, filter_str, 1, PCAP_NETMASK_UNKNOWN) == 0) {
        pcap_setfilter(p, &fp);
        // The compiled program must be freed to avoid a memory leak.
        pcap_freecode(&fp);
    }
    // The allocated filter string must be freed.
    free(filter_str);

    // Target: pcap_sendpacket (0% coverage). This will call pcap_inject,
    // exercising the pcap_inject_dead function path.
    if (size > 0) {
        pcap_sendpacket(p, data, size);
    }

    // Target: pcap_stats (via pcap_stats_dead).
    struct pcap_stat ps;
    pcap_stats(p, &ps);

    // Added call to pcap_breakloop to cover pcap_breakloop_dead.
    // The coverage report showed pcap_breakloop_dead was uncovered.
    if (do_breakloop) {
        pcap_breakloop(p);
    }

    // Added call to pcap_fileno to cover the pcap_fileno function, which was
    // previously uncovered.
    pcap_fileno(p);

    // Clean up the pcap handle to prevent memory leaks.
    pcap_close(p);

    return 0;
}