#include "pcap/pcap.h"
#include <stdint.h>
#include <string.h>
#include <stdlib.h>

// Dummy callback for pcap_loop. This function is called for each captured
// packet, but we don't need to do anything with the packet data for this fuzzer.
void dummy_handler(u_char *user, const struct pcap_pkthdr *h, const u_char *bytes) {
}

// Main fuzzing entry point
int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    char errbuf[PCAP_ERRBUF_SIZE];

    // We need at least one byte for control flow decisions.
    if (size < 1) {
        return 0;
    }
    const uint8_t control_flow = data[0];
    data++;
    size--;

    pcap_t *p = NULL;
    int activation_status = PCAP_ERROR;

    // Use a control bit to switch between two major code paths.
    if (control_flow & 0x80) {
        /*
         * ANALYSIS: The detailed coverage report shows that pcap_activate() never succeeds,
         *           meaning the entire block for handling activated captures (lines 85-122)
         *           is never executed. This is because a fuzzed device name is unlikely to
         *           be valid.
         * IMPLEMENTATION: To ensure an activated handle is available for testing, this path
         *                 uses pcap_open_dead_with_tstamp_precision(). This function returns
         *                 an already-activated handle without needing a real device, allowing
         *                 the fuzzer to test functions like pcap_setfilter, pcap_loop, and
         *                 pcap_inject.
         */
        int linktype = 1; // DLT_EN10MB, a common default
        int snaplen = 2048;
        int precision = PCAP_TSTAMP_PRECISION_MICRO;
        if (size > sizeof(int)) {
            snaplen = *(const int*)data;
            data += sizeof(int);
            size -= sizeof(int);
        }
        p = pcap_open_dead_with_tstamp_precision(linktype, snaplen, precision);
        if (p) {
            activation_status = 0; // Treat as successfully activated.
        }
    } else {
        // Original path: create and attempt to activate a live handle.
        char dev_name[33];
        const size_t dev_name_len = size > 32 ? 32 : size;
        memcpy(dev_name, data, dev_name_len);
        dev_name[dev_name_len] = '\0';
        data += dev_name_len;
        size -= dev_name_len;

        p = pcap_create(dev_name, errbuf);
        if (!p) {
            return 0;
        }

        if (size > sizeof(int)) {
            pcap_set_snaplen(p, *(const int*)data);
            data += sizeof(int);
            size -= sizeof(int);
        }
        if (size > 0) {
            pcap_set_promisc(p, *data % 2);
            data++;
            size--;
        }
        if (size > sizeof(int)) {
            // Use a small, bounded, positive timeout to avoid hangs.
            // A negative timeout to poll() means an infinite wait.
            int timeout_val = *(const int*)data;
            pcap_set_timeout(p, abs(timeout_val % 1000));
            data += sizeof(int);
            size -= sizeof(int);
        }

        /*
         * ANALYSIS: The function-level coverage report shows low coverage for
         *           pcap_set_tstamp_type and pcap_set_tstamp_precision.
         * IMPLEMENTATION: Call these functions on the un-activated handle to
         *                 exercise their logic, which includes checks for
         *                 supported types and precisions before activation.
         */
        if (size > sizeof(int)) {
            pcap_set_tstamp_type(p, *(const int*)data);
            data += sizeof(int);
            size -= sizeof(int);
        }
        if (size > 0) {
            pcap_set_tstamp_precision(p, *data % 2);
            data++;
            size--;
        }
        activation_status = pcap_activate(p);
    }

    if (!p) {
        return 0; // Handle creation failed, nothing more to do.
    }

    struct bpf_program fp;
    int compile_result = -1;

    char filter_str[129];
    const size_t filter_len = size > 128 ? 128 : size;
    memcpy(filter_str, data, filter_len);
    filter_str[filter_len] = '\0';

    if (activation_status < 0 && (control_flow & 0x1)) {
        compile_result = pcap_compile(p, &fp, filter_str, 0, PCAP_NETMASK_UNKNOWN);
        if (compile_result == 0) {
            pcap_freecode(&fp);
        }
    }

    if (activation_status >= 0) {
        if (pcap_setnonblock(p, 1, errbuf) == -1) {
            pcap_close(p);
            return 0;
        }

        compile_result = pcap_compile(p, &fp, filter_str, 0, PCAP_NETMASK_UNKNOWN);

        if (compile_result == 0) {
            if (control_flow & 0x2) {
                pcap_setfilter(p, NULL);
            } else {
                pcap_setfilter(p, &fp);
            }
            pcap_freecode(&fp);
        }

        const int max_packets = (control_flow >> 2) % 10;
        pcap_dispatch(p, max_packets, dummy_handler, NULL);

        /*
         * ANALYSIS: The function-level coverage report shows pcap_inject has low coverage.
         *           This function requires an activated handle to work.
         * IMPLEMENTATION: Since this code block is only entered when a handle is
         *                 successfully activated, we can now call pcap_inject to
         *                 improve its coverage. We use the remaining fuzzer data
         *                 as the packet to inject.
         */
        if (size > 0) {
            pcap_inject(p, data, size);
        }
    }

    pcap_close(p);

    pcap_if_t *alldevs;
    if (pcap_findalldevs(&alldevs, errbuf) == 0) {
        pcap_freealldevs(alldevs);
    }

    return 0;
}