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

    // Create a device name string from fuzzer data, ensuring it's null-terminated.
    // Using a fuzzed name helps discover errors in device handling.
    char dev_name[33];
    const size_t dev_name_len = size > 32 ? 32 : size;
    memcpy(dev_name, data, dev_name_len);
    dev_name[dev_name_len] = '\0';
    data += dev_name_len;
    size -= dev_name_len;

    // Create a pcap handle for a "live" capture. This is more flexible than
    // pcap_open_live() as it allows setting parameters before activation.
    pcap_t *p = pcap_create(dev_name, errbuf);
    if (!p) {
        return 0; // pcap_create failed, nothing more to do.
    }

    // Set capture parameters based on fuzzer input.
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
        pcap_set_timeout(p, *(const int*)data);
        data += sizeof(int);
        size -= sizeof(int);
    }

    struct bpf_program fp;
    int compile_result = -1;

    // Create a filter string from fuzzer data, ensuring it's null-terminated.
    char filter_str[129];
    const size_t filter_len = size > 128 ? 128 : size;
    memcpy(filter_str, data, filter_len);
    filter_str[filter_len] = '\0';

    /*
     * ANALYSIS: The coverage report for pcap_compile shows that the branch
     *           checking if a pcap_t is activated (`if (!p->activated)`)
     *           is never taken.
     * IMPLEMENTATION: We use a control flow byte from the fuzzer input to
     *                 sometimes call pcap_compile() on a handle that has been
     *                 created but not yet activated. This exercises the error path.
     */
    if (control_flow & 0x1) {
        compile_result = pcap_compile(p, &fp, filter_str, 0, PCAP_NETMASK_UNKNOWN);
        if (compile_result == 0) {
            // Must free the code if compilation succeeded.
            pcap_freecode(&fp);
        }
    }

    // Attempt to activate the handle. This may fail with fuzzed device names,
    // which is desirable for testing error paths.
    const int activation_status = pcap_activate(p);

    if (activation_status >= 0) {
        // If activation succeeded, set non-blocking mode to avoid timeouts in pcap_loop.
        if (pcap_setnonblock(p, 1, errbuf) == -1) {
            pcap_close(p);
            return 0;
        }

        // If activation succeeded, proceed with filter setting and packet capture.
        compile_result = pcap_compile(p, &fp, filter_str, 0, PCAP_NETMASK_UNKNOWN);

        if (compile_result == 0) {
            /*
             * ANALYSIS: The line coverage report for pcap_setfilter_linux shows
             *           that the null check `if (!filter)` is never hit.
             * IMPLEMENTATION: We use a control flow byte to sometimes call
             *                 pcap_setfilter() with a NULL pointer for the
             *                 filter program to exercise this error path.
             */
            if (control_flow & 0x2) {
                pcap_setfilter(p, NULL);
            } else {
                pcap_setfilter(p, &fp);
            }
            // The filter is copied by pcap_setfilter, so we must free our copy.
            pcap_freecode(&fp);
        }

        /*
         * ANALYSIS: The coverage report for pcap_loop shows that only the offline
         *           code path (`if (p->rfile != NULL)`) is ever executed. The live
         *           capture path (`else { ... p->read_op ... }`) is never taken.
         * IMPLEMENTATION: By calling pcap_loop() on a handle initialized with
         *                 pcap_create() and pcap_activate(), we ensure `p->rfile`
         *                 is NULL, thus exercising the live capture code path.
         */
        const int loop_count = (control_flow >> 2) % 10;
        pcap_loop(p, loop_count, dummy_handler, NULL);
    }

    // Crucial cleanup: close the handle to free all associated resources.
    pcap_close(p);

    // Also exercise pcap_findalldevs and pcap_freealldevs to improve their coverage.
    pcap_if_t *alldevs;
    if (pcap_findalldevs(&alldevs, errbuf) == 0) {
        pcap_freealldevs(alldevs);
    }

    return 0;
}