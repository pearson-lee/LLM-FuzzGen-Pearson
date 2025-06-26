#include <pcap/pcap.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

// This fuzz target aims to improve coverage by exercising API functions
// on pcap_t handles that are in specific, non-default states:
// 1. "Uninitialized": Created with pcap_create() but not yet activated.
//    Calling most I/O or state-setting functions should fail and trigger
//    the corresponding "*_not_initialized" error handlers, which are currently
//    uncovered.
// 2. "Dead": Created with pcap_open_dead() for offline filter compilation
//    and analysis. Certain operations are not permitted on these handles
//    and should trigger the corresponding "*_dead" error handlers.

// Dummy callback handler required for pcap_loop and pcap_dispatch.
void dummy_handler(u_char *user, const struct pcap_pkthdr *h, const u_char *bytes) {
    // This handler does nothing, as we are not expecting any packets from
    // uninitialized or dead pcap handles.
}

int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size) {
    // Require a minimum amount of data to avoid trivial cases and provide
    // enough bytes for various parameters.
    if (Size < 20) {
        return 0;
    }

    // --- Scenario 1: Test functions on an uninitialized pcap_t handle ---
    // This state is achieved by calling pcap_create() without a subsequent
    // pcap_activate(). This is a valid intermediate state, and the library
    // should handle API calls gracefully.
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t *p_uninit = pcap_create("any", errbuf);

    if (p_uninit) {
        // Target: pcap_set_datalink_not_initialized (0% coverage)
        // Attempt to set the datalink type on the unactivated handle.
        int datalink_to_set = Data[0];
        pcap_set_datalink(p_uninit, datalink_to_set);

        // Target: pcap_stats_not_initialized (0% coverage)
        // Attempt to get statistics from the unactivated handle.
        struct pcap_stat stats;
        pcap_stats(p_uninit, &stats);

        // Target: pcap_getnonblock_not_initialized (0% coverage)
        // Attempt to get the non-blocking status.
        pcap_getnonblock(p_uninit, errbuf);

        // Target: pcap_inject_not_initialized (0% coverage)
        // Attempt to inject a packet.
        const uint8_t dummy_packet[] = {0xDE, 0xAD, 0xBE, 0xEF};
        pcap_inject(p_uninit, dummy_packet, sizeof(dummy_packet));

        // Target: pcap_cant_set_rfmon (0% coverage)
        // Added based on coverage report. This call on an unactivated handle
        // should trigger the default pcap_cant_set_rfmon function.
        pcap_set_rfmon(p_uninit, 1);

        // Target: pcap_setnonblock_unactivated (0% coverage)
        // Added based on coverage report. This call on an unactivated handle
        // should trigger pcap_setnonblock_unactivated.
        pcap_setnonblock(p_uninit, 1, errbuf);

        // Target: pcap_setfilter_not_initialized (0% coverage)
        // pcap_compile is allowed on an uninitialized handle, but pcap_setfilter is not.
        // We compile a filter and then try to set it.
        struct bpf_program prog;
        // Modified to use a static, valid filter. The original fuzzer used random
        // data which almost never resulted in a valid filter, preventing
        // pcap_compile from succeeding and thus never reaching pcap_setfilter.
        const char *filter_str = "ip";

        if (pcap_compile(p_uninit, &prog, filter_str, 1, PCAP_NETMASK_UNKNOWN) == 0) {
            // This call should fail and hit the target function.
            pcap_setfilter(p_uninit, &prog);
            // Free the compiled program regardless of setfilter's success.
            pcap_freecode(&prog);
        }

        // Clean up the pcap_t handle to prevent memory leaks.
        pcap_close(p_uninit);
    }

    // --- Scenario 2: Test functions on a "dead" pcap_t handle ---
    // This handle is for offline processing. We test operations that are invalid
    // in this state.
    int linktype = Data[1];
    int snaplen = 2048; // A reasonable default snapshot length.
    pcap_t *p_dead = pcap_open_dead(linktype, snaplen);

    if (p_dead) {
        // Target: pcap_set_datalink_dead (0% coverage)
        // Attempting to set the datalink on a dead pcap_t after creation is an error.
        int new_datalink = Data[2];
        pcap_set_datalink(p_dead, new_datalink);

        // Exercise the "dead" read path, which should do nothing and return immediately.
        pcap_loop(p_dead, 5, dummy_handler, NULL);
        pcap_dispatch(p_dead, 5, dummy_handler, NULL);

        // Clean up the pcap_t handle to prevent memory leaks.
        pcap_close(p_dead);
    }

    return 0;
}