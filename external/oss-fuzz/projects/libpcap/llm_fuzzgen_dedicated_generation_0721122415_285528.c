/* BLOCKER_STRATEGY_CONTRACT
required_state: getifaddrs() must return a non-zero value.
state_constructor: A fuzzer-controlled `getifaddrs` function is defined with `__attribute__((weak))`. This mock function's return value is determined by the fuzzer input. When the input dictates failure, the mock function returns -1 and sets `errno`.
trigger_api: pcap_findalldevs() is called, which follows the call chain `pcap_findalldevs` -> `pcapint_platform_finddevs` -> `pcapint_findalldevs_interfaces`, where the mock `getifaddrs()` is invoked.
preserved_invariants: The fuzzer must call `pcap_findalldevs()`. The weak `getifaddrs` symbol override must be present to control the predicate.
END_BLOCKER_STRATEGY_CONTRACT */

#include <pcap/pcap.h>
#include <ifaddrs.h>
#include <errno.h>
#include <stdint.h>
#include <stddef.h>
#include <stdlib.h>

// Fuzzer-controlled flag to determine if getifaddrs should fail.
static int g_should_getifaddrs_fail = 0;

// Override getifaddrs using a weak symbol. This allows the linker to
// replace the standard library's implementation with our own. This is a
// standard technique for testing system call failure paths.
__attribute__((weak))
int getifaddrs(struct ifaddrs **ifap) {
    if (g_should_getifaddrs_fail) {
        // Simulate a failure. EACCES is one of the documented errors for getifaddrs.
        errno = EACCES;
        return -1;
    }

    // In the success case, we don't need to provide a real list of interfaces.
    // We can just return success with an empty list, as the fuzzer's goal
    // is to trigger the failure path, not to test the success path logic.
    *ifap = NULL;
    return 0;
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    if (size < 1) {
        return 0;
    }

    // Use the first byte of input to decide if our mock getifaddrs() should fail.
    g_should_getifaddrs_fail = (data[0] & 1);

    pcap_if_t *alldevs = NULL;
    char errbuf[PCAP_ERRBUF_SIZE];

    // This call chain leads to the blocker:
    // pcap_findalldevs -> pcapint_platform_finddevs -> pcapint_findalldevs_interfaces
    // Inside pcapint_findalldevs_interfaces, our mock getifaddrs is called.
    int ret = pcap_findalldevs(&alldevs, errbuf);

    if (ret == 0 && alldevs != NULL) {
        // If the call succeeded (i.e., getifaddrs didn't fail),
        // we must free the device list to prevent memory leaks.
        pcap_freealldevs(alldevs);
    }

    return 0;
}