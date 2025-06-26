#include <pcap.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

// Dummy callback handler
void dummy_handler(u_char *user, const struct pcap_pkthdr *h, const u_char *bytes) {
    (void)user;
    (void)h;
    (void)bytes;
}

// This fuzzer targets several currently uncovered functions in libpcap,
// focusing on Linux-specific and USB-related functionalities.
// The main goal is to increase code coverage by exercising error paths
// and diverse API call sequences that are not reached by existing fuzzers.
int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    if (size < 1) {
        return 0;
    }

    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t *p;
    char dev[] = "lo"; // Use the loopback device for simplicity

    // Create a pcap handle. This is the first step for most pcap operations.
    p = pcap_create(dev, errbuf);
    if (p == NULL) {
        return 0;
    }

    // Target: pcap_set_protocol_linux
    // This function is Linux-specific and sets the protocol for the capture.
    // It's important to test this before activation to ensure the option is correctly handled.
    // We use a value from the fuzzer input to test different protocol settings.
    pcap_set_protocol_linux(p, data[0]);

    // Target: pcap_can_set_rfmon
    // This function checks if monitor mode can be set on the device.
    // It's often a source of errors if the device doesn't support it.
    // Calling it here helps cover the error handling paths.
    pcap_can_set_rfmon(p);

    // Target: iface_get_mtu
    // This function is not directly exposed via the public API, but is an important internal function.
    // We can't call it directly, but by activating the handle, we can trigger its execution path.
    // The activation process will internally determine the MTU.

    // Target: iface_get_offload
    // Similar to iface_get_mtu, this is an internal function.
    // Activating the handle will trigger its path.

    // Target: map_arphrd_to_dlt
    // This internal function maps hardware types to data link types.
    // It has a large switch statement that is a prime candidate for coverage-guided fuzzing.
    // By activating the handle, we trigger this function. The fuzzer input can influence
    // the conditions that lead to different cases in the switch being hit.
    if (pcap_activate(p) == 0) {
        // If activation is successful, we can proceed with other operations.
        // Set non-blocking mode to prevent the fuzzer from hanging while waiting for packets.
        if (pcap_setnonblock(p, 1, errbuf) == 0) {
            // We'll just read a single packet to exercise the read path.
            pcap_dispatch(p, 1, dummy_handler, NULL);
        }
    }

    // Clean up the pcap handle. This is crucial to avoid resource leaks.
    pcap_close(p);

    return 0;
}