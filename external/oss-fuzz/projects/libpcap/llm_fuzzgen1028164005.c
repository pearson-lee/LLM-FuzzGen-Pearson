#include <stdint.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h> // For unlink

// Include libpcap headers
#include "/src/libpcap/pcap/pcap.h"
// No need for pcap-int.h as we avoid direct manipulation of internal structures.

// Macro for unique temporary filenames, though not strictly used in this specific fuzzer.
// Keeping it for adherence to the general principle for file I/O.
#ifndef _FUZZ_TARGET_NAME
#define _FUZZ_TARGET_NAME "libpcap_fuzzer" // Fallback name
#endif

extern int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size) {
    // Ensure we have enough data for various operations
    if (Size < 10) {
        return 0;
    }

    // Use a portion of the fuzzed data for different purposes
    const uint8_t *data_ptr = Data;
    size_t data_remaining = Size;

    // --- Fuzzing pcap_compile for filter expressions ---
    // This targets gen_greater, gen_less, pfreason_to_num, pfaction_to_num
    /*
     * ANALYSIS: The function-level coverage report showed 0% coverage for
     *           gen_greater, gen_less, pfreason_to_num, and pfaction_to_num.
     *           Further investigation showed pfreason_to_num and pfaction_to_num
     *           are called by str2tok, which returns -1 if the string is not found
     *           in its lookup tables (pflog_reasons, pflog_actions). gen_greater
     *           and gen_less are called when parsing '>' and '<' operators in filters.
     * IMPLEMENTATION: We use pcap_compile with various filter strings.
     *                 A portion of the input data is used as the filter string.
     *                 We also prepend specific strings to trigger the uncovered paths:
     *                 - "pflog and reason invalid_reason" and "pflog and action invalid_action"
     *                   to trigger the error branches in pfreason_to_num/pfaction_to_num.
     *                 - "ip > 10" and "len < 100" to trigger gen_greater/gen_less.
     */
    pcap_t *pcap_handle_compile = NULL;
    struct bpf_program fp;
    char errbuf[PCAP_ERRBUF_SIZE]; // Required by pcap_create, pcap_open_live etc.

    // Create a dummy pcap_t for compilation. pcap_open_dead is suitable as it doesn't require a real device.
    pcap_handle_compile = pcap_open_dead(DLT_EN10MB, 65535); // Ethernet, max snaplen
    if (pcap_handle_compile == NULL) {
        return 0; // Handle allocation failure
    }

    // Attempt compilation with a fuzzed filter string
    // Use a portion of the fuzzed data as the filter string
    size_t filter_len = data_remaining / 3; // Allocate roughly a third of the data for this
    if (filter_len > 0) {
        char *filter_str = (char *)malloc(filter_len + 1);
        if (filter_str == NULL) {
            pcap_close(pcap_handle_compile); // Free allocated pcap_t
            return 0; // Handle allocation failure
        }
        // CRITICAL: Ensure the buffer is fully populated and null-terminated
        memcpy(filter_str, data_ptr, filter_len);
        filter_str[filter_len] = '\0';

        // Attempt compilation. If successful, free the compiled code.
        if (pcap_compile(pcap_handle_compile, &fp, filter_str, 1, PCAP_NETMASK_UNKNOWN) == 0) {
            pcap_freecode(&fp); // Free compiled filter
        }
        free(filter_str); // Free filter string
    }
    data_ptr += filter_len;
    data_remaining -= filter_len;

    // Specific filters to hit uncovered branches in pfreason_to_num/pfaction_to_num
    const char *invalid_pf_filter_reason = "pflog and reason invalid_reason";
    if (pcap_compile(pcap_handle_compile, &fp, invalid_pf_filter_reason, 1, PCAP_NETMASK_UNKNOWN) == 0) {
        pcap_freecode(&fp);
    }

    const char *invalid_pf_filter_action = "pflog and action invalid_action";
    if (pcap_compile(pcap_handle_compile, &fp, invalid_pf_filter_action, 1, PCAP_NETMASK_UNKNOWN) == 0) {
        pcap_freecode(&fp);
    }

    // Specific filters with comparison operators for gen_greater/gen_less
    const char *greater_filter = "ip > 10";
    if (pcap_compile(pcap_handle_compile, &fp, greater_filter, 1, PCAP_NETMASK_UNKNOWN) == 0) {
        pcap_freecode(&fp);
    }

    const char *less_filter = "len < 100";
    if (pcap_compile(pcap_handle_compile, &fp, less_filter, 1, PCAP_NETMASK_UNKNOWN) == 0) {
        pcap_freecode(&fp);
    }

    pcap_close(pcap_handle_compile); // Close the pcap_t handle for compilation

    // --- Fuzzing pcap_create and pcap_activate for pcap_can_set_rfmon_linux ---
    /*
     * ANALYSIS: pcap_can_set_rfmon_linux had 0% coverage. To hit its internal
     *           'return (0)' branch, p->opt.rfmon needs to be true, and
     *           p->linktype_ext and p->dlt_force need to be 0.
     * IMPLEMENTATION: We create a pcap handle, set monitor mode with pcap_set_rfmon(p, 1),
     *                 and then call pcap_activate to trigger the internal logic.
     *                 We use a dummy interface name "any" to allow creation.
     */
    pcap_t *pcap_handle_rfmon = NULL;
    char *dev_name = "any"; // Use a generic device name

    pcap_handle_rfmon = pcap_create(dev_name, errbuf);
    if (pcap_handle_rfmon != NULL) {
        // Set monitor mode. This sets p->opt.rfmon to 1.
        if (pcap_set_rfmon(pcap_handle_rfmon, 1) == 0) {
            // Activate the handle to trigger pcap_can_set_rfmon_linux.
            // p->linktype_ext and p->dlt_force are typically 0 by default.
            pcap_activate(pcap_handle_rfmon);
        }
        pcap_close(pcap_handle_rfmon); // Close the pcap_t handle
    }

    // --- Fuzzing pcap_inject for usb_inject_linux ---
    /*
     * ANALYSIS: usb_inject_linux had 0% coverage. It's an internal function
     *           called when pcap_inject is used on a USB device. The function
     *           itself is simple and just returns an error.
     * IMPLEMENTATION: We call pcap_inject on a pcap_t handle opened as a USB_LINUX
     *                 device type. While this doesn't guarantee a real USB device
     *                 interaction, it directs libpcap's internal dispatch towards
     *                 USB-specific code paths, aiming to hit usb_inject_linux.
     */
    pcap_t *pcap_handle_inject = NULL;
    // Attempt to open a dead handle with a USB DLT to direct internal logic towards USB
    pcap_handle_inject = pcap_open_dead(DLT_USB_LINUX, 65535);
    if (pcap_handle_inject != NULL) {
        // Use remaining fuzzed data for the packet to inject
        size_t inject_len = data_remaining;
        if (inject_len > 0) {
            // CRITICAL: Ensure data_ptr points to valid memory and inject_len is correct
            pcap_inject(pcap_handle_inject, data_ptr, inject_len);
        }
        pcap_close(pcap_handle_inject); // Close the pcap_t handle
    }

    return 0;
}