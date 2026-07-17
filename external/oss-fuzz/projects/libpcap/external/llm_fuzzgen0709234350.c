#include <stdint.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>
#include <pcap/pcap.h>
#include <pcap/bpf.h>

// Helper macro to safely consume data from the fuzzing input
#define CONSUME_DATA(type, data, size, dest) \
    do { \
        if (size < sizeof(type)) { \
            return 0; \
        } \
        dest = *(type*)data; \
        data += sizeof(type); \
        size -= sizeof(type); \
    } while (0)

int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size) {
    if (Size < 1) {
        return 0;
    }

    char errbuf[PCAP_ERRBUF_SIZE];

    /*
     * ANALYSIS: The function-level coverage report showed pcap_findalldevs
     *           had 0% coverage.
     * IMPLEMENTATION: The following code block calls pcap_findalldevs to
     *                 discover network interfaces. The resulting list is
     *                 freed immediately to ensure no memory leaks. This
     *                 exercises the device enumeration code paths.
     */
    pcap_if_t *alldevs;
    if (pcap_findalldevs(&alldevs, errbuf) == 0) {
        pcap_freealldevs(alldevs);
    }

    // Consume data for parameters
    int linktype;
    int snaplen;
    int optimize;
    int new_snaplen, promisc, timeout, buffer_size;
    CONSUME_DATA(int, Data, Size, linktype);
    CONSUME_DATA(int, Data, Size, snaplen);
    CONSUME_DATA(int, Data, Size, optimize);
    /*
     * IMPLEMENTATION: Consume additional integer values from the fuzzer input
     *                 to be used as parameters for the newly covered pcap_set_*
     *                 functions.
     */
    CONSUME_DATA(int, Data, Size, new_snaplen);
    CONSUME_DATA(int, Data, Size, promisc);
    CONSUME_DATA(int, Data, Size, timeout);
    CONSUME_DATA(int, Data, Size, buffer_size);
    
    // Ensure snaplen is non-negative
    if (snaplen < 0) {
        snaplen = -snaplen;
    }

    /*
     * ANALYSIS: The function-level coverage report showed pcap_open_dead
     *           had only 50% branch coverage, and pcap_compile had low
     *           coverage (65.91% line, 60.53% branch).
     * IMPLEMENTATION: A "dead" pcap handle is created with fuzzer-driven
     *                 parameters. This handle is then used to compile a
     *                 filter from the remaining fuzzer data. This allows
     *                 fuzzing of the extensive filter compilation logic
     *                 without requiring a live network device.
     */
    pcap_t *p = pcap_open_dead(linktype, snaplen);
    if (p == NULL) {
        return 0;
    }

    // The rest of the data is treated as the filter string.
    // Ensure it's null-terminated.
    char *filter_str = (char *)malloc(Size + 1);
    if (filter_str == NULL) {
        pcap_close(p);
        return 0;
    }
    memcpy(filter_str, Data, Size);
    filter_str[Size] = '\0';

    struct bpf_program fp;
    if (pcap_compile(p, &fp, filter_str, optimize, PCAP_NETMASK_UNKNOWN) == 0) {
        /*
         * ANALYSIS: Functions related to setting filters, such as
         *           pcap_setfilter_dead, showed 0% coverage.
         * IMPLEMENTATION: If the filter compilation is successful, this block
         *                 calls pcap_setfilter on the "dead" handle. This
         *                 specifically exercises the pcap_setfilter_dead
         *                 implementation and its associated code paths.
         */
        pcap_setfilter(p, &fp);

        /*
         * ANALYSIS: The function bpf_dump, used for printing a compiled
         *           filter in a human-readable format, had 0% coverage.
         * IMPLEMENTATION: This call to bpf_dump exercises the filter
         *                 dumping logic. The option '1' requests a
         *                 more detailed output.
         */
        bpf_dump(&fp, 1);

        pcap_freecode(&fp);
    }

    /*
     * ANALYSIS: The core functions pcap_create and pcap_activate both had
     *           0% coverage. These are essential for initializing a capture.
     * IMPLEMENTATION: This block attempts to create and activate a pcap
     *                 handle using the same fuzzer-provided string as a
     *                 device name. While activation will likely fail (as the
     *                 device doesn't exist), this effectively fuzzes the
     *                 error-handling and initialization paths of both
     *                 functions.
     */
    pcap_t *p_live = pcap_create(filter_str, errbuf);
    if (p_live != NULL) {
        /*
         * ANALYSIS: The function-level coverage report showed many pcap_set_*
         *           functions like pcap_set_snaplen, pcap_set_promisc, etc.,
         *           had 0% coverage. These functions are intended to be called
         *           between pcap_create() and pcap_activate().
         * IMPLEMENTATION: The following block calls these configuration
         *                 functions on the newly created handle before activation,
         *                 using fuzzer-driven values. This exercises the
         *                 pre-activation setup paths.
         */
        pcap_set_snaplen(p_live, new_snaplen);
        pcap_set_promisc(p_live, promisc);
        pcap_set_timeout(p_live, timeout);
        pcap_set_buffer_size(p_live, buffer_size);

        /*
         * ANALYSIS: The functions pcap_list_datalinks and pcap_list_tstamp_types
         *           (and their corresponding free functions) had 0% coverage.
         * IMPLEMENTATION: This block calls the functions to list available
         *                 datalink and timestamp types, and then frees the
         *                 resulting lists, exercising the enumeration and
         *                 memory management for these features.
         */
        int *dlt_buf;
        if (pcap_list_datalinks(p_live, &dlt_buf) >= 0) {
            pcap_free_datalinks(dlt_buf);
        }
        int *tstamp_buf;
        if (pcap_list_tstamp_types(p_live, &tstamp_buf) >= 0) {
            pcap_free_tstamp_types(tstamp_buf);
        }

        // Attempt to activate. This will likely fail but exercises the code.
        pcap_activate(p_live);
        pcap_close(p_live);
    }

    // Cleanup
    free(filter_str);
    pcap_close(p);

    return 0;
}