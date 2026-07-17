#include <pcap.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>

// A simple data provider to safely consume fuzzer data.
typedef struct {
    const uint8_t *data;
    size_t size;
    size_t offset;
} fuzz_data_provider_t;

// Safely consume a boolean value.
static bool consume_boolean(fuzz_data_provider_t *fdp) {
    if (fdp->offset >= fdp->size) {
        return false;
    }
    return fdp->data[fdp->offset++] % 2 == 0;
}

// Safely consume an integer value.
static int consume_int(fuzz_data_provider_t *fdp) {
    if (fdp->offset + sizeof(int) > fdp->size) {
        return 0;
    }
    int value;
    memcpy(&value, fdp->data + fdp->offset, sizeof(int));
    fdp->offset += sizeof(int);
    return value;
}

// Safely consume a string. The caller is responsible for freeing the memory.
static char* consume_string(fuzz_data_provider_t *fdp, size_t max_len) {
    if (fdp->offset >= fdp->size) {
        return NULL;
    }
    size_t len = fdp->data[fdp->offset] % (max_len + 1);
    fdp->offset++;
    if (fdp->offset + len > fdp->size) {
        return NULL;
    }
    char *str = (char *)malloc(len + 1);
    if (str == NULL) {
        return NULL;
    }
    memcpy(str, fdp->data + fdp->offset, len);
    str[len] = '\0';
    fdp->offset += len;
    return str;
}


int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    fuzz_data_provider_t fdp = {data, size, 0};
    char errbuf[PCAP_ERRBUF_SIZE];

    /*
     * ANALYSIS: The function-level coverage report shows pcap_findalldevs
     *           has relatively low coverage. While its error paths are hard
     *           to trigger, calling it exercises the core device enumeration
     *           logic and its helpers (e.g., pcapint_add_addr_to_dev).
     * IMPLEMENTATION: Call pcap_findalldevs() and ensure the resulting list
     *                 is always freed with pcap_freealldevs() to prevent
     *                 memory leaks.
     */
    pcap_if_t *alldevs;
    if (pcap_findalldevs(&alldevs, errbuf) == 0 && alldevs != NULL) {
        pcap_freealldevs(alldevs);
    }

    char *dev_name = consume_string(&fdp, 256);
    if (dev_name == NULL) {
        return 0;
    }

    pcap_t *p;
    if (consume_boolean(&fdp)) {
        /*
         * ANALYSIS: The line-level coverage for pcap_create shows the
         *           `if (device == NULL)` branch is never taken.
         * IMPLEMENTATION: Call pcap_create with a NULL device to cover this
         *                 untested branch.
         */
        p = pcap_create(NULL, errbuf);
    } else {
        /*
         * ANALYSIS: The error path for a failing pcapint_create_interface
         *           call inside pcap_create is not covered.
         * IMPLEMENTATION: Use a fuzzer-generated string as a device name,
         *                 which is likely to be invalid and thus trigger the
         *                 intended failure path.
         */
        p = pcap_create(dev_name, errbuf);
    }

    if (p != NULL) {
        /*
         * ANALYSIS: The line-level coverage report for pcap_set_tstamp_type
         *           shows the `if (tstamp_type < 0)` branch is not always
         *           exercised. Additionally, the loop for checking supported
         *           timestamp types is completely uncovered because
         *           `p->tstamp_type_count` is always zero in existing tests.
         * IMPLEMENTATION: We call pcap_set_tstamp_type with both a hardcoded
         *                 negative value and a fuzzer-derived value. Using a
         *                 handle from pcap_create may populate the timestamp
         *                 type list, allowing the fuzzer to explore the
         *                 previously uncovered loop.
         */
        if (consume_boolean(&fdp)) {
            pcap_set_tstamp_type(p, -1); // Target the negative input case.
        } else {
            pcap_set_tstamp_type(p, consume_int(&fdp)); // Target the type-checking loop.
        }
        // Cleanup: A handle created by pcap_create must be closed.
        pcap_close(p);
    }

    // Define parameters for pcap_open
    int snaplen = consume_int(&fdp) % 65535;
    int to_ms = consume_int(&fdp) % 2000;
    int flags = 0;

    if (consume_boolean(&fdp)) {
        /*
         * ANALYSIS: The coverage report for pcap_open reveals that the
         *           `PCAP_OPENFLAG_MAX_RESPONSIVENESS` flag is never used.
         * IMPLEMENTATION: Explicitly add this flag to the open call to
         *                 exercise the corresponding code path.
         */
        flags |= PCAP_OPENFLAG_MAX_RESPONSIVENESS;
    }

    pcap_t *p2;
    if (consume_boolean(&fdp)) {
        /*
         * ANALYSIS: Similar to pcap_create, the line-level coverage for
         *           pcap_open shows the `if (source == NULL)` branch is
         *           never taken.
         * IMPLEMENTATION: Call pcap_open with a NULL source, which should
         *                 default to the "any" device and cover the branch.
         */
        p2 = pcap_open(NULL, snaplen, flags, to_ms, NULL, errbuf);
    } else {
        p2 = pcap_open(dev_name, snaplen, flags, to_ms, NULL, errbuf);
    }

    if (p2 != NULL) {
        // Cleanup: A handle from pcap_open must be closed.
        pcap_close(p2);
    }

    // Final cleanup for the allocated device name string.
    free(dev_name);
    return 0;
}