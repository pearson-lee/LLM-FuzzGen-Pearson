#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <errno.h>

#include "/src/libpcap/pcap/pcap.h"
#include "/src/libpcap/pcap/bpf.h"
#include "/src/libpcap/pcap/dlt.h"
// No need for pcap-int.h as compiler_state_t is internal to libpcap and not directly manipulated by the fuzzer.

// Define a simple structure to simulate FuzzedDataProvider for C
// This structure holds the fuzzer's input data and tracks the current offset.
typedef struct {
    const uint8_t *data;
    size_t size;
    size_t offset;
} FuzzerData;

// Function to consume a certain number of bytes from the fuzzer's input.
// Returns a pointer to the consumed bytes or NULL if not enough data is available.
const uint8_t *ConsumeBytes(FuzzerData *fdp, size_t num_bytes) {
    if (fdp->offset + num_bytes > fdp->size) {
        return NULL;
    }
    const uint8_t *result = fdp->data + fdp->offset;
    fdp->offset += num_bytes;
    return result;
}

// Function to consume a string from the fuzzer's input.
// It reads up to `max_len` bytes or until a null terminator is found.
// The returned string is dynamically allocated and must be freed by the caller.
char *ConsumeString(FuzzerData *fdp, size_t max_len) {
    size_t remaining_size = fdp->size - fdp->offset;
    size_t len_to_read = remaining_size < max_len ? remaining_size : max_len;

    // Find null terminator or end of data within the allowed length
    size_t actual_len = 0;
    while (actual_len < len_to_read && fdp->data[fdp->offset + actual_len] != '\0') {
        actual_len++;
    }

    char *str = (char *)malloc(actual_len + 1);
    if (!str) {
        return NULL;
    }
    memcpy(str, fdp->data + fdp->offset, actual_len);
    str[actual_len] = '\0'; // Null-terminate the string

    fdp->offset += actual_len; // Consume the string bytes
    // Consume the null terminator if it was explicitly present in the fuzzer input
    if (fdp->offset < fdp->size && fdp->data[fdp->offset] == '\0') {
        fdp->offset++;
    }
    return str;
}

// Function to consume a pseudo-random integer from the fuzzer's input.
// It uses a byte from the input to generate a value, ensuring it doesn't read past the end.
int ConsumeInt(FuzzerData *fdp) {
    if (fdp->offset + 1 > fdp->size) {
        return 0; // Not enough data, return a default value
    }
    int val = fdp->data[fdp->offset];
    fdp->offset++;
    return val;
}

// List of Data Link Types (DLT) to randomly choose from, covering various network types.
const int dlt_types[] = {
    DLT_EN10MB,        // Ethernet
    DLT_RAW,           // Raw IP
    DLT_ARCNET,        // ARCnet - for gen_acode coverage
    DLT_FDDI,          // FDDI - for gen_multicast coverage
    DLT_IEEE802,       // Token Ring - for gen_multicast coverage
    DLT_IEEE802_11,    // 802.11 Wireless - for gen_multicast coverage
    DLT_IP_OVER_FC,    // IP over Fibre Channel - for gen_multicast coverage
    DLT_ATM_RFC1483,   // ATM LANE - for gen_atmtype_abbrev coverage
    DLT_LINUX_SLL,     // Linux cooked-mode capture
    DLT_NULL,          // BSD loopback encapsulation
    DLT_LOOP,          // OpenBSD loopback encapsulation
    DLT_PPP,           // Point-to-Point Protocol
    DLT_C_HDLC,        // Cisco HDLC - for ISO protocol in gen_proto
    DLT_ATM_CLIP,      // Classical IP over ATM - for gen_atmtype_abbrev coverage
};
const size_t num_dlt_types = sizeof(dlt_types) / sizeof(dlt_types[0]);

// List of filter keywords and components to construct diverse filter strings.
// This list is designed to hit various lexical tokens and grammar rules in pcap_lex and pcap_parse,
// and to trigger specific code generation functions like gen_protochain, gen_multicast, etc.
const char *filter_keywords[] = {
    "host", "net", "port", "tcp", "udp", "ip", "ip6", "and", "or", "not",
    "sctp", "igmp", "igrp", "pim", "carp", "icmp6", "esp", "iso", "esis", "isis",
    "clnp", "ipx", "netbeui", "l1", "l2", "iih", "lsp", "snp", "csnp", "psnp",
    "radio", "pf_ifname", "pf_rset", "pf_rnr", "pf_srnr", "pf_reason", "pf_action",
    "type", "subtype", "dir", "addr1", "addr2", "addr3", "addr4", "ra", "ta",
    "less", "greater", "byte", "broadcast", "multicast", "protochain", "aid",
    "ether", "arp", "rarp", "vlan", "mpls", "pppoed", "pppoes", "geneve",
    "atm", "metac", "bcc", "oam", "oamf4", "oamf4ec", "oamf4sc", "sc", "ilmic",
    "vpi", "vci", "connectmsg", "metaconnect", "len", "inbound", "outbound", "ifindex",
    "portrange",
    "1", "10", "100", "12345", "65535", // Numbers
    "1.2.3.4", "255.255.255.0",         // IPv4 addresses/masks
    "::1", "fe80::1", "2001:0db8:85a3:0000:0000:8a2e:0370:7334", // IPv6 addresses
    "00:11:22:33:44:55",                // MAC addresses
    "foo", "bar", "long_interface_name_that_might_cause_overflow_if_not_handled_properly_in_some_ancient_buffer", // Random strings
    "=", ">", "<", ">=", "<=", "!=", "<<", ">>", "+", "-", "*", "/", "%", "&", "|", "^", // Operators
    "src", "dst", // for host/net/port
};
const size_t num_filter_keywords = sizeof(filter_keywords) / sizeof(filter_keywords[0]);

// Helper function to build a diverse filter string from fuzzer data.
// It randomly selects keywords, numbers, and operators to construct a filter expression.
char *BuildFilterString(FuzzerData *fdp, size_t max_len) {
    size_t current_len = 0;
    char *filter_str = (char *)malloc(max_len + 1);
    if (!filter_str) {
        return NULL;
    }
    filter_str[0] = '\0'; // Initialize as an empty string

    // Loop to append components to the filter string
    while (fdp->offset < fdp->size && current_len < max_len) {
        // Randomly decide to add a keyword/operator or a number/address
        // Use a byte from fuzzer data for decision to ensure determinism
        int choice = ConsumeInt(fdp);
        if (choice == 0) { // Not enough data for a choice
            break;
        }

        if (choice % 3 != 0) { // Bias towards keywords/operators
            const char *keyword = filter_keywords[choice % num_filter_keywords];
            size_t keyword_len = strlen(keyword);
            if (current_len + keyword_len + 1 < max_len) {
                strcat(filter_str, keyword);
                strcat(filter_str, " ");
                current_len += keyword_len + 1;
            } else {
                break;
            }
        } else { // Add a number or address
            if (current_len + 32 < max_len) { // Enough space for a number or short address
                char num_buf[64];
                // Consume more data for a larger random number
                uint32_t val;
                const uint8_t *bytes = ConsumeBytes(fdp, sizeof(uint32_t));
                if (bytes) {
                    memcpy(&val, bytes, sizeof(uint32_t));
                } else {
                    val = 0; // Default if not enough bytes
                }
                snprintf(num_buf, sizeof(num_buf), "%u", val);
                strcat(filter_str, num_buf);
                strcat(filter_str, " ");
                current_len += strlen(num_buf) + 1;
            } else {
                break;
            }
        }

        // Randomly add parentheses to create more complex expressions
        if (fdp->offset < fdp->size && ConsumeInt(fdp) % 5 == 0) {
            if (current_len + 2 < max_len) {
                if (ConsumeInt(fdp) % 2 == 0) {
                    strcat(filter_str, "( ");
                } else {
                    strcat(filter_str, ") ");
                }
                current_len += 2;
            }
        }
    }
    return filter_str;
}

// Main fuzzer entry point
int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size) {
    FuzzerData fdp = {Data, Size, 0};

    pcap_t *pcap_handle = NULL;
    struct bpf_program fp;
    char errbuf[PCAP_ERRBUF_SIZE];
    char *filter_string = NULL;

    // Ensure there's at least enough data for basic operations
    if (Size < 5) { // Minimum for linktype, snaplen, optimize, netmask, and a tiny bit for filter string
        return 0;
    }

    // 1. Select a random link type and snaplen using fuzzer data
    int linktype = dlt_types[ConsumeInt(&fdp) % num_dlt_types];
    int snaplen_val = ConsumeInt(&fdp); // Use a byte for snaplen
    int snaplen = (snaplen_val << 8) | ConsumeInt(&fdp); // Combine two bytes for a wider range up to 65535
    if (snaplen == 0) snaplen = 65535; // Avoid snaplen 0 as it rejects all packets

    /*
     * ANALYSIS: The function-level coverage report showed pcap_compile had a branch
     *           with zero hits when p->activated is false (line 733 in gencode.c).
     * IMPLEMENTATION: pcap_open_dead creates a pcap_t handle that is not yet activated.
     *                 This ensures that the `if (!p->activated)` branch in pcap_compile
     *                 is exercised if pcap_compile is called with such a handle.
     */
    pcap_handle = pcap_open_dead(linktype, snaplen);
    if (pcap_handle == NULL) {
        // If pcap_open_dead fails, there's not much more we can do.
        return 0;
    }

    // 2. Generate a filter string using fuzzer data
    // Limit max filter string length to prevent excessive memory allocation and long execution times
    size_t max_filter_len = (Size > 2048) ? 2048 : Size;
    filter_string = BuildFilterString(&fdp, max_filter_len);
    if (!filter_string) {
        pcap_close(pcap_handle);
        return 0;
    }

    // ANALYSIS: pcap_compile expects a non-empty filter string. If the fuzzer produces an empty string,
    //           it might lead to unexpected behavior or missed coverage.
    // IMPLEMENTATION: Provide a default minimal valid filter if the fuzzer produces an empty string.
    if (strlen(filter_string) == 0) {
        free(filter_string);
        filter_string = strdup("ip"); // A simple, valid filter
        if (!filter_string) {
            pcap_close(pcap_handle);
            return 0;
        }
    }

    // 3. Call pcap_compile
    /*
     * ANALYSIS: pcap_compile, pcap_parse, and pcap_lex showed low line and branch coverage.
     *           Specifically, many grammar rules and lexical tokens had zero hits.
     *           gen_protochain, gen_multicast, gen_acode, gen_atmtype_abbrev also had low coverage.
     * IMPLEMENTATION: The fuzzer generates diverse filter strings using `BuildFilterString`,
     *                 including keywords and structures designed to trigger these low-coverage paths.
     *                 - Randomly selected DLTs for `pcap_open_dead` help exercise link-type specific
     *                   branches in `gen_multicast`, `gen_acode`, `gen_atmtype_abbrev`.
     *                 - Including keywords like "protochain", "multicast", "aid", "atm metac"
     *                   directly targets the corresponding code generation functions.
     *                 - Generating complex combinations of operators and keywords aims to
     *                   exercise different grammar reduction rules in `pcap_parse` and token
     *                   recognition in `pcap_lex`.
     *                 - The `optimize` flag is randomly set to exercise both optimized and
     *                   unoptimized code paths (line 825 in gencode.c).
     *                 - Invalid filter strings will exercise error handling paths in all related functions.
     */
    int optimize = ConsumeInt(&fdp) % 2; // 0 or 1
    bpf_u_int32 netmask_val;
    const uint8_t *netmask_bytes = ConsumeBytes(&fdp, sizeof(bpf_u_int32));
    if (netmask_bytes) {
        memcpy(&netmask_val, netmask_bytes, sizeof(bpf_u_int32));
    } else {
        netmask_val = 0xFFFFFFFF; // Default if not enough bytes
    }

    int compile_result = pcap_compile(pcap_handle, &fp, filter_string, optimize, netmask_val);

    // 4. Cleanup: Ensure all dynamically allocated resources are freed.
    /*
     * ANALYSIS: Memory leaks can occur if pcap_freecode and pcap_close are not called.
     * IMPLEMENTATION: pcap_freecode is called if pcap_compile succeeded, and pcap_close
     *                 is always called on the pcap_handle. The filter_string is also freed.
     */
    if (compile_result == 0) {
        pcap_freecode(&fp);
    }

    free(filter_string);
    pcap_close(pcap_handle);

    return 0;
}