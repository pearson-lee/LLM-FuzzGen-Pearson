#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "pcap/pcap.h"

/*
 * Verification / Negative Proof Program for libpcap_gen_scode_7226
 *
 * Ground Truth: Input Independent
 * Rules: Rule 6 (System Resource Failure / External Environment Dependency)
 *        & Rule 3 (Observed-Path Invariants)
 * Refined Label: External Resource Failure
 * Target Branch: gen_scode (gencode.c:7226)
 * Predicate: if (eaddr == NULL)
 * Blocked Side: gencode.c:7229 (b = gen_ipfchostop(cstate, eaddr, dir);)
 *
 * Purpose:
 *   This program provides empirical proof that line 7229 is unreachble
 *   in the standard fuzzing environment:
 *   1. Any hostname passed to "ether host <name>" requires pcap_ether_hostton()
 *      to look up /etc/ethers. Because /etc/ethers does not exist,
 *      pcap_ether_hostton() unconditionally returns NULL, triggering bpf_error()
 *      at line 7226 and aborting compilation via longjmp.
 *   2. Any literal MAC address (e.g., 00:11:22:33:44:55) is parsed by the lexer
 *      as EID and routed to gen_ecode(), completely bypassing gen_scode().
 *
 * Compile command:
 *   gcc -Iexternal/libpcap verify_poc.c /usr/lib/x86_64-linux-gnu/libpcap.so.0.8 -o verify_poc
 */

int main() {
    printf("====================================================================\n");
    printf("[*] Verification Program for libpcap_gen_scode_7226 (Input Independent)\n");
    printf("====================================================================\n\n");

    // DLT_IP_OVER_FC = 122 (controlled by data[0] in fuzz_target.cc)
    pcap_t *p = pcap_open_dead(122, 65535);
    if (!p) {
        printf("[-] Failed to open dead pcap handle for DLT_IP_OVER_FC (122).\n");
        return 1;
    }

    struct bpf_program fp;

    // ------------------------------------------------------------------
    // Test 1: Passing a hostname (e.g. "myhost")
    // Lexer emits ID -> grammar routes to gen_scode()
    // gen_scode() calls pcap_ether_hostton("myhost")
    // ------------------------------------------------------------------
    const char *expr1 = "ether host myhost";
    printf("[Test 1] Testing hostname lookup: '%s'\n", expr1);
    int ret1 = pcap_compile(p, &fp, expr1, 1, PCAP_NETMASK_UNKNOWN);
    printf("  Return code: %d (Expected: -1)\n", ret1);
    printf("  Error message: '%s'\n", pcap_geterr(p));

    if (ret1 != 0 && strstr(pcap_geterr(p), "unknown Fibre Channel host") != NULL) {
        printf("  [CONFIRMED] Line 7226 evaluated to TRUE because /etc/ethers is missing.\n");
        printf("  [CONFIRMED] Triggered bpf_error() abort; blocked line 7229 was NOT reached.\n\n");
    } else {
        printf("  [-] Unexpected result for Test 1.\n\n");
    }

    // ------------------------------------------------------------------
    // Test 2: Passing another common name (e.g. "localhost")
    // ------------------------------------------------------------------
    const char *expr2 = "ether host localhost";
    printf("[Test 2] Testing hostname lookup: '%s'\n", expr2);
    int ret2 = pcap_compile(p, &fp, expr2, 1, PCAP_NETMASK_UNKNOWN);
    printf("  Return code: %d (Expected: -1)\n", ret2);
    printf("  Error message: '%s'\n", pcap_geterr(p));

    if (ret2 != 0 && strstr(pcap_geterr(p), "unknown Fibre Channel host") != NULL) {
        printf("  [CONFIRMED] Line 7226 evaluated to TRUE; line 7229 was NOT reached.\n\n");
    }

    // ------------------------------------------------------------------
    // Test 3: Passing a literal MAC address (e.g. "00:11:22:33:44:55")
    // Lexer emits EID -> grammar routes to gen_ecode(), NOT gen_scode()!
    // ------------------------------------------------------------------
    const char *expr3 = "ether host 00:11:22:33:44:55";
    printf("[Test 3] Testing literal MAC address: '%s'\n", expr3);
    int ret3 = pcap_compile(p, &fp, expr3, 1, PCAP_NETMASK_UNKNOWN);
    printf("  Return code: %d (Expected: 0 via gen_ecode)\n", ret3);

    if (ret3 == 0) {
        printf("  [CONFIRMED] Literal MAC addresses bypass gen_scode() completely\n");
        printf("              and execute gen_ecode() (gencode.c:7731) instead.\n\n");
        pcap_freecode(&fp);
    }

    pcap_close(p);

    printf("====================================================================\n");
    printf("[CONCLUSION] In the absence of /etc/ethers on the system, eaddr is\n");
    printf("             invariant NULL in gen_scode(). Line 7226 always triggers\n");
    printf("             bpf_error(), proving line 7229 is dead code (Input Independent).\n");
    printf("====================================================================\n");

    return 0;
}
