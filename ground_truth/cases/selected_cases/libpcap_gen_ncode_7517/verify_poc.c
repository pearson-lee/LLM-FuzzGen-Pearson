#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include "pcap/pcap.h"

/*
 * Verification Program for libpcap_gen_ncode_7517
 *
 * Ground Truth: Input Dependent (Rule 1: Direct Data Flow & Rule 2: Implicit Flow & Semantic Properties)
 * Target Branch: gen_ncode (gencode.c:7517)
 * Predicate: } else if (proto == Q_DECNET) {
 * Blocked Side: gencode.c:7523 (vlen = pcapint_atodn(s, &v);)
 *
 * This program constructs a 32-byte input payload demonstrating that
 * the blocked branch at line 7523 is reachable under the original
 * fuzz target logic without any modifications to the fuzz target code.
 *
 * Compile command:
 *   gcc -Iexternal/libpcap verify_poc.c /usr/lib/x86_64-linux-gnu/libpcap.so.0.8 -o verify_poc
 */

int main() {
    // 1. Construct raw fuzzer input payload
    // Target splits input: source_len = size / 2
    // We provide a 32-byte payload where the first 16 bytes contain "decnet host 1.2"
    const char filter_expr[] = "decnet host 1.2";
    size_t filter_len = strlen(filter_expr); // 15
    size_t source_len = filter_len + 1;      // 16
    size_t total_size = source_len * 2;      // 32

    uint8_t *data = (uint8_t *)calloc(1, total_size);
    memcpy(data, filter_expr, filter_len);
    // Pad second half with dummy packet bytes (matching fuzz target file_content_data)
    memset(data + source_len, 0xAA, source_len);

    printf("[+] Input payload constructed. Total size: %zu bytes.\n", total_size);

    // 2. Simulate target extraction of source_str (fuzz_target.cc:59-68)
    size_t extracted_source_len = total_size / 2;
    char *source_str = (char *)malloc(extracted_source_len + 1);
    memcpy(source_str, data, extracted_source_len);
    source_str[extracted_source_len] = '\0';
    printf("[+] Extracted source_str: '%s'\n", source_str);

    // 3. Open pcap handle (DLT_LINUX_SLL matches device 'any' used in target line 276)
    pcap_t *p = pcap_open_dead(DLT_LINUX_SLL, 65535);
    if (!p) {
        printf("[-] Failed to initialize pcap handle.\n");
        free(source_str);
        free(data);
        return 1;
    }

    // 4. Execute pcap_compile with source_str (fuzz_target.cc:378)
    struct bpf_program fp;
    int ret = pcap_compile(p, &fp, source_str, 1, PCAP_NETMASK_UNKNOWN);
    if (ret != 0) {
        printf("[-] pcap_compile failed: %s\n", pcap_geterr(p));
        pcap_close(p);
        free(source_str);
        free(data);
        return 1;
    }

    printf("[+] pcap_compile succeeded! BPF program length: %u instructions.\n", fp.bf_len);

    // 5. Verify the generated BPF code reflects the DECnet protocol and address parsing
    // In gencode.c: Line 7517 evaluates (proto == Q_DECNET) -> TRUE
    // Line 7523 executes: vlen = pcapint_atodn(s, &v) -> parses "1.2" to 0x0402 (Area 1, Node 2)
    // gen_host then emits Ethertype 0x6003 (DECnet) and address comparison 0x204 (little-endian)
    int found_decnet_ethertype = 0;
    int found_decnet_addr = 0;
    for (u_int i = 0; i < fp.bf_len; i++) {
        struct bpf_insn *insn = &fp.bf_insns[i];
        if (insn->code == (BPF_JMP | BPF_JEQ | BPF_K)) {
            if (insn->k == 0x6003) {
                found_decnet_ethertype = 1;
            }
            if (insn->k == 0x204) {
                found_decnet_addr = 1;
            }
        }
    }

    if (found_decnet_ethertype && found_decnet_addr) {
        printf("[SUCCESS] Verified DECnet EtherType (0x6003) and Address (0x204) in compiled BPF bytecode!\n");
        printf("[SUCCESS] Condition at gencode.c:7517 (proto == Q_DECNET) evaluated to TRUE!\n");
        printf("[SUCCESS] Reached blocked line 7523 (vlen = pcapint_atodn(s, &v))!\n");
    } else {
        printf("[-] DECnet bytecode signatures not found.\n");
        ret = 1;
    }

    pcap_freecode(&fp);
    pcap_close(p);
    free(source_str);
    free(data);
    return ret;
}
