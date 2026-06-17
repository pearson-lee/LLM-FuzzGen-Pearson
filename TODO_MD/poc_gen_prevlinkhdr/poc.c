/* PoC: does a filter reach gen_prevlinkhdr_check's geneve blocked side (gencode.c:3150)?
 * Mirrors the libpcap fuzzer harness: pcap_open_dead(DLT_EN10MB) + pcap_compile.
 * Usage: ./poc "geneve and ether host 00:11:22:33:44:55"
 */
#include <pcap.h>
#include <stdio.h>
#include <unistd.h>

int main(int argc, char **argv) {
    if (argc < 2) { fprintf(stderr, "usage: %s <filter>\n", argv[0]); return 2; }
    const char *filter = argv[1];
    struct bpf_program fcode;
    pcap_t *p = pcap_open_dead(DLT_EN10MB, 65535);
    if (!p) { printf("pcap_open_dead failed\n"); return 1; }
    int r = pcap_compile(p, &fcode, filter, 1, PCAP_NETMASK_UNKNOWN);
    printf("pcap_compile(\"%s\") = %d : %s\n", filter, r, (r == 0) ? "OK(compiled)" : pcap_geterr(p));
    if (r == 0) pcap_freecode(&fcode);
    pcap_close(p);
    /* The prebuilt libpcap coverage runtime SEGVs in its atexit profile writer
     * on this toolchain; flush and _exit to bypass atexit handlers cleanly. */
    fflush(stdout);
    _exit(r == 0 ? 0 : 3);
}
