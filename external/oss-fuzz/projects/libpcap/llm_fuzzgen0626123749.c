#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include "/src/libpcap/pcap/pcap.h"
#include "/src/libpcap/pcap/bpf.h"

// Dummy callback for pcap_dispatch
static void dummy_handler(u_char *user, const struct pcap_pkthdr *h, const u_char *bytes) {
    (void)user;
    (void)h;
    (void)bytes;
}

// This function creates a temporary file with the given data and returns its name.
// The caller is responsible for deleting the file.
static char *buffer_to_file(const uint8_t *data, size_t size) {
    char *name = strdup("/tmp/libpcap_fuzz-XXXXXX");
    if (!name) {
        return NULL;
    }

    int fd = mkstemp(name);
    if (fd < 0) {
        free(name);
        return NULL;
    }

    // Write the data to the file.
    ssize_t written = write(fd, data, size);
    close(fd);

    if (written < (ssize_t)size) {
        // If the write failed, we can't use the file.
        unlink(name);
        free(name);
        return NULL;
    }

    return name;
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    if (size < 1) {
        return 0;
    }

    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t *p;
    char *fname = NULL;

    // Use a portion of the input to decide which code path to take.
    unsigned char path_selector = data[0];
    data++;
    size--;

    // Create a pcap_t handle.
    if (path_selector % 2 == 0) {
        // Path 1: Create a "dead" handle for testing functions on non-activated handles.
        p = pcap_open_dead(DLT_EN10MB, 65535);
    } else {
        // Path 2: Create a handle from an offline file (using the fuzzing data).
        fname = buffer_to_file(data, size);
        if (!fname) {
            return 0;
        }
        p = pcap_open_offline(fname, errbuf);
    }

    if (p == NULL) {
        if (fname) {
            unlink(fname);
            free(fname);
        }
        return 0;
    }

    // Added to improve coverage of the BPF filter compiler (gencode.c).
    // The existing fuzzer does not exercise pcap_compile.
    if (size > 1) {
        char filter_string[257];
        size_t filter_len = size < sizeof(filter_string) - 1 ? size : sizeof(filter_string) - 1;
        memcpy(filter_string, data, filter_len);
        filter_string[filter_len] = '\0';

        struct bpf_program prog_compiled;
        if (pcap_compile(p, &prog_compiled, filter_string, 1, PCAP_NETMASK_UNKNOWN) == 0) {
            // pcap_compile allocates memory that must be freed.
            pcap_freecode(&prog_compiled);
        }
    }

    // Added to improve coverage of pcap_dump_open_append in sf-pcap.c,
    // which has complex logic for appending to existing files.
    char* dump_fname = buffer_to_file(data, size);
    if (dump_fname) {
        pcap_dumper_t *dumper = pcap_dump_open_append(p, dump_fname);
        if (dumper) {
            // pcap_dump_close handles closing the underlying file.
            pcap_dump_close(dumper);
        }
        // The temporary file and its name buffer must be cleaned up.
        unlink(dump_fname);
        free(dump_fname);
    }

    // Added to improve coverage of device lookup functions (pcap_lookupdev, pcap_findalldevs).
    // pcap_lookupdev() returns a pointer to a static buffer, not a heap allocation.
    // Do not free the result.
    (void)pcap_lookupdev(errbuf);

    // Target 1: Set a filter on a non-activated handle.
    // We create a dummy BPF program to pass to it.
    struct bpf_program prog;
    prog.bf_len = 1;
    prog.bf_insns = (struct bpf_insn *)malloc(sizeof(struct bpf_insn));
    if (prog.bf_insns) {
        prog.bf_insns[0].code = BPF_RET | BPF_K;
        prog.bf_insns[0].jt = 0;
        prog.bf_insns[0].jf = 0;
        prog.bf_insns[0].k = 0;
        pcap_setfilter(p, &prog);
        // pcap_setfilter() makes a copy, so we must free the original.
        free(prog.bf_insns);
    }

    // Target 2: Set the datalink on a non-activated handle.
    if (size > 0) {
        pcap_set_datalink(p, data[0]);
    }

    // Target 3: Try to set monitor mode.
    // This is the public API to do what sf_cant_set_rfmon and pcap_cant_set_rfmon
    // were intended to test. It will correctly fail on handle types that don't support it.
    pcap_set_rfmon(p, 1);

    // Clean up resources.
    pcap_close(p);
    if (fname) {
        unlink(fname);
        free(fname);
    }

    return 0;
}