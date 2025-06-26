#include <pcap/pcap.h>
#include <pcap/bpf.h>
#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>

// Dummy handler for pcap_loop, does nothing.
static void dummy_handler(u_char *user, const struct pcap_pkthdr *h, const u_char *bytes) {
    (void)user;
    (void)h;
    (void)bytes;
}

// This fuzzer targets several core, previously uncovered libpcap functionalities:
// 1. pcap_compile_nopcap: Compiles a filter without a pcap handle.
// 2. bpf_filter: Executes a BPF filter against a packet.
// 3. pcap_dump_open: Opens a savefile for writing packets.
// 4. pcap_dump: Writes a packet to the savefile.
// 5. pcap_loop: Processes packets from a handle.
int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    if (size < 2) {
        return 0;
    }

    // Use one byte for linktype and one for optimization flag.
    const int linktype = data[0];
    const int optimize = data[1] & 1;
    data += 2;
    size -= 2;

    // The rest of the data is split between the filter string and packet data.
    if (size == 0) {
        return 0;
    }
    size_t filter_len = size / 2;
    size_t packet_len = size - filter_len;
    const uint8_t *packet_data = data + filter_len;

    // Create a null-terminated filter string.
    char *filter_string = (char *)malloc(filter_len + 1);
    if (!filter_string) {
        return 0;
    }
    memcpy(filter_string, data, filter_len);
    filter_string[filter_len] = '\0';

    struct bpf_program program;
    // Target 1: pcap_compile_nopcap (0% coverage)
    // Compile the filter string without needing a live pcap_t handle.
    if (pcap_compile_nopcap(65535, linktype, &program, filter_string, optimize, PCAP_NETMASK_UNKNOWN) == 0) {
        // If compilation is successful, proceed to use the filter.

        // Target 2: bpf_filter (0% coverage)
        // Execute the compiled filter against the packet data.
        (void)bpf_filter(program.bf_insns, packet_data, packet_len, packet_len);

        // Added calls to bpf_dump to cover it and bpf_image, which had 0% coverage.
        // Calling with different options exercises different code paths.
        bpf_dump(&program, 1);
        bpf_dump(&program, 2);
        bpf_dump(&program, 3);


        // Memory safety: Free the compiled program.
        pcap_freecode(&program);
    }

    // Create a dead pcap handle to test dumping functionality.
    pcap_t *p = pcap_open_dead(linktype, 65535);
    if (p) {
        // Create a temporary file for the dump.
        // Using a fixed name is safe in fuzzing environments which often sandbox execution.
        const char *dump_filename = "/tmp/fuzz_dump.pcap";

        // Target 3: pcap_dump_open (0% coverage)
        // Open a dumper to write packets to a file.
        pcap_dumper_t *dumper = pcap_dump_open(p, dump_filename);
        if (dumper) {
            struct pcap_pkthdr hdr;
            hdr.ts.tv_sec = 0;
            hdr.ts.tv_usec = 0;
            hdr.caplen = packet_len;
            hdr.len = packet_len;

            // Target 4: pcap_dump (0% coverage)
            // Write the packet data to the opened dumper.
            pcap_dump((u_char *)dumper, &hdr, packet_data);

            // Memory safety: Close the dumper.
            pcap_dump_close(dumper);
        }
        
        // Added call to pcap_dump_open_append to cover it, as it had 0% coverage.
        // This function requires an existing file, so it's called after the first dump.
        pcap_dumper_t *dumper_append = pcap_dump_open_append(p, dump_filename);
        if (dumper_append) {
            // Memory safety: Close the appended dumper.
            pcap_dump_close(dumper_append);
        }


        // Target 5: pcap_loop (0% coverage)
        // Although the handle is "dead" and has no packets, calling pcap_loop
        // exercises the function's internal logic for different handle types.
        pcap_loop(p, 5, dummy_handler, NULL);

        // Memory safety: Close the pcap handle.
        pcap_close(p);
        
        // Clean up the temporary file.
        remove(dump_filename);
    }

    // Memory safety: Free the allocated filter string.
    free(filter_string);

    return 0;
}