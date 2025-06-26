#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <stdint.h>

// Include the main libpcap header using its project-relative path.
#include "/src/libpcap/pcap/pcap.h"

// Helper function to write a data buffer to a temporary file.
// This is necessary because pcap_fopen_offline requires a FILE* handle.
//
// @param data The byte buffer to write to the file.
// @param size The size of the buffer.
// @param temp_name_out A buffer to store the generated temporary file name.
// @return A FILE* handle to the newly created and opened temporary file,
//         or NULL on failure. The caller is responsible for closing the
//         FILE* and unlinking the file.
static FILE *buffer_to_file(const uint8_t *data, size_t size, char *temp_name_out) {
    // Create a temporary file name template.
    strcpy(temp_name_out, "/tmp/fuzz-pcap-XXXXXX");

    // Create a unique temporary file.
    int fd = mkstemp(temp_name_out);
    if (fd < 0) {
        return NULL;
    }

    // Write the provided data to the file.
    ssize_t written = write(fd, data, size);
    close(fd); // Close the file descriptor, the file persists.

    if (written < 0 || (size_t)written != size) {
        unlink(temp_name_out);
        return NULL;
    }

    // Reopen the file for reading, which is what pcap_fopen_offline expects.
    FILE *file = fopen(temp_name_out, "rb");
    if (!file) {
        unlink(temp_name_out);
        return NULL;
    }

    return file;
}

// The entry point for the fuzzer.
// This function is designed to exercise several of libpcap's offline file
// processing APIs, focusing on those with low or zero code coverage.
int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size) {
    // We need at least a few bytes to work with.
    if (Size < 4) {
        return 0;
    }

    // Declare all resources that will need to be cleaned up.
    char errbuf[PCAP_ERRBUF_SIZE];
    char temp_pcap_file_name[32] = {0};
    pcap_t *p = NULL;
    pcap_dumper_t *dumper = NULL;
    FILE *pcap_file = NULL;
    FILE *dump_file = NULL;
    struct bpf_program fcode;
    int *tstamp_types = NULL;
    char *filter_string = NULL;

    // --- Input Structuring ---
    // Split the input data into three parts to drive different APIs:
    // 1. A byte to be used as a data link type for pcap_set_datalink.
    // 2. The first half of the remaining data for the pcap file content.
    // 3. The second half for the BPF filter string.
    const int dlt = Data[0];
    const size_t pcap_data_size = (Size - 1) / 2;
    const uint8_t *pcap_data = Data + 1;
    const char *filter_string_data = (const char *)(pcap_data + pcap_data_size);
    const size_t filter_string_size = Size - 1 - pcap_data_size;

    // Create a null-terminated filter string from the input data.
    filter_string = (char *)malloc(filter_string_size + 1);
    if (!filter_string) {
        return 0; // Allocation failure
    }
    memcpy(filter_string, filter_string_data, filter_string_size);
    filter_string[filter_string_size] = '\0';

    // Create a temporary file containing the fuzzer-generated pcap data.
    pcap_file = buffer_to_file(pcap_data, pcap_data_size, temp_pcap_file_name);
    if (!pcap_file) {
        free(filter_string);
        return 0;
    }

    // --- API Call Sequence ---

    // Target 1: pcap_fopen_offline (0% coverage)
    // Attempt to open the temporary file as a pcap savefile.
    p = pcap_fopen_offline(pcap_file, errbuf);
    if (!p) {
        goto cleanup; // If opening fails, we can't proceed.
    }

    // --- Added to improve coverage based on reports ---
    // Target simple accessor functions in pcap.c with 0% coverage.
    (void)pcap_is_swapped(p);
    (void)pcap_major_version(p);
    (void)pcap_minor_version(p);
    (void)pcap_geterr(p);

    // Target functions in savefile.c (via pcap.c wrappers) with 0% coverage
    // by calling them on an offline handle, which is an unsupported configuration.
    pcap_setdirection(p, PCAP_D_IN);
    pcap_inject(p, "dummy_data", 10);

    // Target functions in nametoaddr.c with low or 0% coverage.
    // Use the existing filter_string as a source of varied string input.
    int port, proto, port1, port2;
    pcap_nametoport(filter_string, &port, &proto);
    pcap_nametoportrange(filter_string, &port1, &port2, &proto);
    pcap_nametoproto(filter_string);
    // --- End of coverage improvements ---

    // Target 2: pcap_set_datalink (45% coverage)
    // Attempt to set the data link type using a value from the fuzzer input.
    pcap_set_datalink(p, dlt);

    // Target 3 & 4: pcap_list_tstamp_types (0%) and pcap_free_tstamp_types (0%)
    // List and then immediately free the supported timestamp types to exercise the code.
    if (pcap_list_tstamp_types(p, &tstamp_types) >= 0) {
        pcap_free_tstamp_types(tstamp_types);
        tstamp_types = NULL; // Set to NULL to prevent double-free in cleanup.
    }

    // Compile the filter string. This is a prerequisite for setting a filter.
    if (pcap_compile(p, &fcode, filter_string, 1, PCAP_NETMASK_UNKNOWN) == 0) {
        // If compilation succeeds, set the filter on the pcap handle.
        pcap_setfilter(p, &fcode);
        // The compiled program must be freed regardless of whether setfilter succeeds.
        pcap_freecode(&fcode);
    }

    // Target 5: pcap_dump_fopen (0% coverage)
    // Open a dumper to /dev/null to exercise the dumping logic without disk I/O.
    dump_file = fopen("/dev/null", "w");
    if (dump_file) {
        dumper = pcap_dump_fopen(p, dump_file);
    }

    // Read packets from the file and, if a dumper is available, dump them.
    // This drives the core packet processing loop.
    struct pcap_pkthdr *header;
    const u_char *packet;
    // Modified to use pcap_next() to improve coverage. pcap_next() was 0% covered.
    // This also covers pcap_dispatch(), which was also 0% covered.
    struct pcap_pkthdr header_for_next;
    while ((packet = pcap_next(p, &header_for_next)) != NULL) {
        if (dumper) {
            // Exercises pcap_dump
            pcap_dump((u_char *)dumper, &header_for_next, packet);
        }
    }

    // --- API Call Sequence for Dead Handle ---
    // Create a dead handle to exercise APIs that are not available on offline handles
    // and to hit uncovered branches identified in coverage reports.
    pcap_t *dead_p = pcap_open_dead(DLT_EN10MB, 65535);
    if (dead_p) {
        // Set a timestamp type to improve coverage in pcap_list_tstamp_types.
        // The coverage report showed that the branch where p->tstamp_type_count > 0
        // was never taken. Calling pcap_set_tstamp_type populates this list.
        pcap_set_tstamp_type(dead_p, PCAP_TSTAMP_HOST);

        int *dead_tstamp_types = NULL;
        if (pcap_list_tstamp_types(dead_p, &dead_tstamp_types) >= 0) {
            pcap_free_tstamp_types(dead_tstamp_types);
        }
        pcap_close(dead_p);
    }


cleanup:
    // --- Resource Management ---
    // Meticulously clean up all allocated resources in reverse order of creation
    // to prevent memory and resource leaks.
    if (dumper) {
        // pcap_dump_close also closes the FILE * passed to pcap_dump_fopen.
        pcap_dump_close(dumper);
    } else if (dump_file) {
        // If the dumper wasn't created, we still need to close the file.
        fclose(dump_file);
    }
    if (p) {
        // pcap_close closes the FILE * passed to pcap_fopen_offline.
        pcap_close(p);
    }
    if (pcap_file) {
        // If pcap_fopen_offline() failed, p will be NULL, and pcap_close()
        // will not be called. In that case, we are responsible for closing
        // the file. If pcap_fopen_offline() succeeded, pcap_close() will
        // close the file, so we must not.
        if (!p) {
            fclose(pcap_file);
        }
        // The file still exists on disk, so we must remove it.
        unlink(temp_pcap_file_name);
    }
    free(filter_string);
    // This should have been freed already, but as a safeguard.
    if (tstamp_types) {
        pcap_free_tstamp_types(tstamp_types);
    }

    return 0;
}