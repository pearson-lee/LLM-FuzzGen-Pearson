#include <pcap.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <stdint.h>
#include <stddef.h>

#ifndef _FUZZ_TARGET_NAME
#define _FUZZ_TARGET_NAME "fuzz_pcap_combined"
#endif

// Dummy callback for pcap_loop and pcap_dispatch
void dummy_handler(u_char *user, const struct pcap_pkthdr *h, const u_char *bytes) {
    // No-op
}

int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size) {
    if (Size < 1) {
        return 0;
    }

    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_if_t *alldevs = NULL;
    pcap_t *handle = NULL;
    struct bpf_program fp;

    // Create a null-terminated string from the fuzzer data for use in various APIs.
    char *fuzz_string = (char *)malloc(Size + 1);
    if (!fuzz_string) {
        return 0;
    }
    memcpy(fuzz_string, Data, Size);
    fuzz_string[Size] = '\0';

    // Sanitize the string to remove embedded nulls that can confuse string-parsing functions.
    for (size_t i = 0; i < Size; i++) {
        if (fuzz_string[i] == '\0') {
            fuzz_string[i] = ' ';
        }
    }

    /*
     * ANALYSIS: The function-level coverage report shows that pcap_findalldevs_ex
     *           has low coverage (64.16%), especially for the PCAP_SRC_FILE case. The
     *           line-level report confirms many error paths and directory
     *           traversal logic are untested.
     * IMPLEMENTATION: The following block calls pcap_findalldevs_ex with a fuzzed
     *                 source string. This string can be a simple "rpcap://" to
     *                 test local device enumeration or a path to a temporary file
     *                 containing fuzzed data, to test the file-based enumeration.
     */
    if (Size != 7 || memcmp(Data, "file://", 7) != 0) {
      if (pcap_findalldevs_ex(fuzz_string, NULL, &alldevs, errbuf) == 0) {
          pcap_freealldevs(alldevs);
          alldevs = NULL;
      }
    }

    /*
     * ANALYSIS: The coverage report for gencode.c and bpf_filter.c shows many
     *           functions with low or zero coverage related to filter compilation.
     *           For example, gen_proto (39.17%), gen_multicast (43.37%), and many others have
     *           significant uncovered branches.
     * IMPLEMENTATION: The following code block uses the fuzzed input as a filter
     *                 expression. It creates a dummy pcap handle with pcap_open_dead,
     *                 compiles the filter with pcap_compile(), and if successful, applies
     *                 it with pcap_setfilter(). This directly targets the complex
     *                 filter compilation engine.
     */
    handle = pcap_open_dead(DLT_NULL, 65535);
    if (handle != NULL) {
        if (pcap_compile(handle, &fp, fuzz_string, 1, PCAP_NETMASK_UNKNOWN) == 0) {
            pcap_setfilter(handle, &fp);
            pcap_freecode(&fp);
        }
        pcap_close(handle);
        handle = NULL;
    }

    /*
     * ANALYSIS: The coverage report for sf-pcap.c and sf-pcapng.c indicates
     *           that file parsing logic has room for improvement. Specifically,
     *           handling of malformed headers and blocks is not fully covered.
     *           pcap_findalldevs also shows low coverage (52.38%).
     * IMPLEMENTATION: The code below writes the fuzzer data to a temporary file
     *                 and then attempts to open it with pcap_open_offline(). This
     *                 tests the library's ability to handle potentially malformed
     *                 pcap/pcapng files. pcap_loop is then called to exercise the
     *                 packet reading and processing logic. This also helps cover
     *                 pcap_findalldevs when called on file sources.
    */
    char path[256];
    snprintf(path, sizeof(path), "/tmp/%s.tmp", _FUZZ_TARGET_NAME);

    FILE *fp_out = fopen(path, "wb");
    if (fp_out) {
        fwrite(Data, 1, Size, fp_out);
        fclose(fp_out);

        handle = pcap_open_offline(path, errbuf);
        if (handle) {
            /*
             * ANALYSIS: The function pcap_list_datalinks has low coverage (65.22%).
             *           It is a simple function but is not exercised by the fuzzer.
             * IMPLEMENTATION: Call pcap_list_datalinks on the valid, activated handle
             *                 from pcap_open_offline. The returned list is freed with
             *                 pcap_free_datalinks to prevent memory leaks.
             */
            int *dlt_buf = NULL;
            int dlt_count = pcap_list_datalinks(handle, &dlt_buf);
            if (dlt_count > 0 && dlt_buf != NULL) {
                pcap_free_datalinks(dlt_buf);
            }

            // Exercise packet reading
            pcap_loop(handle, 10, dummy_handler, NULL);
            pcap_close(handle);
            handle = NULL;
        }
        unlink(path);
    }
    
    /*
     * ANALYSIS: The line-level coverage for pcap_dump_open_append in sf-pcap.c shows that
     *           the branch at line 1109, which checks for a timestamp precision
     *           mismatch, is never taken. This occurs when trying to append to a
     *           microsecond-precision file with a nanosecond-precision handle.
     * IMPLEMENTATION: The following block creates a dummy pcap file with a
     *                 microsecond-precision header. It then creates a
     *                 nanosecond-precision pcap handle and attempts to append to the
     *                 file using pcap_dump_open_append. This is expected to fail and
     *                 trigger the uncovered error-handling path.
     */
    char path_append[256];
    snprintf(path_append, sizeof(path_append), "/tmp/%s_append.tmp", _FUZZ_TARGET_NAME);

    // Create a microsecond-precision file using the pcap API
    pcap_t *p_micro = pcap_open_dead_with_tstamp_precision(DLT_NULL, 65535, PCAP_TSTAMP_PRECISION_MICRO);
    if (p_micro) {
        pcap_dumper_t *dumper = pcap_dump_open(p_micro, path_append);
        if (dumper) {
            pcap_dump_close(dumper);
        }
        pcap_close(p_micro);

        // Now, attempt to append to it with a nanosecond-precision handle
        pcap_t *p_nano = pcap_open_dead_with_tstamp_precision(DLT_NULL, 65535, PCAP_TSTAMP_PRECISION_NANO);
        if (p_nano) {
            pcap_dumper_t *dumper_append = pcap_dump_open_append(p_nano, path_append);
            if (dumper_append) {
                pcap_dump_close(dumper_append);
            }
            pcap_close(p_nano);
        }
        unlink(path_append);
    }


    free(fuzz_string);
    return 0;
}