#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>
#include <dirent.h>

#include "pcap/pcap.h"

#ifndef _FUZZ_TARGET_NAME
#define _FUZZ_TARGET_NAME "fuzz_pcap_api"
#endif

// Helper to create a null-terminated string from fuzzer data.
// The caller is responsible for freeing the returned string.
char *get_null_terminated_string(const uint8_t **data, size_t *size, size_t max_len) {
    if (*size == 0) {
        return NULL;
    }
    size_t len = 0;
    while (len < *size && len < max_len && (*data)[len] != '\0') {
        len++;
    }
    char *str = (char *)malloc(len + 1);
    if (!str) {
        return NULL;
    }
    memcpy(str, *data, len);
    str[len] = '\0';
    *data += len;
    *size -= len;
    if (*size > 0) { // Consume the null terminator if it was present
        *data += 1;
        *size -= 1;
    }
    return str;
}

int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size) {
    if (Size < 10) {
        return 0;
    }

    char errbuf[PCAP_ERRBUF_SIZE];

    /*
     * ANALYSIS: The function-level coverage report showed pcap_findalldevs_ex
     *           had several uncovered branches related to file-based source strings.
     *           Specifically, the PCAP_SRC_FILE case was not well-tested.
     * IMPLEMENTATION: The following code block creates a temporary directory and a
     *                 file to exercise the file-based device discovery logic in
     *                 pcap_findalldevs_ex.
     */
    char dir_path[256];
    snprintf(dir_path, sizeof(dir_path), "/tmp/%s.dir", _FUZZ_TARGET_NAME);
    mkdir(dir_path, 0755);

    char file_path[512];
    snprintf(file_path, sizeof(file_path), "%s/fuzz.pcap", dir_path);
    FILE *fp = fopen(file_path, "wb");
    if (fp) {
        size_t bytes_to_write = Size > 1024 ? 1024 : Size;
        fwrite(Data, 1, bytes_to_write, fp);
        fclose(fp);
    }

    char source_str[512];
    snprintf(source_str, sizeof(source_str), "file://%s/", dir_path);

    pcap_if_t *alldevs;
    if (pcap_findalldevs_ex(source_str, NULL, &alldevs, errbuf) == 0) {
        pcap_freealldevs(alldevs);
    }

    // Also test the long source string case
    char long_source[PCAP_BUF_SIZE + 10];
    memset(long_source, 'A', sizeof(long_source) -1);
    long_source[sizeof(long_source)-1] = '\0';
    pcap_findalldevs_ex(long_source, NULL, &alldevs, errbuf);


    /*
     * ANALYSIS: The line-level coverage for pcap_open_dead_with_tstamp_precision
     *           showed that the switch statement for timestamp precision was not
     *           fully covered. The PCAP_TSTAMP_PRECISION_NANO and default cases
     *           were never hit.
     * IMPLEMENTATION: The following code uses a byte from the fuzzer input to
     *                 select the timestamp precision, ensuring all cases of the
     *                 switch statement can be exercised.
     */
    u_int precision;
    uint8_t precision_selector = Data[0];
    Data++;
    Size--;
    if (precision_selector < 85) {
        precision = PCAP_TSTAMP_PRECISION_MICRO;
    } else if (precision_selector < 170) {
        precision = PCAP_TSTAMP_PRECISION_NANO;
    } else {
        precision = 99; // Invalid precision to hit the default case
    }

    pcap_t *p = pcap_open_dead_with_tstamp_precision(DLT_NULL, 65535, precision);
    if (!p) {
        unlink(file_path);
        rmdir(dir_path);
        return 0;
    }

    /*
     * ANALYSIS: The function-level coverage report showed that pcap_compile and
     *           pcap_setfilter had room for improvement. These functions are
     *           critical for packet filtering.
     * IMPLEMENTATION: This section uses the fuzzer-provided data to generate a
     *                 filter string, which is then compiled with pcap_compile and
     *                 applied with pcap_setfilter. This tests the filter compilation
     *                 and installation logic.
     */
    char *filter_str = get_null_terminated_string(&Data, &Size, 512);
    if (filter_str) {
        struct bpf_program fp_prog;
        if (pcap_compile(p, &fp_prog, filter_str, 1, PCAP_NETMASK_UNKNOWN) == 0) {
            pcap_setfilter(p, &fp_prog);
            pcap_freecode(&fp_prog);
        }
        free(filter_str);
    }

    pcap_close(p);

    // Cleanup temporary files
    unlink(file_path);
    rmdir(dir_path);

    return 0;
}