#include <pcap.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/stat.h>
#include <fcntl.h>

#ifndef O_BINARY
#define O_BINARY 0
#endif

// The fuzzer name is not available at compile time in all environments,
// so we define a fallback.
#ifndef _FUZZ_TARGET_NAME
#define _FUZZ_TARGET_NAME "fuzz_target"
#endif

#define MAX_FILTER_LEN 256

// De-macroify to avoid shadowing the function declaration.
#ifdef pcap_parse
#undef pcap_parse
#endif
int pcap_parse(void);

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_if_t *alldevs;
    pcap_if_t *dev;
    char filter[MAX_FILTER_LEN];
    struct bpf_program fp;
    pcap_t *handle;

    /*
     * ANALYSIS: The function-level coverage report showed pcap_findalldevs_ex had
     *           low coverage. The line-level report confirmed this was due to
     *           untested error paths and the PCAP_SRC_FILE case not being exercised.
     * IMPLEMENTATION: The following code block calls pcap_findalldevs_ex with a
     *                 source string derived from the fuzzer input. This will
     *                 exercise the parsing of different source types.
     */
    if (size > 1) {
        char *source = (char *)malloc(size);
        if (source) {
            memcpy(source, data, size - 1);
            source[size - 1] = '\0';
            if (pcap_findalldevs_ex(source, NULL, &alldevs, errbuf) == 0) {
                pcap_freealldevs(alldevs);
            }
            free(source);
        }
    }

    /*
     * ANALYSIS: The PCAP_SRC_FILE case in pcap_findalldevs_ex was identified as
     *           having significant uncovered code paths related to file and
     *           directory handling.
     * IMPLEMENTATION: A temporary file is created and its path is used as a
     *                 source for pcap_findalldevs_ex to specifically exercise
     *                 the file-based device listing functionality.
     */
    char path[256];
    snprintf(path, sizeof(path), "/tmp/%s.pcap", _FUZZ_TARGET_NAME);
    int fd = open(path, O_WRONLY | O_CREAT | O_TRUNC | O_BINARY, 0644);
    if (fd >= 0) {
        write(fd, data, size);
        close(fd);

        char source[512];
        snprintf(source, sizeof(source), "file://%s", path);
        if (pcap_findalldevs_ex(source, NULL, &alldevs, errbuf) == 0) {
            pcap_freealldevs(alldevs);
        }
        unlink(path);
    }

    /*
     * ANALYSIS: pcap_findalldevs and pcap_lookupnet have low coverage in their
     *           error handling and device iteration logic.
     * IMPLEMENTATION: The code calls pcap_findalldevs to get a list of all
     *                 devices, then iterates through them, calling pcap_lookupnet
     *                 on each to exercise the network and netmask lookup logic for
     *                 a variety of interfaces.
     */
    if (pcap_findalldevs(&alldevs, errbuf) == 0) {
        for (dev = alldevs; dev; dev = dev->next) {
            bpf_u_int32 net, mask;
            pcap_lookupnet(dev->name, &net, &mask, errbuf);
        }
        pcap_freealldevs(alldevs);
    }

    /*
     * ANALYSIS: pcap_lookupdev has uncovered branches related to finding no
     *           suitable devices.
     * IMPLEMENTATION: pcap_lookupdev is called to exercise the logic for finding
     *                 a default device.
     */
    char *dev_name = pcap_lookupdev(errbuf);

    /*
     * ANALYSIS: The gencode.c file, which contains pcap_compile, has a large
     *           number of functions with low or zero coverage. This indicates
     *           the filter compilation logic is not well-tested.
     * IMPLEMENTATION: A pcap handle is created, and a filter string from the
     *                 fuzzer input is compiled with pcap_compile and then set
     *                 with pcap_setfilter. This will exercise the complex filter
     *                 parsing and compilation code.
     */
    handle = pcap_open_dead(DLT_EN10MB, 65535);
    if (handle) {
        size_t filter_len = size > MAX_FILTER_LEN ? MAX_FILTER_LEN : size;
        if (filter_len > 0) {
            memcpy(filter, data, filter_len);
            filter[filter_len - 1] = '\0';

            if (pcap_compile(handle, &fp, filter, 0, PCAP_NETMASK_UNKNOWN) == 0) {
                pcap_setfilter(handle, &fp);
                pcap_freecode(&fp);
            }
        }
        pcap_close(handle);
    }

    return 0;
}