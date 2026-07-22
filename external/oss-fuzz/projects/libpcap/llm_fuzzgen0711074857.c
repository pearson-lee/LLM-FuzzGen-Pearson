#include <pcap.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <stdint.h>
#include <stddef.h>

#ifndef _FUZZ_TARGET_NAME
#define _FUZZ_TARGET_NAME "fuzz_target"
#endif

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    if (size < 1) {
        return 0;
    }

    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_if_t *alldevs;

    /*
     * ANALYSIS: The function-level coverage report showed pcap_findalldevs_ex
     *           had several uncovered branches related to error handling and
     *           different source string types.
     * IMPLEMENTATION: The following code block creates a dummy pcap file and
     *                 calls pcap_findalldevs_ex with a file source string to
     *                 exercise file-based device enumeration.
     */
    char path[256];
    snprintf(path, sizeof(path), "/tmp/%s.pcap", _FUZZ_TARGET_NAME);
    pcap_t *p_for_dump = pcap_open_dead(DLT_EN10MB, 65535);
    if (p_for_dump) {
        pcap_dumper_t *dumper = pcap_dump_open(p_for_dump, path);
        if (dumper) {
            /*
             * ANALYSIS: The detailed fuzz target coverage report shows that the success
             *           path for pcap_findalldevs_ex (line 39) is never taken. This is
             *           because the pcap file created is empty.
             * IMPLEMENTATION: A single dummy packet is now written to the pcap file.
             *                 This makes the file a valid source for pcap_findalldevs_ex,
             *                 allowing it to succeed and execute pcap_freealldevs.
             */
            if (size > sizeof(struct pcap_pkthdr)) {
                struct pcap_pkthdr hdr;
                memcpy(&hdr, data, sizeof(struct pcap_pkthdr));
                hdr.caplen = size - sizeof(struct pcap_pkthdr);
                if (hdr.caplen > 100) {
                    hdr.caplen = 100;
                }
                hdr.len = hdr.caplen;
                pcap_dump((u_char *)dumper, &hdr, data + sizeof(struct pcap_pkthdr));
            }
            pcap_dump_close(dumper);

            char filesource[512];
            snprintf(filesource, sizeof(filesource), "file://%s", path);
            if (pcap_findalldevs_ex(filesource, NULL, &alldevs, errbuf) == 0) {
                pcap_freealldevs(alldevs);
            }
        }
        pcap_close(p_for_dump);
        unlink(path);
    }

    /*
     * ANALYSIS: The function-level coverage report showed pcap_compile and
     *           pcap_setfilter_linux have low coverage.
     * IMPLEMENTATION: This block creates a dead pcap handle, compiles a
     *                 fuzzer-provided filter string, and applies it to the
     *                 handle, exercising the filter compilation and installation
     *                 logic.
     */
    pcap_t *p = pcap_open_dead(DLT_EN10MB, 65535);
    if (p) {
        struct bpf_program fp;
        size_t filter_len = size > 256 ? 256 : size;
        char *filter = (char *)malloc(filter_len + 1);
        if(filter) {
            memcpy(filter, data, filter_len);
            filter[filter_len] = '\0';
            if (pcap_compile(p, &fp, filter, 1, PCAP_NETMASK_UNKNOWN) == 0) {
                pcap_setfilter(p, &fp);
                pcap_freecode(&fp);
            }
            free(filter);
        }
        pcap_close(p);
    }

    /*
     * ANALYSIS: The function-level coverage report showed pcap_dump_open
     *           has low coverage.
     * IMPLEMENTATION: This block creates a dead pcap handle and opens a
     *                 dumper to write fuzzer-provided packet data to a
     *                 temporary file, exercising the packet dumping logic.
     */
    p = pcap_open_dead(DLT_EN10MB, 65535);
    if (p) {
        char dumppath[256];
        snprintf(dumppath, sizeof(dumppath), "/tmp/%s.dump.pcap", _FUZZ_TARGET_NAME);
        pcap_dumper_t *dumper = pcap_dump_open(p, dumppath);
        if (dumper) {
            struct pcap_pkthdr hdr;
            if (size >= sizeof(hdr)) {
                memcpy(&hdr, data, sizeof(hdr));
                hdr.caplen = hdr.caplen % 1024;
                hdr.len = hdr.caplen;
                if (size >= sizeof(hdr) + hdr.caplen) {
                    pcap_dump((u_char *)dumper, &hdr, data + sizeof(hdr));
                }
            }
            pcap_dump_close(dumper);
        }
        unlink(dumppath);
        pcap_close(p);
    }

    /*
     * ANALYSIS: The function-level coverage report showed pcap_list_tstamp_types
     *           and pcap_set_tstamp_type have low coverage.
     * IMPLEMENTATION: This block lists available timestamp types for a dead
     *                 pcap handle and then sets a fuzzer-chosen timestamp type,
     *                 exercising the timestamp type handling logic.
     */
    p = pcap_open_dead(DLT_EN10MB, 65535);
    if (p) {
        int *tstamp_types;
        int n_tstamp_types = pcap_list_tstamp_types(p, &tstamp_types);
        if (n_tstamp_types > 0) {
            int tstamp_type_to_set = tstamp_types[data[0] % n_tstamp_types];
            pcap_set_tstamp_type(p, tstamp_type_to_set);
            pcap_free_tstamp_types(tstamp_types);
        }
        pcap_close(p);
    }

    /*
     * ANALYSIS: The function-level coverage report from the prompt shows that
     *           many functions in pcap-usb-linux.c, such as usb_dev_add and
     *           usb_activate, have zero coverage.
     * IMPLEMENTATION: This block calls pcap_findalldevs_ex with the "usbmon"
     *                 source. This specifically targets the code paths for enumerating
     *                 USB devices, directly addressing the coverage gap.
     */
    if (pcap_findalldevs_ex("usbmon", NULL, &alldevs, errbuf) == 0) {
        pcap_freealldevs(alldevs);
    }

    /*
     * ANALYSIS: The function-level coverage report shows pcap_open has low
     *           coverage (69.57%). The fuzzer primarily uses pcap_open_dead, which
     *           avoids the more complex logic for opening live devices.
     * IMPLEMENTATION: This block first gets a list of all available devices using
     *                 pcap_findalldevs. It then attempts to open the first device
     *                 in the list with pcap_open. This exercises the code for opening
     *                 a live capture handle.
     */
    if (pcap_findalldevs(&alldevs, errbuf) == 0) {
        if (alldevs != NULL) {
            pcap_t *p_live = pcap_open(alldevs->name, 65535, 0, 100, NULL, errbuf);
            if (p_live != NULL) {
                pcap_close(p_live);
            }
        }
        pcap_freealldevs(alldevs);
    }

    return 0;
}