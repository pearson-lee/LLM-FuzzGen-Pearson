#include <sys/types.h>
#include <stdint.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "pcap/pcap.h"
#include "pcap-int.h"

// Forward declaration for function in pcap.c
void pcap_freealldevs(pcap_if_t *alldevs);

#ifndef _FUZZ_TARGET_NAME
#define _FUZZ_TARGET_NAME "llm_fuzzgen0710071916"
#endif

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    if (size < 1) {
        return 0;
    }

    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_if_t *alldevs;
    pcap_t *p;

    /*
     * ANALYSIS: The detailed fuzz target coverage report shows that the error
     *           handling path for pcap_lookupnet is never taken.
     * IMPLEMENTATION: Call pcap_lookupnet with a deliberately invalid device name
     *                 to trigger and exercise the error handling code.
     */
    bpf_u_int32 net_err, mask_err;
    pcap_lookupnet("invalid-device-for-fuzzing", &net_err, &mask_err, errbuf);


    /*
     * ANALYSIS: The function-level coverage report showed pcap_findalldevs had low
     *           branch coverage. The line-level report confirmed this was in the
     *           error handling paths.
     * IMPLEMENTATION: The following code block calls pcap_findalldevs to get a
     *                 list of devices, which is then used in subsequent API calls.
     *                 This helps to exercise the device enumeration logic.
     */
    if (pcap_findalldevs(&alldevs, errbuf) == 0 && alldevs != NULL) {
        /*
         * ANALYSIS: The function-level coverage report showed pcapint_add_addr_to_dev
         *           had low branch coverage. The line-level report showed that the
         *           error handling for malloc failures and other error conditions
         *           was not being exercised.
         * IMPLEMENTATION: The following code block iterates through the found devices
         *                 and calls pcapint_add_addr_to_dev with data from the fuzzer
         *                 to try and trigger these error conditions.
         */
        if (size > sizeof(struct sockaddr_storage)) {
            pcapint_add_addr_to_dev(alldevs, (struct sockaddr*)data, sizeof(struct sockaddr_storage),
                                    (struct sockaddr*)(data + sizeof(struct sockaddr_storage)), sizeof(struct sockaddr_storage),
                                    NULL, 0, NULL, 0, errbuf);
        }

        /*
         * ANALYSIS: The function-level coverage report showed pcap_lookupnet had low
         *           branch coverage.
         * IMPLEMENTATION: The following code block calls pcap_lookupnet with a valid
         *                 device name obtained from pcap_findalldevs to exercise its logic.
         */
        bpf_u_int32 net, mask;
        if (pcap_lookupnet(alldevs->name, &net, &mask, errbuf) == -1) {
            net = 0;
            mask = 0;
        }

        /*
         * ANALYSIS: The original fuzz target's call to pcap_open_live always failed
         *           because it used invalid device names from the fuzzer input. This
         *           prevented coverage of the success path and related functions like
         *           pcap_compile and pcap_setfilter.
         * IMPLEMENTATION: This block now uses a valid device name from pcap_findalldevs
         *                 to successfully create a pcap handle. It then uses this handle
         *                 to compile and apply a BPF filter from the fuzzer input,
         *                 targeting a large amount of uncovered code in gencode.c.
         */
        p = pcap_open_live(alldevs->name, 65535, 1, 1000, errbuf);
        if (p != NULL) {
            /*
             * ANALYSIS: The function-level coverage for pcap_setdirection shows it is not
             *           fully covered.
             * IMPLEMENTATION: Call pcap_setdirection with a value from the fuzzer input
             *                 to exercise its different branches (PCAP_D_IN, PCAP_D_OUT,
             *                 PCAP_D_INOUT).
             */
            pcap_setdirection(p, (pcap_direction_t)data[0]);

            if (size > 1) {
                struct bpf_program fp;
                char* filter = (char*)malloc(size);
                if (filter) {
                    memcpy(filter, data, size - 1);
                    filter[size - 1] = '\0';
                    if (pcap_compile(p, &fp, filter, 1, net) == 0) {
                        pcap_setfilter(p, &fp);
                        pcap_freecode(&fp);
                    }
                    free(filter);
                }
            }
            pcap_close(p);
        }

        pcap_freealldevs(alldevs);
    }

    /*
     * ANALYSIS: The function-level coverage report showed pcap_list_tstamp_types had
     *           low branch coverage. The line-level report showed that the else
     *           branch was never taken because p->tstamp_type_count was always 0.
     * IMPLEMENTATION: The following code block creates a pcap_t object, sets
     *                 tstamp_type_count to a non-zero value from the fuzzer input,
     *                 and then calls pcap_list_tstamp_types to exercise the else
     *                 branch.
     */
    p = pcap_create("any", errbuf);
    if (p != NULL) {
        p->tstamp_type_count = data[0];
        p->tstamp_type_list = NULL;
        if (p->tstamp_type_count > 0) {
            // This memory is freed by pcap_close()
            p->tstamp_type_list = (int*)malloc(sizeof(int) * p->tstamp_type_count);
        }

        // We can only call pcap_list_tstamp_types if the list is allocated
        // (or if the count is 0).
        if (p->tstamp_type_count == 0 || p->tstamp_type_list != NULL) {
            int *tstamp_types;
            int n_tstamp_types = pcap_list_tstamp_types(p, &tstamp_types);
            if (n_tstamp_types > 0) {
                // This memory is allocated by pcap_list_tstamp_types and
                // must be freed by the caller.
                free(tstamp_types);
            }
        }

        // pcap_close will free p->tstamp_type_list if it's not NULL.
        pcap_close(p);
    }

    /*
     * ANALYSIS: The function-level coverage report for sf-pcap.c shows that
     *           pcap_dump_open_append and pcap_dump are not covered.
     * IMPLEMENTATION: This block creates a temporary file and uses pcap_dump_open_append
     *                 and pcap_dump to write a packet to it, exercising the
     *                 pcap file writing and appending functionality. The temporary file is
     *                 deleted before the function returns.
     */
    const char dmp_path[] = "/tmp/" _FUZZ_TARGET_NAME ".dmp";
    pcap_t *p_dead = pcap_open_dead(DLT_EN10MB, 65535);
    if (p_dead) {
        pcap_dumper_t *dumper = pcap_dump_open_append(p_dead, dmp_path);
        if (dumper) {
            struct pcap_pkthdr hdr;
            hdr.ts.tv_sec = 12345;
            hdr.ts.tv_usec = 67890;
            hdr.caplen = size;
            hdr.len = size;
            pcap_dump((u_char *)dumper, &hdr, data);
            pcap_dump_close(dumper);
        }
        pcap_close(p_dead);
        unlink(dmp_path);
    }

    /*
     * ANALYSIS: The function-level coverage report showed pcapint_createsrcstr_ex
     *           had low branch coverage. The line-level report showed that the
     *           PCAP_SRC_IFREMOTE and default cases were not being exercised.
     * IMPLEMENTATION: The following code block calls pcapint_createsrcstr_ex with
     *                 PCAP_SRC_IFREMOTE and an invalid type to exercise these
     *                 uncovered branches.
     */
    char source[PCAP_BUF_SIZE];
    pcapint_createsrcstr_ex(source, PCAP_SRC_IFREMOTE, NULL, "host", "port", "name", 0, errbuf);
    pcapint_createsrcstr_ex(source, -1, NULL, NULL, NULL, NULL, 0, errbuf);

    /*
     * ANALYSIS: The function pcap_statustostr has low coverage (53.85%).
     * IMPLEMENTATION: Call pcap_statustostr with various PCAP status codes, including
     *                 one from the fuzzer input, to cover more of its logic.
     */
    pcap_statustostr(PCAP_WARNING);
    pcap_statustostr(PCAP_ERROR_BREAK);
    pcap_statustostr((int)data[size-1]);

    return 0;
}