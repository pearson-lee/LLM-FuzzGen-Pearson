#include <sys/types.h>
#include <pcap.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <stdio.h>
#include <sys/stat.h>

// Define a default name for the fuzz target if not provided by the build system.
// This is used to create unique temporary filenames.
#ifndef _FUZZ_TARGET_NAME
#define _FUZZ_TARGET_NAME "fuzz_pcap_api"
#endif

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    if (size < 1) {
        return 0;
    }

    // Use the first byte to select which API group to fuzz in this execution.
    uint8_t selector = data[0];
    const uint8_t *orig_data = data; // Keep a pointer to the original data
    size_t orig_size = size;
    data++;
    size--;

    char errbuf[PCAP_ERRBUF_SIZE];

    switch (selector % 6) {
        case 0: {
            /*
             * ANALYSIS: The function-level coverage report shows that pcap_init has
             *           uncovered branches for different initialization options.
             * IMPLEMENTATION: The following code calls pcap_init with a fuzzer-derived
             *                 option to explore these different initialization paths.
             *                 The fuzzing engine's repeated execution will naturally test
             *                 the re-initialization logic.
             */
            if (size > 0) {
                unsigned int opts = data[0];
                pcap_init(opts, errbuf);
            }
            break;
        }

        case 1: {
            /*
             * ANALYSIS: The coverage report indicates that gen_inbound_outbound and
             *           gen_multicast in gencode.c have very low coverage. These
             *           internal functions are invoked by pcap_compile, and their
             *           behavior is contingent on the link-layer type (DLT) and the
             *           filter string. bpf_dump also has low coverage.
             * IMPLEMENTATION: A variety of pcap handles with different DLTs are created.
             *                 pcap_compile is then called with specific filter strings
             *                 like "inbound" and "multicast", as well as a fuzzer-
             *                 provided string, to exercise these code generation paths.
             *                 bpf_dump is then called to improve its coverage.
             */
            int dlt_types[] = {DLT_EN10MB, DLT_SLIP, DLT_FDDI, DLT_IEEE802, DLT_ARCNET, DLT_LINUX_SLL};
            const char *filters[] = {"inbound", "outbound", "multicast", "ip multicast", "ipv6 multicast"};
            char *fuzzed_filter = NULL;

            if (size > 1) {
                fuzzed_filter = (char *)malloc(size);
                if (fuzzed_filter) {
                    memcpy(fuzzed_filter, data, size - 1);
                    fuzzed_filter[size - 1] = '\0';
                }
            }

            for (size_t i = 0; i < sizeof(dlt_types) / sizeof(dlt_types[0]); ++i) {
                pcap_t *p = pcap_open_dead(dlt_types[i], 65535);
                if (!p) continue;

                struct bpf_program prog;

                // Test with predefined, targeted filter strings
                for (size_t j = 0; j < sizeof(filters) / sizeof(filters[0]); ++j) {
                    if (pcap_compile(p, &prog, filters[j], 1, PCAP_NETMASK_UNKNOWN) == 0) {
                        /*
                         * ANALYSIS: The function bpf_dump has low coverage. It takes an integer
                         *           option that controls its output format.
                         * IMPLEMENTATION: Call bpf_dump with a fuzzer-controlled option
                         *                 after a successful compilation to exercise its different
                         *                 code paths.
                         */
                        if (orig_size > 1) {
                            bpf_dump(&prog, orig_data[1]);
                        }
                        pcap_freecode(&prog);
                    }
                }

                // Test with a fuzzer-provided filter string
                if (fuzzed_filter) {
                    if (pcap_compile(p, &prog, fuzzed_filter, 1, PCAP_NETMASK_UNKNOWN) == 0) {
                        if (orig_size > 1) {
                            bpf_dump(&prog, orig_data[1]);
                        }
                        pcap_freecode(&prog);
                    }
                }

                pcap_close(p);
            }
            free(fuzzed_filter);
            break;
        }

        case 2: {
            /*
             * ANALYSIS: pcap_list_tstamp_types has an uncovered 'else' branch that is
             *           only taken when a pcap handle supports multiple timestamp types
             *           (p->tstamp_type_count > 0).
             * IMPLEMENTATION: pcap_activate() is called on a "dead" pcap handle. This
             *                 action can populate the list of supported timestamp types,
             *                 allowing the fuzzer to enter the previously unreachable branch.
             */
            pcap_t *p = pcap_open_dead(DLT_EN10MB, 65535);
            if (!p) break;

            pcap_activate(p);

            int *tstamp_types = NULL;
            int n_tstamp_types = pcap_list_tstamp_types(p, &tstamp_types);

            if (n_tstamp_types >= 0) {
                pcap_free_tstamp_types(tstamp_types);
            }

            pcap_close(p);
            break;
        }

        case 3: {
            /*
             * ANALYSIS: pcap_dump_open_append has many untested error handling paths
             *           related to file I/O and pcap header validation.
             * IMPLEMENTATION: A temporary file is created with fuzzer-controlled content
             *                 to simulate various states (empty, corrupted header, valid
             *                 header). pcap_dump_open_append is then called on this file
             *                 to trigger these error conditions. The fuzzer also tests
             *                 special filenames like NULL and "-".
             */
            char path[256];
            snprintf(path, sizeof(path), "/tmp/%s.pcap", _FUZZ_TARGET_NAME);

            FILE *f = fopen(path, "wb");
            if (f) {
                if (size > 0) {
                    fwrite(data, 1, size, f);
                }
                fclose(f);
            }

            pcap_t *p = pcap_open_dead(DLT_EN10MB, 65535);
            if (!p) {
                unlink(path);
                break;
            }

            pcap_dumper_t *dumper = pcap_dump_open_append(p, path);
            if (dumper) {
                pcap_dump_close(dumper);
            }
            
            dumper = pcap_dump_open_append(p, NULL);
            if (dumper) {
                pcap_dump_close(dumper);
            }

            pcap_close(p);
            unlink(path);
            break;
        }
        case 4: {
            /*
             * ANALYSIS: The function-level coverage report showed low coverage for
             *           pcap_findalldevs and pcap_findalldevs_ex. The line-level report
             *           confirmed that error paths and file-based source paths were
             *           uncovered.
             * IMPLEMENTATION: This case calls pcap_findalldevs_ex with different source
             *                 strings to exercise these paths. A "pcap://" source triggers
             *                 the local device lookup (pcap_findalldevs), and a "file://"
             *                 source triggers the directory traversal logic. pcap_lookupdev
             *                 is also called to cover another under-tested function.
             */
            pcap_if_t *alldevs;
            
            // Test finding local devices
            if (pcap_findalldevs_ex("pcap://", NULL, &alldevs, errbuf) == 0) {
                pcap_freealldevs(alldevs);
            }

            // Test finding file-based sources
            char dir_path[256];
            snprintf(dir_path, sizeof(dir_path), "/tmp/%s_dir/", _FUZZ_TARGET_NAME);
            mkdir(dir_path, 0755);

            char file_path[512];
            snprintf(file_path, sizeof(file_path), "%sfuzz.pcap", dir_path);

            FILE *f = fopen(file_path, "wb");
            if (f) {
                if (size > 0) {
                    fwrite(data, 1, size, f);
                }
                fclose(f);
            }

            char source_str[512];
            snprintf(source_str, sizeof(source_str), "file://%s", dir_path);
            if (pcap_findalldevs_ex(source_str, NULL, &alldevs, errbuf) == 0) {
                pcap_freealldevs(alldevs);
            }

            unlink(file_path);
            rmdir(dir_path);

            // Test looking up the default device
            pcap_lookupdev(errbuf);
            break;
        }
        case 5: {
            /*
             * ANALYSIS: The function-level coverage report shows low coverage for
             *           pcap_lookupnet and pcap_statustostr.
             * IMPLEMENTATION: This case calls pcap_lookupnet on the default device
             *                 to exercise its code paths. It also calls pcap_statustostr
             *                 with a fuzzer-derived status code to improve its coverage.
             */
            if (size < 1) break;

            char *dev = pcap_lookupdev(errbuf);
            if (dev) {
                bpf_u_int32 net, mask;
                pcap_lookupnet(dev, &net, &mask, errbuf);
            }

            pcap_statustostr(data[0]);
            break;
        }
    }
    return 0;
}