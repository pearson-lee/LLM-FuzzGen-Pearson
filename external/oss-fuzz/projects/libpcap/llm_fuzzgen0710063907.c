#include <sys/types.h>
#include "/src/libpcap/pcap-int.h"
#include "/src/libpcap/pcap/namedb.h"
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

    switch (selector % 8) {
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
             * ANALYSIS: pcap_dump_open_append has many untested error handling paths.
             *           The existing implementation rarely created a valid pcap file,
             *           causing pcap_dump_open_append to fail and miss coverage.
             * IMPLEMENTATION: A valid pcap global header is now written to the temp
             *                 file before appending fuzzer data. This increases the
             *                 likelihood of pcap_dump_open_append succeeding. A call
             *                 with "-" is also added to test the stdout path.
             */
            char path[256];
            snprintf(path, sizeof(path), "/tmp/%s.pcap", _FUZZ_TARGET_NAME);

            FILE *f = fopen(path, "wb");
            if (f) {
                // Write a valid pcap header to make pcap_dump_open_append more likely to succeed
                struct pcap_file_header hdr = {
                    .magic = 0xa1b2c3d4,
                    .version_major = PCAP_VERSION_MAJOR,
                    .version_minor = PCAP_VERSION_MINOR,
                    .thiszone = 0,
                    .sigfigs = 0,
                    .snaplen = 65535,
                    .linktype = DLT_EN10MB
                };
                fwrite(&hdr, sizeof(hdr), 1, f);
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

            // Test opening stdout
            dumper = pcap_dump_open_append(p, "-");
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
             *           pcap_lookupnet. The fuzz target's coverage report showed the
             *           call to pcap_lookupnet was never reached because pcap_lookupdev
             *           returns NULL in the fuzzing environment.
             * IMPLEMENTATION: This case now calls pcap_lookupnet directly with a
             *                 fuzzer-provided string and the special "any" device string.
             *                 This bypasses the dependency on a real device and allows
             *                 the fuzzer to explore branches within pcap_lookupnet.
             *                 pcap_statustostr is also called to improve its coverage.
             */
            if (size < 1) break;
            
            bpf_u_int32 net, mask;

            // Call with "any" to exercise the special-case logic.
            pcap_lookupnet("any", &net, &mask, errbuf);

            // Create a null-terminated string from fuzzer data for the device.
            char *dev = (char *)malloc(size);
            if (dev) {
                memcpy(dev, data, size -1);
                dev[size - 1] = '\0';
                pcap_lookupnet(dev, &net, &mask, errbuf);
                free(dev);
            }

            pcap_statustostr(data[0]);
            break;
        }
        case 6: {
            /*
             * ANALYSIS: The fuzz target coverage report showed the loop calling
             *           pcap_next_etherent was never entered because the fuzzer-
             *           provided data was not in the correct format.
             * IMPLEMENTATION: A correctly formatted line is now prepended to the
             *                 fuzzer data before writing it to the file. This ensures
             *                 pcap_next_etherent will succeed at least once, entering
             *                 the parsing loop and improving coverage.
             */
            char path[256];
            snprintf(path, sizeof(path), "/tmp/%s.ethers", _FUZZ_TARGET_NAME);

            FILE *f = fopen(path, "wb");
            if (f) {
                // Prepend a valid line to ensure the parsing loop is entered.
                const char *valid_line = "01:02:03:04:05:06 fuzz_host\n";
                fwrite(valid_line, 1, strlen(valid_line), f);
                if (size > 0) {
                    fwrite(data, 1, size, f);
                }
                fclose(f);

                // Re-open for reading
                f = fopen(path, "rb");
                if (f) {
                    while (pcap_next_etherent(f) != NULL) {
                        // Loop to exhaust the file content
                    }
                    fclose(f);
                }
            }
            unlink(path);
            break;
        }
        case 7: {
            /*
             * ANALYSIS: The function-level coverage report showed that pcap_cant_set_rfmon
             *           had zero coverage. This function is called when pcap_activate is
             *           invoked on a handle that has monitor mode requested but does not
             *           support it.
             * IMPLEMENTATION: A "dead" pcap handle is created, which does not support
             *                 monitor mode. pcap_set_rfmon(p, 1) is called to request
             *                 monitor mode, and then pcap_activate(p) is called, which
             *                 will trigger the call to the uncovered pcap_cant_set_rfmon.
             */
            pcap_t *p = pcap_open_dead(DLT_EN10MB, 65535);
            if (!p) break;

            if (pcap_set_rfmon(p, 1) == 0) {
                pcap_activate(p);
            }

            pcap_close(p);
            break;
        }
    }
    return 0;
}