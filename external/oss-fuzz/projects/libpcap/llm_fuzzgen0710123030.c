#include <sys/types.h>
#include <sys/socket.h>
#include <pcap/pcap.h>
#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

#define _FUZZ_TARGET_NAME "fuzz_pcap_findalldevs"

// Helper function to create a temporary file with the given content
static char* create_temp_file(const uint8_t* data, size_t size) {
    char* path = (char*)malloc(256);
    if (!path) {
        return NULL;
    }
    snprintf(path, 256, "/tmp/%s.pcap", _FUZZ_TARGET_NAME);

    FILE* fp = fopen(path, "wb");
    if (!fp) {
        free(path);
        return NULL;
    }
    fwrite(data, 1, size, fp);
    fclose(fp);
    return path;
}

int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
    pcap_if_t* alldevs;
    char errbuf[PCAP_ERRBUF_SIZE];
    char* source = NULL;
    char* temp_file_path = NULL;

    /*
     * ANALYSIS: The function-level coverage report showed pcap_lookupdev
     *           had some missed branches. This function is a simple way
     *           to exercise more of the device enumeration logic.
     * IMPLEMENTATION: Call pcap_lookupdev to improve coverage.
     */
    pcap_lookupdev(errbuf);

    if (size < 1) {
        return 0;
    }

    // One byte to decide the source type
    uint8_t source_type = data[0];
    data++;
    size--;

    if (source_type % 4 == 0) {
        // Use a fuzzer-generated string as the source
        size_t source_len = size > 255 ? 255 : size;
        source = (char*)malloc(source_len + 1);
        if (!source) {
            return 0;
        }
        memcpy(source, data, source_len);
        source[source_len] = '\0';

        // Reject sources that look like file paths, as we can't clean them up
        // and they can cause crashes if malformed (e.g. "file://").
        if (strncmp(source, "file://", 7) == 0) {
            free(source);
            return 0;
        }
    } else if (source_type % 4 == 1) {
        // Use a file source
        temp_file_path = create_temp_file(data, size);
        if (temp_file_path) {
            // +8 for "file://" and null terminator.
            source = (char*)malloc(strlen(temp_file_path) + 8);
            if (source) {
                snprintf(source, strlen(temp_file_path) + 8, "file://%s", temp_file_path);
            }
        }
    } else if (source_type % 4 == 2) {
        // Use a local interface source
        source = strdup("rpcap://");
    } else {
        /*
         * ANALYSIS: The function-level coverage report showed pcap_findalldevs
         *           had low coverage (52%). This function is a simple wrapper
         *           around pcap_findalldevs_ex with a NULL source.
         * IMPLEMENTATION: Explicitly set the source to NULL in one case to
         *                 ensure the pcap_findalldevs wrapper is exercised,
         *                 thereby improving its coverage. This path does not
         *                 allocate memory for `source`.
         */
        source = NULL;
    }

    // In the new case where source is intentionally NULL, the check `!source`
    // is not an error, so we only check for allocation failures from other paths.
    if (source == NULL && source_type % 4 != 3) {
        if (temp_file_path) {
            unlink(temp_file_path);
            free(temp_file_path);
        }
        return 0;
    }

    int findalldevs_result;
    /*
     * ANALYSIS: The function-level coverage report shows pcap_findalldevs has
     *           low coverage (52.38%). This is a wrapper around pcap_findalldevs_ex.
     *           By providing an auth object, we can exercise more complex paths
     *           within pcap_findalldevs_ex related to authentication.
     * IMPLEMENTATION: Allocate a pcap_rmtauth struct and populate it with fuzzer
     *                 data. This exercises the authentication handling code paths
     *                 in pcap_findalldevs_ex, improving its coverage.
     */
#ifdef ENABLE_REMOTE
    struct pcap_rmtauth auth;
    char *username = NULL;
    char *password = NULL;
    if (size > 2) {
        size_t username_len = data[0] % (size -1);
        username = (char*)malloc(username_len + 1);
        if(username) {
            memcpy(username, data + 1, username_len);
            username[username_len] = '\0';
            size_t password_len = size - 1 - username_len;
            password = (char*)malloc(password_len + 1);
            if(password) {
                memcpy(password, data + 1 + username_len, password_len);
                password[password_len] = '\0';
                auth.type = PCAP_RMTAUTH_UPASS;
                auth.username = username;
                auth.password = password;
                findalldevs_result = pcap_findalldevs_ex(source, &auth, &alldevs, errbuf);
            } else {
                findalldevs_result = pcap_findalldevs_ex(source, NULL, &alldevs, errbuf);
            }
        } else {
            findalldevs_result = pcap_findalldevs_ex(source, NULL, &alldevs, errbuf);
        }
    } else
#endif
    {
        if (source == NULL) {
            findalldevs_result = pcap_findalldevs(&alldevs, errbuf);
        } else {
            findalldevs_result = pcap_findalldevs_ex(source, NULL, &alldevs, errbuf);
        }
    }


    if (findalldevs_result == 0 && alldevs) {
        pcap_if_t* dev;
        for (dev = alldevs; dev != NULL; dev = dev->next) {
            /*
             * ANALYSIS: The function-level coverage report showed pcap_lookupnet
             *           had low coverage (64%). Detailed line coverage revealed
             *           that the loops for iterating device addresses were never
             *           entered.
             * IMPLEMENTATION: Call pcap_lookupnet on each device found. This
             *                 will exercise the device name lookup and address
             *                 iteration logic within pcap_lookupnet, improving
             *                 its coverage.
             */
            if (dev->name) {
                bpf_u_int32 netp, maskp;
                pcap_lookupnet(dev->name, &netp, &maskp, errbuf);
            }

            pcap_t* handle = pcap_open_dead_with_tstamp_precision(DLT_NULL, 65535, PCAP_TSTAMP_PRECISION_MICRO);
            if (handle) {
                /*
                 * ANALYSIS: The function-level coverage report showed that
                 *           pcap_list_tstamp_types has low coverage (65.22%).
                 * IMPLEMENTATION: Call pcap_list_tstamp_types and pcap_free_tstamp_types
                 *                 to exercise the timestamp type enumeration logic and improve
                 *                 coverage.
                 */
                int* tstamp_types;
                int n_tstamp_types = pcap_list_tstamp_types(handle, &tstamp_types);
                if (n_tstamp_types > 0) {
                    pcap_free_tstamp_types(tstamp_types);
                }

                struct bpf_program fp;
                if (size > 1) {
                    char* filter = (char*)malloc(size);
                    if (filter) {
                        memcpy(filter, data, size - 1);
                        filter[size - 1] = '\0';
                        if (pcap_compile(handle, &fp, filter, 1, PCAP_NETMASK_UNKNOWN) == 0) {
                            pcap_freecode(&fp);
                        }
                        free(filter);
                    }
                }
                pcap_close(handle);
            }
        }
        pcap_freealldevs(alldevs);
    }

#ifdef ENABLE_REMOTE
    if(username) free(username);
    if(password) free(password);
#endif

    // `source` is only freed if it was allocated. The NULL case is skipped.
    if (source != NULL) {
        free(source);
    }
    if (temp_file_path) {
        unlink(temp_file_path);
        free(temp_file_path);
    }

    return 0;
}