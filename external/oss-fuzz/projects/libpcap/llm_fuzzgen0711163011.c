#include <pcap.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <stdint.h>
#include <stddef.h>

// Define a macro for the fuzzer name if it's not provided by the build system.
#ifndef _FUZZ_TARGET_NAME
#define _FUZZ_TARGET_NAME "fuzz_pcap_api"
#endif

// Helper function to create a temporary file with fuzzer data.
static int bufferToFile(const char *dir_path, const char *name, const uint8_t *data, size_t size) {
    char path[256];
    snprintf(path, sizeof(path), "%s/%s", dir_path, name);
    FILE *fp = fopen(path, "wb");
    if (!fp) {
        return -1;
    }
    if (fwrite(data, 1, size, fp) != size) {
        fclose(fp);
        return -1;
    }
    fclose(fp);
    return 0;
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    if (size < 1) {
        return 0;
    }

    // Use a byte from the fuzzer data to select a scenario.
    unsigned char scenario = data[0];
    data++;
    size--;

    char errbuf[PCAP_ERRBUF_SIZE];

    switch (scenario % 3) {
        case 0: {
            /*
             * ANALYSIS: The function-level coverage report showed pcap_findalldevs_ex
             *           had low branch coverage, particularly in the code path for handling
             *           PCAP_SRC_FILE. The line-level report confirmed that error-handling
             *           branches for directory and file operations were not being exercised.
             * IMPLEMENTATION: This block creates a temporary directory and a file within it
             *                 using fuzzer data. It then calls pcap_findalldevs_ex with a
             *                 'file://' source string to specifically target this code path.
             *                 This exercises file system interactions and related error checks.
             */
            pcap_if_t *alldevs;
            char dir_path[128];
            snprintf(dir_path, sizeof(dir_path), "/tmp/%s_dir", _FUZZ_TARGET_NAME);

            // Create a temporary directory.
            mkdir(dir_path, 0700);

            // Create a temporary file in the directory with fuzzer data.
            if (size > 0) {
                bufferToFile(dir_path, "fuzz.pcap", data, size);
            }

            char source[256];
            snprintf(source, sizeof(source), "file://%s/", dir_path);

            if (pcap_findalldevs_ex(source, NULL, &alldevs, errbuf) == 0) {
                pcap_if_t *dev;
                for (dev = alldevs; dev != NULL; dev = dev->next) {
                    // Attempt to open the found files to increase interaction.
                    pcap_t *p = pcap_open_offline(dev->name, errbuf);
                    if (p) {
                        pcap_close(p);
                    }
                }
                pcap_freealldevs(alldevs);
            }

            // Cleanup
            char file_path[256];
            snprintf(file_path, sizeof(file_path), "%s/fuzz.pcap", dir_path);
            unlink(file_path);
            rmdir(dir_path);
            break;
        }

        case 1: {
            /*
             * ANALYSIS: The function pcap_findalldevs_ex has a code path for handling
             *           remote interfaces (PCAP_SRC_IFREMOTE) which may not be enabled
             *           or tested.
             * IMPLEMENTATION: This block calls pcap_findalldevs_ex with a source string
             *                 formatted for remote interfaces ('rpcap://'). This ensures
             *                 that the logic for parsing this source type and the corresponding
             *                 error path (if remote capture is disabled) are exercised.
             */
            pcap_if_t *alldevs;
            if (pcap_findalldevs_ex("rpcap://", NULL, &alldevs, errbuf) == 0) {
                pcap_freealldevs(alldevs);
            }
            break;
        }

        case 2: {
            /*
             * ANALYSIS: The coverage report for pcap_statustostr indicated that many
             *           'case' statements in its switch block were never executed. These
             *           uncovered branches correspond to various PCAP warning and error codes.
             * IMPLEMENTATION: This block iterates through an array of libpcap status codes
             *                 and calls pcap_statustostr for each one. A value from the
             *                 fuzzer input is used to select which code to test, ensuring
             *                 all possible error-to-string conversions are exercised over time.
             */
            int codes[] = {
                PCAP_WARNING,
                PCAP_WARNING_TSTAMP_TYPE_NOTSUP,
                PCAP_WARNING_PROMISC_NOTSUP,
                PCAP_ERROR,
                PCAP_ERROR_BREAK,
                PCAP_ERROR_NOT_ACTIVATED,
                PCAP_ERROR_ACTIVATED,
                PCAP_ERROR_NO_SUCH_DEVICE,
                PCAP_ERROR_RFMON_NOTSUP,
                PCAP_ERROR_NOT_RFMON,
                PCAP_ERROR_PERM_DENIED,
                PCAP_ERROR_IFACE_NOT_UP,
                PCAP_ERROR_CANTSET_TSTAMP_TYPE,
                PCAP_ERROR_PROMISC_PERM_DENIED,
                PCAP_ERROR_TSTAMP_PRECISION_NOTSUP,
                PCAP_ERROR_CAPTURE_NOTSUP
            };
            int num_codes = sizeof(codes) / sizeof(codes[0]);
            if (size > 0) {
                int code_to_test = codes[data[0] % num_codes];
                pcap_statustostr(code_to_test);
            }
            break;
        }
    }

    return 0;
}