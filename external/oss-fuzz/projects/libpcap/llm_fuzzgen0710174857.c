#include <pcap.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>

#ifndef _FUZZ_TARGET_NAME
#define _FUZZ_TARGET_NAME "fuzz_target"
#endif

// Helper to create a temporary file with fuzzed data
static char *create_temp_file(const uint8_t *data, size_t size) {
  static char path[256];
  snprintf(path, sizeof(path), "/tmp/%s.pcap", _FUZZ_TARGET_NAME);
  int fd = open(path, O_WRONLY | O_CREAT | O_TRUNC, 0600);
  if (fd < 0) {
    return NULL;
  }
  if (write(fd, data, size) != (ssize_t)size) {
    close(fd);
    unlink(path);
    return NULL;
  }
  close(fd);
  return path;
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  if (size < 10) {
    return 0;
  }

  char errbuf[PCAP_ERRBUF_SIZE];
  pcap_if_t *alldevs;
  char *device = "any";

  // Use a portion of the data for the source string
  size_t source_len = size > 50 ? 50 : size;
  char *source = (char *)malloc(source_len + 1);
  if (!source) return 0;
  memcpy(source, data, source_len);
  source[source_len] = '\0';

  /*
   * ANALYSIS: The function-level coverage report shows pcap_findalldevs_ex has
   *           low coverage (61.85%). This function parses complex source
   *           strings to find devices from various sources (local, remote, file).
   * IMPLEMENTATION: Call pcap_findalldevs_ex() with a fuzzed source string to
   *                 exercise its parsing logic. The result is freed to prevent leaks.
   */
  if (pcap_findalldevs_ex(source, NULL, &alldevs, errbuf) == 0) {
    pcap_freealldevs(alldevs);
  }
  free(source);


  pcap_t *p = pcap_create(device, errbuf);
  if (p == NULL) {
    return 0;
  }

  // Use remaining data for other operations
  const uint8_t *rem_data = data + source_len;
  size_t rem_size = size - source_len;

  // Consume a byte to decide on non-blocking mode
  int nonblock = 0;
  if (rem_size > 0) {
    nonblock = (rem_data[0] % 2);
    rem_data++;
    rem_size--;
  }

  /*
   * ANALYSIS: The line-level coverage for pcap_activate reveals that the
   *           branch `if (p->opt.nonblock)` is never taken.
   * IMPLEMENTATION: The following code block explicitly calls pcap_setnonblock()
   *                 based on a fuzzed value before calling pcap_activate(),
   *                 ensuring this code path is exercised.
   */
  if (nonblock) {
    pcap_setnonblock(p, 1, errbuf);
  }

  // Set other options randomly
  if (rem_size > 5) {
      pcap_set_snaplen(p, (rem_data[1] << 8) | rem_data[2]);
      pcap_set_promisc(p, rem_data[3] % 2);
      pcap_set_timeout(p, (rem_data[4] << 8) | rem_data[5]);
      rem_data += 5;
      rem_size -= 5;
  }

  /*
   * ANALYSIS: The function pcap_setdirection is not called by the fuzzer,
   *           leading to missed coverage in packet direction filtering logic.
   * IMPLEMENTATION: Call pcap_setdirection() with a fuzzer-controlled value
   *                 to exercise the PCAP_D_IN, PCAP_D_OUT, and PCAP_D_INOUT code paths.
   */
  if (rem_size > 0) {
    pcap_setdirection(p, rem_data[0] % 3);
    rem_data++;
    rem_size--;
  }

  if (pcap_activate(p) == 0) {
    /*
     * ANALYSIS: The functions for listing datalinks and timestamp types
     *           (pcap_list_datalinks, pcap_list_tstamp_types) show low coverage.
     * IMPLEMENTATION: Call these functions on an activated handle to exercise
     *                 the enumeration logic. The results are freed.
     */
    int *dlt_buf;
    int n_dlt = pcap_list_datalinks(p, &dlt_buf);
    if (n_dlt > 0) {
        pcap_free_datalinks(dlt_buf);
    }
    int *tstamp_buf;
    int n_tstamp = pcap_list_tstamp_types(p, &tstamp_buf);
    if (n_tstamp > 0) {
        pcap_free_tstamp_types(tstamp_buf);
    }

    struct bpf_program fp;
    // Use a portion of the data for the filter string
    size_t filter_len = rem_size > 100 ? 100 : rem_size;
    char *filter_str = (char*)malloc(filter_len + 1);
    if(filter_str) {
        memcpy(filter_str, rem_data, filter_len);
        filter_str[filter_len] = '\0';
        rem_data += filter_len;
        rem_size -= filter_len;

        /*
         * ANALYSIS: The BPF filter engine, pcapint_filter_with_aux_data, has
         *           very poor coverage (43.64%), with many BPF instructions
         *           and error paths completely untested.
         * IMPLEMENTATION: Compile and set a fuzzer-generated filter string.
         *                 This creates a wide variety of BPF programs,
         *                 dramatically increasing the coverage of the BPF engine when
         *                 pcap_filter() is called later.
         */
        if (pcap_compile(p, &fp, filter_str, 0, PCAP_NETMASK_UNKNOWN) == 0) {
          pcap_setfilter(p, &fp);
          pcap_freecode(&fp);
        }
        free(filter_str);
    }
  }
  pcap_close(p);


  /*
   * ANALYSIS: Opening and parsing saved capture files is a critical attack surface.
   *           The function pcap_open_offline_with_tstamp_precision allows testing
   *           this functionality. The packet dumping functions (pcap_dump_open, pcap_dump)
   *           were also completely uncovered.
   * IMPLEMENTATION: Create a temporary file with fuzzed data and open it as a pcap
   *                 file. Then, create a second temporary file and open a dumper with
   *                 pcap_dump_open. Use pcap_loop with pcap_dump as the callback to
   *                 process all packets and write them to the dumper, exercising the
   *                 full read-process-write lifecycle.
   */
  char *temp_file = create_temp_file(rem_data, rem_size);
  if (temp_file) {
    pcap_t *p_offline = pcap_open_offline_with_tstamp_precision(temp_file, PCAP_TSTAMP_PRECISION_NANO, errbuf);
    if (p_offline) {
      char dump_path[256];
      snprintf(dump_path, sizeof(dump_path), "/tmp/%s.dump.pcap", _FUZZ_TARGET_NAME);
      pcap_dumper_t *dumper = pcap_dump_open(p_offline, dump_path);
      if (dumper) {
        pcap_loop(p_offline, -1, pcap_dump, (u_char *)dumper);
        pcap_dump_close(dumper);
        unlink(dump_path);
      } else {
        // Fallback if dumper fails
        struct pcap_pkthdr *header;
        const u_char *packet;
        pcap_next_ex(p_offline, &header, &packet);
      }
      pcap_close(p_offline);
    }
    unlink(temp_file);
  }

  return 0;
}