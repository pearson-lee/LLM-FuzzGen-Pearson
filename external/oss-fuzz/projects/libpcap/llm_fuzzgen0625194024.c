#include <pcap.h>
#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>

// Dummy handler for pcap_dispatch
void dummy_handler(u_char *user, const struct pcap_pkthdr *h, const u_char *bytes) {
  // Do nothing
}

// Main fuzzing function
int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  char errbuf[PCAP_ERRBUF_SIZE];
  pcap_if_t *alldevs = NULL;
  char *dev_name = NULL;

  // --- Environment Setup ---
  // Find an available network interface to use for live capture.
  if (pcap_findalldevs(&alldevs, errbuf) == -1 || alldevs == NULL) {
    return 0;
  }
  dev_name = alldevs->name;

  // --- Fuzzer Setup ---
  if (size < 10) {
    pcap_freealldevs(alldevs);
    return 0;
  }

  pcap_t *p = NULL;
  struct bpf_program fp;

  // Use a variable portion of the input for the filter string, leaving the rest for other operations.
  size_t filter_len = data[0];
  data++;
  size--;

  // Added to improve coverage: Cap filter length to ensure data remains for packet content.
  // This is to ensure the branch for pcap_dump (lines 112-122) is taken.
  if (filter_len > size / 2) {
      filter_len = size / 2;
  }

  char *filter_str = (char *)malloc(filter_len + 1);
  if (!filter_str) {
    pcap_freealldevs(alldevs);
    return 0;
  }
  memcpy(filter_str, data, filter_len);
  filter_str[filter_len] = '\0';
  const uint8_t *remaining_data = data + filter_len;
  size_t remaining_size = size - filter_len;

  // --- API Calls ---
  // 1. Create a pcap handle for live capture.
  p = pcap_create(dev_name, errbuf);
  if (p == NULL) {
    free(filter_str);
    pcap_freealldevs(alldevs);
    return 0;
  }

  // 2. Set various options on the handle.
  if (remaining_size > 4) {
    pcap_set_snaplen(p, *(int*)remaining_data);
    pcap_set_promisc(p, remaining_data[0] % 2);
  }
  pcap_set_timeout(p, 1); // 1ms timeout

  // 3. Activate the handle.
  if (pcap_activate(p) != 0) {
    pcap_close(p);
    free(filter_str);
    pcap_freealldevs(alldevs);
    return 0;
  }

  // 4. Set the handle to non-blocking mode after activation.
  if (pcap_setnonblock(p, 1, errbuf) == -1) {
    pcap_close(p);
    free(filter_str);
    pcap_freealldevs(alldevs);
    return 0;
  }

  if (remaining_size > 0) {
    pcap_setdirection(p, (pcap_direction_t)(remaining_data[0] % 3));
  }

  // 5. Compile and set a BPF filter from fuzzed data.
  if (pcap_compile(p, &fp, filter_str, 1, PCAP_NETMASK_UNKNOWN) == 0) {
    if (pcap_setfilter(p, &fp) != 0) {
      pcap_freecode(&fp);
    }
  }

  // 6. Inject a packet.
  if (remaining_size > 0) {
    pcap_inject(p, remaining_data, remaining_size);
  }

  // 7. Read packets.
  pcap_dispatch(p, 5, dummy_handler, NULL);

  // 8. Get capture statistics.
  struct pcap_stat ps;
  pcap_stats(p, &ps);

  FILE *temp_file = tmpfile();
  if (temp_file) {
    pcap_dumper_t *dumper = pcap_dump_fopen(p, temp_file);
    if (dumper) {
      if (remaining_size > sizeof(struct pcap_pkthdr)) {
        struct pcap_pkthdr header;
        memcpy(&header, remaining_data, sizeof(struct pcap_pkthdr));
        const u_char *pkt_data = (const u_char *)(remaining_data + sizeof(struct pcap_pkthdr));
        size_t pkt_size = remaining_size - sizeof(struct pcap_pkthdr);

        header.caplen = (header.caplen > pkt_size) ? pkt_size : header.caplen;
        header.len = (header.len > pkt_size) ? pkt_size : header.len;

        pcap_dump((u_char *)dumper, &header, pkt_data);
      }
      pcap_dump_close(dumper);
    } else {
      fclose(temp_file);
    }
  }

  // --- Added to improve coverage: Offline/Dead handle tests ---
  // Call functions on a dead handle to cover offline code paths.
  pcap_t *dead_p = pcap_open_dead(DLT_EN10MB, 65535);
  if (dead_p) {
    int *dlt_buf = NULL;
    // pcap_list_datalinks had low coverage.
    if (pcap_list_datalinks(dead_p, &dlt_buf) >= 0) {
        // pcap_free_datalinks is the required cleanup function.
        pcap_free_datalinks(dlt_buf);
    }
    pcap_close(dead_p); // This is memory-safe; cleans up the dead handle.
  }

  // --- Added to improve coverage: Standalone function tests ---
  // Call simple, uncovered conversion functions identified in the coverage report.
  if (remaining_size > 0) {
    pcap_statustostr(remaining_data[0]);
    pcap_tstamp_type_val_to_name(remaining_data[0]);
    pcap_tstamp_type_val_to_description(remaining_data[0]);
  }

  // --- Cleanup ---
  pcap_close(p);
  free(filter_str);
  pcap_freealldevs(alldevs);

  return 0;
}