#include <pcap/pcap.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

// A simple callback handler for pcap_dispatch and pcap_loop.
// It doesn't need to do anything for this fuzz target.
static void dummy_handler(u_char *user, const struct pcap_pkthdr *h, const u_char *bytes) {
  // Do nothing.
  (void)user;
  (void)h;
  (void)bytes;
}

// Main fuzzing function
int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  pcap_t *p = NULL;
  pcap_if_t *alldevs = NULL;
  char errbuf[PCAP_ERRBUF_SIZE];
  struct pcap_stat ps;

  // We need at least a few bytes to work with for all the settings.
  if (size < 40) {
    return 0;
  }

  const char *dev = "any"; // Default to "any" device
  char invalid_dev[17];    // Buffer for invalid device name from fuzzer data

  // Use a byte from the fuzzer to select a device strategy.
  int dev_choice = data[0] % 13;
  data++;
  size--;

  if (dev_choice < 10) {
    // Strategy 0-9: Use a real device if available.
    // This provides coverage for device enumeration and selection.
    if (pcap_findalldevs(&alldevs, errbuf) == 0 && alldevs != NULL) {
      pcap_if_t *d = alldevs;
      // dev_choice is 0-9, loop dev_choice times.
      for (int i = 0; i < dev_choice && d->next != NULL; i++) {
        d = d->next;
      }
      dev = d->name;
    }
  } else if (dev_choice == 10) {
    // Strategy 10: Target netfilter code by explicitly selecting 'nflog'.
    // This improves coverage in pcap-netfilter-linux.c.
    dev = "nflog";
  } else if (dev_choice == 11) {
    // Strategy 11: Target netfilter code by explicitly selecting 'nfqueue'.
    // This also improves coverage in pcap-netfilter-linux.c.
    dev = "nfqueue";
  } else { // dev_choice == 12
    // Strategy 12: Use fuzzer data for the device name to trigger pcap_create()
    // failures, covering error-handling paths shown as missed in the report.
    size_t name_len = size < 16 ? size : 16;
    memcpy(invalid_dev, data, name_len);
    invalid_dev[name_len] = '\0';
    dev = invalid_dev;
    data += name_len;
    size -= name_len;
  }

  // Create a pcap handle.
  p = pcap_create(dev, errbuf);
  if (p == NULL) {
    // This path is now reachable due to the invalid device name strategy.
    if (alldevs) {
      pcap_freealldevs(alldevs);
    }
    return 0;
  }

  // Added to improve coverage in pcap.c by exercising datalink APIs.
  int *dlt_buf = NULL;
  int dlt_count = pcap_list_datalinks(p, &dlt_buf);
  if (dlt_count > 0 && dlt_buf != NULL) {
    pcap_set_datalink(p, dlt_buf[data[0] % dlt_count]);
    // Memory safety: pcap_free_datalinks is called to free the allocated buffer.
    pcap_free_datalinks(dlt_buf);
  }
  data++;
  size--;

  // Added to improve coverage in pcap.c by exercising timestamp APIs.
  int *tstamp_buf = NULL;
  int tstamp_count = pcap_list_tstamp_types(p, &tstamp_buf);
  if (tstamp_count > 0 && tstamp_buf != NULL) {
    pcap_set_tstamp_type(p, tstamp_buf[data[0] % tstamp_count]);
    // Memory safety: pcap_free_tstamp_types is called to free the allocated buffer.
    pcap_free_tstamp_types(tstamp_buf);
  }
  data++;
  size--;

  // Fuzz various pre-activation settings.
  pcap_set_snaplen(p, *(const int *)(data));
  data += sizeof(int);
  size -= sizeof(int);

  pcap_set_promisc(p, data[0] % 2);
  data++;
  size--;

  pcap_set_timeout(p, *(const int *)(data));
  data += sizeof(int);
  size -= sizeof(int);

  pcap_set_buffer_size(p, *(const int *)(data));
  data += sizeof(int);
  size -= sizeof(int);

  // Attempt to activate the handle.
  int ret = pcap_activate(p);

  // Added to exercise BPF filter compilation and application, which was a
  // major coverage gap in gencode.c, optimize.c, and bpf_filter.c.
  if (size > 0) {
    struct bpf_program fp;
    // Use a small, null-terminated string from the fuzzer input.
    size_t filter_len = size < 32 ? size : 32;
    char filter_str[33];
    memcpy(filter_str, data, filter_len);
    filter_str[filter_len] = '\0';
    data += filter_len;
    size -= filter_len;

    if (pcap_compile(p, &fp, filter_str, 1, PCAP_NETMASK_UNKNOWN) == 0) {
      pcap_setfilter(p, &fp);
      // Memory safety: pcap_freecode is called to free the compiled program.
      pcap_freecode(&fp);
    }
  }

  if (ret == 0) {
    // If activation succeeds, fuzz the post-activation functions.
    pcap_setnonblock(p, 1, errbuf);

    if (size > 0) {
      pcap_inject(p, data, size);
    }

    pcap_dispatch(p, 1, dummy_handler, NULL);
    pcap_stats(p, &ps);
    if (size > 0) {
      pcap_setdirection(p, (pcap_direction_t)(data[0] % 3));
    }
  }

  // Clean up resources.
  pcap_close(p);
  if (alldevs) {
    pcap_freealldevs(alldevs);
  }

  return 0;
}