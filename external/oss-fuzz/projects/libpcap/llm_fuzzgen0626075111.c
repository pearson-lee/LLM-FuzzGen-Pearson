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

  // Increased minimum size to 80. The previous value was too small, preventing
  // code paths like pcap_inject and the pcap_dump logic from being reached,
  // as shown by the detailed coverage report.
  if (size < 80) {
    return 0;
  }

  const char *dev = "any"; // Default to "any" device
  char invalid_dev[17];    // Buffer for invalid device name from fuzzer data

  // Use a byte from the fuzzer to select a device strategy.
  // Increased from 14 to 15 to add a NULL device case.
  int dev_choice = data[0] % 15;
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
  } else if (dev_choice == 12) {
    // Strategy 12: Use fuzzer data for the device name to trigger pcap_create()
    // failures, covering error-handling paths shown as missed in the report.
    size_t name_len = size < 16 ? size : 16;
    memcpy(invalid_dev, data, name_len);
    invalid_dev[name_len] = '\0';
    dev = invalid_dev;
    data += name_len;
    size -= name_len;
  } else if (dev_choice == 13) {
    // Added to improve coverage in sf-pcap.c by exercising pcap_dump APIs.
    // This path creates a dummy pcap file in memory, writes to it, and closes it.
    if (size > sizeof(struct pcap_pkthdr)) {
      pcap_dumper_t *dumper;
      pcap_t *pd = pcap_open_dead(DLT_EN10MB, 65535);
      if (pd) {
        dumper = pcap_dump_open(pd, "-"); // "-" means stdout, but without a real file, it's just in memory.
        if (dumper) {
          struct pcap_pkthdr hdr;
          hdr.ts.tv_sec = 0;
          hdr.ts.tv_usec = 0;
          hdr.caplen = hdr.len = size;
          pcap_dump((u_char *)dumper, &hdr, data);
          pcap_dump_close(dumper);
        }
        pcap_close(pd);
      }
    }
    if (alldevs) {
      pcap_freealldevs(alldevs);
    }
    return 0;
  } else { // dev_choice == 14
    // Added to guarantee pcap_create() failure path is taken, which the
    // coverage report showed was previously unreachable.
    dev = NULL;
  }

  // Create a pcap handle.
  p = pcap_create(dev, errbuf);
  if (p == NULL) {
    // This path is now reachable due to the NULL device name strategy.
    if (alldevs) {
      pcap_freealldevs(alldevs);
    }
    return 0;
  }

  // Added to improve coverage in pcap.c by exercising timestamp APIs.
  if (size > 0) {
    int *tstamp_buf = NULL;
    int tstamp_count = pcap_list_tstamp_types(p, &tstamp_buf);
    if (tstamp_count > 0 && tstamp_buf != NULL) {
      pcap_set_tstamp_type(p, tstamp_buf[data[0] % tstamp_count]);
      pcap_free_tstamp_types(tstamp_buf);
    }
    data++;
    size--;
  }

  // Fuzz various pre-activation settings.
  // Ensure we have enough data for snaplen(int), promisc(char), timeout(int), and buffer_size(int).
  if (size < (sizeof(int) * 3 + 1)) {
    pcap_close(p);
    if (alldevs) {
      pcap_freealldevs(alldevs);
    }
    return 0;
  }

  pcap_set_snaplen(p, *(const int *)data);
  data += sizeof(int);
  size -= sizeof(int);

  pcap_set_promisc(p, data[0] % 2);
  data++;
  size--;

  pcap_set_timeout(p, *(const int *)data);
  data += sizeof(int);
  size -= sizeof(int);

  pcap_set_buffer_size(p, *(const int *)data);
  data += sizeof(int);
  size -= sizeof(int);

  // Attempt to activate the handle.
  int ret = pcap_activate(p);

  // Moved datalink calls after pcap_activate to improve chances of success,
  // as an activated handle is more likely to provide a list of datalinks.
  if (size > 0) {
    int *dlt_buf = NULL;
    int dlt_count = pcap_list_datalinks(p, &dlt_buf);
    if (dlt_count > 0 && dlt_buf != NULL) {
      pcap_set_datalink(p, dlt_buf[data[0] % dlt_count]);
      pcap_free_datalinks(dlt_buf);
    }
    data++;
    size--;
  }

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

    // Added to cover pcap_breakloop and related functions (e.g., pcap_breakloop_linux)
    // which the coverage report showed were uncovered (0% coverage).
    pcap_breakloop(p);

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