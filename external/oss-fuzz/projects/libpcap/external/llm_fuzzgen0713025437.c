#include <pcap.h>
#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#define _FUZZ_TARGET_NAME "fuzz_pcap_api"

// Dummy callback for pcap_loop
void dummy_handler(u_char *user, const struct pcap_pkthdr *h, const u_char *bytes) {
  // Do nothing
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  if (size < 1) {
    return 0;
  }

  char errbuf[PCAP_ERRBUF_SIZE];
  pcap_if_t *alldevs;
  char *source;

  /*
   * ANALYSIS: The function-level coverage report shows that pcap_findalldevs_ex
   *           has a branch coverage of 72.22%, indicating that some paths are
   *           not being exercised.
   * IMPLEMENTATION: The following code block calls pcap_findalldevs_ex with a
   *                 fuzzer-controlled source string. This will exercise the
   *                 device enumeration logic with a variety of inputs.
   */
  if (data[0] % 2 == 0) {
    // Consume up to 256 bytes for the source string
    size_t source_len = size > 256 ? 256 : size;
    source = (char *)malloc(source_len);
    if (!source) {
      return 0;
    }
    memcpy(source, data, source_len);
    if (source_len > 0) {
      source[source_len - 1] = '\0';
    }

    if (pcap_findalldevs_ex(source, NULL, &alldevs, errbuf) == 0) {
      pcap_freealldevs(alldevs);
    }
    free(source);
  } else {
    if (pcap_findalldevs(&alldevs, errbuf) == 0) {
      pcap_freealldevs(alldevs);
    }
  }

  pcap_t *p;
  // Use a fixed source for creating a handle to avoid errors.
  source = "any";

  p = pcap_create(source, errbuf);
  if (p == NULL) {
    return 0;
  }

  /*
   * ANALYSIS: The function-level coverage report shows that pcap_activate has
   *           high but not perfect coverage.
   * IMPLEMENTATION: The following code block activates the pcap handle, which
   *                 is a necessary step for many subsequent operations.
   */
  if (pcap_activate(p) != 0) {
    pcap_close(p);
    return 0;
  }

  // Set non-blocking mode to prevent timeouts
  if (pcap_setnonblock(p, 1, errbuf) != 0) {
    pcap_close(p);
    return 0;
  }

  struct bpf_program fp;
  // Use the remaining data for the filter string
  char *filter_exp = (char *)malloc(size + 1);
  if (!filter_exp) {
    pcap_close(p);
    return 0;
  }
  memcpy(filter_exp, data, size);
  filter_exp[size] = '\0';

  /*
   * ANALYSIS: The function-level coverage report shows that pcap_compile has
   *           many uncovered branches related to filter expression parsing.
   * IMPLEMENTATION: The following code block calls pcap_compile with a
   *                 fuzzer-controlled string to explore the filter parsing
   *                 and compilation logic.
   */
  if (pcap_compile(p, &fp, filter_exp, 1, PCAP_NETMASK_UNKNOWN) == 0) {
    pcap_setfilter(p, &fp);
    pcap_freecode(&fp);
  }

  free(filter_exp);

  // Exercise pcap_dispatch to process some packets
  pcap_dispatch(p, 1, dummy_handler, NULL);

  pcap_close(p);

  return 0;
}