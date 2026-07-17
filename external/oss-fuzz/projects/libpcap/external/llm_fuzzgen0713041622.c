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
   * ANALYSIS: The function-level coverage report showed pcap_set_tstamp_type
   *           had low coverage (66.67%). The source code shows it handles
   *           various integer inputs before the pcap handle is activated.
   * IMPLEMENTATION: The following code block calls pcap_set_tstamp_type with a
   *                 fuzzer-controlled value to explore its logic. This must be
   *                 called before pcap_activate().
   */
  if (size > 1) {
    pcap_set_tstamp_type(p, data[1]);
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

  /*
   * ANALYSIS: The function-level coverage report showed pcap_inject had low
   *           coverage (69.23%). This function is responsible for sending
   *           packets.
   * IMPLEMENTATION: The following code block calls pcap_inject with fuzzer-
   *                 controlled data to exercise the packet injection code paths.
   *                 We use a small, fuzzer-determined portion of the input data.
   */
  if (size > 2) {
    // Use one byte to determine a small injection size.
    size_t inject_size = data[2] % 128;
    if (inject_size > 0 && inject_size <= size) {
      // Inject from the original data buffer.
      pcap_inject(p, data, inject_size);
    }
  }

  /*
   * ANALYSIS: The function-level coverage report showed pcap_list_datalinks
   *           (66.67%) and pcap_set_datalink (89.19%) had room for coverage
   *           improvement.
   * IMPLEMENTATION: The following block lists available datalink types,
   *                 selects one based on fuzzer input, and then attempts to
   *                 set it. This explores the logic for datalink enumeration
   *                 and selection. The allocated buffer for DLTs is freed.
   */
  int *dlt_buf = NULL;
  int dlt_count = pcap_list_datalinks(p, &dlt_buf);
  if (dlt_count > 0 && dlt_buf != NULL) {
    if (size > 3) {
      int dlt_index = data[3] % dlt_count;
      pcap_set_datalink(p, dlt_buf[dlt_index]);
    }
  }
  if (dlt_buf != NULL) {
    // pcap_list_datalinks requires the caller to free the buffer.
    pcap_free_datalinks(dlt_buf);
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