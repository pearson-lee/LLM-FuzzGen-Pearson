#include <pcap.h>
#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <unistd.h>

#define _FUZZ_TARGET_NAME "fuzz_pcap_api"

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  if (size < 2) {
    return 0;
  }

  // Use a portion of the data for a device name.
  size_t dev_name_len = data[0];
  if (dev_name_len > size - 1) {
    dev_name_len = size - 1;
  }
  char *dev_name = (char *)malloc(dev_name_len + 1);
  if (!dev_name) {
    return 0;
  }
  memcpy(dev_name, data + 1, dev_name_len);
  dev_name[dev_name_len] = '\0';
  data += dev_name_len + 1;
  size -= dev_name_len + 1;

  // Use the rest of the data for the filter string.
  char *filter_string = (char *)malloc(size + 1);
  if (!filter_string) {
    free(dev_name);
    return 0;
  }
  memcpy(filter_string, data, size);
  filter_string[size] = '\0';

  char errbuf[PCAP_ERRBUF_SIZE];

  /*
   * ANALYSIS: The function-level coverage report showed pcap_lookupnet had
   *           uncovered branches. The line-level report confirmed this was at
   *           lines 1585, 1631, and 1640, related to error handling and
   *           netmask calculation.
   * IMPLEMENTATION: The following code calls pcap_lookupnet with a fuzzed
   *                 device name to exercise these uncovered paths.
   */
  bpf_u_int32 net, mask;
  pcap_lookupnet(dev_name, &net, &mask, errbuf);

  /*
   * ANALYSIS: The function-level coverage report showed pcap_findalldevs had
   *           uncovered branches. The line-level report confirmed this was at
   *           lines 682 and 698, in error-handling paths.
   * IMPLEMENTATION: The following code calls pcap_findalldevs to exercise
   *                 device enumeration logic. Although triggering the error
   *                 conditions is difficult without influencing system calls,
   *                 this call contributes to overall coverage.
   */
  pcap_if_t *alldevs;
  if (pcap_findalldevs(&alldevs, errbuf) == 0) {
    pcap_freealldevs(alldevs);
  }

  /*
   * ANALYSIS: The function-level coverage report showed pcap_findalldevs_ex
   *           had many uncovered error-handling branches.
   * IMPLEMENTATION: The following code calls pcap_findalldevs_ex with a
   *                 fuzzed source string to exercise these code paths.
   *                 Specifically, using "rpcap://" will hit the "Remote packet
   *                 capture is not supported" path as ENABLE_REMOTE is not defined.
   */
  char source[PCAP_BUF_SIZE];
  snprintf(source, sizeof(source), "rpcap://%s/", dev_name);
  if (pcap_findalldevs_ex(source, NULL, &alldevs, errbuf) == 0) {
      pcap_freealldevs(alldevs);
  }

  // Create a dummy pcap_t handle
  pcap_t *p = pcap_open_dead(DLT_EN10MB, 65535);
  if (p) {
    /*
     * ANALYSIS: The function-level coverage report showed pcap_list_tstamp_types
     *           had low coverage.
     * IMPLEMENTATION: The following code calls pcap_list_tstamp_types to
     *                 exercise the timestamp type enumeration logic.
     */
    int *tstamp_types;
    int n_tstamp_types = pcap_list_tstamp_types(p, &tstamp_types);
    if (n_tstamp_types >= 0) {
        pcap_free_tstamp_types(tstamp_types);
    }

    /*
     * ANALYSIS: The function-level coverage report showed pcap_compile and
     *           pcap_setfilter had significant uncovered branches. These
     *           functions are core to the library's filtering mechanism.
     * IMPLEMENTATION: The following code calls pcap_compile with a fuzzed
     *                 filter string and, if successful, applies the filter
     *                 with pcap_setfilter. This directly targets the complex
     *                 parsing and filter installation logic.
     */
    struct bpf_program fp;
    if (pcap_compile(p, &fp, filter_string, 1, PCAP_NETMASK_UNKNOWN) == 0) {
      pcap_setfilter(p, &fp);
      pcap_freecode(&fp);
    }
    pcap_close(p);
  }

  free(dev_name);
  free(filter_string);

  return 0;
}