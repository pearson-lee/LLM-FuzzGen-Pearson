#include <pcap.h>
#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <stdio.h>

#define _FUZZ_TARGET_NAME "llm_fuzzgen0713041622"

// Dummy callback for pcap_loop
void dummy_handler(u_char *user, const struct pcap_pkthdr *h, const u_char *bytes) {
  // Do nothing
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  if (size < 5) {
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

  /*
   * ANALYSIS: The function-level coverage report showed pcap_lookupnet had low
   *           coverage (67.16%). This function is used to get the network
   *           address and mask for a device.
   * IMPLEMENTATION: The following code block calls pcap_lookupnet with a
   *                 static device name "any" to exercise its basic functionality.
   */
  bpf_u_int32 net, mask;
  pcap_lookupnet("any", &net, &mask, errbuf);

  pcap_t *p;
  // Use a fixed source for creating a handle to avoid errors.
  source = "any";

  p = pcap_create(source, errbuf);
  if (p == NULL) {
    return 0;
  }

  /*
   * ANALYSIS: The function-level coverage report showed pcap_set_tstamp_precision
   *           had room for improvement (83.33% branch coverage). The function
   *           is called before activation to set the timestamp precision.
   * IMPLEMENTATION: The following code block calls pcap_set_tstamp_precision
   *                 with a fuzzer-controlled value (micro or nano) to explore
   *                 its different precision-handling paths.
   */
  if (size > 4) {
      int precision = (data[4] % 2 == 0) ? PCAP_TSTAMP_PRECISION_MICRO : PCAP_TSTAMP_PRECISION_NANO;
      pcap_set_tstamp_precision(p, precision);
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

  if (pcap_activate(p) != 0) {
    pcap_close(p);
    return 0;
  }

  /*
   * ANALYSIS: The function-level coverage report showed pcap_list_tstamp_types
   *           had low coverage (65.22%). This function lists supported
   *           timestamp types.
   * IMPLEMENTATION: The following code block calls pcap_list_tstamp_types and
   *                 frees the resulting buffer. This exercises the timestamp
   *                 type enumeration logic. The source of pcap_list_tstamp_types
   *                 shows it uses malloc, so we must free the buffer.
   */
  int *tstamp_types = NULL;
  if (pcap_list_tstamp_types(p, &tstamp_types) > 0) {
      free(tstamp_types);
  }

  /*
   * ANALYSIS: The function-level coverage report showed low coverage for file
   *           dumping functions like pcap_dump_open (74.29%) and pcap_dump (50% branch).
   * IMPLEMENTATION: The following block creates a temporary file, opens it for
   *                 dumping, writes a fuzzer-controlled packet to it, and then
   *                 cleans up. This covers the packet dumping workflow.
   */
  char path[256];
  snprintf(path, sizeof(path), "/tmp/%s.pcap", _FUZZ_TARGET_NAME);
  pcap_dumper_t *dumper = pcap_dump_open(p, path);
  if (dumper != NULL) {
    struct pcap_pkthdr hdr;
    hdr.ts.tv_sec = 0;
    hdr.ts.tv_usec = 0;
    hdr.caplen = size > 1500 ? 1500 : size;
    hdr.len = size > 1500 ? 1500 : size;
    pcap_dump((u_char *)dumper, &hdr, data);
    pcap_dump_close(dumper);
  }
  unlink(path);


  if (size > 2) {
    size_t inject_size = data[2] % 128;
    if (inject_size > 0 && inject_size <= size) {
      pcap_inject(p, data, inject_size);
    }
  }

  int *dlt_buf = NULL;
  int dlt_count = pcap_list_datalinks(p, &dlt_buf);
  if (dlt_count > 0 && dlt_buf != NULL) {
    if (size > 3) {
      int dlt_index = data[3] % dlt_count;
      pcap_set_datalink(p, dlt_buf[dlt_index]);
    }
  }
  if (dlt_buf != NULL) {
    pcap_free_datalinks(dlt_buf);
  }

  if (pcap_setnonblock(p, 1, errbuf) != 0) {
    pcap_close(p);
    return 0;
  }

  struct bpf_program fp;
  char *filter_exp = (char *)malloc(size + 1);
  if (!filter_exp) {
    pcap_close(p);
    return 0;
  }
  memcpy(filter_exp, data, size);
  filter_exp[size] = '\0';

  if (pcap_compile(p, &fp, filter_exp, 1, PCAP_NETMASK_UNKNOWN) == 0) {
    pcap_setfilter(p, &fp);
    pcap_freecode(&fp);
  }

  free(filter_exp);

  pcap_dispatch(p, 1, dummy_handler, NULL);

  pcap_close(p);

  return 0;
}