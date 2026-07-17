#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include "/src/libpcap/pcap/pcap.h"
#include <sys/time.h>

#ifndef _FUZZ_TARGET_NAME
#define _FUZZ_TARGET_NAME "fuzz_pcap_findalldevs_ex"
#endif

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  if (size < 1) {
    return 0;
  }

  char errbuf[PCAP_ERRBUF_SIZE];
  pcap_if_t *alldevs = NULL;

  // Create a temporary file with fuzzed data to test the PCAP_SRC_FILE path
  char path[256];
  snprintf(path, sizeof(path), "/tmp/%s.pcap", _FUZZ_TARGET_NAME);
  FILE *fp = fopen(path, "wb");
  if (fp) {
    fwrite(data, 1, size, fp);
    fclose(fp);
  }

  /*
   * ANALYSIS: The function-level coverage report showed pcap_findalldevs_ex had
   *           low coverage. This function has different code paths for handling
   *           local interfaces and files.
   * IMPLEMENTATION: The following code block calls pcap_findalldevs_ex with
   *                 different source strings to exercise these paths.
   */
  if (data[0] % 2) {
    // Target the PCAP_SRC_IFLOCAL path
    pcap_findalldevs_ex((char *)"local", NULL, &alldevs, errbuf);
  } else {
    // Target the PCAP_SRC_FILE path
    char source[512];
    snprintf(source, sizeof(source), "file://%s", path);
    pcap_findalldevs_ex(source, NULL, &alldevs, errbuf);
  }

  if (alldevs) {
    pcap_if_t *dev;
    for (dev = alldevs; dev != NULL; dev = dev->next) {
      /*
       * ANALYSIS: The functions pcap_compile and pcap_setfilter are core to
       *           libpcap's functionality but could have untested code paths.
       * IMPLEMENTATION: The following code block creates a dead pcap handle,
       *                 compiles a filter from the fuzzed data, and applies it
       *                 to the handle to exercise these functions.
       */
      pcap_t *p = pcap_open_dead(DLT_EN10MB, 65535);
      if (p) {
        // pcap_compile expects a null-terminated string, but the input data is
        // not. Create a null-terminated copy.
        char *filter_string = (char *)malloc(size + 1);
        if (filter_string) {
          memcpy(filter_string, data, size);
          filter_string[size] = '\0';

          struct bpf_program fp;
          if (pcap_compile(p, &fp, filter_string, 1, PCAP_NETMASK_UNKNOWN) == 0) {
            pcap_setfilter(p, &fp);
            pcap_freecode(&fp);
          }
          free(filter_string);
        }
        pcap_close(p);
      }
    }
    pcap_freealldevs(alldevs);
  }

  /*
   * ANALYSIS: The function-level coverage report showed pcap_dump_open, pcap_dump,
   *           and pcap_dump_flush were not being exercised.
   * IMPLEMENTATION: The following code block creates a dead pcap handle, opens a
   *                 dumper, and writes fuzzer-controlled packet data to a
   *                 temporary file to exercise the pcap dumping functionality.
   */
  char dump_path[256];
  snprintf(dump_path, sizeof(dump_path), "/tmp/%s.dump.pcap", _FUZZ_TARGET_NAME);
  pcap_t *p_dump = pcap_open_dead(DLT_EN10MB, 65535);
  if (p_dump) {
    pcap_dumper_t *dumper = pcap_dump_open(p_dump, dump_path);
    if (dumper) {
      if (size > sizeof(struct pcap_pkthdr)) {
        struct pcap_pkthdr hdr;
        // Use part of the fuzzing data to populate the packet header.
        memcpy(&hdr, data, sizeof(struct pcap_pkthdr));

        const uint8_t *pkt_data = data + sizeof(struct pcap_pkthdr);
        const size_t pkt_size = size - sizeof(struct pcap_pkthdr);

        // Memory safety: Ensure caplen and len from the fuzzed data do not
        // exceed the actual available packet data to prevent out-of-bounds reads.
        if (hdr.caplen > pkt_size) {
          hdr.caplen = pkt_size;
        }
        if (hdr.len > pkt_size) {
          hdr.len = pkt_size;
        }

        pcap_dump((u_char *)dumper, &hdr, pkt_data);
        pcap_dump_flush(dumper);
      }
      pcap_dump_close(dumper);
    }
    pcap_close(p_dump);
  }
  unlink(dump_path);

  /*
   * ANALYSIS: The function-level coverage report showed pcap_lookupdev had
   *           room for improvement (82.61%).
   * IMPLEMENTATION: The following code block calls pcap_lookupdev to
   *                 exercise this basic functionality.
   */
  pcap_lookupdev(errbuf);


  unlink(path);

  return 0;
}