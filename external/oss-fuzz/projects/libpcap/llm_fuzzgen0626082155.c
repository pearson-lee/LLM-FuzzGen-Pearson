#include <pcap/pcap.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

// Forward declaration for functions not in public headers
int pcap_do_addexit(pcap_t *p);
void pcap_add_to_pcaps_to_close(pcap_t *p);
void pcap_remove_from_pcaps_to_close(pcap_t *p);
int pcap_getnonblock_fd(pcap_t *p);

// A simple handler for pcap_dispatch
void dummy_handler(u_char *user, const struct pcap_pkthdr *h, const u_char *bytes) {
  // Do nothing
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  if (size < 1) {
    return 0;
  }

  char errbuf[PCAP_ERRBUF_SIZE];

  // Create a dead pcap handle to test some of the functions
  pcap_t *p = pcap_open_dead(DLT_EN10MB, 65535);
  if (p == NULL) {
    return 0;
  }

  // To test pcap_getnonblock_fd, we need a pcap_t with a real fd.
  // We'll create a temporary file and use pcap_open_offline.
  char tmpfile[] = "/tmp/fuzz-XXXXXX";
  int fd = mkstemp(tmpfile);
  if (fd == -1) {
    pcap_close(p);
    return 0;
  }
  // Write the fuzzer data to the temp file to make it a valid pcap file
  if (write(fd, data, size) != size) {
    close(fd);
    unlink(tmpfile);
    pcap_close(p);
    return 0;
  }
  close(fd);

  pcap_t *p_live = pcap_open_offline(tmpfile, errbuf);
  if (p_live != NULL) {
    // We have a live pcap handle now, let's test the functions
    pcap_getnonblock_fd(p_live);
    pcap_dispatch(p_live, 1, dummy_handler, NULL);
    pcap_close(p_live);
  }
  unlink(tmpfile);

  // Test the exit handling functions
  pcap_do_addexit(p);
  pcap_add_to_pcaps_to_close(p);
  pcap_remove_from_pcaps_to_close(p);

  // Test pcap_dump_ftell64
  pcap_dumper_t *dumper = pcap_dump_open(p, "-");
  if (dumper != NULL) {
    pcap_dump_ftell64(dumper);
    pcap_dump_close(dumper);
  }

  pcap_close(p);

  return 0;
}