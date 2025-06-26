#include <sys/types.h>
#include <pcap/bpf.h>
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

  // Added to cover pcap_set_datalink_dead, which was at 0% coverage.
  pcap_set_datalink(p, DLT_NULL);

  // Added to cover pcap_get_required_select_timeout, which was at 0% coverage.
  pcap_get_required_select_timeout(p);

  // Added to cover BPF filter compilation and installation on dead handles.
  // This addresses large coverage gaps in gencode.c, optimize.c, and pcap.c.
  struct bpf_program fp;
  if (pcap_compile(p, &fp, "udp", 1, PCAP_NETMASK_UNKNOWN) == 0) {
    pcap_setfilter(p, &fp);
    pcap_freecode(&fp);
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
  if (write(fd, data, size) != (ssize_t)size) {
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

    // Added to cover sf_getnonblock and sf_setnonblock, which were at 0% coverage.
    pcap_getnonblock(p_live, errbuf);
    pcap_setnonblock(p_live, 1, errbuf);

    // Added to cover pcap_inject on an offline handle (sf_inject).
    pcap_inject(p_live, data, size);

    // Added to cover BPF filter logic for offline handles.
    struct bpf_program fp_live;
    if (pcap_compile(p_live, &fp_live, "tcp", 1, PCAP_NETMASK_UNKNOWN) == 0) {
        pcap_setfilter(p_live, &fp_live);
        pcap_freecode(&fp_live);
    }

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