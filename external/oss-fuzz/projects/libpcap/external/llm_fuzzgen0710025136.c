#include "/src/libpcap/pcap/pcap.h"
#include "/src/libpcap/pcap/bpf.h"
#include "/src/libpcap/pcap/namedb.h"
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <stdio.h>
#include <sys/time.h>

// A compile-time macro to create unique filenames. This is expected to be
// provided by the build system. If not, we define a default.
#ifndef _FUZZ_TARGET_NAME
#define _FUZZ_TARGET_NAME "fuzz_target"
#endif

static void dummy_handler(u_char *user, const struct pcap_pkthdr *h, const u_char *bytes) {
  // Do nothing, the goal is to exercise the pcap_loop machinery.
  (void)user;
  (void)h;
  (void)bytes;
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  if (size < 1) {
    return 0;
  }

  char errbuf[PCAP_ERRBUF_SIZE];
  pcap_if_t *alldevs = NULL;
  pcap_t *p = NULL;
  pcap_dumper_t *d = NULL;

  /*
   * ANALYSIS: The function pcap_init has low coverage (48.65%) and is a
   *           fundamental library initialization function that was not being called.
   * IMPLEMENTATION: A call to pcap_init is added at the beginning of the
   *                 fuzz target to exercise its setup and configuration logic.
   */
  pcap_init(PCAP_CHAR_ENC_UTF_8, NULL);

  /*
   * ANALYSIS: The function pcap_statustostr has low coverage (48.72%) and
   *           is a simple utility function that can be easily called.
   * IMPLEMENTATION: Calls to pcap_statustostr are added with common status
   *                 codes to exercise this error-reporting utility.
   */
  (void)pcap_statustostr(PCAP_WARNING);
  (void)pcap_statustostr(PCAP_ERROR);

  // Split data into a source string and file content.
  const size_t source_len = size / 2;
  const uint8_t *file_content_data = data + source_len;
  const size_t file_content_size = size - source_len;

  char *source_str = (char *)malloc(source_len + 1);
  if (!source_str) {
    return 0;
  }
  memcpy(source_str, data, source_len);
  source_str[source_len] = '\0';

  /*
   * ANALYSIS: The function-level coverage report showed pcap_lookupdev
   *           had low coverage (43.48%).
   * IMPLEMENTATION: A call to pcap_lookupdev is added to exercise this
   *                 basic device lookup functionality. The result does not
   *                 need to be freed as it points to a static buffer.
   */
  char *dev = pcap_lookupdev(errbuf);
  (void)dev; // Prevent unused variable warning

  /*
   * ANALYSIS: The function pcap_lookupnet has low coverage (46.27%) and is
   *           a fundamental API function that was not being called.
   * IMPLEMENTATION: A call to pcap_lookupnet is added, using the device
   *                 name returned by the existing pcap_lookupdev call.
   */
  if (dev != NULL) {
    bpf_u_int32 net, mask;
    pcap_lookupnet(dev, &net, &mask, errbuf);
  }

  /*
   * ANALYSIS: The function pcap_nametoportrange had 0% coverage and was not
   *           being called.
   * IMPLEMENTATION: A call to pcap_nametoportrange is added to exercise this
   *                 string parsing utility with fuzzer-provided data.
   */
  int p1, p2;
  (void)pcap_nametoportrange(source_str, &p1, &p2, errbuf);

  /*
   * ANALYSIS: The function-level coverage report showed that pcap_findalldevs_ex
   *           had very low coverage (23.70%). The line-level report confirmed
   *           that code paths for handling file and remote sources were completely
   *           uncovered.
   * IMPLEMENTATION: The following calls use specially crafted source strings to
   *                 exercise the file-based and remote-based device listing logic.
   */
  if (pcap_findalldevs_ex("file:///tmp/", NULL, &alldevs, errbuf) == 0) {
    pcap_freealldevs(alldevs);
    alldevs = NULL;
  }
  if (pcap_findalldevs_ex("rpcap://127.0.0.1/", NULL, &alldevs, errbuf) == 0) {
    pcap_freealldevs(alldevs);
    alldevs = NULL;
  }
  // Also test with fuzzer-provided string.
  if (pcap_findalldevs_ex(source_str, NULL, &alldevs, errbuf) == 0) {
    pcap_freealldevs(alldevs);
    alldevs = NULL;
  }

  /*
   * ANALYSIS: The detailed coverage report showed that pcap_open() on a
   *           temporary file of raw fuzzer data always fails, preventing
   *           coverage of any offline file reading (pcap_loop) or packet
   *           processing logic. Additionally, pcap_dump_open_append has very
   *           low coverage (28.57%).
   * IMPLEMENTATION: A valid, single-packet pcap file is now created using
   *                 pcap_dump_open() and pcap_dump(). This file is then opened
   *                 with pcap_open_offline(), and pcap_loop() is called to
   *                 process it. pcap_dump_open_append() is then called on the
   *                 same file to specifically target that function's logic.
   */
  char *temp_path = (char *)malloc(256);
  if (temp_path) {
    snprintf(temp_path, 256, "/tmp/%s.pcap", _FUZZ_TARGET_NAME);

    pcap_t *p_dead = pcap_open_dead(DLT_EN10MB, 65535);
    if (p_dead) {
      d = pcap_dump_open(p_dead, temp_path);
      if (d) {
        struct pcap_pkthdr hdr;
        hdr.caplen = file_content_size;
        hdr.len = file_content_size;
        hdr.ts.tv_sec = 123;  // Use constant for determinism
        hdr.ts.tv_usec = 456;
        pcap_dump((u_char *)d, &hdr, file_content_data);
        pcap_dump_close(d);
        d = NULL;

        d = pcap_dump_open_append(p_dead, temp_path);
        if (d) {
          pcap_dump_close(d);
          d = NULL;
        }
      }
      /*
       * ANALYSIS: The functions pcap_can_set_rfmon_dead and pcap_read_dead
       *           had 0% coverage.
       * IMPLEMENTATION: Call pcap_can_set_rfmon and pcap_next_ex on the
       *                 "dead" pcap handle to cover these functions.
       */
      pcap_can_set_rfmon(p_dead);
      struct pcap_pkthdr *pkt_header_dead;
      const u_char *pkt_data_dead;
      pcap_next_ex(p_dead, &pkt_header_dead, &pkt_data_dead);

      pcap_close(p_dead);
    }

    p = pcap_open_offline(temp_path, errbuf);
    if (p) {
      pcap_loop(p, 1, dummy_handler, NULL);
      pcap_close(p);
      p = NULL;
    }

    /*
     * ANALYSIS: The function pcap_fopen_offline had 0% coverage.
     * IMPLEMENTATION: Open the temporary pcap file with fopen and pass the
     *                 resulting FILE* to pcap_fopen_offline to exercise this
     *                 code path.
     */
    FILE *f = fopen(temp_path, "r");
    if (f) {
      p = pcap_fopen_offline(f, errbuf);
      if (p) {
        pcap_loop(p, 1, dummy_handler, NULL);
        pcap_close(p);
        p = NULL;
      } else {
        fclose(f);
      }
    }


    unlink(temp_path);
    free(temp_path);
  }

  p = pcap_open(source_str, 65535, PCAP_OPENFLAG_PROMISCUOUS, 100, NULL, errbuf);
  if (p) {
    /*
     * ANALYSIS: A call to pcap_next_ex on a live capture handle can block
     *           indefinitely if no packets are available, causing a timeout.
     * IMPLEMENTATION: The pcap handle is set to non-blocking mode to ensure
     *                 that calls like pcap_next_ex and pcap_dispatch return
     *                 immediately instead of blocking.
     */
    pcap_setnonblock(p, 1, errbuf);

    /*
     * ANALYSIS: The bpf_filter and pcap_compile functions have very low or
     *           zero coverage. This is because pcap_compile almost always fails
     *           when given raw fuzzer data. A successful compilation is needed
     *           to reach pcap_setfilter, pcap_freecode, and the BPF optimizer
     *           and filter execution code.
     * IMPLEMENTATION: A small, valid filter string ("ip") is now also passed
     *                 to pcap_compile to ensure it can succeed, unlocking coverage
     *                 in the filter installation and execution paths. The original
     *                 call with raw data is kept to continue fuzzing the compiler.
     */
    struct bpf_program fp;
    if (pcap_compile(p, &fp, "ip", 1, PCAP_NETMASK_UNKNOWN) == 0) {
      pcap_setfilter(p, &fp);
      /*
       * ANALYSIS: The function bpf_dump had low coverage (47.83%) and was
       *           not being called.
       * IMPLEMENTATION: A call to bpf_dump is added after a successful filter
       *                 compilation to exercise the BPF program dumping logic.
       */
      bpf_dump(&fp, 1);
      /*
       * ANALYSIS: The function bpf_validate had 0% coverage.
       * IMPLEMENTATION: A call to bpf_validate is added after successful
       *                 filter compilation to exercise BPF validation logic.
       */
      bpf_validate(fp.bf_insns, fp.bf_len);
      pcap_freecode(&fp);
    }
    if (pcap_compile(p, &fp, source_str, 1, PCAP_NETMASK_UNKNOWN) == 0) {
      pcap_setfilter(p, &fp);
      pcap_freecode(&fp);
    }

    /*
     * ANALYSIS: pcap_next_ex and pcap_dispatch were only being called on
     *           offline captures. This exercises the live capture read path.
     * IMPLEMENTATION: Call pcap_next_ex and pcap_dispatch on the live handle.
     */
    struct pcap_pkthdr *pkt_header;
    const u_char *pkt_data;
    pcap_next_ex(p, &pkt_header, &pkt_data);
    pcap_dispatch(p, 1, dummy_handler, NULL);

    /*
     * ANALYSIS: pcap_stats_linux had an uncovered branch for promiscuous mode.
     * IMPLEMENTATION: Call pcap_stats() on the live handle (opened with
     *                 PCAP_OPENFLAG_PROMISCUOUS) to exercise this path.
     */
    struct pcap_stat stats;
    pcap_stats(p, &stats);

    /*
     * ANALYSIS: pcap_set_datalink has low branch coverage (20.83%), with many
     *           error conditions and logic paths for supported DLTs not being
     *           exercised.
     * IMPLEMENTATION: If a pcap handle is successfully activated, list its
     *                 supported DLTs and attempt to set the first one in the list.
     *                 This tests the success path. Also, attempt to set an invalid
     *                 DLT (-1) to test the error handling path.
     */
    int *dlt_buf = NULL;
    int dlt_count = pcap_list_datalinks(p, &dlt_buf);
    if (dlt_count > 0 && dlt_buf) {
      pcap_set_datalink(p, dlt_buf[0]);
      pcap_free_datalinks(dlt_buf);
    }
    pcap_set_datalink(p, -1); // Test invalid DLT.

    /*
     * ANALYSIS: The functions pcap_inject and pcap_setdirection have low
     *           coverage and were not being called on activated handles.
     * IMPLEMENTATION: Calls to pcap_setdirection and pcap_inject are added
     *                 within the block where an activated pcap_t exists,
     *                 exercising packet injection and direction setting logic.
     */
    pcap_setdirection(p, PCAP_D_IN);
    pcap_inject(p, file_content_data, file_content_size);

    /*
     * ANALYSIS: pcap_dump_open has low coverage (42.86%) and misses several
     *           error-handling branches, such as handling NULL or "-" as filenames.
     * IMPLEMENTATION: Call pcap_dump_open with a valid temporary file path,
     *                 as well as with NULL and "-" to ensure these specific
     *                 edge cases are tested.
     */
    char dumper_path[256];
    snprintf(dumper_path, sizeof(dumper_path), "/tmp/%s.dumper.pcap", _FUZZ_TARGET_NAME);
    d = pcap_dump_open(p, dumper_path);
    if (d) {
      pcap_dump_close(d);
    }
    unlink(dumper_path);

    d = pcap_dump_open(p, NULL);
    if (d) pcap_dump_close(d);

    d = pcap_dump_open(p, "-");
    if (d) pcap_dump_close(d);

    pcap_close(p);
  }

  /*
   * ANALYSIS: The pcap_offline_filter function never hit the branch where the
   *           filter code is NULL.
   * IMPLEMENTATION: Explicitly call pcap_offline_filter with a bpf_program
   *                 struct that has a NULL bf_insns field to cover this path.
   */
  struct bpf_program null_fp;
  null_fp.bf_insns = NULL;
  struct pcap_pkthdr dummy_hdr;
  dummy_hdr.len = file_content_size;
  dummy_hdr.caplen = file_content_size;
  pcap_offline_filter(&null_fp, &dummy_hdr, file_content_data);

  /*
   * ANALYSIS: The coverage report shows that calling pcap_dump_open with a
   *           non-activated pcap_t handle is an untested path. Additionally,
   *           pcap_list_tstamp_types (34.78%) and pcap_set_tstamp_type (61.90%)
   *           have low coverage and can be called on a non-activated handle.
   * IMPLEMENTATION: Create a pcap handle using pcap_create but do not activate
   *                 it. Then, pass this handle to pcap_dump_open to exercise the
   *                 code path that handles this specific state. Also, list and
   *                 set timestamp types on this handle.
   */
  p = pcap_create(source_str, errbuf);
  if (p) {
    int *tstamp_types = NULL;
    int n_tstamp_types = pcap_list_tstamp_types(p, &tstamp_types);
    if (n_tstamp_types > 0 && tstamp_types) {
      pcap_set_tstamp_type(p, tstamp_types[0]);
      pcap_free_tstamp_types(tstamp_types);
    }
    pcap_set_tstamp_type(p, -1); // Test invalid type

    /*
     * ANALYSIS: pcap_stats_not_initialized had 0% coverage. This is called
     *           when pcap_stats is used on a non-activated handle.
     * IMPLEMENTATION: Call pcap_stats() on the non-activated handle.
     */
    struct pcap_stat stats_unactivated;
    pcap_stats(p, &stats_unactivated);

    /*
     * ANALYSIS: A family of error-handling functions for unactivated handles
     *           (e.g., pcap_inject_not_initialized) had 0% coverage.
     * IMPLEMENTATION: Call the relevant functions on the unactivated handle
     *                 to trigger and cover these error-reporting code paths.
     */
    pcap_setnonblock(p, 1, errbuf);
    pcap_getnonblock(p, errbuf);
    pcap_inject(p, file_content_data, file_content_size);
    struct bpf_program fp_unactivated;
    pcap_setfilter(p, &fp_unactivated);
    pcap_setdirection(p, PCAP_D_IN);
    pcap_set_datalink(p, DLT_EN10MB);


    // Path for dumper doesn't matter much here as it should fail early.
    d = pcap_dump_open(p, "/dev/null");
    if (d) {
      pcap_dump_close(d);
    }
    pcap_close(p);
  }

  /*
   * ANALYSIS: The functions pcap_ether_hostton and pcap_next_etherent had
   *           0% coverage as they require a file like /etc/ethers to parse.
   * IMPLEMENTATION: Create a temporary ethers file with fuzzer data, then
   *                 call the functions to parse it. This covers the file
   *                 parsing and name/address resolution logic.
   */
  char ethers_path[256];
  snprintf(ethers_path, sizeof(ethers_path), "/tmp/%s.ethers", _FUZZ_TARGET_NAME);
  FILE *ethers_file = fopen(ethers_path, "wb");
  if (ethers_file) {
    fwrite(file_content_data, 1, file_content_size, ethers_file);
    // pcap_ether_hostton requires the FILE* to be closed before it can read,
    // as it will rewind and read from the beginning.
    fclose(ethers_file);

    struct ether_addr *addr = (struct ether_addr *)pcap_ether_hostton(source_str);
    free(addr); // Must free the result of pcap_ether_hostton

    // Re-open to pass to pcap_next_etherent
    ethers_file = fopen(ethers_path, "r");
    if (ethers_file) {
      addr = pcap_next_etherent(ethers_file);
      free(addr); // Must free the result of pcap_next_etherent
      fclose(ethers_file);
    }
  }
  unlink(ethers_path);


  free(source_str);
  return 0;
}