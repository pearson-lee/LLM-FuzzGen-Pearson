#include "/src/libpcap/pcap/pcap.h"
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
      pcap_close(p_dead);
    }

    p = pcap_open_offline(temp_path, errbuf);
    if (p) {
      pcap_loop(p, 1, dummy_handler, NULL);
      pcap_close(p);
      p = NULL;
    }

    unlink(temp_path);
    free(temp_path);
  }

  p = pcap_open(source_str, 65535, PCAP_OPENFLAG_PROMISCUOUS, 100, NULL, errbuf);
  if (p) {
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
      pcap_freecode(&fp);
    }
    if (pcap_compile(p, &fp, source_str, 1, PCAP_NETMASK_UNKNOWN) == 0) {
      pcap_setfilter(p, &fp);
      pcap_freecode(&fp);
    }

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

    // Path for dumper doesn't matter much here as it should fail early.
    d = pcap_dump_open(p, "/dev/null");
    if (d) {
      pcap_dump_close(d);
    }
    pcap_close(p);
  }

  free(source_str);
  return 0;
}