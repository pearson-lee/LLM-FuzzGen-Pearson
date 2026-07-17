#include "/src/libpcap/pcap/pcap.h"
#include "/src/libpcap/pcap/bpf.h"
#include "/src/libpcap/pcap/namedb.h"
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <stdio.h>
#include <sys/time.h>
#include <net/if.h>
#include <linux/if_ether.h>

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
   *           a fundamental API function that was not being called because the
   *           preceding `pcap_lookupdev` call often fails in a containerized
   *           environment.
   * IMPLEMENTATION: A call to pcap_lookupnet is added, using the fuzzer-
   *                 provided string to ensure it is always called.
   */
  bpf_u_int32 net, mask;
  pcap_lookupnet(source_str, &net, &mask, errbuf);


  /*
   * ANALYSIS: The function pcap_nametoportrange had 0% coverage and was not
   *           being called.
   * IMPLEMENTATION: A call to pcap_nametoportrange is added to exercise this
   *                 string parsing utility with fuzzer-provided data.
   */
  int p1, p2;
  (void)pcap_nametoportrange(source_str, &p1, &p2, errbuf);

  /*
   * ANALYSIS: The function pcap_findalldevs had low coverage (52.38%) and
   *           provides a simpler interface than the already-fuzzed
   *           pcap_findalldevs_ex.
   * IMPLEMENTATION: A call to pcap_findalldevs is added to exercise this
   *                 common device enumeration API.
   */
  if (pcap_findalldevs(&alldevs, errbuf) == 0) {
    pcap_freealldevs(alldevs);
    alldevs = NULL;
  }

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

        /*
         * ANALYSIS: The functions pcap_dump_ftell and pcap_dump_ftell64
         *           had 0% coverage.
         * IMPLEMENTATION: Call these functions on a valid dumper to
         *                 exercise the underlying ftell/ftello calls.
         */
        (void)pcap_dump_ftell(d);
        (void)pcap_dump_ftell64(d);

        pcap_dump_close(d);
        d = NULL;

        d = pcap_dump_open_append(p_dead, temp_path);
        if (d) {
          pcap_dump_close(d);
          d = NULL;
        }
      }
      /*
       * ANALYSIS: The function pcap_dump_fopen had 0% coverage.
       * IMPLEMENTATION: Open a temporary file using fopen and pass the
       *                 resulting FILE* to pcap_dump_fopen to exercise this
       *                 code path.
       */
      char dump_fopen_path[256];
      snprintf(dump_fopen_path, sizeof(dump_fopen_path), "/tmp/%s.dump_fopen.pcap", _FUZZ_TARGET_NAME);
      FILE *dfp = fopen(dump_fopen_path, "wb");
      if (dfp) {
        d = pcap_dump_fopen(p_dead, dfp);
        if (d) {
          pcap_dump_close(d); // This also closes the FILE*
          d = NULL;
        } else {
          fclose(dfp);
        }
      }
      unlink(dump_fopen_path);

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

      /*
       * ANALYSIS: The function pcap_dump_open_append has low coverage (28.57%),
       *           specifically in the error path where the existing file's
       *           snapshot length does not match the handle's snapshot length.
       * IMPLEMENTATION: Create a second dead handle with a different snaplen.
       *                 Attempt to append to the existing file with this new
       *                 handle to trigger the snaplen mismatch error condition.
       */
      pcap_t *p_dead_snaplen = pcap_open_dead(DLT_EN10MB, 100); // Different snaplen
      if (p_dead_snaplen) {
        d = pcap_dump_open_append(p_dead_snaplen, temp_path);
        if (d) {
          pcap_dump_close(d);
          d = NULL;
        }
        pcap_close(p_dead_snaplen);
      }

      pcap_close(p_dead);
    }

    p = pcap_open_offline(temp_path, errbuf);
    if (p) {
      /*
       * ANALYSIS: The functions sf_cant_set_rfmon and sf_inject in savefile.c
       *           had 0% coverage. They are called when live-capture functions
       *           are used on an offline handle.
       * IMPLEMENTATION: Call pcap_set_rfmon and pcap_inject on the offline
       *                 handle to trigger these specific error-handling paths.
       */
      pcap_set_rfmon(p, 1);
      pcap_inject(p, file_content_data, file_content_size);

      /*
       * ANALYSIS: The function pcap_breakloop had 0% coverage.
       * IMPLEMENTATION: Call pcap_breakloop on the handle. Although pcap_loop
       *                 is called with a count of 1 and will terminate quickly,
       *                 this ensures the pcap_breakloop logic is exercised.
       */
      pcap_breakloop(p);
      pcap_loop(p, 1, dummy_handler, NULL);

      /*
       * ANALYSIS: The function pcap_next had low coverage (90%).
       * IMPLEMENTATION: Call pcap_next on the offline handle to
       *                 exercise this simpler packet reading function.
       */
      struct pcap_pkthdr hdr;
      pcap_next(p, &hdr);

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

  // Keep fuzzing the error path for pcap_open with the original random string.
  p = pcap_open(source_str, 65535, PCAP_OPENFLAG_PROMISCUOUS, 100, NULL, errbuf);
  if (p) {
    pcap_close(p);
  }

  /*
   * ANALYSIS: The pcap_open() call with a random string from the fuzzer almost
   *           always fails, leaving a large block of code for handling activated
   *           handles completely uncovered.
   * IMPLEMENTATION: Add a call to pcap_open() with the special device name "any",
   *                 which is likely to succeed on a Linux system and allow an
   *                 activated handle to be created. The subsequent block of code
   *                 now operates on this potentially valid handle.
   */
  p = pcap_open("any", 65535, PCAP_OPENFLAG_PROMISCUOUS, 100, NULL, errbuf);
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

      /*
       * ANALYSIS: The function bpf_filter() had 0% coverage. It is the BPF
       *           interpreter and is not called unless a filter is executed.
       * IMPLEMENTATION: Call pcap_offline_filter() with the compiled filter
       *                 and some data to execute the filter and cover bpf_filter().
       */
      struct pcap_pkthdr dummy_hdr_bpf;
      dummy_hdr_bpf.len = file_content_size;
      dummy_hdr_bpf.caplen = file_content_size;
      pcap_offline_filter(&fp, &dummy_hdr_bpf, file_content_data);

      pcap_freecode(&fp);
    }
    /*
     * ANALYSIS: The BPF filter compiler in gencode.c has many uncovered
     *           functions. The "any" device may not support all filter types.
     * IMPLEMENTATION: Create a dead handle with DLT_EN10MB and compile
     *                 ethernet-specific filters against it to improve coverage.
     */
    pcap_t *p_dead_eth = pcap_open_dead(DLT_EN10MB, 65535);
    if (p_dead_eth) {
        if (pcap_compile(p_dead_eth, &fp, "vlan 100", 1, PCAP_NETMASK_UNKNOWN) == 0) {
            pcap_freecode(&fp);
        }
        if (pcap_compile(p_dead_eth, &fp, "broadcast", 1, PCAP_NETMASK_UNKNOWN) == 0) {
            pcap_freecode(&fp);
        }
        if (pcap_compile(p_dead_eth, &fp, "multicast", 1, PCAP_NETMASK_UNKNOWN) == 0) {
            pcap_freecode(&fp);
        }
        /*
         * ANALYSIS: The gencode.c file contains many uncovered functions for
         *           compiling different filter types.
         * IMPLEMENTATION: Add a variety of filter strings to exercise more of the
         *           BPF compiler logic, such as `inbound`, `llc`, `pppoes`, and `wlan ra`.
         */
        if (pcap_compile(p_dead_eth, &fp, "inbound", 1, PCAP_NETMASK_UNKNOWN) == 0) {
            pcap_freecode(&fp);
        }
        if (pcap_compile(p_dead_eth, &fp, "llc", 1, PCAP_NETMASK_UNKNOWN) == 0) {
            pcap_freecode(&fp);
        }
        if (pcap_compile(p_dead_eth, &fp, "pppoes", 1, PCAP_NETMASK_UNKNOWN) == 0) {
            pcap_freecode(&fp);
        }
        if (pcap_compile(p_dead_eth, &fp, "wlan ra e0:f8:47:00:00:00", 1, PCAP_NETMASK_UNKNOWN) == 0) {
            pcap_freecode(&fp);
        }
        if (pcap_compile(p_dead_eth, &fp, "mpls 1", 1, PCAP_NETMASK_UNKNOWN) == 0) {
            pcap_freecode(&fp);
        }
        if (pcap_compile(p_dead_eth, &fp, "ip6 dst portrange 10-100", 1, PCAP_NETMASK_UNKNOWN) == 0) {
            pcap_freecode(&fp);
        }
        pcap_close(p_dead_eth);
    }
    
    /*
     * ANALYSIS: The `gen_wlanhostop` function in gencode.c had 0% coverage.
     *           This code is triggered when compiling a `wlan` filter on a handle
     *           with a Wi-Fi link-layer type.
     * IMPLEMENTATION: Create a dead handle with `DLT_IEEE802_11_RADIO` and
     *                 compile a `wlan` filter against it to exercise this code.
     */
    pcap_t *p_dead_wlan = pcap_open_dead(DLT_IEEE802_11_RADIO, 65535);
    if (p_dead_wlan) {
        if (pcap_compile(p_dead_wlan, &fp, "wlan ra e0:f8:47:00:00:00", 1, PCAP_NETMASK_UNKNOWN) == 0) {
            pcap_freecode(&fp);
        }
        pcap_close(p_dead_wlan);
    }

    if (pcap_compile(p, &fp, "tcp port 80", 1, PCAP_NETMASK_UNKNOWN) == 0) {
      pcap_freecode(&fp);
    }
    if (pcap_compile(p, &fp, "ip protochain 6", 1, PCAP_NETMASK_UNKNOWN) == 0) {
        pcap_freecode(&fp);
    }
    if (pcap_compile(p, &fp, "vxlan", 1, PCAP_NETMASK_UNKNOWN) == 0) {
        pcap_freecode(&fp);
    }
    if (pcap_compile(p, &fp, "less 128", 1, PCAP_NETMASK_UNKNOWN) == 0) {
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
     * ANALYSIS: The function pcap_breakloop_linux had 0% coverage. This is the
     *           platform-specific implementation for pcap_breakloop on live
     *           Linux captures.
     * IMPLEMENTATION: Call pcap_breakloop on the live handle to exercise this
     *                 uncovered code path.
     */
    pcap_breakloop(p);

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
      /*
       * ANALYSIS: The function pcap_dump_file had 0% coverage.
       * IMPLEMENTATION: Call pcap_dump_file on the valid dumper to
       *                 exercise this accessor function.
       */
      (void)pcap_dump_file(d);
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
    /*
     * ANALYSIS: The function pcap_set_protocol_linux has 0% coverage. It needs
     *           to be called on a non-activated handle.
     * IMPLEMENTATION: Call pcap_set_protocol_linux on the created handle
     *                 before activation to exercise this function.
     */
    pcap_set_protocol_linux(p, ETH_P_IP);

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
   * ANALYSIS: The functions in pcap-usb-linux.c have very low coverage because
   *           a USB device is never opened.
   * IMPLEMENTATION: Attempt to create and activate a "usbmon1" device. Even
   *                 if it fails, it will exercise the USB-specific code paths
   *                 in pcap_create and pcap_activate.
   */
  p = pcap_create("usbmon1", errbuf);
  if (p) {
    pcap_activate(p); // This is expected to fail, but covers the code path.
    pcap_close(p);
  }

  /*
   * ANALYSIS: The functions in pcap-netfilter-linux.c have very low coverage.
   * IMPLEMENTATION: Attempt to create and activate a "nfqueue" device to
   *                 exercise the netfilter-specific code paths.
   */
  p = pcap_create("nfqueue", errbuf);
  if (p) {
    pcap_activate(p); // Expected to fail, but exercises code path
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