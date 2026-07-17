#include "/src/libpcap/pcap/pcap.h"
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <stdio.h>

// A compile-time macro to create unique filenames. This is expected to be
// provided by the build system. If not, we define a default.
#ifndef _FUZZ_TARGET_NAME
#define _FUZZ_TARGET_NAME "fuzz_target"
#endif

// Helper function to write data to a temporary file and return its path.
// The caller is responsible for freeing the returned path and unlinking the file.
static char *buffer_to_file(const uint8_t *data, size_t size) {
  char *path = (char *)malloc(256);
  if (!path) {
    return NULL;
  }
  snprintf(path, 256, "/tmp/%s.pcap", _FUZZ_TARGET_NAME);

  FILE *fp = fopen(path, "wb");
  if (!fp) {
    free(path);
    return NULL;
  }
  fwrite(data, 1, size, fp);
  fclose(fp);
  return path;
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  if (size < 1) {
    return 0;
  }

  char errbuf[PCAP_ERRBUF_SIZE];
  pcap_if_t *alldevs = NULL;
  pcap_t *p = NULL;
  pcap_dumper_t *d = NULL;

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
   * ANALYSIS: The pcap_open function had 0% coverage. It's a critical entry
   *           point that dispatches based on the source string (file vs. device).
   * IMPLEMENTATION: A temporary file is created with fuzzer data. pcap_open is
   *                 then called with the path to this file to test the offline/file
   *                 parsing capabilities. It is also called with the fuzzer-provided
   *                 string to test the live/device opening path.
   */
  char *temp_path = buffer_to_file(file_content_data, file_content_size);
  if (temp_path) {
    p = pcap_open(temp_path, 65535, 0, 100, NULL, errbuf);
    if (p) {
      pcap_close(p);
    }
    unlink(temp_path);
    free(temp_path);
  }

  p = pcap_open(source_str, 65535, PCAP_OPENFLAG_PROMISCUOUS, 100, NULL, errbuf);
  if (p) {
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
   *           non-activated pcap_t handle is an untested path.
   * IMPLEMENTATION: Create a pcap handle using pcap_create but do not activate
   *                 it. Then, pass this handle to pcap_dump_open to exercise the
   *                 code path that handles this specific state.
   */
  p = pcap_create(source_str, errbuf);
  if (p) {
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