#include <pcap/pcap.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

// A simple callback handler for pcap_dispatch and pcap_loop.
// It doesn't need to do anything for this fuzz target.
static void dummy_handler(u_char *user, const struct pcap_pkthdr *h, const u_char *bytes) {
  // Do nothing.
  (void)user;
  (void)h;
  (void)bytes;
}

// Main fuzzing function
int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  pcap_t *p = NULL;
  pcap_if_t *alldevs = NULL;
  char errbuf[PCAP_ERRBUF_SIZE];
  struct pcap_stat ps;

  // We need at least a few bytes to work with.
  if (size < 20) {
    return 0;
  }

  const char *dev = "usbmon0"; // Default to usbmon to ensure it gets tested.

  // Try to find and use a real device based on fuzzer input.
  // This provides coverage for device enumeration and selection.
  if (pcap_findalldevs(&alldevs, errbuf) == 0 && alldevs != NULL) {
    // Use a byte from the fuzzer to pick a device.
    // If the byte is 0, we stick with the default "usbmon0".
    // Otherwise, we pick from the list.
    int dev_index = data[0] % 10;
    if (dev_index > 0) {
      pcap_if_t *d = alldevs;
      // dev_index is 1-based now, so loop dev_index - 1 times.
      for (int i = 0; i < (dev_index - 1) && d->next != NULL; i++) {
        d = d->next;
      }
      dev = d->name;
    }
  }
  data++;
  size--;

  // Create a pcap handle. This will set up the function pointers in the handle
  // to the USB-specific implementations if a "usbmon" device is chosen.
  p = pcap_create(dev, errbuf);
  if (p == NULL) {
    if (alldevs) {
      pcap_freealldevs(alldevs);
    }
    return 0;
  }

  // Fuzz various pre-activation settings.
  // These calls will target functions like usb_set_ring_size.
  pcap_set_snaplen(p, *(const int *)(data));
  data += sizeof(int);
  size -= sizeof(int);

  pcap_set_promisc(p, data[0] % 2);
  data++;
  size--;

  pcap_set_timeout(p, *(const int *)(data));
  data += sizeof(int);
  size -= sizeof(int);

  pcap_set_buffer_size(p, *(const int *)(data));
  data += sizeof(int);
  size -= sizeof(int);

  // Attempt to activate the handle. For a "usbmon" device, this will call
  // usb_activate(), which has 0% coverage. While it's likely to fail in a
  // typical fuzzing environment, this call is crucial for exercising the
  // numerous error-handling paths in that function.
  int ret = pcap_activate(p);
  if (ret == 0) {
    // If activation succeeds (e.g., in a specialized environment),
    // fuzz the post-activation functions.

    // Set non-blocking mode to prevent timeouts during packet capture.
    pcap_setnonblock(p, 1, errbuf);

    // Fuzz packet injection (targets usb_inject_linux).
    if (size > 0) {
      pcap_inject(p, data, size);
    }

    // Fuzz packet reading (targets usb_read_linux_mmap or usb_read_linux_bin).
    pcap_dispatch(p, 1, dummy_handler, NULL);

    // Fuzz statistics gathering (targets usb_stats_linux_bin).
    pcap_stats(p, &ps);

    // Fuzz direction setting (targets usb_setdirection_linux).
    pcap_setdirection(p, (pcap_direction_t)(data[0] % 3));
  }

  // Clean up resources.
  pcap_close(p);
  if (alldevs) {
    pcap_freealldevs(alldevs);
  }

  return 0;
}