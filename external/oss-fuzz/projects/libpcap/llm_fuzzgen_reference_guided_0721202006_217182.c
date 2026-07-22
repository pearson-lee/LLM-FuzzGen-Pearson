/* BLOCKER_STRATEGY_CONTRACT
required_state: handle->opt.rfmon must be false within the usb_activate function to bypass an early exit. handle->fd must also be a valid file descriptor.
state_constructor: A dummy file is created at "/dev/usbmon1" to ensure the open() call inside usb_activate succeeds. The pcap handle is used with its default settings, where rfmon is false.
trigger_api: pcap_activate() is called on a pcap handle created for the "usbmon1" device.
preserved_invariants: The dummy file at "/dev/usbmon1" must exist before pcap_activate is called. The core logic of creating a pcap handle for "usbmon1" and activating it is preserved.
END_BLOCKER_STRATEGY_CONTRACT */

#include <pcap.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    char errbuf[PCAP_ERRBUF_SIZE];
    const char *dev = "usbmon1";
    char path[256];

    // In pcap-usb-linux.c, usb_activate constructs this path to open.
    snprintf(path, sizeof(path), "/dev/%s", dev);

    // 1. Create the dummy device file so that the open() call in usb_activate succeeds.
    // This is required to get a valid file descriptor in the handle.
    int fd = creat(path, 0644);
    if (fd != -1) {
        close(fd);
    }

    pcap_t *p = pcap_create(dev, errbuf);
    if (p) {
        // The blocker is 'if (handle->opt.rfmon)', which causes an early exit.
        // To bypass it, handle->opt.rfmon must be false.
        // The default value is false, so we don't call pcap_set_rfmon(p, 1).
        // pcap_activate will call usb_activate, which contains the blocker.
        pcap_activate(p);
        pcap_close(p);
    }

    // Clean up the dummy file.
    if (fd != -1) {
        unlink(path);
    }

    return 0;
}