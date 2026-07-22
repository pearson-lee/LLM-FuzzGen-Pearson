/* BLOCKER_STRATEGY_CONTRACT
required_state: handle->fd must be a valid file descriptor (>= 0) and handle->opt.rfmon must be true within the usb_activate function.
state_constructor: A dummy file is created at "/dev/usbmon1" to ensure the open() call inside usb_activate succeeds. pcap_set_rfmon() is called to set the rfmon flag on the pcap handle.
trigger_api: pcap_activate() is called on a pcap handle created for the "usbmon1" device.
preserved_invariants: The dummy file at "/dev/usbmon1" must exist before pcap_activate is called, and pcap_set_rfmon must have been successfully called on the handle.
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
    // This is the first part of solving the blocker.
    int fd = creat(path, 0644);
    if (fd != -1) {
        close(fd);
    }

    pcap_t *p = pcap_create(dev, errbuf);
    if (p) {
        // 2. Set rfmon to true. This is the second part of solving the blocker.
        // The check 'if (handle->opt.rfmon)' will now be true.
        if (pcap_set_rfmon(p, 1) == 0) {
            // pcap_activate will call usb_activate, which contains the blocker.
            // With the file created and rfmon set, we should hit the target branch.
            pcap_activate(p);
        }
        pcap_close(p);
    }

    // Clean up the dummy file.
    if (fd != -1) {
        unlink(path);
    }

    return 0;
}
