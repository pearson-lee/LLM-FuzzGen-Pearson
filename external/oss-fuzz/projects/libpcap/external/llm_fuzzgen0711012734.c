#include <pcap.h>
#include <pcap-int.h>
#include <string.h>
#include <stdlib.h>
#include <stdbool.h>
#include <stdint.h>
#include <stddef.h>
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>


#define _FUZZ_TARGET_NAME "fuzz_pcap"

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    if (size < 1) {
        return 0;
    }

    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_if_t *alldevs;

    /*
     * ANALYSIS: The function-level coverage report showed pcap_findalldevs had low
     *           coverage. The line-level report confirmed this was due to error-handling
     *           branches not being taken.
     * IMPLEMENTATION: The following code block calls pcap_findalldevs to exercise
     *                 the device enumeration logic.
     */
    if (pcap_findalldevs(&alldevs, errbuf) == 0) {
        pcap_freealldevs(alldevs);
    }

    // Create a dummy interface name
    char name[20] = {0};
    if (size > 19) {
        size = 19;
    }
    memcpy(name, data, size);


    /*
     * ANALYSIS: The function-level coverage report showed pcap_open_live had low
     *           coverage. The line-level report confirmed this was due to error-handling
     *           branches not being taken.
     * IMPLEMENTATION: The following code block calls pcap_open_live with a dummy
     *                 interface name to exercise the live capture opening logic.
     */
    pcap_t *p = pcap_open_live(name, 65535, 1, 1000, errbuf);
    if (p) {
        pcap_close(p);
    }

    /*
    * ANALYSIS: The function-level coverage report showed usb_activate had very low coverage.
    * This function is called by pcap_activate when the device is a USB device.
    * IMPLEMENTATION: Create a pcap_t with a USB device name and then call pcap_activate.
    */
    pcap_t *p_usb = pcap_create("usbmon1", errbuf);
    if (p_usb) {
        pcap_activate(p_usb);
        pcap_close(p_usb);
    }

    /*
     * ANALYSIS: The function-level coverage report showed pcapint_add_addr_to_dev
     *           had low coverage. The line-level report confirmed this was due to
     *           unexercised branches for different address types.
     * IMPLEMENTATION: The following code creates a dummy device and adds various
     *                 address types to it to exercise the uncovered branches.
     */
    pcap_if_t dev;
    memset(&dev, 0, sizeof(dev));
    dev.name = "dummy";

    struct sockaddr_in addr, netmask, broadaddr, dstaddr;
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = 0x01020304;
    netmask.sin_family = AF_INET;
    netmask.sin_addr.s_addr = 0x00ffffff;
    broadaddr.sin_family = AF_INET;
    broadaddr.sin_addr.s_addr = 0x05060708;
    dstaddr.sin_family = AF_INET;
    dstaddr.sin_addr.s_addr = 0x090a0b0c;

    pcapint_add_addr_to_dev(&dev, (struct sockaddr *)&addr, sizeof(addr),
                            (struct sockaddr *)&netmask, sizeof(netmask),
                            (struct sockaddr *)&broadaddr, sizeof(broadaddr),
                            (struct sockaddr *)&dstaddr, sizeof(dstaddr), errbuf);

    // Free allocated memory
    if (dev.addresses) {
        pcap_addr_t *next_addr;
        for (pcap_addr_t *addr_ptr = dev.addresses; addr_ptr; addr_ptr = next_addr) {
            next_addr = addr_ptr->next;
            free(addr_ptr->addr);
            free(addr_ptr->netmask);
            free(addr_ptr->broadaddr);
            free(addr_ptr->dstaddr);
            free(addr_ptr);
        }
    }

    return 0;
}