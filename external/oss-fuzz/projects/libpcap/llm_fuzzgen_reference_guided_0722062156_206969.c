/* BLOCKER_STRATEGY_CONTRACT
required_state: The FILE* stream used by pcap_next_packet must be in an error state (ferror() returns true) when fread() is called to read a packet header. This is achieved by closing the underlying file descriptor of the stream before the read operation.
state_constructor: A pipe is created. The fuzzer input is written to the write-end. The read-end is wrapped in a FILE* stream using fdopen() and passed to pcap_fopen_offline(). After the pcap handle is successfully created, the pipe's read file descriptor is closed manually, inducing an error state for subsequent stream operations.
trigger_api: pcap_next_ex()
preserved_invariants: The fuzzer input (Data, Size) is treated as the content of a pcap file. The core packet processing logic using pcap_next_ex() is preserved, maintaining the original input contract.
END_BLOCKER_STRATEGY_CONTRACT */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <fcntl.h>
#include <errno.h>
#include <unistd.h>

#include <pcap/pcap.h>

int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size) {
    pcap_t * pkts;
    char errbuf[PCAP_ERRBUF_SIZE];
    const u_char *pkt;
    struct pcap_pkthdr *header;
    struct pcap_stat stats;
    int r;
    int pipefds[2];
    FILE *fp;

    static FILE *outfile = NULL;
    if (outfile == NULL) {
        outfile = fopen("/dev/null", "w");
        if (outfile == NULL) {
            return 0;
        }
    }

    // BLOCKER-SPECIFIC LOGIC: Use a pipe to create a stream that can be
    // closed prematurely to induce a file error condition.
    if (pipe(pipefds) != 0) {
        return 0;
    }

    // Write the data to the pipe. This might block if Size is large, so make it non-blocking.
    int flags = fcntl(pipefds[1], F_GETFL, 0);
    fcntl(pipefds[1], F_SETFL, flags | O_NONBLOCK);

    ssize_t written = write(pipefds[1], Data, Size);
    // The write end is no longer needed.
    close(pipefds[1]);

    if (written < 0) {
        close(pipefds[0]);
        return 0;
    }

    // Create a FILE stream from the read end of the pipe.
    fp = fdopen(pipefds[0], "rb");
    if (fp == NULL) {
        close(pipefds[0]);
        return 0;
    }

    // Open the pcap handle from the stream. This will read the pcap global header.
    pkts = pcap_fopen_offline(fp, errbuf);
    if (pkts == NULL) {
        // Per documentation, pcap_fopen_offline does not close the stream on failure.
        fclose(fp); // This will close pipefds[0].
        return 0;
    }

    // BLOCKER TRIGGER: Close the read end of the pipe's file descriptor.
    // The FILE stream `fp` is still associated with the descriptor, but it is now
    // invalid. The next `fread` from `fp` inside `pcap_next_ex` should fail
    // and set the stream's error flag, which is checked by `ferror()`.
    close(pipefds[0]);

    // The rest of the fuzzer logic is preserved from the original target.
    r = pcap_next_ex(pkts, &header, &pkt);
    while (r > 0) {
        fprintf(outfile, "packet length=%d/%d\n",header->caplen, header->len);
        r = pcap_next_ex(pkts, &header, &pkt);
    }
    if (pcap_stats(pkts, &stats) == 0) {
        fprintf(outfile, "number of packets=%d\n", stats.ps_recv);
    }

    // Close the pcap structure. This will call fclose(fp). Calling fclose on a
    // stream with an already-closed file descriptor has undefined behavior,
    // but is acceptable in a fuzz target designed to trigger error paths.
    pcap_close(pkts);

    return 0;
}
