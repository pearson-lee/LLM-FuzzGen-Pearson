#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>

#include "vpx_config.h"
#include "vpx/vpx_decoder.h"
#include "vpx/vp8dx.h"

// ==============================================================================
// POC Verification: libvpx read_uncompressed_header:2717
// Blocked Predicate: if (cm->profile > PROFILE_0)
// Target Line 2718:  read_bitdepth_colorspace_sampling(cm, rb);
// ==============================================================================

int main() {
    printf("===================================================================\n");
    printf("[POC Verification] libvpx read_uncompressed_header:2717\n");
    printf("Target Predicate: if (cm->profile > PROFILE_0)\n");
    printf("Target Line 2718: read_bitdepth_colorspace_sampling(cm, rb);\n");
    printf("===================================================================\n\n");

    uint8_t bitstream[64];
    memset(bitstream, 0, sizeof(bitstream));

    int bit_pos = 0;
    #define WRITE_BITS(val, n) do { \
        for (int i = (n) - 1; i >= 0; --i) { \
            int b = ((val) >> i) & 1; \
            bitstream[bit_pos / 8] |= (b << (7 - (bit_pos % 8))); \
            bit_pos++; \
        } \
    } while(0)

    // Construct VP9 bitstream header:
    WRITE_BITS(0b10, 2);      // Frame marker
    WRITE_BITS(1, 1);         // profile bit 0 = 1
    WRITE_BITS(0, 1);         // profile bit 1 = 0 -> profile = 1 (PROFILE_1 > PROFILE_0)
    WRITE_BITS(0, 1);         // show_existing_frame = 0
    WRITE_BITS(1, 1);         // frame_type = 1 (INTER / Non-keyframe)
    WRITE_BITS(0, 1);         // show_frame = 0 (required for intra_only)
    WRITE_BITS(0, 1);         // error_resilient_mode = 0

    // Intra-only frame header:
    WRITE_BITS(1, 1);         // intra_only = 1
    WRITE_BITS(0, 2);         // reset_frame_context = 0

    // Sync code: 0x49, 0x83, 0x42
    WRITE_BITS(0x49, 8);
    WRITE_BITS(0x83, 8);
    WRITE_BITS(0x42, 8);

    // Line 2717 evaluates (cm->profile > PROFILE_0) -> TRUE!
    // Line 2718 executes: read_bitdepth_colorspace_sampling(cm, rb)
    // Inside read_bitdepth_colorspace_sampling:
    WRITE_BITS(0, 3);         // color_space = CS_UNKNOWN (0)
    WRITE_BITS(0, 1);         // color_range = 0
    WRITE_BITS(1, 1);         // subsampling_x = 1
    WRITE_BITS(1, 1);         // subsampling_y = 1 -> triggers "4:2:0 color not supported in profile 1 or 3"
    WRITE_BITS(0, 1);         // reserved bit = 0

    // Remaining fields required for stream info peek:
    WRITE_BITS(0b00000001, 8);// refresh_frame_flags = 1
    WRITE_BITS(64 - 1, 16);   // frame width = 64
    WRITE_BITS(64 - 1, 16);   // frame height = 64

    int total_bytes = 32;     // Pad to 32 bytes

    printf("[Step 1] Crafting VP9 Bitstream with Profile 1 intra-only frame:\n");
    printf("  Profile:               PROFILE_1 (1 > 0)\n");
    printf("  Frame Type:            Non-keyframe (frame_type = 1)\n");
    printf("  Intra-only flag:       1\n");
    printf("  Sync Code:             0x49 0x83 0x42\n");
    printf("  Colorspace sampling:   4:2:0 in Profile 1 (to observe exact Line 2718 error)\n");
    printf("  Bitstream size:        %d bytes\n\n", total_bytes);

    // Initialize decoder
    vpx_codec_ctx_t codec;
    vpx_codec_dec_cfg_t cfg = { 1, 0, 0 };
    if (vpx_codec_dec_init(&codec, vpx_codec_vp9_dx(), &cfg, 0) != VPX_CODEC_OK) {
        printf("Failed to init decoder\n");
        return 1;
    }

    // Decode frame
    printf("[Step 2] Executing vpx_codec_decode...\n");
    vpx_codec_err_t err = vpx_codec_decode(&codec, bitstream, total_bytes, NULL, 0);

    const char *detail = vpx_codec_error_detail(&codec);
    printf("  Decoder return code:   %d (%s)\n", err, vpx_codec_err_to_string(err));
    printf("  Decoder error detail:  \"%s\"\n\n", detail ? detail : "(null)");

    if (err == VPX_CODEC_UNSUP_BITSTREAM && detail &&
        strstr(detail, "4:2:0 color not supported in profile 1 or 3") != NULL) {
        printf("===================================================================\n");
        printf("[SUCCESS] Line 2717 evaluated to TRUE and Line 2718 was EXECUTED!\n");
        printf("Verified Error from read_bitdepth_colorspace_sampling: \"%s\"\n", detail);
        printf("Branch is 100%% reachable via direct input bitstream!\n");
        printf("===================================================================\n");
    } else {
        printf("Verification failed.\n");
        vpx_codec_destroy(&codec);
        return 1;
    }

    vpx_codec_destroy(&codec);
    return 0;
}
