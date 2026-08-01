/*
 * Copyright (c) 2024 The Fuzzing Company. All rights reserved.
 *
 * Use of this source code is governed by a BSD-style license that can be
 * found in the LICENSE file.
 */

#include <cstddef>
#include <cstdint>
#include <cstring>

// Required for vpx types and RTCD function declarations.
#include <vpx/vpx_integer.h>
#include <vpx_dsp/vpx_dsp_common.h>
#include <vpx_dsp_rtcd.h>

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
    // The function vpx_highbd_lpf_horizontal_16 takes several pointer arguments
    // and a buffer 's' that is accessed with offsets.

    // We use a fixed pitch for simplicity and to avoid large allocations.
    // The function name contains '16', so a pitch of 16 is a natural choice.
    const int pitch = 16;

    // The function accesses memory in the range [s - 8*pitch, s + 7*pitch].
    // To accommodate this, we create a buffer of size 16*pitch and point 's'
    // to the middle.
    const int s_buffer_len = 16 * pitch; // 256
    const size_t s_buffer_size = s_buffer_len * sizeof(uint16_t); // 512 bytes

    // We need 16 bytes for blimit, 16 for limit, 16 for thresh, and
    // s_buffer_size bytes for the main buffer.
    const size_t required_size = 48 + s_buffer_size;
    if (size < required_size) {
        return 0;
    }

    // Directly map parts of the input data to the function's parameters.
    const uint8_t* blimit = data;
    const uint8_t* limit = data + 16;
    const uint8_t* thresh = data + 32;
    const uint8_t* s_data = data + 48;

    // Use a stack-allocated buffer for 's' to avoid heap operations.
    uint16_t s_buffer[s_buffer_len];
    memcpy(s_buffer, s_data, s_buffer_size);

    // Point 's' to the middle of the buffer to allow for negative indexing.
    uint16_t* s = s_buffer + 8 * pitch;

    // Hardcode the bit depth to 8 to hit the target branch in the blocker.
    const int bit_depth = 8;

    // Call the RTCD function pointer. On an SSE2-capable CPU, this will resolve
    // to vpx_highbd_lpf_horizontal_16_sse2, the function containing the blocker.
    // The RTCD initialization is expected to be handled by the build environment.
    vpx_highbd_lpf_horizontal_16(s, pitch, blimit, limit, thresh, bit_depth);

    return 0;
}