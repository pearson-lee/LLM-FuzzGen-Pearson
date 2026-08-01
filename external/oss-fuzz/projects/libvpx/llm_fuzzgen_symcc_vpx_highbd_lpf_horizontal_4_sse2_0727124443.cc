#include <cstddef>
#include <cstdint>
#include <cstdlib>
#include <cstring>

#include <vpx/vpx_integer.h>
#include <vpx_dsp_rtcd.h>

// The RTCD header declares the function pointers but not the init function itself.
// Explicitly declare vpx_dsp_rtcd() to ensure it can be called.
extern "C" void vpx_dsp_rtcd(void);

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
    // The target function reads from s[-2*pitch] to s[+1*pitch].
    // A buffer is set up to accommodate this access pattern safely.
    const int kPitch = 8;
    const int kHeight = 8;
    const int kBlockSize = kPitch * kHeight;
    const size_t kPixelBufSize = kBlockSize * sizeof(uint16_t);
    const size_t kParamSize = 16; // blimit, limit, thresh are read in 16-byte chunks
    const size_t kMinInputSize = kPixelBufSize + (kParamSize * 3);

    if (size < kMinInputSize) {
        return 0;
    }

    // Initialize the Run-Time CPU Dependant function pointers. This is
    // necessary for direct calls to DSP functions, as it's normally handled
    // by the full decoder initialization.
    vpx_dsp_rtcd();

    uint16_t pixel_buffer[kBlockSize];
    uint8_t blimit[kParamSize];
    uint8_t limit[kParamSize];
    uint8_t thresh[kParamSize];

    const uint8_t* current_data = data;

    memcpy(pixel_buffer, current_data, kPixelBufSize);
    current_data += kPixelBufSize;

    memcpy(blimit, current_data, kParamSize);
    current_data += kParamSize;

    memcpy(limit, current_data, kParamSize);
    current_data += kParamSize;

    memcpy(thresh, current_data, kParamSize);

    // Set bit depth to 8 to hit the target branch. The original execution
    // failed to cover this path because it used the stream's default bd=12.
    const int bit_depth = 8;

    // The function pointer is initialized by vpx_dsp_rtcd().
    if (vpx_highbd_lpf_horizontal_4) {
        // Offset the pointer to avoid out-of-bounds reads. The function
        // accesses memory from s - 2 * pitch. A 4-row margin is provided.
        uint16_t* s_ptr = pixel_buffer + (4 * kPitch);
        vpx_highbd_lpf_horizontal_4(s_ptr, kPitch, blimit, limit, thresh, bit_depth);
    }

    return 0;
}