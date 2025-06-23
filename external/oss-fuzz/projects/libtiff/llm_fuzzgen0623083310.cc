#include <cstddef>
#include <cstdint>
#include <vector>
#include <fuzzer/FuzzedDataProvider.h>
#include "/src/libtiff/libtiff/tiffiop.h"

// Dummy implementation for the tag extender callback
void TagExtender(TIFF* tif) {
    (void)tif;
}

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    FuzzedDataProvider fdp(data, size);

    // Target: _TIFFsetShortArray
    // This part of the fuzzer tests the library's ability to handle arrays of short integers.
    // We allocate a buffer for the array and fill it with fuzzed data.
    uint16_t* short_array_ptr = nullptr;
    const uint32_t short_array_count = fdp.ConsumeIntegralInRange<uint32_t>(0, 100);
    std::vector<uint16_t> short_array_data;
    for (uint32_t i = 0; i < short_array_count; ++i) {
        short_array_data.push_back(fdp.ConsumeIntegral<uint16_t>());
    }
    _TIFFsetShortArray(&short_array_ptr, short_array_data.data(), short_array_count);
    // Ensure memory allocated by the library is freed.
    if (short_array_ptr) {
        _TIFFfree(short_array_ptr);
    }

    // Target: _TIFFsetLongArray
    // This tests the handling of long integer arrays, which are common for certain TIFF tags.
    // Similar to the short array test, we create and populate a buffer with fuzzed data.
    uint32_t* long_array_ptr = nullptr;
    const uint32_t long_array_count = fdp.ConsumeIntegralInRange<uint32_t>(0, 100);
    std::vector<uint32_t> long_array_data;
    for (uint32_t i = 0; i < long_array_count; ++i) {
        long_array_data.push_back(fdp.ConsumeIntegral<uint32_t>());
    }
    _TIFFsetLongArray(&long_array_ptr, long_array_data.data(), long_array_count);
    // Free the memory to prevent leaks.
    if (long_array_ptr) {
        _TIFFfree(long_array_ptr);
    }

    // Target: _TIFFsetFloatArray
    // This section focuses on floating-point data, which has a different memory layout and
    // potential for different kinds of errors compared to integers.
    float* float_array_ptr = nullptr;
    const uint32_t float_array_count = fdp.ConsumeIntegralInRange<uint32_t>(0, 100);
    std::vector<float> float_array_data;
    for (uint32_t i = 0; i < float_array_count; ++i) {
        float_array_data.push_back(fdp.ConsumeFloatingPoint<float>());
    }
    _TIFFsetFloatArray(&float_array_ptr, float_array_data.data(), float_array_count);
    // Memory cleanup is crucial.
    if (float_array_ptr) {
        _TIFFfree(float_array_ptr);
    }

    // Target: _TIFFsetDoubleArray
    // This tests double-precision floating-point arrays, expanding our coverage of
    // floating-point handling in the library.
    double* double_array_ptr = nullptr;
    const uint32_t double_array_count = fdp.ConsumeIntegralInRange<uint32_t>(0, 100);
    std::vector<double> double_array_data;
    for (uint32_t i = 0; i < double_array_count; ++i) {
        double_array_data.push_back(fdp.ConsumeFloatingPoint<double>());
    }
    _TIFFsetDoubleArray(&double_array_ptr, double_array_data.data(), double_array_count);
    // Free the allocated memory.
    if (double_array_ptr) {
        _TIFFfree(double_array_ptr);
    }

    // Target: TIFFSetTagExtender
    // This function sets a callback for handling unknown TIFF tags. We test this by
    // providing a dummy callback function. This is important for checking the
    // library's extensibility and handling of non-standard tags.
    TIFFSetTagExtender(TagExtender);

    return 0;
}