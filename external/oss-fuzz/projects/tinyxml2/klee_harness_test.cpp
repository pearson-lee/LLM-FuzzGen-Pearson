#include "tinyxml2.h"
#include <klee/klee.h>
#include <cstring>
#include <cstdint>

#define MAX_INPUT_SIZE 1024

using namespace tinyxml2;

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size);

int main(int argc, char **argv) {
    unsigned char input[MAX_INPUT_SIZE];
    size_t input_size;
    
    // Make input size symbolic
    klee_make_symbolic(&input_size, sizeof(input_size), "input_size");
    klee_assume(input_size > 0 && input_size < MAX_INPUT_SIZE);
    
    // Make input data symbolic
    klee_make_symbolic(&input, input_size, "input");
    
    // Add basic XML constraint - first char should be '<'
    if (input_size > 0) {
        klee_assume(input[0] == '<');
    }
    
    // Ensure null termination
    input[input_size] = '\0';
    
    // Call the fuzzer entry point
    LLVMFuzzerTestOneInput(input, input_size);
    
    return 0;
}