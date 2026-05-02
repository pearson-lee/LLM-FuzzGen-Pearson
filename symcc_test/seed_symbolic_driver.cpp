#include <cstdint>
#include <cstdio>
#include <iostream>
#include <vector>

#include <klee/klee.h>

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size);

namespace {

bool ReadAllBytes(FILE* input, std::vector<uint8_t>* out) {
    uint8_t buffer[4096];
    out->clear();

    while (true) {
        const size_t n = fread(buffer, 1, sizeof(buffer), input);
        if (n > 0) {
            out->insert(out->end(), buffer, buffer + n);
        }

        if (n < sizeof(buffer)) {
            if (feof(input)) {
                return true;
            }
            return false;
        }
    }
}

}  // namespace

int main(int argc, char** argv) {
    if (argc != 2) {
        std::cerr << "usage: " << argv[0] << " <seed-file>\n";
        return 1;
    }

    FILE* input = fopen(argv[1], "rb");
    if (!input) {
        std::cerr << "failed to open: " << argv[1] << "\n";
        return 1;
    }

    std::vector<uint8_t> bytes;
    const bool ok = ReadAllBytes(input, &bytes);
    fclose(input);

    if (!ok) {
        std::cerr << "failed to read input\n";
        return 1;
    }

    if (!bytes.empty()) {
        klee_make_symbolic(bytes.data(), bytes.size(), "input");
    }

    return LLVMFuzzerTestOneInput(bytes.data(), bytes.size());
}
