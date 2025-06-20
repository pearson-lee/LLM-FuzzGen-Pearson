#include <cstddef>
#include <cstdint>
#include <vector>
#include <memory>
#include <algorithm> // Required for std::max
#include <fuzzer/FuzzedDataProvider.h>

// Include necessary astc-encoder headers
#include "/src/astc-encoder/Source/astcenc_internal.h"
#include "/src/astc-encoder/Source/astcenc_mathlib.h"

// Helper to get the number of bytes needed for a given number of bits
size_t bits_to_bytes(unsigned int bits) {
    // Add 7 before dividing by 8 to round up
    return (bits + 7) / 8;
}

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size) {
    FuzzedDataProvider fdp(Data, Size);

    // --- Fuzzing is_legal_2d_block_size ---
    // Generate random dimensions for 2D block size check
    unsigned int xdim_2d = fdp.ConsumeIntegral<unsigned int>();
    unsigned int ydim_2d = fdp.ConsumeIntegral<unsigned int>();
    is_legal_2d_block_size(xdim_2d, ydim_2d);

    // --- Fuzzing is_legal_3d_block_size ---
    // Generate random dimensions for 3D block size check
    unsigned int xdim_3d = fdp.ConsumeIntegral<unsigned int>();
    unsigned int ydim_3d = fdp.ConsumeIntegral<unsigned int>();
    unsigned int zdim_3d = fdp.ConsumeIntegral<unsigned int>();
    is_legal_3d_block_size(xdim_3d, ydim_3d, zdim_3d);

    // --- Fuzzing get_quant_level ---
    // quant_method enum values range from 0 to 20 (QUANT_2 to QUANT_256)
    // Generate a random integer within the enum range and cast to quant_method
    unsigned int quant_method_val = fdp.ConsumeIntegralInRange<unsigned int>(0, 20);
    quant_method qm = static_cast<quant_method>(quant_method_val);
    get_quant_level(qm);

    // --- Fuzzing encode_ise ---
    // Generate random values for quant_method, character count
    unsigned int encode_ise_quant_val = fdp.ConsumeIntegralInRange<unsigned int>(0, 20); // quant_method enum range
    quant_method encode_ise_qm = static_cast<quant_method>(encode_ise_quant_val);
    unsigned int encode_ise_char_count = fdp.ConsumeIntegralInRange<unsigned int>(0, 256); // Limit character count to a reasonable size

    // Generate random input data for encode_ise
    std::vector<uint8_t> encode_ise_input_data = fdp.ConsumeBytes<uint8_t>(encode_ise_char_count);

    // Calculate the required bits for the sequence
    unsigned int required_bits = get_ise_sequence_bitcount(encode_ise_char_count, encode_ise_qm);

    // Calculate the required output buffer size based on required_bits
    size_t encode_ise_output_size = bits_to_bytes(required_bits);
    // Limit buffer size to avoid excessive memory allocation
    if (encode_ise_output_size > 4096) encode_ise_output_size = 4096;

    // Allocate output buffer for encoded data
    std::vector<uint8_t> encode_ise_output_data(encode_ise_output_size);

    // Determine the maximum safe bit offset based on buffer size and required bits
    // The total bits available in the buffer are encode_ise_output_data.size() * 8.
    // The bits to be written are required_bits.
    // The last bit index accessed will be encode_ise_bit_offset + required_bits - 1.
    // This must be less than encode_ise_output_data.size() * 8.
    // encode_ise_bit_offset + required_bits <= encode_ise_output_data.size() * 8
    // encode_ise_bit_offset <= encode_ise_output_data.size() * 8 - required_bits
    unsigned int max_safe_bit_offset = 0;
    if (encode_ise_output_data.size() * 8 >= required_bits) {
        max_safe_bit_offset = encode_ise_output_data.size() * 8 - required_bits;
    }

    // Fuzz bit offset within the safe range
    // Constrained bit_offset to prevent heap-buffer-overflow in write_bits.
    unsigned int encode_ise_bit_offset = fdp.ConsumeIntegralInRange<unsigned int>(0, max_safe_bit_offset);

    // Call encode_ise only if the input data size matches character_count, output buffer is not empty,
    // and character_count > 0. The bit offset is already constrained to prevent overflow.
    if (encode_ise_char_count > 0 &&
        encode_ise_input_data.size() == encode_ise_char_count &&
        !encode_ise_output_data.empty())
    {
         encode_ise(encode_ise_qm, encode_ise_char_count, encode_ise_input_data.data(), encode_ise_output_data.data(), encode_ise_bit_offset);
    }


    // --- Fuzzing symbolic_to_physical ---
    // This function requires a block_size_descriptor and a symbolic_compressed_block.
    // We will create and populate these structs with fuzzed data.

    // Allocate block_size_descriptor on the heap to avoid stack overflow
    block_size_descriptor* bsd = aligned_malloc<block_size_descriptor>(sizeof(block_size_descriptor), ASTCENC_VECALIGN);
    if (!bsd) {
        return 0; // Allocation failed
    }

    unsigned int bsd_x, bsd_y, bsd_z;

    // Choose between 2D and 3D block sizes
    bool is_3d_block = fdp.ConsumeBool();
    if (is_3d_block) {
        // Array of common legal 3D block dimensions
        unsigned int legal_3d_dims[][3] = {{3,3,3}, {4,3,3}, {4,4,3}, {4,4,4}, {5,4,4}, {5,5,4}, {5,5,5}, {6,5,5}, {6,6,5}, {6,6,6}};
        // Select a random legal 3D dimension set
        unsigned int dim_idx = fdp.ConsumeIntegralInRange<unsigned int>(0, sizeof(legal_3d_dims) / sizeof(legal_3d_dims[0]) - 1);
        bsd_x = legal_3d_dims[dim_idx][0];
        bsd_y = legal_3d_dims[dim_idx][1];
        bsd_z = legal_3d_dims[dim_idx][2];
    } else {
         // Array of common legal 2D block dimensions
         unsigned int legal_2d_dims[][2] = {{4,4}, {5,4}, {5,5}, {6,5}, {6,6}, {8,5}, {8,6}, {8,8}, {10,5}, {10,6}, {10,8}, {10,10}, {12,10}, {12,12}};
         // Select a random legal 2D dimension set
         unsigned int dim_idx = fdp.ConsumeIntegralInRange<unsigned int>(0, sizeof(legal_2d_dims) / sizeof(legal_2d_dims[0]) - 1);
        bsd_x = legal_2d_dims[dim_idx][0];
        bsd_y = legal_2d_dims[dim_idx][1];
        bsd_z = 1; // For 2D blocks, zdim is 1
    }

    // Generate other parameters for init_block_size_descriptor
    bool bsd_can_omit_modes = fdp.ConsumeBool();
    unsigned int bsd_partition_count_cutoff = fdp.ConsumeIntegralInRange<unsigned int>(1, BLOCK_MAX_PARTITIONS);
    float bsd_mode_cutoff = fdp.ConsumeFloatingPoint<float>();

    // Initialize the block_size_descriptor. This also initializes partition table metadata within bsd.
    init_block_size_descriptor(bsd_x, bsd_y, bsd_z, bsd_can_omit_modes, bsd_partition_count_cutoff, bsd_mode_cutoff, *bsd);

    // Initialize partition tables within the block_size_descriptor
    bool init_part_can_omit = fdp.ConsumeBool();
    unsigned int init_part_cutoff = fdp.ConsumeIntegralInRange<unsigned int>(1, BLOCK_MAX_PARTITIONS);
    init_partition_tables(*bsd, init_part_can_omit, init_part_cutoff);


    // Create and populate symbolic_compressed_block with fuzzed data
    std::unique_ptr<symbolic_compressed_block> scb = std::make_unique<symbolic_compressed_block>();
    if (!scb) {
        aligned_free(bsd);
        return 0; // Allocation failed
    }

    // Fuzz block_type (0-3)
    scb->block_type = fdp.ConsumeIntegralInRange<uint8_t>(0, 3); // SYM_BTYPE_ERROR to SYM_BTYPE_NONCONST
    // Fuzz partition_count (1-BLOCK_MAX_PARTITIONS)
    scb->partition_count = fdp.ConsumeIntegralInRange<uint8_t>(1, BLOCK_MAX_PARTITIONS);
    // Fuzz color_formats_matched
    scb->color_formats_matched = fdp.ConsumeBool();
    // Fuzz plane2_component (-1 or 0-3)
    scb->plane2_component = fdp.ConsumeIntegralInRange<int8_t>(-1, 3);
    // Fuzz block_mode index
    scb->block_mode = fdp.ConsumeIntegral<uint16_t>();
    // Fuzz partition_index
    scb->partition_index = fdp.ConsumeIntegral<uint16_t>();

    // Populate color_formats array with fuzzed data, constrained to valid endpoint_formats range
    for (int i = 0; i < BLOCK_MAX_PARTITIONS; ++i) {
        scb->color_formats[i] = fdp.ConsumeIntegralInRange<uint8_t>(0, 15); // endpoint_formats enum range
    }

    // Populate quant_mode with a fuzzed quant_method enum value
    unsigned int scb_quant_val = fdp.ConsumeIntegralInRange<unsigned int>(0, 20); // quant_method enum range
    scb->quant_mode = static_cast<quant_method>(scb_quant_val);

    // Fuzz errorval
    scb->errorval = fdp.ConsumeFloatingPoint<float>();

    // Populate the union based on block_type
    if (scb->block_type == SYM_BTYPE_CONST_F16 || scb->block_type == SYM_BTYPE_CONST_U16) {
        // Populate constant_color for constant color block types
        for (int i = 0; i < BLOCK_MAX_COMPONENTS; ++i) {
            scb->constant_color[i] = fdp.ConsumeIntegral<int>();
        }
    } else { // SYM_BTYPE_NONCONST or SYM_BTYPE_ERROR
        // Populate color_values for non-constant block types
         for (int i = 0; i < BLOCK_MAX_PARTITIONS; ++i) {
            for (int j = 0; j < 8; ++j) { // color_values is [BLOCK_MAX_PARTITIONS][8]
                 scb->color_values[i][j] = fdp.ConsumeIntegral<uint8_t>();
            }
        }
    }

    // Populate weights array with fuzzed data
    for (int i = 0; i < BLOCK_MAX_WEIGHTS; ++i) {
        scb->weights[i] = fdp.ConsumeIntegral<uint8_t>();
    }

    // Allocate output buffer for the physical compressed block (16 bytes) on the stack
    uint8_t pcb[16]; // ASTC physical block size is 16 bytes

    // Call the target function symbolic_to_physical
    // Only call if block_type is not SYM_BTYPE_ERROR, as the function asserts this.
    if (scb->block_type != SYM_BTYPE_ERROR) {
        symbolic_to_physical(*bsd, *scb, pcb);
    }

    // --- Fuzzing symbolic_compressed_block::get_color_quant_mode ---
    // Added call to an uncovered member function based on coverage report.
    // Fixed: Removed incorrect argument.
    scb->get_color_quant_mode();

    // --- Fuzzing get_packed_table ---
    // Added call to a partially covered function with fuzzed inputs to improve coverage.
    // Fixed: Removed call to undeclared function.

    // Free the heap-allocated block_size_descriptor
    aligned_free(bsd);

    return 0;
}