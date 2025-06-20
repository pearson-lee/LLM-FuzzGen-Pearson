#include <cstddef>
#include <cstdint>
#include <vector>
#include <fuzzer/FuzzedDataProvider.h>
#include <memory> // Required for std::unique_ptr and std::make_unique

// Include necessary astc-encoder headers with project-relative paths.
// These headers define the structs and functions we will be fuzzing.
#include "/src/astc-encoder/Source/astcenc_internal.h"
#include "/src/astc-encoder/Source/astcenc_mathlib.h" // Included as it contains some low-coverage functions and utilities

// DW_TAG_enumeration_typequant_method is an alias for astcenc_quant_method
// defined in astcenc_internal.h. Using the alias directly as per API info.
// Correcting the alias based on the actual enum name 'quant_method' in the header.
using DW_TAG_enumeration_typequant_method = quant_method;

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size) {
  FuzzedDataProvider fdp(Data, Size);

  // --- Fuzzing symbolic_to_physical (0.0% coverage) ---
  // This function converts a symbolic block representation back to the physical compressed bytes.
  // It requires a block_size_descriptor and a symbolic_compressed_block.
  // We will generate these using other functions or fuzzer data.

  // Generate block dimensions within valid ranges for 2D or 3D ASTC blocks.
  unsigned int xdim, ydim, zdim;
  bool is_2d = fdp.ConsumeBool();

  if (is_2d) {
    xdim = fdp.ConsumeIntegralInRange<unsigned int>(4, 12);
    ydim = fdp.ConsumeIntegralInRange<unsigned int>(4, 12);
    zdim = 1; // For 2D blocks, zdim is 1
  } else {
    xdim = fdp.ConsumeIntegralInRange<unsigned int>(3, 6);
    ydim = fdp.ConsumeIntegralInRange<unsigned int>(3, 6);
    zdim = fdp.ConsumeIntegralInRange<unsigned int>(3, 6);
  }

  // Check if the generated block size is legal before proceeding.
  bool is_legal = false;
  if (is_2d) {
      is_legal = is_legal_2d_block_size(xdim, ydim);
  } else {
      is_legal = is_legal_3d_block_size(xdim, ydim, zdim);
  }

  if (!is_legal) {
      // If the block size is not legal, skip fuzzing functions that depend on a valid bsd.
      // Continue with other independent fuzzing targets if any.
      // For now, just return as the rest of the code depends on a valid bsd.
      return 0;
  }

  // Allocate block_size_descriptor and symbolic_compressed_block on the heap using std::unique_ptr.
  // This is to avoid stack overflow issues with large structs.
  auto bsd = std::make_unique<block_size_descriptor>();
  auto scb = std::make_unique<symbolic_compressed_block>();

  // Construct block_size_descriptor using init_block_size_descriptor.
  bool can_omit_modes = fdp.ConsumeBool();
  unsigned int partition_count_cutoff = fdp.ConsumeIntegralInRange<unsigned int>(0, 4); // Max 4 partitions
  float mode_cutoff = fdp.ConsumeFloatingPoint<float>();

  init_block_size_descriptor(xdim, ydim, zdim, can_omit_modes, partition_count_cutoff, mode_cutoff, *bsd);


  // Generate input data for physical_to_symbolic.
  // We use physical_to_symbolic (which has 100% coverage) as a helper to generate a
  // potentially valid symbolic_compressed_block for symbolic_to_physical.
  // Assuming RGBA 8-bit input (4 bytes per texel).
  size_t physical_input_buffer_size = xdim * ydim * zdim * 4;
  std::vector<uint8_t> physical_input_buffer = fdp.ConsumeBytes<uint8_t>(physical_input_buffer_size);

  // Ensure the buffer has the required size, even if fuzzer data is small.
  // Pad with zeros if necessary. std::vector handles deallocation.
  if (physical_input_buffer.size() < physical_input_buffer_size) {
      physical_input_buffer.resize(physical_input_buffer_size, 0);
  }

  // Create a symbolic_compressed_block struct on the heap using std::unique_ptr.
  // physical_to_symbolic will populate this struct based on the input pixel data.
  // auto scb = std::make_unique<symbolic_compressed_block>(); // Already declared at the beginning

  // Call physical_to_symbolic to get a populated symbolic_compressed_block.
  physical_to_symbolic(*bsd, physical_input_buffer.data(), *scb);

  // Allocate output buffer for symbolic_to_physical.
  // ASTC compressed blocks are always 16 bytes. std::vector handles deallocation.
  std::vector<uint8_t> physical_output_buffer(16);

  // Call the target function symbolic_to_physical (0.0% coverage) only if the block type is not an error.
  if (scb->block_type != SYM_BTYPE_ERROR) {
      symbolic_to_physical(*bsd, *scb, physical_output_buffer.data());
  }


  // --- Fuzzing encode_ise (0.0% coverage) ---
  // This function encodes an integer sequence.

  // Generate inputs for encode_ise.
  // DW_TAG_enumeration_typequant_method is an alias for astcenc_quant_method.
  // Generate a value within the valid enum range. The enum quant_method has 21 values (0-20).
  DW_TAG_enumeration_typequant_method quant_method = static_cast<DW_TAG_enumeration_typequant_method>(fdp.ConsumeIntegralInRange<int>(0, 20));
  // Limit element count to avoid excessive memory allocations and ensure it's > 0 for encode_ise.
  unsigned int element_count = fdp.ConsumeIntegralInRange<unsigned int>(1, 1024); // Start from 1 to avoid assert in encode_ise
  unsigned int stride = fdp.ConsumeIntegral<unsigned int>();

  // Allocate input buffer for encode_ise. std::vector handles deallocation.
  std::vector<uint8_t> ise_input_buffer = fdp.ConsumeBytes<uint8_t>(element_count);
  // Ensure the buffer has the required size.
  if (ise_input_buffer.size() < element_count) {
      ise_input_buffer.resize(ise_input_buffer.size(), 0); // Pad with existing data, then zeros
      ise_input_buffer.resize(element_count, 0); // Pad with zeros if needed
  }

  // Allocate output buffer for encode_ise. std::vector handles deallocation.
  // Estimate output size. A safe upper bound is needed as the exact size depends on input data and quant method.
  // Use a portion of remaining fuzzer data size, with a minimum and maximum cap.
  size_t ise_output_buffer_size = fdp.remaining_bytes() / 2;
  if (ise_output_buffer_size < element_count) ise_output_buffer_size = element_count * 2; // Ensure minimum size based on input
  if (ise_output_buffer_size > 4096) ise_output_buffer_size = 4096; // Cap size to prevent excessive allocation
  std::vector<uint8_t> ise_output_buffer(ise_output_buffer_size);

  // Call the target function encode_ise (0.0% coverage).
  encode_ise(quant_method, element_count, ise_input_buffer.data(), ise_output_buffer.data(), stride);


  // --- Fuzzing other low-coverage functions ---

  // Removed call to get_packed_table as it appears to be an internal function not declared in public headers.
  // int p_table_arg1 = fdp.ConsumeIntegral<int>();
  // int p_table_arg2 = fdp.ConsumeIntegral<int>();
  // get_packed_table(p_table_arg1, p_table_arg2); // Returns const pointer, no memory to manage.

  // Call get_ise_sequence_bitcount (66.66% coverage).
  unsigned int ise_bitcount_arg1 = fdp.ConsumeIntegral<unsigned int>();
  DW_TAG_enumeration_typequant_method ise_bitcount_arg2 = static_cast<DW_TAG_enumeration_typequant_method>(fdp.ConsumeIntegralInRange<int>(0, 20)); // Use 20 for max enum value
  get_ise_sequence_bitcount(ise_bitcount_arg1, ise_bitcount_arg2); // Returns unsigned int.

  // Call get_quant_level (96.29% coverage).
  DW_TAG_enumeration_typequant_method quant_level_arg = static_cast<DW_TAG_enumeration_typequant_method>(fdp.ConsumeIntegralInRange<int>(0, 20)); // Use 20 for max enum value
  get_quant_level(quant_level_arg); // Returns unsigned int.

  // Memory management: std::vector and heap allocated structs via std::unique_ptr handle memory automatically.
  // No explicit free or delete calls are needed, ensuring memory safety.

  return 0; // Fuzzer succeeded
}