/* BLOCKER_STRATEGY_CONTRACT
required_state: A `toml::value<long>` must have the `value_flags::format_as_octal` flag set, and it must be formatted by a `toml_formatter` whose `int_format_mask_` does not have the `format_flags::allow_octal_integers` bit set.
state_constructor: A `toml::value<int64_t>` is created and its flags are explicitly set to `toml::value_flags::format_as_octal` using the `.flags()` method. A `toml_formatter` is then constructed, passing a `toml::format_flags` argument that omits `toml::format_flags::allow_octal_integers`.
trigger_api: Streaming the `toml_formatter` object to a `std::stringstream` (`ss << formatter;`), which calls the formatter's `print()` method, eventually dispatching to `toml::v3::impl::formatter::print(toml::v3::value<long> const&)`.
preserved_invariants: The fuzzer creates objects and calls APIs directly to set up the required state. There are no complex invariants from a parsed structure to preserve.
END_BLOCKER_STRATEGY_CONTRACT */

#include "/src/tomlplusplus/toml.hpp"
#include <fuzzer/FuzzedDataProvider.h>
#include <sstream>

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  FuzzedDataProvider fdp(data, size);

  // Create a long value from fuzzer input.
  int64_t int_val = fdp.ConsumeIntegral<int64_t>();

  // Create a toml::value and explicitly set its format flag to octal.
  // This is the first part of the required state for the blocker.
  toml::value<int64_t> val(int_val);
  val.flags(toml::value_flags::format_as_octal);

  // Define format flags for the formatter that disable octal integer formatting.
  // By default, format_flags::defaults includes allow_octal_integers. We must
  // construct a mask that excludes it to create the required state.
  toml::format_flags formatter_flags = toml::format_flags::allow_binary_integers | toml::format_flags::allow_hexadecimal_integers;

  // Create a formatter with the value as the source and the custom flags.
  // The formatter's internal int_format_mask_ will not have the allow_octal_integers bit set.
  // This is the second part of the required state.
  toml::toml_formatter formatter{ val, formatter_flags };

  // Stream the formatter to trigger the print() method.
  // This will call formatter::print(const value<int64_t>&). Inside this function,
  // the code checks if the value has the format_as_octal flag (it does) and then
  // checks if the formatter allows octal printing (it does not). This makes the
  // 'if' condition false, hitting the target 'break;' statement.
  std::stringstream ss;
  ss << formatter;

  return 0;
}
