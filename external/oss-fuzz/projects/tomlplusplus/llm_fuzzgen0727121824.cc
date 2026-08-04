#include <iostream>
#include <fstream>
#include <string>
#include <vector>
#include <unistd.h>
#include <fuzzer/FuzzedDataProvider.h>
#include "/src/tomlplusplus/include/toml++/toml.h"

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  FuzzedDataProvider fdp(data, size);

  // The TOML library can be fuzzed by parsing a string or a file.
  // We will do both in this fuzz target.
  if (fdp.ConsumeBool()) {
    /*
     * ANALYSIS: The function-level coverage report showed that toml::v3::ex::parse_file
     *           had 0% coverage.
     * IMPLEMENTATION: The following code block writes the fuzzer input to a
     *                 temporary file and then calls toml::parse_file to exercise
     *                 this uncovered function.
     */
    // Create a temporary file with a unique name.
    std::string path = std::string("/tmp/") + _FUZZ_TARGET_NAME + ".tmp";
    std::ofstream out(path);
    out << fdp.ConsumeRemainingBytesAsString();
    out.close();

    // Parse the temporary file.
    try {
      toml::parse_file(path);
    } catch (const toml::parse_error &) {
      // Ignore parsing errors, as expected.
    }

    // Clean up the temporary file.
    unlink(path.c_str());
  } else {
    std::string toml_string = fdp.ConsumeRemainingBytesAsString();
    /*
     * ANALYSIS: The function-level coverage report showed that
     *           toml::v3::impl::impl_ex::parser::parse_literal_string and
     *           toml::v3::impl::impl_ex::parser::parse_basic_string had low
     *           branch coverage, especially for multi-line strings.
     *           The functions toml::v3::impl::impl_ex::parser::parse_inf_or_nan and
     *           toml::v3::impl::impl_ex::parser::parse_hex_float had 0% coverage.
     * IMPLEMENTATION: The following code block generates various TOML constructs
     *                 to exercise these uncovered code paths.
     */
    if (fdp.ConsumeBool()) {
      // Add a multi-line literal string.
      toml_string += "\nkey = ''''\n";
      toml_string += fdp.ConsumeRandomLengthString(100);
      toml_string += "''''\n";
    }
    if (fdp.ConsumeBool()) {
      // Add a multi-line basic string.
      toml_string += "\nkey = \"\"\"\n";
      toml_string += fdp.ConsumeRandomLengthString(100);
      toml_string += "\\\n";
      toml_string += fdp.ConsumeRandomLengthString(100);
      toml_string += "\"\"\"\n";
    }
    if (fdp.ConsumeBool()) {
      // Add inf or nan.
      toml_string += "\nkey = ";
      if (fdp.ConsumeBool()) {
        toml_string += fdp.PickValueInArray({"+inf", "-inf", "inf"});
      } else {
        toml_string += fdp.PickValueInArray({"+nan", "-nan", "nan"});
      }
      toml_string += "\n";
    }
    if (fdp.ConsumeBool()) {
      // Add a hex float.
      toml_string += "\nkey = 0x";
      toml_string += fdp.ConsumeRandomLengthString(5);
      toml_string += ".";
      toml_string += fdp.ConsumeRandomLengthString(5);
      toml_string += "p-";
      toml_string += fdp.ConsumeIntegralInRange<int>(0, 10);
      toml_string += "\n";
    }

    try {
      toml::parse(toml_string);
    } catch (const toml::parse_error &) {
      // Ignore parsing errors, as expected.
    }
  }

  return 0;
}