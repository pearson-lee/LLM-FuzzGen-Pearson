/* BLOCKER_STRATEGY_CONTRACT
required_state: The `root` node passed to `toml::v3::at_path` must be a `toml::value`, such that `root.is_value()` returns `true`.
state_constructor: A `toml::value` is instantiated directly with a primitive type (e.g., `toml::value<int64_t> val(...)`). This is in contrast to the previous fuzzer which parsed a TOML string into a `toml::table`, for which `is_value()` is false.
trigger_api: `toml::node::at_path()` is called on the `toml::value` object.
preserved_invariants: A `toml::value` object must be created and `at_path` must be called on it.
END_BLOCKER_STRATEGY_CONTRACT */

#include <fuzzer/FuzzedDataProvider.h>
#include "/src/tomlplusplus/include/toml++/toml.h"
#include <string>

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    FuzzedDataProvider fdp(data, size);

    std::string path_str = fdp.ConsumeRandomLengthString(50);
    toml::path path(path_str);

    // The blocker is hit when at_path is called on a value node.
    // The previous fuzzer called it on a table node, for which is_value() is false.
    // Here we create different types of value nodes and call at_path on them.
    // This will cause the `root.is_value()` check to be true and hit the blocker.
    int type = fdp.ConsumeIntegralInRange(0, 3);
    switch(type) {
        case 0: {
            toml::value<std::string> val(fdp.ConsumeRandomLengthString(100));
            val.at_path(path);
            break;
        }
        case 1: {
            toml::value<int64_t> val(fdp.ConsumeIntegral<int64_t>());
            val.at_path(path);
            break;
        }
        case 2: {
            toml::value<double> val(fdp.ConsumeFloatingPoint<double>());
            val.at_path(path);
            break;
        }
        case 3: {
            toml::value<bool> val(fdp.ConsumeBool());
            val.at_path(path);
            break;
        }
    }

    return 0;
}