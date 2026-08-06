/* BLOCKER_STRATEGY_CONTRACT
required_state: The `root` node passed to `toml::v3::at_path` must be a `toml::value` (e.g., string, integer, float, boolean, date, time), for which `is_value()` returns `true`.
state_constructor: A `toml::table` is created programmatically, and a key-value pair is inserted. The value part of this pair, a `toml::value` node, is retrieved using `table::get()`.
trigger_api: The free function `toml::at_path(toml::node&, const toml::path&)` is called with the retrieved `toml::value` node as the first argument.
preserved_invariants: The call to `toml::at_path` must be on a `toml::node` that is a `toml::value`, not a `toml::table` or `toml::array`.
END_BLOCKER_STRATEGY_CONTRACT */

#include <fuzzer/FuzzedDataProvider.h>
#include "/src/tomlplusplus/include/toml++/toml.h"
#include <string>

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    FuzzedDataProvider fdp(data, size);

    // The blocker `if (root.is_value())` requires the root node to be a TOML
    // value (string, int, etc.), not a container like a table or array.
    // The previous fuzzer called `at_path` on a `toml::table`, for which
    // `is_value()` returns false.
    // This fuzzer constructs a table, inserts a value, retrieves the value
    // node, and then calls `at_path` on that node to satisfy the predicate.

    toml::table tbl;
    std::string key = fdp.ConsumeRandomLengthString(16);
    // Ensure key is not empty for retrieval.
    if (key.empty()) {
        return 0;
    }

    // Insert a value of a random TOML-supported type.
    // All of these will create a `toml::value` node, for which `is_value()` is true.
    int type = fdp.ConsumeIntegralInRange(0, 7);
    switch (type) {
        case 0:
            tbl.insert(key, fdp.ConsumeRandomLengthString(100));
            break;
        case 1:
            tbl.insert(key, fdp.ConsumeIntegral<int64_t>());
            break;
        case 2:
            tbl.insert(key, fdp.ConsumeFloatingPoint<double>());
            break;
        case 3:
            tbl.insert(key, fdp.ConsumeBool());
            break;
        case 4:
            tbl.insert(key, toml::date{
                fdp.ConsumeIntegral<uint16_t>(),
                fdp.ConsumeIntegralInRange<uint8_t>(1, 12),
                fdp.ConsumeIntegralInRange<uint8_t>(1, 28) // Use 28 to be safe for all months
            });
            break;
        case 5:
            tbl.insert(key, toml::time{
                fdp.ConsumeIntegralInRange<uint8_t>(0, 23),
                fdp.ConsumeIntegralInRange<uint8_t>(0, 59),
                fdp.ConsumeIntegralInRange<uint8_t>(0, 59),
                fdp.ConsumeIntegral<uint32_t>()
            });
            break;
        case 6:
            tbl.insert(key, toml::date_time{
                toml::date{
                    fdp.ConsumeIntegral<uint16_t>(),
                    fdp.ConsumeIntegralInRange<uint8_t>(1, 12),
                    fdp.ConsumeIntegralInRange<uint8_t>(1, 28)
                },
                toml::time{
                    fdp.ConsumeIntegralInRange<uint8_t>(0, 23),
                    fdp.ConsumeIntegralInRange<uint8_t>(0, 59),
                    fdp.ConsumeIntegralInRange<uint8_t>(0, 59)
                }
            });
            break;
        case 7:
            tbl.insert(key, toml::date_time{
                toml::date{
                    fdp.ConsumeIntegral<uint16_t>(),
                    fdp.ConsumeIntegralInRange<uint8_t>(1, 12),
                    fdp.ConsumeIntegralInRange<uint8_t>(1, 28)
                },
                toml::time{
                    fdp.ConsumeIntegralInRange<uint8_t>(0, 23),
                    fdp.ConsumeIntegralInRange<uint8_t>(0, 59),
                    fdp.ConsumeIntegralInRange<uint8_t>(0, 59)
                },
                toml::time_offset{
                    fdp.ConsumeIntegralInRange<int8_t>(-23, 23),
                    fdp.ConsumeIntegralInRange<int8_t>(0, 59)
                }
            });
            break;
    }

    // Retrieve the node we just inserted. It will be a `toml::value`.
    if (toml::node* value_node = tbl.get(key)) {
        // Create a path object from fuzzed data.
        toml::path path(fdp.ConsumeRemainingBytesAsString());

        // Call `at_path` with the value node as the root.
        // This should trigger the `if (root.is_value())` branch.
        (void)toml::at_path(*value_node, path);
    }

    return 0;
}