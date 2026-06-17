import os
import argparse

def build_seeds():
    """
    Generates a list of (filename, payload) tuples for libpcap fuzzing.

    The goal is to reach the blocked side of `gen_prevlinkhdr_check` at line 3150
    (`return gen_geneve_ll_check(cstate);`). This requires `cstate->is_geneve` to be true.

    Strategy:
    1. The `cstate->is_geneve` flag is set to `1` when the filter string contains the keyword "geneve".
    2. The `gen_geneve` function (which sets `is_geneve`) directly calls `gen_geneve_ll_check`,
       which is the target blocked side. This is the most direct way to reach the blocked side.
    3. Seeds are BPF filter strings that include "geneve".
    """
    seeds = []

    # F01_geneve_base: Basic 'geneve' filter strings
    seeds.append(("F01_geneve_base_01.bpf", b"geneve"))
    seeds.append(("F01_geneve_base_02.bpf", b"geneve and host 1.2.3.4"))
    seeds.append(("F01_geneve_base_03.bpf", b"ip and geneve"))
    seeds.append(("F01_geneve_base_04.bpf", b"tcp port 6081 and geneve"))
    seeds.append(("F01_geneve_base_05.bpf", b"geneve or udp"))

    # F02_geneve_with_modifiers: 'geneve' with common BPF filter modifiers
    # These explore variations around the 'geneve' keyword.
    seeds.append(("F02_geneve_with_modifiers_01.bpf", b"src geneve"))
    seeds.append(("F02_geneve_with_modifiers_02.bpf", b"dst geneve"))
    seeds.append(("F02_geneve_with_modifiers_03.bpf", b"not geneve")) # This might not trigger the setter, but good for coverage
    seeds.append(("F02_geneve_with_modifiers_04.bpf", b"vlan and geneve"))
    seeds.append(("F02_geneve_with_modifiers_05.bpf", b"geneve proto 0x6558")) # Example for a specific protocol type

    return seeds


def main():
    parser = argparse.ArgumentParser(description="Generate libpcap fuzzing seeds.")
    parser.add_argument("--output-dir", required=True, help="Directory to write seed files.")
    args = parser.parse_args()

    os.makedirs(args.output_dir, exist_ok=True)

    for filename, payload in build_seeds():
        filepath = os.path.join(args.output_dir, filename)
        with open(filepath, "wb") as f:
            f.write(payload)
        print(f"Generated seed: {filepath}")


if __name__ == "__main__":
    main()