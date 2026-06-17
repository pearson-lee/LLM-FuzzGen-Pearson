import os
import argparse

def build_seeds():
    """
    Generates a list of (filename, seed_bytes) tuples for the libpcap fuzz target.

    The goal is to reach line 3149 in gen_prevlinkhdr_check (if (cstate->is_geneve))
    and then cross into the blocked side at line 3150 (return gen_geneve_ll_check(cstate);).

    Strategy:
    1.  Set `cstate->is_geneve` to true: This is achieved by including the keyword "geneve"
        in the filter string. The `pcap_parse` function will process "geneve", leading
        to a call to `gen_geneve`, which sets `cstate->is_geneve = 1`.
    2.  Ensure `gen_prevlinkhdr_check` is called: The observed runtime call site
        (gencode.c:3208 in gen_linktype) is guarded by `!cstate->is_geneve`, making it
        incompatible with our goal. We hypothesize that another call site,
        gencode.c:6713 (in gen_scode), which is guarded by `if (proto == Q_LINK)`,
        is active and compatible. To trigger this path, the filter string must
        include a "link" primitive (e.g., "ether host").

    Seed families:
    - F01_geneve_link_base: Basic "geneve" filter combined with a "link" primitive.
    - F02_geneve_link_variations: Variations of the link primitive.
    - F03_geneve_simple: Simpler 'geneve' filters to ensure the flag is set.
    """
    seeds = []

    # F01_geneve_link_base: Basic "geneve" filter with a compatible link-layer primitive
    # This seed aims to satisfy both conditions: set is_geneve and trigger a call
    # to gen_prevlinkhdr_check via a compatible path.
    seeds.append(
        (
            "F01_geneve_link_base_01.bpf",
            b"geneve and ether host 00:00:00:00:00:00"
        )
    )

    # F02_geneve_link_variations: Variations of the link primitive
    # Explore different link-layer filter types that might trigger the same call path.
    link_host_variants = [
        "src host 00:11:22:33:44:55",
        "dst host 00:11:22:33:44:55",
        "host 00:00:00:00:00:00",
        "broadcast",
        "multicast",
    ]

    for i, variant in enumerate(link_host_variants):
        seed_name = f"F02_geneve_link_variant_{i+1:02d}.bpf"
        filter_string = f"geneve and link {variant}"
        seeds.append((seed_name, filter_string.encode('ascii')))

    # F03_geneve_simple: Simple 'geneve' filters
    # These ensure the 'is_geneve' flag is set, even if the 'link' primitive path
    # is not the one that ultimately calls gen_prevlinkhdr_check.
    simple_geneve_filters = [
        "geneve",
        "geneve or ip",
        "geneve and tcp port 80",
    ]

    for i, filter_str in enumerate(simple_geneve_filters):
        seed_name = f"F03_geneve_simple_{i+1:02d}.bpf"
        seeds.append((seed_name, filter_str.encode('ascii')))

    return seeds

if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description="Generate libpcap filter seeds for gen_prevlinkhdr_check blocker."
    )
    parser.add_argument(
        "--output-dir",
        dest="output_dir",
        default=".",
        help="Directory to write generated seeds."
    )
    args = parser.parse_args()

    os.makedirs(args.output_dir, exist_ok=True)

    for filename, content in build_seeds():
        filepath = os.path.join(args.output_dir, filename)
        with open(filepath, "wb") as f:
            f.write(content)
        print(f"Generated seed: {filepath}")