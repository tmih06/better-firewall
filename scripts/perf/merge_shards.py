#!/usr/bin/env python3
"""Merge complete performance artifacts split by rule cardinality."""

import argparse
import json
import os
import shutil
import sys
from typing import Any, Dict, List, Tuple

import compare


def _read_json(path: str) -> Any:
    with open(path, "r", encoding="utf-8") as source:
        return json.load(source)


def _cardinalities(metadata: Dict[str, Any], shard_name: str) -> List[int]:
    value = metadata.get("cardinalities")
    tokens = value.split() if isinstance(value, str) else value if isinstance(value, list) else []
    try:
        cards = [int(token) for token in tokens]
    except (TypeError, ValueError) as error:
        raise ValueError(f"Invalid cardinalities in shard '{shard_name}'") from error
    if len(cards) != 1 or cards[0] <= 0:
        raise ValueError(f"Shard '{shard_name}' must contain exactly one positive cardinality")
    return cards


def _load_shard(shard_dir: str) -> Tuple[int, Dict[str, Any], Dict[str, Any], Dict[str, Any]]:
    shard_name = os.path.basename(shard_dir)
    document = _read_json(os.path.join(shard_dir, "metadata.json"))
    if not isinstance(document, dict) or not isinstance(document.get("metadata"), dict):
        raise ValueError(f"Invalid metadata in shard '{shard_name}'")
    metadata = document["metadata"]
    controls = document.get("controls")
    if not isinstance(controls, dict):
        raise ValueError(f"Missing controls in shard '{shard_name}'")
    cardinality = _cardinalities(metadata, shard_name)[0]

    apply_times = _read_json(os.path.join(shard_dir, "apply_times.json"))
    parsed_times = compare.load_apply_times_from_dict(apply_times)
    expected_card = str(cardinality)
    if any(set(parsed_times.get(engine, {})) != {expected_card} for engine in compare.ENGINES):
        raise ValueError(f"Apply times in shard '{shard_name}' do not match cardinality {cardinality}")

    scenarios = compare.load_results_directory(shard_dir)
    violations = compare.validate_complete_matrix(scenarios, metadata, controls, parsed_times, True)
    if violations:
        raise ValueError(f"Invalid performance shard '{shard_name}': {'; '.join(violations)}")
    return cardinality, metadata, controls, apply_times


def merge_shards(
    shards_dir: str, output_dir: str, expected_cardinalities: List[int] | None = None
) -> None:
    """Merge validated one-cardinality shards into a complete comparison input."""
    if not os.path.isdir(shards_dir):
        raise FileNotFoundError(f"Shard directory not found: {shards_dir}")
    shard_dirs = sorted(
        (os.path.join(shards_dir, entry) for entry in os.listdir(shards_dir)
         if os.path.isdir(os.path.join(shards_dir, entry))),
        key=lambda path: _cardinalities(
            _read_json(os.path.join(path, "metadata.json"))["metadata"], os.path.basename(path)
        )[0],
    )
    if not shard_dirs:
        raise ValueError(f"No performance shards found in {shards_dir}")

    scenario_sources: Dict[str, str] = {}
    apply_times: Dict[str, Dict[str, Any]] = {engine: {} for engine in compare.ENGINES}
    cardinalities: List[int] = []
    metadata_base: Dict[str, Any] | None = None
    kernel_values: set[str] = set()
    arch_values: set[str] = set()
    controls_base: Dict[str, Any] | None = None
    rulesets_verified = 0
    varying_metadata = {"cardinalities", "kernel", "arch"}

    for shard_dir in shard_dirs:
        cardinality, metadata, controls, shard_times = _load_shard(shard_dir)
        if cardinality in cardinalities:
            raise ValueError(f"Duplicate performance shard for cardinality {cardinality}")
        cardinalities.append(cardinality)

        comparable_metadata = {key: value for key, value in metadata.items() if key not in varying_metadata}
        if metadata_base is None:
            metadata_base = comparable_metadata
        elif comparable_metadata != metadata_base:
            raise ValueError(f"Benchmark metadata differs in shard '{os.path.basename(shard_dir)}'")
        kernel_values.add(str(metadata.get("kernel", "unknown")))
        arch_values.add(str(metadata.get("arch", "unknown")))

        control_flags = {key: value for key, value in controls.items() if key != "benchmark_rulesets_verified"}
        if controls_base is None:
            controls_base = control_flags
        elif control_flags != controls_base:
            raise ValueError(f"Security control results differ in shard '{os.path.basename(shard_dir)}'")
        rulesets_verified += controls["benchmark_rulesets_verified"]

        for engine in compare.ENGINES:
            apply_times[engine][str(cardinality)] = shard_times[engine][str(cardinality)]

        for filename in os.listdir(shard_dir):
            if not filename.endswith(".json") or filename in {"metadata.json", "apply_times.json"}:
                continue
            stem = filename[:-5]
            match = compare.SCENARIO_FILENAME.fullmatch(stem)
            if match is None:
                raise ValueError(f"Unrecognized result file in shard '{os.path.basename(shard_dir)}': {filename}")
            if int(match.group(2)) != cardinality:
                raise ValueError(f"Scenario '{filename}' is in the wrong cardinality shard")
            if stem in scenario_sources:
                raise ValueError(f"Duplicate scenario '{stem}' across performance shards")
            scenario_sources[stem] = os.path.join(shard_dir, filename)

    if metadata_base is None or controls_base is None:
        raise ValueError("No valid performance shards found")
    if expected_cardinalities is not None:
        if (
            any(type(cardinality) is not int or cardinality <= 0 for cardinality in expected_cardinalities)
            or len(set(expected_cardinalities)) != len(expected_cardinalities)
            or cardinalities != sorted(expected_cardinalities)
        ):
            raise ValueError(
                f"Shard set has cardinalities {cardinalities}; expected cardinalities "
                f"{sorted(expected_cardinalities)}"
            )

    merged_metadata = dict(metadata_base)
    merged_metadata["cardinalities"] = " ".join(str(cardinality) for cardinality in cardinalities)
    merged_metadata["kernel"] = ", ".join(sorted(kernel_values))
    merged_metadata["arch"] = ", ".join(sorted(arch_values))
    merged_controls = dict(controls_base)
    merged_controls["benchmark_rulesets_verified"] = rulesets_verified

    if os.path.exists(output_dir):
        if not os.path.isdir(output_dir) or os.listdir(output_dir):
            raise ValueError(f"Output directory must be empty: {output_dir}")
    else:
        os.makedirs(output_dir)

    for stem, source_path in scenario_sources.items():
        shutil.copyfile(source_path, os.path.join(output_dir, f"{stem}.json"))
    with open(os.path.join(output_dir, "apply_times.json"), "w", encoding="utf-8") as output:
        json.dump(apply_times, output, indent=2)
        output.write("\n")
    with open(os.path.join(output_dir, "metadata.json"), "w", encoding="utf-8") as output:
        json.dump({"metadata": merged_metadata, "controls": merged_controls}, output, indent=2)
        output.write("\n")


def main(argv: List[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--shards-dir", required=True, help="Directory containing one subdirectory per shard")
    parser.add_argument("--output-dir", required=True, help="Empty directory for merged comparison inputs")
    parser.add_argument(
        "--expected-cardinalities",
        type=int,
        nargs="+",
        required=True,
        help="Complete rule-cardinality matrix expected across all shards",
    )
    args = parser.parse_args(sys.argv[1:] if argv is None else argv)
    try:
        merge_shards(args.shards_dir, args.output_dir, args.expected_cardinalities)
    except (OSError, ValueError, KeyError, json.JSONDecodeError) as error:
        print(f"FATAL: performance shard merge failed: {error}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
