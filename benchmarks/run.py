"""Reproduce measurements: python -m benchmarks.run --iterations 2000 --warmup 100 --oss.

All work is local after optional dependencies are installed. Stored artifacts contain
counts and timings, never raw protected values, reference mappings, or sink transcripts.
"""

import argparse
import gc
import hashlib
import importlib.metadata
import json
import math
import platform
import statistics
import sys
from collections.abc import Callable
from datetime import datetime, timedelta, timezone
from pathlib import Path
from time import perf_counter_ns
from typing import TypedDict

from baseline.travel_support import Denied
from examples.travel_support.application import create_session
from examples.travel_support.fixtures import BOOKING_A, Sinks
from maskroute import Classification as C
from maskroute import MaskRouteError, ProtectedRef, PublicText, detect_best_effort

from .adapters import FACTORIES, Factory
from .detection_data import CASES, DICTIONARY, expected_spans
from .scenarios import booking_flow, evaluate, proposal

ROOT = Path(__file__).resolve().parents[1]


class Timing(TypedDict):
    samples: int
    p50_us: float
    p95_us: float


def measure(operation: Callable[[], object], iterations: int, warmup: int) -> Timing:
    for _ in range(warmup):
        operation()
    times: list[float] = []
    for _ in range(iterations):
        start = perf_counter_ns()
        operation()
        times.append((perf_counter_ns() - start) / 1000)
    times.sort()
    return {
        "samples": iterations,
        "p50_us": round(statistics.median(times), 3),
        "p95_us": round(times[math.ceil(0.95 * iterations) - 1], 3),
    }


def workflow_operation(factory: Factory) -> None:
    sinks = Sinks()
    app = factory(sinks)
    try:
        booking_flow(app, sinks)
    except (Denied, MaskRouteError):
        # The irreversible redaction control stops early; report labels that latency.
        pass
    finally:
        app.close()


def core_timings(iterations: int, warmup: int) -> dict[str, Timing]:
    sinks = Sinks()
    app = create_session(sinks)
    ref = app.protect_value(BOOKING_A, kind="BOOKING", classification=C.CONFIDENTIAL)
    app.send_model(sinks.model_send, [ref])
    call = proposal("lookup_booking", booking_ref=ref.token)
    result = app.execute_tool_call(call)
    app.send_tool_result(sinks.model_send, result)
    passenger = result.fields["passenger"]
    assert isinstance(passenger, ProtectedRef)

    def discard(payload: str) -> None:
        return None

    def lookup() -> None:
        app.execute_tool_call(call)
        sinks.internal.clear()

    counter = 0

    def new_value() -> None:
        nonlocal counter
        counter += 1
        app.protect_value(f"BK-MEASURE-{counter}", kind="BOOKING", classification=C.CONFIDENTIAL)

    operations: dict[str, Callable[[], object]] = {
        "unmediated_noop_provider": lambda: discard(ref.token),
        "new_value_protection": new_value,
        "stable_value_protection": lambda: app.protect_value(
            BOOKING_A, kind="BOOKING", classification=C.CONFIDENTIAL
        ),
        "mediated_model_send": lambda: app.send_model(discard, [PublicText("Lookup "), ref]),
        "authorized_lookup_and_output_filter": lookup,
        "protected_result_send": lambda: app.send_tool_result(discard, result),
        "authorized_plain_text_render": lambda: app.render_plain_text(
            passenger.token, allowed_kinds=frozenset({"PERSON"})
        ),
    }
    try:
        return {
            name: measure(operation, iterations, warmup) for name, operation in operations.items()
        }
    finally:
        app.close()


def detection_metrics() -> dict[str, dict[str, int | float]]:
    metrics: dict[str, dict[str, int | float]] = {}
    for language in ("en", "ru", "all"):
        tp = fp = fn = messages = 0
        for case in CASES:
            if language != "all" and case.language != language:
                continue
            messages += 1
            predicted = {
                (s.start, s.end, s.kind) for s in detect_best_effort(case.text, DICTIONARY)
            }
            expected = expected_spans(case)
            tp += len(predicted & expected)
            fp += len(predicted - expected)
            fn += len(expected - predicted)
        precision, recall = tp / (tp + fp), tp / (tp + fn)
        metrics[language] = {
            "messages": messages,
            "tp": tp,
            "fp": fp,
            "fn": fn,
            "precision": precision,
            "recall": recall,
            "f1": 2 * precision * recall / (precision + recall),
        }
    return metrics


def source_measurements() -> dict[str, object]:
    groups = {
        "sdk_core": list((ROOT / "src/maskroute").rglob("*.py")),
        "sdk_app_configuration": [ROOT / "examples/travel_support/application.py"],
        "handwritten_boundary": [ROOT / "baseline/travel_support.py"],
        "shared_fixtures": [ROOT / "examples/travel_support/fixtures.py"],
        "oss_additional_adapter": [ROOT / "benchmarks/oss.py"],
    }
    counts = {
        name: sum(
            bool(line.strip()) and not line.lstrip().startswith("#")
            for path in paths
            for line in path.read_text(encoding="utf-8").splitlines()
        )
        for name, paths in groups.items()
    }
    digest = hashlib.sha256()
    for folder in ("src", "baseline", "examples", "benchmarks", "tests"):
        for path in sorted((ROOT / folder).rglob("*.py")):
            digest.update(path.relative_to(ROOT).as_posix().encode())
            digest.update(path.read_text(encoding="utf-8").replace("\r\n", "\n").encode())
    return {
        "nonblank_noncomment_physical_lines_including_docstrings": counts,
        "python_sources_sha256": digest.hexdigest(),
    }


def build_report(
    data: dict[str, object],
    comparisons: dict[str, dict[str, object]],
    timings: dict[str, Timing],
    core: dict[str, Timing],
) -> str:
    lines = [
        "# MaskRoute v0.1 measured comparison",
        "",
        "Generated by `python -m benchmarks.run`; machine-readable results are in `results.json`.",
        "All numbers below are actual local observations. No network/model inference is timed.",
        "",
        "## Environment and method",
        "",
        "```json",
        json.dumps(data["environment"], indent=2),
        "```",
        "",
        "One serial process; `perf_counter_ns`; garbage collection left enabled. Each timing",
        "has its own warmup. p50 is the median; p95 is the nearest-rank 95th percentile.",
        "Random tokens remain random; scenario inputs and scoring are deterministic.",
        "Warm-cache results on this one machine do not predict provider/network latency.",
        "",
        "## Same synthetic tasks and threats",
        "",
        "Four valid tasks: booking lookup followed by each baggage topic, plus two independent",
        "public searches. Fifteen identical hostile cases per implementation. Every score reads",
        "actual captured model/search payloads and internal handler arguments. The full S01–S16",
        "SDK acceptance suite also tests surfaces and failures outside this comparison subset.",
        "",
        "| Implementation | Tasks / 4 | False denials | Forbidden disclosures | "
        "Roundtrips / 2 | Cross-scope / 1 | Rejected / 15 |",
        "|---|---:|---:|---:|---:|---:|---:|",
    ]
    for name, result in comparisons.items():
        lines.append(
            f"| {name} | {result['legitimate_task_success']} | {result['false_denials']} | "
            f"{result['forbidden_sink_disclosures']} | "
            f"{result['reference_roundtrip_correctness']} | "
            f"{result['cross_scope_rejections']} | {result['forbidden_paths_rejected']} |"
        )
    lines.extend(
        [
            "",
            "Disclosure count = (outbound payload, exact protected fixture value) pairs across",
            "all 19 cases, including setup messages. It is not a percentage or a semantic leakage",
            "estimate. Public search intent still reaches the search provider. Rejection requires",
            "a denial and no handler side effect, except the intentionally hostile return case",
            "which permits the authorized lookup but withholds its result. Per-case counts are",
            "retained in JSON. Unprotected retains business authorization and fixed query rules;",
            "blanket redaction gets to keep genuinely public airline names. Neither is sabotaged",
            "by adding an unrestricted tool. Missing reference isolation in these controls is",
            "reported as such; irreversible redaction can deny an attack by losing all utility.",
            "",
            "## Complete workflow latency",
            "",
            "Includes session creation, protection, model stubs, lookup, output filtering, public",
            "search and teardown. PIIGhost includes its synchronous-to-async runner; this is an",
            "integration measurement, not an intrinsic speed ranking between async libraries.",
            "",
            "| Implementation | p50 µs | p95 µs | Samples |",
            "|---|---:|---:|---:|",
        ]
    )
    for name, timing in timings.items():
        suffix = " (early denial; not comparable completion)" if name == "blanket_redaction" else ""
        lines.append(
            f"| {name}{suffix} | {timing['p50_us']} | {timing['p95_us']} | {timing['samples']} |"
        )
    lines.extend(
        [
            "",
            "## Core SDK operations",
            "",
            "Existing serial session; no-op model provider. Lookup includes the same in-memory",
            "tool and output protection. Audit allocation is included. Exact-value reuse is",
            "measured separately from new randomized registrations.",
            "",
            "| Operation | p50 µs | p95 µs | Samples |",
            "|---|---:|---:|---:|",
        ]
    )
    for name, timing in core.items():
        lines.append(f"| {name} | {timing['p50_us']} | {timing['p95_us']} | {timing['samples']} |")
    delta = {
        "p50_us": round(
            core["mediated_model_send"]["p50_us"] - core["unmediated_noop_provider"]["p50_us"], 3
        ),
        "p95_us": round(
            core["mediated_model_send"]["p95_us"] - core["unmediated_noop_provider"]["p95_us"], 3
        ),
    }
    lines.extend(
        [
            "",
            f"Mediated send minus no-op provider percentile differences: {delta}.",
            "These are differences of percentiles, not percentiles of paired differences.",
            "",
            "## Optional detection (not the explicit-protection invariant)",
            "",
            "```json",
            json.dumps(data["detection"], indent=2),
            "```",
            "",
            "Four known misses (unknown fictional names and obfuscated emails) actually remain",
            "in captured model input. Two phone-like public numeric strings are overmasked.",
            "Tiny hand-labeled RU/EN examples are illustrative, not population accuracy estimates.",
            "",
            "## Integration effort and decision",
            "",
            "```json",
            json.dumps(data["source_measurements"], indent=2),
            "```",
            "",
            "Counts are physical nonblank/noncomment lines including docstrings, not developer",
            "hours. Shared fixtures are counted separately. SDK configuration needs two tool",
            "schemas, two disclosure rules and a host authorizer. The handwritten boundary needs",
            "two explicit branches and the same business authorizer; it has no package dependency.",
            "The optional PIIGhost adapter adds the reported lines to that handwritten boundary.",
            "",
            "The handwritten baseline matches MaskRoute on this shared enforcement/utility gate",
            "with less total code and lower measured overhead. The SDK centralizes reusable",
            "schemas, explicit spans, output classifications, audit and display checks, but one",
            "vertical slice does not establish that this abstraction pays for itself.",
            "Decision: retain v0.1 as an engineering experiment; NO-GO on expanding product scope",
            "or claiming superiority without a second real integration showing reuse benefits.",
            "PIIGhost plus the same host checks also passes this gate; this is evidence of",
            "substantial overlap, not evidence that MaskRoute is novel or uniquely secure.",
            "",
            "See [architecture and limitations](../docs/ARCHITECTURE.md),",
            "[milestone history](../docs/IMPLEMENTATION_LOG.md), and",
            "[OSS comparison choices and sources](../docs/OSS_COMPARISON.md).",
            "",
        ]
    )
    return "\n".join(lines)


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--iterations", type=int, default=2000)
    parser.add_argument("--warmup", type=int, default=100)
    parser.add_argument("--oss", action="store_true")
    parser.add_argument("--machine", default=platform.processor())
    parser.add_argument("--output-dir", type=Path, default=ROOT / "benchmarks")
    args = parser.parse_args()
    if args.iterations < 20 or args.warmup < 0:
        parser.error("Use at least 20 iterations and a nonnegative warmup")
    factories = dict(FACTORIES)
    versions = {package: importlib.metadata.version(package) for package in ("maskroute",)}
    if args.oss:
        from .oss import PiighostTravel

        factories["piighost_with_host_checks"] = PiighostTravel
        versions["piighost"] = importlib.metadata.version("piighost")
    comparisons = {name: evaluate(factory) for name, factory in factories.items()}
    timings: dict[str, Timing] = {}
    for name, factory in factories.items():

        def operation(selected: Factory = factory) -> None:
            workflow_operation(selected)

        timings[name] = measure(operation, args.iterations, args.warmup)
    core = core_timings(args.iterations, args.warmup)
    data: dict[str, object] = {
        "environment": {
            "date_samara": str(datetime.now(timezone(timedelta(hours=4))).date()),
            "python": sys.version,
            "platform": platform.platform(),
            "machine": args.machine,
            "packages": versions,
            "iterations": args.iterations,
            "warmup": args.warmup,
            "gc_enabled": gc.isenabled(),
        },
        "comparisons": comparisons,
        "workflow_latency": timings,
        "core_latency": core,
        "detection": detection_metrics(),
        "source_measurements": source_measurements(),
    }
    args.output_dir.mkdir(parents=True, exist_ok=True)
    (args.output_dir / "results.json").write_text(
        json.dumps(data, indent=2) + "\n", encoding="utf-8"
    )
    (args.output_dir / "report.md").write_text(
        build_report(data, comparisons, timings, core), encoding="utf-8"
    )
    print(json.dumps({"reports_written": True, "implementations": list(factories)}, indent=2))


if __name__ == "__main__":
    main()
