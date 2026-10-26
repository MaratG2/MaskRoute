"""Measure the frozen second integration: python -m benchmarks.reuse."""

import argparse
import ast
import hashlib
import json
import platform
from dataclasses import asdict
from pathlib import Path

from .project_scenarios import FACTORIES, Factory, Trial, evaluate, trial
from .run import Timing, measure

ROOT = Path(__file__).resolve().parents[1]


def code_metrics(path: Path) -> dict[str, object]:
    text = path.read_text(encoding="utf-8")
    tree = ast.parse(text)
    branch_nodes = (ast.If, ast.For, ast.While, ast.Try, ast.IfExp, ast.comprehension)
    return {
        "file": path.relative_to(ROOT).as_posix(),
        "nonblank_noncomment_lines_including_docstrings": sum(
            bool(line.strip()) and not line.lstrip().startswith("#") for line in text.splitlines()
        ),
        "function_definitions": sum(isinstance(n, ast.FunctionDef) for n in ast.walk(tree)),
        "branch_and_loop_nodes": sum(isinstance(n, branch_nodes) for n in ast.walk(tree)),
        "sha256": hashlib.sha256(text.encode()).hexdigest(),
    }


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--iterations", type=int, default=1000)
    parser.add_argument("--warmup", type=int, default=50)
    parser.add_argument("--output-dir", type=Path, default=ROOT / "benchmarks/project_management")
    args = parser.parse_args()
    if args.iterations < 20 or args.warmup < 0:
        parser.error("Use at least 20 iterations and nonnegative warmup")
    comparisons = {name: evaluate(factory) for name, factory in FACTORIES.items()}
    timings: dict[str, Timing] = {}
    for name, factory in FACTORIES.items():

        def operation(selected: Factory = factory) -> Trial:
            return trial(selected, "maintainer_notes", valid=True)

        timings[name] = measure(operation, args.iterations, args.warmup)
    metrics = {
        name: code_metrics(ROOT / path)
        for name, path in {
            "sdk_host_wiring": "examples/project_management/application.py",
            "handwritten_boundary": "baseline/project_management.py",
            "shared_domain_authorization_and_sinks": "examples/project_management/fixtures.py",
            "benchmark_adapters_and_scenarios": "benchmarks/project_scenarios.py",
        }.items()
    }
    baseline = json.loads((ROOT / "docs/validation/sdk_baseline_hashes.json").read_text())
    changes = [
        name
        for name, digest in baseline.items()
        if hashlib.sha256((ROOT / "src" / name).read_text(encoding="utf-8").encode()).hexdigest()
        != digest
    ]
    data = {
        "python": platform.python_version(),
        "platform": platform.platform(),
        "iterations": args.iterations,
        "warmup": args.warmup,
        "comparisons": comparisons,
        "timing_common_successful_workflow": timings,
        "code_metrics": metrics,
        "sdk_files_changed_since_validation_started": changes,
        "known_sdk_limitation": asdict(
            trial(FACTORIES["maskroute"], "multi_issue_shared_contact", valid=True)
        ),
    }
    lines = [
        "# Project-management reuse evaluation",
        "",
        "Generated from actual recording-sink trials by `python -m benchmarks.reuse`.",
        "This second integration freezes SDK features and uses only existing public APIs.",
        "",
        "| Implementation | Valid tasks / 4 | False denials | "
        "Rejected attacks / 19 | Disclosures |",
        "|---|---:|---:|---:|---:|",
    ]
    for name, row in comparisons.items():
        lines.append(
            f"| {name} | {row['legitimate_task_success']} | {row['false_denials']} | "
            f"{row['forbidden_paths_rejected']} | {row['forbidden_sink_disclosures']} |"
        )
    lines += [
        "",
        "Valid workflows: reviewer reads an issue and researches a public dependency;",
        "maintainer also reads restricted notes; member uses a different active project; and",
        "maintainer reads two authorized issues sharing one private contact before research.",
        "Attacks cover project/issue relationship, role and issue ACL, multiple reference fields,",
        "issuance/scope/lifecycle, malformed schema, output injection and fixed research terms.",
        "Disclosures count exact protected-value/outbound-payload pairs. Neither test population",
        "nor zero observed disclosures is a general confidentiality guarantee.",
        "",
        "## Confirmed reuse limitation",
        "",
        "The two-issue task fails in the SDK with METADATA_CONFLICT. Its identity key is exact",
        "(value, kind, classification), while each entry holds only one authorization resource.",
        "The same email legitimately belongs to two authorized issue results; the second output",
        "is withheld before the model send. The handwritten code includes resource in identity.",
        "This is a safe false denial, not an observed leak. The positive requirement remains a",
        "strict expected-failure test. No resource permission was broadened to force success.",
        "",
        "## Integration effort",
        "",
        "```json",
        json.dumps(metrics, indent=2),
        "```",
        "",
        "The SDK host wiring registers 3 tool schemas, 4 disclosure rules and 6 output fields.",
        "The handwritten implementation has 3 explicit dispatch branches plus its own reference,",
        "issuance and output-validation code. Domain authorization is shared and excluded from",
        "both wiring counts. The larger benchmark adapter file is test infrastructure, not an",
        "application dependency. Counts include docstrings and are not measured developer hours.",
        "Branch/loop AST counts are descriptive, not calibrated complexity or risk scores.",
        "",
        "## Developer experience observations",
        "",
        "The same SDK configures new kinds, multiple private input fields and stricter notes",
        "authorization without a travel-specific code path. That is evidence of mechanical reuse.",
        "It centralizes otherwise duplicated schema, issuance and output protection checks.",
        "Host policy still needs to bind project/issue relationships using trusted context; the",
        "SDK does not infer relational authorization. Flat output schemas are straightforward",
        "for the fixture but do not support real issue lists or arbitrary research prose.",
        "The single-resource identity constraint blocks a realistic valid multi-issue flow.",
        "These are implementation observations by the integration author, not an independent",
        "developer usability study. No onboarding time or developer satisfaction was measured.",
        "",
        "## Descriptive timing",
        "",
        "Only the common successful maintainer workflow is timed, including scenario checks,",
        "local stubs and teardown. No timing optimization or speed marketing claim was made.",
        "```json",
        json.dumps(
            {
                "python": data["python"],
                "platform": data["platform"],
                "samples": args.iterations,
                "warmup": args.warmup,
                "timings": timings,
            },
            indent=2,
        ),
        "```",
        "",
        "## Decision",
        "",
        "Prefer an engineering case study with experimental source over positioning this as a",
        "maintained reusable security SDK. Configuration reuse is real, but the frozen SDK",
        "does not complete all valid second-application tasks and has not demonstrated enough",
        "benefit to justify its general maintenance/security burden. No publication is authorized",
        "by this recommendation. Independent review and hosted CI status are recorded separately",
        "in `docs/VALIDATION_REPORT.md`; neither is implied by passing local tests.",
        "",
        f"SDK files changed during validation (audit separately): {changes}",
        "",
    ]
    args.output_dir.mkdir(parents=True, exist_ok=True)
    (args.output_dir / "results.json").write_text(
        json.dumps(data, indent=2) + "\n", encoding="utf-8"
    )
    (args.output_dir / "report.md").write_text("\n".join(lines), encoding="utf-8")
    print(
        json.dumps(
            {
                "report_written": True,
                "task_success": {
                    name: row["legitimate_task_success"] for name, row in comparisons.items()
                },
            },
            indent=2,
        )
    )


if __name__ == "__main__":
    main()
