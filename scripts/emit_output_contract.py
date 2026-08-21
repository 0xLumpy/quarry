#!/usr/bin/env python3
"""Collect or verify the internal C-OUTPUT-CONTRACT nine-case matrix."""
from __future__ import annotations

import argparse
import json
import shutil
from pathlib import Path

from quarry_recon import output_contract, release_evidence, runner, runner_native, store
from quarry_recon.runner_repository import RepositoryOutput


def _read(path: Path, label: str):
    try:
        return json.loads(path.read_bytes())
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise SystemExit(f"invalid {label} {path}: {exc}") from exc


def _write(path: Path, document: object) -> None:
    path.write_bytes(release_evidence.canonical_json_bytes(document) + b"\n")


def _case_argv(root: Path, run: store.Run, case: dict) -> list[str]:
    if case["executor"] == "gitleaks":
        report = run.dir.joinpath(
            "raw", "c-output-contract", case["id"], "gitleaks.json",
        )
        return [
            "gitleaks", "dir", "--no-banner", "--report-path", str(report),
            "--report-format", "json", str(root / case["fixture"]["path"]),
        ]
    argv = [str(root / "tests/helpers/c_output_fixture.py"), "--case", case["id"]]
    if case["fixture"] is not None:
        argv += [
            "--payload", str(root / case["fixture"]["path"]),
            "--encoding", case["fixture"]["encoding"],
        ]
    if case["stderr"] is not None:
        argv += ["--stderr", str(root / case["stderr"]["path"])]
    return argv


def _execute(root: Path, run: store.Run, case: dict) -> runner.RunResult:
    case_id = case["id"]
    argv = _case_argv(root, run, case)
    native_outputs = ()
    ok_codes = (0,)
    if case["executor"] == "gitleaks":
        native_outputs = (runner_native.RepositoryNativeOutput.file(
            4, "raw", "c-output-contract", case_id, "gitleaks.json",
        ),)
        ok_codes = (0, 1)
    return runner.run(
        "gitleaks" if case["executor"] == "gitleaks" else "c-output-python-helper",
        argv,
        repository=run,
        stdout=RepositoryOutput.publish(
            "raw", "c-output-contract", case_id, "stdout.bin",
        ),
        stderr=RepositoryOutput.publish(
            "raw", "c-output-contract", case_id, "stderr.bin",
        ),
        native_outputs=native_outputs,
        timeout=1 if case_id == "timeout" else 20,
        max_output_bytes=(
            output_contract.RETAINED_STREAM_CAP_BYTES if case_id == "truncated" else None
        ),
        ok_codes=ok_codes,
    )


def _collect(args: argparse.Namespace) -> int:
    root = args.candidate_root.resolve(strict=True)
    project_dir = args.project_dir.resolve()
    output_dir = args.output_dir.resolve()
    if project_dir.is_relative_to(root) or output_dir.is_relative_to(root):
        raise SystemExit("project and output directories must be outside the candidate tree")
    manifest_path = root / output_contract.FROZEN_FIXTURE_MANIFEST_PATH
    manifest = _read(manifest_path, "fixture manifest")
    output_contract.validate_fixture_manifest(manifest)
    git = shutil.which("git")
    if git is None:
        raise SystemExit("git is required")
    identity = release_evidence.collect_candidate_identity(
        root, release_evidence.RELEASE_SCOPE,
        git_executable=Path(git).resolve(),
        inputs=output_contract.fixture_identity_inputs(manifest),
    )
    run = store.Run.create(project_dir, "c-output.invalid", run_id=args.run_id)
    run.write_state("running")
    version = runner.run(
        "gitleaks", ["gitleaks", "version"], repository=run,
        stdout=RepositoryOutput.publish(
            "raw", "c-output-contract", "gitleaks-version", "stdout.bin",
        ),
        stderr=RepositoryOutput.publish(
            "raw", "c-output-contract", "gitleaks-version", "stderr.bin",
        ),
        timeout=20,
    )
    receipts = []
    for case in manifest["cases"]:
        result = _execute(root, run, case)
        receipts.append(output_contract.receipt_from_runner(
            fixture_manifest=manifest, case_id=case["id"], run=run,
            candidate_identity=identity, candidate_root=root, result=result,
            gitleaks_version_result=version,
        ))
    matrix = output_contract.collect_case_matrix(
        fixture_manifest=manifest, receipts=receipts,
    )
    try:
        output_dir.mkdir(parents=True, exist_ok=False)
    except FileExistsError as exc:
        raise SystemExit(f"output directory already exists: {output_dir}") from exc
    for index, receipt in enumerate(receipts):
        _write(output_dir / f"{index:02d}-{receipt['case_id']}.json", receipt)
    _write(output_dir / "case-matrix.json", matrix)
    summary = {
        "matrix_digest": release_evidence.canonical_digest(matrix),
        "output_dir": str(output_dir),
        "run_dir": str(run.dir),
        "cases": [
            {
                "id": row["id"], "status": row["effective_status"],
                "parser": row["parser"]["outcome"],
                "records": row["parser"]["records"],
            }
            for row in matrix["cases"]
        ],
    }
    print(json.dumps(summary, sort_keys=True))
    return 0


def _verify(args: argparse.Namespace) -> int:
    manifest = _read(args.fixture_manifest, "fixture manifest")
    matrix = _read(args.matrix, "case matrix")
    receipts = [_read(path, "raw receipt") for path in args.raw_receipt]
    output_contract.verify_case_matrix(
        matrix, fixture_manifest=manifest, receipts=receipts,
    )
    print(release_evidence.canonical_digest(matrix))
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)
    collect = commands.add_parser("collect")
    collect.add_argument("--candidate-root", type=Path, required=True)
    collect.add_argument("--project-dir", type=Path, required=True)
    collect.add_argument("--output-dir", type=Path, required=True)
    collect.add_argument("--run-id", default="v310-c-output-contract")
    collect.set_defaults(handler=_collect)
    verify = commands.add_parser("verify")
    verify.add_argument("--fixture-manifest", type=Path, required=True)
    verify.add_argument("--matrix", type=Path, required=True)
    verify.add_argument("--raw-receipt", type=Path, action="append", required=True)
    verify.set_defaults(handler=_verify)
    args = parser.parse_args(argv)
    try:
        return args.handler(args)
    except (output_contract.OutputContractError, release_evidence.EvidenceError) as exc:
        raise SystemExit(f"C-OUTPUT-CONTRACT failed: {exc}") from exc


if __name__ == "__main__":
    raise SystemExit(main())
