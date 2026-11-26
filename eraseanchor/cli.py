"""Command line interface: plan, replay and verify local JSON artifacts."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any

from . import REPLAY_SCHEMA_VERSION, VERIFY_SCHEMA_VERSION, __version__
from .engine import (
    commitment_event,
    plan_events,
    replay_all_boundaries,
    resume_existing_journal,
    simulate_boundary,
    verify_actions,
)
from .journal import Journal
from .model import CaseError, load_json_file, normalize_case
from .planner import plan_case


def _print_json(doc: Any, out: str | Path | None = None) -> None:
    text = json.dumps(doc, ensure_ascii=False, indent=2, sort_keys=False)
    if out:
        path = Path(out)
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(text + "\n", encoding="utf-8")
    print(text)


def _load_case(path: str | Path) -> dict[str, Any]:
    return normalize_case(load_json_file(path))


def _extract_action_ids(plan_doc: Any) -> list[str] | None:
    if plan_doc is None:
        return None
    if isinstance(plan_doc, list):
        return [str(x) for x in plan_doc]
    if not isinstance(plan_doc, dict):
        raise CaseError("--plan must be a plan JSON object")
    if plan_doc.get("optimal"):
        return list(plan_doc["optimal"]["action_ids"])
    if plan_doc.get("action_ids"):
        return list(plan_doc["action_ids"])
    plans = plan_doc.get("plans")
    if plans:
        return list(plans[0]["action_ids"])
    return None


def _load_actions_or_plan(args: argparse.Namespace, case: dict[str, Any]) -> tuple[list[str], dict[str, Any] | None]:
    plan_doc = None
    if getattr(args, "actions", None):
        ids = [x.strip() for x in args.actions.split(",") if x.strip()]
    elif getattr(args, "plan", None) or getattr(args, "plan_positional", None):
        plan_path = getattr(args, "plan", None) or args.plan_positional
        plan_doc = load_json_file(plan_path)
        ids = _extract_action_ids(plan_doc) or []
    else:
        planned = plan_case(case, plan_limit=1)
        plan_doc = planned
        if not planned.get("optimal"):
            raise CaseError(
                "case has no feasible optimal plan; run plan and inspect conflicts/first_failure"
            )
        ids = planned["optimal"]["action_ids"]
    unknown = [x for x in ids if x not in case["action_by_id"]]
    if unknown:
        raise CaseError(f"plan references unknown actions: {unknown}")
    return ids, plan_doc


def _add_case_and_output(p: argparse.ArgumentParser) -> None:
    p.add_argument("case_positional", nargs="?", help=argparse.SUPPRESS)
    p.add_argument("--case", "--input", "-i", dest="case", help="synthetic case JSON")
    p.add_argument("--out", "--output", "-o", dest="out", help="write JSON output to this path")


def _case_path(args: argparse.Namespace) -> str:
    path = args.case or getattr(args, "case_positional", None)
    if not path:
        raise CaseError("a case JSON path is required (--case/--input or positional)")
    return str(path)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="eraseanchor",
        description="Synthetic crypto-erasure planner, transaction replay and verifier.",
    )
    parser.add_argument("--version", action="version", version=f"eraseanchor {__version__}")
    sub = parser.add_subparsers(dest="command", required=True)

    p = sub.add_parser("plan", help="rank finite candidate actions")
    _add_case_and_output(p)
    p.add_argument("--limit", type=int, default=1, help="number of feasible full plans to return")
    p.add_argument("--rank-limit", type=int, default=25, help="number of sorted ranking rows")
    p.add_argument("--no-verify", action="store_true", help=argparse.SUPPRESS)
    p.add_argument("--strict", action="store_true", help="exit 3 for conflict/infeasible")

    r = sub.add_parser("replay", help="replay append transactions and power boundaries")
    _add_case_and_output(r)
    r.add_argument("plan_positional", nargs="?", help=argparse.SUPPRESS)
    r.add_argument("--plan", "--plan-file", dest="plan", help="plan JSON; omitted computes optimal")
    r.add_argument("--actions", help="comma-separated action IDs instead of --plan")
    r.add_argument("--journal", help="JSONL journal for one boundary/manual crash scenario")
    r.add_argument("--journal-dir", help="directory for per-boundary JSONL journals")
    r.add_argument("--boundary", type=int, help="simulate crash after N events, recover and continue")
    r.add_argument("--all-boundaries", action="store_true", help="test every event boundary")
    r.add_argument("--crash-after", type=int, help="initialize journal and stop after N events")
    r.add_argument("--resume", action="store_true", help="resume an existing --journal")

    v = sub.add_parser("verify", help="independently verify plan, power and domain faults")
    _add_case_and_output(v)
    v.add_argument("plan_positional", nargs="?", help=argparse.SUPPRESS)
    v.add_argument("--plan", "--plan-file", dest="plan", help="plan JSON; omitted computes optimal")
    v.add_argument("--actions", help="comma-separated action IDs instead of --plan")
    v.add_argument("--replay", help="optional replay JSON to cross-check")
    return parser


def cmd_plan(args: argparse.Namespace) -> int:
    case = _load_case(_case_path(args))
    doc = plan_case(
        case,
        plan_limit=max(1, args.limit),
        rank_limit=max(0, args.rank_limit),
        verify=not args.no_verify,
    )
    _print_json(doc, args.out)
    if args.strict and not doc.get("feasible"):
        return 3
    return 0


def cmd_replay(args: argparse.Namespace) -> int:
    case = _load_case(_case_path(args))
    ids, _ = _load_actions_or_plan(args, case)

    if args.resume:
        if not args.journal:
            raise CaseError("--resume requires --journal")
        doc = resume_existing_journal(case, ids, args.journal)
        _print_json(doc, args.out)
        return 0 if doc["ok"] else 1

    if args.crash_after is not None:
        if not args.journal:
            raise CaseError("--crash-after requires --journal")
        events = plan_events(case, ids) + [commitment_event(case, ids)]
        if args.crash_after < 0 or args.crash_after > len(events):
            raise CaseError(f"--crash-after must be 0..{len(events)}")
        path = Path(args.journal)
        if path.exists():
            path.unlink()
        journal = Journal(path)
        for event in events[: args.crash_after]:
            journal.append({k: v for k, v in event.items() if k not in {"lsn", "hash", "prev_hash"}})
        doc = {
            "schema": REPLAY_SCHEMA_VERSION,
            "status": "power_lost",
            "ok": True,
            "case_id": case["case_id"],
            "crashed_after_events": args.crash_after,
            "durable_records": len(journal.records),
            "journal_path": str(path),
            "next_command": (
                f"python -m eraseanchor replay --case {args.case} "
                f"--journal {path} --resume"
            ),
        }
        _print_json(doc, args.out)
        return 0

    if args.boundary is not None:
        doc = simulate_boundary(case, ids, args.boundary, args.journal)
        doc["schema"] = REPLAY_SCHEMA_VERSION
        doc["case_id"] = case["case_id"]
        _print_json(doc, args.out)
        return 0 if doc["ok"] else 1

    # Default: traverse every power boundary.  If --journal is supplied, use it
    # as a directory prefix only when there are multiple boundaries.
    journal_dir = args.journal_dir
    if journal_dir is None and args.journal and args.all_boundaries:
        journal_dir = str(Path(args.journal).with_suffix("")) + "-boundaries"
    doc = replay_all_boundaries(case, ids, journal_dir)
    doc["schema"] = REPLAY_SCHEMA_VERSION
    doc["case_id"] = case["case_id"]
    doc["action_ids"] = ids
    _print_json(doc, args.out)
    return 0 if doc["ok"] else 1


def _verify_conflict_doc(case: dict[str, Any], plan_doc: dict[str, Any]) -> dict[str, Any]:
    conflicts = plan_doc.get("conflicts", [])
    violations = []
    verified_proofs = 0
    for c in conflicts:
        proof = c.get("readable_proof")
        eproof = c.get("erase_readable_proof")
        if proof and proof.get("readable"):
            verified_proofs += 1
        else:
            violations.append(
                {
                    "code": "conflict_without_readable_proof",
                    "content_id": c.get("content_id"),
                }
            )
        if eproof and not eproof.get("readable"):
            violations.append(
                {
                    "code": "erase_side_conflict_proof_not_readable",
                    "content_id": c.get("content_id"),
                }
            )
    # Recompute independently rather than trusting the supplied plan file.
    fresh = plan_case(case, plan_limit=1)
    if fresh.get("status") != "conflict":
        violations.append({"code": "case_no_longer_plans_as_conflict", "fresh_status": fresh.get("status")})
    return {
        "schema": VERIFY_SCHEMA_VERSION,
        "ok": not violations,
        "status": "conflict_verified" if not violations else "invalid_conflict",
        "case_id": case["case_id"],
        "conflict_count": len(conflicts),
        "readable_proof_count": verified_proofs,
        "violations": violations,
    }


def cmd_verify(args: argparse.Namespace) -> int:
    case = _load_case(_case_path(args))
    plan_doc = None
    plan_path = getattr(args, "plan", None) or getattr(args, "plan_positional", None)
    if plan_path:
        plan_doc = load_json_file(plan_path)
        if plan_doc.get("status") == "conflict":
            doc = _verify_conflict_doc(case, plan_doc)
            _cross_check_replay(doc, args.replay)
            _print_json(doc, args.out)
            return 0 if doc["ok"] else 1
        ids = _extract_action_ids(plan_doc)
        if ids is None:
            raise CaseError("could not find action_ids/optimal action in --plan")
    elif args.actions:
        ids = [x.strip() for x in args.actions.split(",") if x.strip()]
    else:
        planned = plan_case(case, plan_limit=1)
        plan_doc = planned
        if planned.get("status") == "conflict":
            doc = _verify_conflict_doc(case, planned)
            _cross_check_replay(doc, args.replay)
            _print_json(doc, args.out)
            return 0 if doc["ok"] else 1
        if not planned.get("optimal"):
            doc = {
                "schema": VERIFY_SCHEMA_VERSION,
                "ok": False,
                "status": "infeasible",
                "case_id": case["case_id"],
                "first_failure": planned.get("first_failure"),
            }
            _print_json(doc, args.out)
            return 1
        ids = planned["optimal"]["action_ids"]

    if plan_doc and plan_doc.get("status") == "conflict":
        doc = _verify_conflict_doc(case, plan_doc)
    else:
        doc = {
            "schema": VERIFY_SCHEMA_VERSION,
            "case_id": case["case_id"],
            **verify_actions(case, ids),
        }
    _cross_check_replay(doc, args.replay)
    _print_json(doc, args.out)
    return 0 if doc.get("ok") else 1


def _cross_check_replay(doc: dict[str, Any], replay_path: str | None) -> None:
    if not replay_path:
        return
    replay = load_json_file(replay_path)
    doc["replay_cross_check"] = {
        "path": str(replay_path),
        "replay_ok": bool(replay.get("ok")),
        "status": replay.get("status"),
    }
    if not replay.get("ok"):
        doc["ok"] = False
        doc.setdefault("violations", []).append(
            {"code": "supplied_replay_reports_failure", "replay": str(replay_path)}
        )


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    try:
        if args.command == "plan":
            return cmd_plan(args)
        if args.command == "replay":
            return cmd_replay(args)
        if args.command == "verify":
            return cmd_verify(args)
        parser.error(f"unknown command {args.command}")
        return 2
    except CaseError as exc:
        err = {"ok": False, "status": "error", "error": str(exc)}
        print(json.dumps(err, ensure_ascii=False, indent=2), file=sys.stderr)
        return 2
    except FileNotFoundError as exc:
        err = {"ok": False, "status": "error", "error": str(exc)}
        print(json.dumps(err, ensure_ascii=False, indent=2), file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
