"""Execution, crash replay and exhaustive fault-domain verification."""

from __future__ import annotations

import tempfile
from pathlib import Path
from typing import Any

from .journal import Journal, read_journal
from .model import (
    CaseError,
    World,
    apply_event,
    build_refs,
    domains_survive_loss,
    local_image_has_domains,
    state_for_actions,
    witness_ref,
    witnesses_for_refs,
)


def plan_events(case: dict[str, Any], action_ids: list[str]) -> list[dict[str, Any]]:
    events: list[dict[str, Any]] = []
    for aid in action_ids:
        action = case["action_by_id"].get(aid)
        if action is None:
            raise CaseError(f"unknown action id {aid!r}")
        atype = action["type"]
        record_domains = list(action.get("record_domains", ["*"]))
        if atype == "migrate_ciphertext":
            events.append(
                {
                    "event_id": f"{aid}:data-write",
                    "action_id": aid,
                    "type": atype,
                    "stage": "data_write",
                    "journal_domains": record_domains,
                    "copy_domains": record_domains,
                    "data_domains": list(action.get("write_domains", [])),
                    "irreversible": False,
                    "action": action,
                    "attempt": 1,
                }
            )
        events.append(
            {
                "event_id": f"{aid}:commit",
                "action_id": aid,
                "type": atype,
                "stage": "commit",
                "journal_domains": record_domains,
                "copy_domains": record_domains,
                "irreversible": bool(action.get("irreversible", False)),
                "action": action,
                "attempt": 1,
            }
        )
    return events


def commitment_event(case: dict[str, Any], action_ids: list[str]) -> dict[str, Any]:
    domains = list(case.get("policy", {}).get("recovery_domains") or case.get("domains") or ["*"])
    return {
        "event_id": "erasure-commitment:1",
        "action_id": None,
        "type": "erasure_commitment",
        "stage": "commitment",
        "journal_domains": domains,
        "copy_domains": domains,
        "irreversible": True,
        "statement": "all erasure anchors are committed; later allowed images are safe",
        "plan_action_ids": list(action_ids),
    }


def check_order(case: dict[str, Any], action_ids: list[str]) -> list[dict[str, Any]]:
    violations: list[dict[str, Any]] = []
    seen: set[str] = set()
    for pos, aid in enumerate(action_ids):
        action = case["action_by_id"].get(aid)
        if action is None:
            violations.append({"code": "unknown_action", "action_id": aid})
            continue
        for req in action.get("requires", []):
            if req not in seen:
                violations.append(
                    {
                        "code": "missing_dependency_order",
                        "action_id": aid,
                        "required_action_id": req,
                        "position": pos,
                    }
                )
        for mig in action.get("migration_dependencies", []):
            req_action = case["action_by_id"].get(mig)
            if req_action is None or req_action.get("type") != "migrate_ciphertext":
                violations.append(
                    {
                        "code": "revocation_dependency_not_migration",
                        "action_id": aid,
                        "required_action_id": mig,
                    }
                )
            elif mig not in seen:
                violations.append(
                    {
                        "code": "revocation_before_dependent_migration",
                        "action_id": aid,
                        "required_migration_id": mig,
                    }
                )
        seen.add(aid)

    # Natural state-machine errors (duplicate revocation, unknown envelope...).
    try:
        state_for_actions(case, action_ids)
    except CaseError as exc:
        violations.append({"code": "invalid_action_state_transition", "message": str(exc)})
    return violations


def _goal_violations(
    witnesses: list[dict[str, Any]],
    context: str,
    *,
    require_holds: bool = True,
) -> list[dict[str, Any]]:
    out: list[dict[str, Any]] = []
    for w in witnesses:
        kind = w["ref"]["kind"]
        if kind == "preserve" and require_holds and not w["readable"]:
            out.append(
                {
                    "code": "preservation_version_unreadable",
                    "context": context,
                    "ref": w["ref"],
                    "reason": w.get("reason"),
                    "witness": w,
                }
            )
        if kind == "erase" and w["readable"]:
            out.append(
                {
                    "code": "erase_target_readable",
                    "context": context,
                    "ref": w["ref"],
                    "witness": w,
                }
            )
    return out


def irreversible_boundaries(
    case: dict[str, Any],
    action_ids: list[str],
    refs: list[dict[str, Any]] | None = None,
) -> list[dict[str, Any]]:
    refs = refs or build_refs(case)
    world = World(case)
    out: list[dict[str, Any]] = []
    for event in plan_events(case, action_ids):
        before = world.clone()
        apply_event(world, event)
        if event.get("stage") == "commit" and event.get("irreversible"):
            before_w = witnesses_for_refs(before, refs)
            after_w = witnesses_for_refs(world, refs)
            out.append(
                {
                    "boundary_id": f"irreversible:{event['action_id']}:commit",
                    "action_id": event["action_id"],
                    "action_type": event["type"],
                    "stage": "metadata_commit",
                    "before_witnesses": before_w,
                    "after_witnesses": after_w,
                    "before_all_holds_readable": all(
                        w["readable"] for w in before_w if w["ref"]["kind"] == "preserve"
                    ),
                    "after_all_holds_readable": all(
                        w["readable"] for w in after_w if w["ref"]["kind"] == "preserve"
                    ),
                    "after_all_erase_targets_unreadable": all(
                        not w["readable"] for w in after_w if w["ref"]["kind"] == "erase"
                    ),
                }
            )
    return out


def power_scan(
    case: dict[str, Any],
    action_ids: list[str],
    refs: list[dict[str, Any]],
) -> dict[str, Any]:
    """Traverse every durable event boundary in one continuous world."""

    events = plan_events(case, action_ids)
    world = World(case)
    boundaries: list[dict[str, Any]] = []
    violations: list[dict[str, Any]] = []

    def record_boundary(index: int, event: dict[str, Any] | None, w: World) -> None:
        witnesses = witnesses_for_refs(w, refs)
        hold_wits = [x for x in witnesses if x["ref"]["kind"] == "preserve"]
        erase_wits = [x for x in witnesses if x["ref"]["kind"] == "erase"]
        hold_ok = all(x["readable"] for x in hold_wits)
        entry = {
            "boundary_index": index,
            "after_event_id": event["event_id"] if event else None,
            "stage": event.get("stage") if event else "initial",
            "action_id": event.get("action_id") if event else None,
            "all_holds_readable": hold_ok,
            "erase_targets_readable_count": sum(1 for x in erase_wits if x["readable"]),
        }
        boundaries.append(entry)
        if not hold_ok:
            bad = [x for x in hold_wits if not x["readable"]]
            violations.append(
                {
                    "code": "hold_unreadable_at_power_boundary",
                    "context": f"boundary-{index}",
                    "boundary": entry,
                    "witnesses": bad,
                }
            )

    record_boundary(0, None, world)
    for i, event in enumerate(events, 1):
        apply_event(world, event)
        record_boundary(i, event, world)

    final_witnesses = witnesses_for_refs(world, refs)
    violations.extend(_goal_violations(final_witnesses, "power-recovered-final"))
    return {
        "event_count": len(events),
        "boundary_count": len(boundaries),
        "boundaries": boundaries,
        "violations": violations,
        "final_witnesses": final_witnesses,
    }


def _anchors_from_events(
    events: list[dict[str, Any]], lost: str | None
) -> tuple[dict[str, dict[str, Any]], set[str]]:
    revocations: dict[str, dict[str, Any]] = {}
    tombstones: set[str] = set()
    for e in events:
        if e.get("type") == "revoke_root" and e.get("stage") == "commit":
            action = e["action"]
            rid = action["root_id"]
            domains = e.get("journal_domains", ["*"])
            rec = {"action_id": e["action_id"], "domains": domains}
            if domains_survive_loss(domains, lost):
                revocations[rid] = rec
        if e.get("type") == "delete_envelope" and e.get("stage") == "commit":
            action = e["action"]
            domains = e.get("journal_domains", ["*"])
            if action.get("persistent_anchor") and domains_survive_loss(domains, lost):
                tombstones.add(action["envelope_id"])
    return revocations, tombstones


def _world_from_available_events(case: dict[str, Any], events: list[dict[str, Any]]) -> World:
    w = World(case)
    for e in events:
        apply_event(w, e)
    return w


def _snapshot_anchor_world(
    case: dict[str, Any],
    events: list[dict[str, Any]],
    lost: str | None,
) -> World:
    """Pessimistic old snapshot plus durable protection/anchor records.

    Old envelopes remain from the baseline snapshot.  New additive protection
    (migrations/add-envelope), surviving revocations and explicitly persistent
    tombstones are carried into every allowed snapshot recovery.
    """

    w = World(case)
    policy = case["policy"]
    for e in events:
        if e.get("stage") != "commit":
            continue
        atype = e.get("type")
        domains = e.get("journal_domains", ["*"])
        if not domains_survive_loss(domains, lost):
            continue
        action = e.get("action", {})
        if atype in {"add_envelope", "migrate_ciphertext", "revoke_root"}:
            apply_event(w, e)
        elif atype == "delete_envelope" and action.get("persistent_anchor"):
            if policy.get("apply_persistent_tombstones_in_snapshots", True):
                apply_event(w, e)
    return w


def domain_scan(
    case: dict[str, Any],
    action_ids: list[str],
    refs: list[dict[str, Any]],
) -> dict[str, Any]:
    # The erasure commitment is part of every post-commitment recovery image.
    events = plan_events(case, action_ids) + [commitment_event(case, action_ids)]
    final_world = state_for_actions(case, action_ids)
    domains = list(case.get("domains") or [])
    hold_policy = bool(case["policy"].get("hold_survives_domain_loss", False))
    violations: list[dict[str, Any]] = []
    summaries: list[dict[str, Any]] = []
    revocation_anchors: list[dict[str, Any]] = []
    recovery_image_count = 0

    loss_values: list[str | None] = domains if domains else [None]

    for lost in loss_values:
        context_prefix = f"loss:{lost or 'none'}"

        # 1. Current committed state with one domain physically removed.
        wits = witnesses_for_refs(final_world, refs, lost_domain=lost)
        current_violations = _goal_violations(
            wits, f"{context_prefix}/current-committed", require_holds=hold_policy
        )
        violations.extend(current_violations)
        recovery_image_count += 1
        summaries.append(
            {
                "lost_domain": lost,
                "image": "current-committed",
                "violation_count": len(current_violations),
            }
        )

        # Explicit revocation-record persistence under single-domain loss.
        for rid, rec in final_world.revocations.items():
            survives = lost is None or domains_survive_loss(rec.get("domains"), lost)
            revocation_anchors.append(
                {
                    "lost_domain": lost,
                    "root_id": rid,
                    "revocation_id": rec.get("revocation_id"),
                    "record_domains": rec.get("domains"),
                    "survives_domain_loss": survives,
                    "retained_in_all_snapshot_recoveries": survives
                    and bool(case["policy"].get("snapshot_anchor_revocations", True)),
                    "snapshot_images": sorted(case["snapshots"]) if survives else [],
                }
            )
            if lost is not None and not survives:
                violations.append(
                    {
                        "code": "revocation_record_does_not_survive_domain_loss",
                        "context": context_prefix,
                        "root_id": rid,
                        "lost_domain": lost,
                        "record_domains": rec.get("domains"),
                    }
                )

        surviving_rev, surviving_tombs = _anchors_from_events(events, lost)

        # 2. Merged journal containing every record with a surviving copy.
        if lost is not None:
            merged_events = [
                e for e in events if domains_survive_loss(e.get("journal_domains", ["*"]), lost)
            ]
            merged_world = _world_from_available_events(case, merged_events)
            wits = witnesses_for_refs(
                merged_world,
                refs,
                lost_domain=lost,
                anchor_revocations=surviving_rev,
                anchor_tombstones=surviving_tombs,
            )
            v = _goal_violations(
                wits, f"{context_prefix}/merged-journal", require_holds=hold_policy
            )
            violations.extend(v)
            recovery_image_count += 1
            summaries.append(
                {"lost_domain": lost, "image": "merged-journal", "violation_count": len(v)}
            )

            # 3. Any surviving recovery domain's local append image.
            for recovery_domain in domains:
                if recovery_domain == lost:
                    continue
                local_events = [
                    e
                    for e in events
                    if local_image_has_domains(e.get("journal_domains", ["*"]), recovery_domain)
                ]
                local_world = _world_from_available_events(case, local_events)
                wits = witnesses_for_refs(
                    local_world,
                    refs,
                    lost_domain=lost,
                    recovery_domain=recovery_domain,
                    anchor_revocations=surviving_rev,
                    anchor_tombstones=surviving_tombs,
                )
                context = f"{context_prefix}/local-image:{recovery_domain}"
                v = _goal_violations(wits, context, require_holds=hold_policy)
                violations.extend(v)
                recovery_image_count += 1
                summaries.append(
                    {
                        "lost_domain": lost,
                        "image": f"local-image:{recovery_domain}",
                        "violation_count": len(v),
                    }
                )

        # 4. Every historical snapshot with persistent anchors carried forward.
        anchor_world = _snapshot_anchor_world(case, events, lost)
        # Every snapshot image is tested against every ticket reference.  The
        # witness retains the ticket's logical name while recovery_image names
        # the image currently being booted/restored.
        for sid in sorted(case["snapshots"]):
            if not refs:
                continue
            wits = witnesses_for_refs(
                anchor_world,
                refs,
                lost_domain=lost,
                recovery_domain=f"snapshot:{sid}",
                anchor_revocations=surviving_rev,
            )
            for w in wits:
                w["recovery_image"] = f"snapshot:{sid}"
            v = _goal_violations(
                wits,
                f"{context_prefix}/snapshot:{sid}",
                # A legal hold must also survive an allowed anchored recovery.
                require_holds=True,
            )
            violations.extend(v)
            recovery_image_count += 1
            summaries.append(
                {
                    "lost_domain": lost,
                    "image": f"snapshot:{sid}",
                    "violation_count": len(v),
                }
            )

    return {
        "domain_count": len(domains),
        "domain_loss_cases": len(loss_values),
        "recovery_image_count": recovery_image_count,
        "images": summaries,
        "revocation_anchors": revocation_anchors,
        "violations": violations,
    }


def verify_actions(
    case: dict[str, Any],
    action_ids: list[str],
    *,
    run_power: bool = True,
    run_domains: bool = True,
    early_on_goal_failure: bool = False,
) -> dict[str, Any]:
    violations = check_order(case, action_ids)
    if violations:
        return {
            "ok": False,
            "status": "invalid_order",
            "action_ids": list(action_ids),
            "violation_count": len(violations),
            "violations": violations,
        }

    refs = build_refs(case)
    final_world = state_for_actions(case, action_ids)
    final_witnesses = witnesses_for_refs(final_world, refs)
    normal_violations = _goal_violations(final_witnesses, "normal-final", require_holds=True)
    violations.extend(normal_violations)

    if early_on_goal_failure and normal_violations:
        return {
            "ok": False,
            "status": "violations",
            "action_ids": list(action_ids),
            "violation_count": len(violations),
            "violations": violations[:100],
            "checks": {"refs": len(refs), "early_exit": "normal_final"},
            "final_witnesses": final_witnesses,
            "power_boundaries": [],
            "domain_images": [],
        }

    power = power_scan(case, action_ids, refs) if run_power else {"violations": [], "boundaries": []}
    violations.extend(power.get("violations", []))

    domains = domain_scan(case, action_ids, refs) if run_domains else {"violations": []}
    violations.extend(domains.get("violations", []))

    return {
        "ok": not violations,
        "status": "verified" if not violations else "violations",
        "action_ids": list(action_ids),
        "violation_count": len(violations),
        "violations": violations[:100],
        "checks": {
            "refs": len(refs),
            "power_boundaries": power.get("boundary_count", 0),
            "domain_loss_cases": domains.get("domain_loss_cases", 0),
            "recovery_images": domains.get("recovery_image_count", 0),
        },
        "final_witnesses": final_witnesses,
        "power_boundaries": power.get("boundaries", []),
        "domain_images": domains.get("images", []),
        "revocation_anchors": domains.get("revocation_anchors", []),
    }


def simulate_boundary(
    case: dict[str, Any],
    action_ids: list[str],
    boundary: int,
    journal_path: str | Path | None = None,
) -> dict[str, Any]:
    """Crash after ``boundary`` durable events, then recover and continue."""

    canonical = plan_events(case, action_ids)
    commit = commitment_event(case, action_ids)
    all_events = canonical + [commit]
    if boundary < 0 or boundary > len(all_events):
        raise CaseError(f"boundary must be 0..{len(all_events)}, got {boundary}")

    if journal_path is not None:
        path = Path(journal_path)
        if path.exists():
            path.unlink()
        journal = Journal(path)
    else:
        journal = Journal(None)

    for event in all_events[:boundary]:
        journal.append({k: v for k, v in event.items() if k not in {"lsn", "hash", "prev_hash"}})

    if journal_path is not None:
        loaded = read_journal(journal_path)
        if not loaded["chain_valid"]:
            raise CaseError("synthetic journal hash chain invalid after simulated crash")
        journal.torn_tail = loaded["torn_tail"]

    recovered_world = World(case)
    for rec in journal.records:
        apply_event(recovered_world, rec)

    committed_actions = {
        rec.get("action_id")
        for rec in journal.records
        if rec.get("stage") == "commit" and rec.get("action_id")
    }
    pending_writes = sorted(
        {
            rec.get("action_id")
            for rec in journal.records
            if rec.get("stage") == "data_write" and rec.get("action_id") not in committed_actions
        }
    )

    refs = build_refs(case)
    immediate_witnesses = witnesses_for_refs(recovered_world, refs)
    immediate_hold_ok = all(
        w["readable"] for w in immediate_witnesses if w["ref"]["kind"] == "preserve"
    )

    recovery_markers: list[dict[str, Any]] = []
    for aid in action_ids:
        if aid in committed_actions:
            recovery_markers.append({"action_id": aid, "decision": "skip_committed"})
            continue
        action = case["action_by_id"][aid]
        if action["type"] == "migrate_ciphertext":
            if aid in pending_writes:
                marker = {
                    "stage": "recovery",
                    "event": "roll_forward_pending_data_write",
                    "action_id": aid,
                    "decision": "idempotent_retry_then_commit",
                }
                journal.append(marker)
                recovery_markers.append(marker)
                retry_events = plan_events(case, [aid])
                data_event = dict(retry_events[0])
                data_event["attempt"] = 2
                journal.append(data_event)
                journal.append(retry_events[1])
            else:
                for event in plan_events(case, [aid]):
                    journal.append(event)
        else:
            for event in plan_events(case, [aid]):
                journal.append(event)

    has_commitment = any(rec.get("stage") == "commitment" for rec in journal.records)
    if not has_commitment:
        journal.append(commit)

    final_world = World(case)
    for rec in journal.records:
        apply_event(final_world, rec)
    final_witnesses = witnesses_for_refs(final_world, refs)
    final_violations = _goal_violations(final_witnesses, f"boundary-{boundary}-resumed-final")

    chain_valid = all(rec.get("hash") for rec in journal.records)
    return {
        "boundary": boundary,
        "total_durable_boundaries": len(all_events) + 1,
        "crashed_after_events": boundary,
        "journal_path": str(journal_path) if journal_path is not None else None,
        "journal_records": len(journal.records),
        "hash_chain_valid": chain_valid,
        "torn_tail": journal.torn_tail,
        "committed_actions_at_recovery": sorted(x for x in committed_actions if x),
        "pending_data_writes_at_recovery": pending_writes,
        "recovery_markers": recovery_markers,
        "immediate_all_holds_readable": immediate_hold_ok,
        "immediate_witnesses": immediate_witnesses,
        "final_witnesses": final_witnesses,
        "ok": immediate_hold_ok and not final_violations and chain_valid,
        "violations": final_violations,
    }


def resume_existing_journal(
    case: dict[str, Any],
    action_ids: list[str],
    journal_path: str | Path,
) -> dict[str, Any]:
    """Recover an on-disk journal left by a simulated power loss and continue."""

    path = Path(journal_path)
    loaded = read_journal(path)
    if not loaded["chain_valid"]:
        raise CaseError(f"refusing to resume corrupt journal: {loaded['errors']}")
    journal = Journal(path)
    journal.torn_tail = loaded["torn_tail"]
    if loaded["torn_tail"]:
        # A partial final line is never a committed transaction; recovery may
        # truncate that torn tail before resuming the append-only stream.
        journal.rewrite_valid_prefix()

    recovered_world = World(case)
    for rec in journal.records:
        apply_event(recovered_world, rec)
    committed_actions = {
        rec.get("action_id")
        for rec in journal.records
        if rec.get("stage") == "commit" and rec.get("action_id")
    }
    pending_writes = sorted(
        {
            rec.get("action_id")
            for rec in journal.records
            if rec.get("stage") == "data_write" and rec.get("action_id") not in committed_actions
        }
    )
    refs = build_refs(case)
    immediate_witnesses = witnesses_for_refs(recovered_world, refs)
    immediate_hold_ok = all(
        w["readable"] for w in immediate_witnesses if w["ref"]["kind"] == "preserve"
    )

    recovery_markers: list[dict[str, Any]] = []
    for aid in action_ids:
        if aid in committed_actions:
            recovery_markers.append({"action_id": aid, "decision": "skip_committed"})
            continue
        action = case["action_by_id"][aid]
        if action["type"] == "migrate_ciphertext" and aid in pending_writes:
            marker = {
                "stage": "recovery",
                "event": "roll_forward_pending_data_write",
                "action_id": aid,
                "decision": "idempotent_retry_then_commit",
            }
            journal.append(marker)
            recovery_markers.append(marker)
            retry_events = plan_events(case, [aid])
            data_event = dict(retry_events[0])
            data_event["attempt"] = 2
            journal.append(data_event)
            journal.append(retry_events[1])
        else:
            for event in plan_events(case, [aid]):
                journal.append(event)

    if not any(rec.get("stage") == "commitment" for rec in journal.records):
        journal.append(commitment_event(case, action_ids))

    final_world = World(case)
    for rec in journal.records:
        apply_event(final_world, rec)
    final_witnesses = witnesses_for_refs(final_world, refs)
    violations = _goal_violations(final_witnesses, "manual-resume-final")
    return {
        "schema": "eraseanchor.replay/v1",
        "status": "completed",
        "ok": immediate_hold_ok and not violations,
        "journal_path": str(path),
        "journal_records": len(journal.records),
        "hash_chain_valid": True,
        "torn_tail": journal.torn_tail,
        "committed_actions_at_recovery": sorted(x for x in committed_actions if x),
        "pending_data_writes_at_recovery": pending_writes,
        "recovery_markers": recovery_markers,
        "immediate_all_holds_readable": immediate_hold_ok,
        "immediate_witnesses": immediate_witnesses,
        "final_witnesses": final_witnesses,
        "violations": violations,
    }


def replay_all_boundaries(
    case: dict[str, Any],
    action_ids: list[str],
    journal_dir: str | Path | None = None,
) -> dict[str, Any]:
    events = plan_events(case, action_ids)
    total = len(events) + 1  # plus commitment
    results = []
    all_ok = True
    temp_ctx = None
    if journal_dir is None:
        temp_ctx = tempfile.TemporaryDirectory(prefix="eraseanchor-journal-")
        base = Path(temp_ctx.name)
    else:
        base = Path(journal_dir)
        base.mkdir(parents=True, exist_ok=True)
    try:
        for b in range(total + 1):
            path = base / f"boundary-{b:02d}.jsonl"
            r = simulate_boundary(case, action_ids, b, path)
            results.append(
                {
                    "boundary": b,
                    "ok": r["ok"],
                    "journal_records": r["journal_records"],
                    "pending_data_writes": r["pending_data_writes_at_recovery"],
                    "immediate_all_holds_readable": r["immediate_all_holds_readable"],
                    "violation_count": len(r["violations"]),
                    "journal_path": r["journal_path"],
                }
            )
            all_ok = all_ok and r["ok"]
    finally:
        if temp_ctx is not None:
            temp_ctx.cleanup()
    return {
        "ok": all_ok,
        "boundary_count": len(results),
        "boundaries": results,
    }
