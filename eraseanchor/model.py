"""Synthetic domain model for eraseanchor.

The model intentionally contains no real cryptographic material.  Ciphertext
and key identifiers are immutable synthetic labels.  Readability is an
existential graph property: a complete ciphertext replica and a rooted chain of
available envelopes must both exist.
"""

from __future__ import annotations

import copy
import json
from collections import deque
from pathlib import Path
from typing import Any, Iterable

SCHEMA = "eraseanchor.case/v1"
MAX_ACTIONS = 18
MAX_DOMAINS = 6
GLOBAL_DOMAIN = "*"


class CaseError(ValueError):
    """Raised when a synthetic case is malformed."""


def load_json_file(path: str | Path) -> Any:
    p = Path(path)
    try:
        return json.loads(p.read_text(encoding="utf-8"))
    except FileNotFoundError as exc:
        raise CaseError(f"input file not found: {p}") from exc
    except json.JSONDecodeError as exc:
        raise CaseError(f"invalid JSON in {p}: {exc}") from exc


def as_list(value: Any) -> list[Any]:
    if value is None:
        return []
    if isinstance(value, list):
        return value
    if isinstance(value, tuple | set):
        return list(value)
    return [value]


def domain_list(value: Any, default: Iterable[str] | None = None) -> list[str]:
    """Normalize a domain list.

    A missing domain list means a global synthetic object, represented by ``*``.
    An explicit empty list means the object currently has no available replica.
    """

    if value is None:
        return list(default) if default is not None else [GLOBAL_DOMAIN]
    if isinstance(value, str):
        if value.lower() in {"*", "global", "all"}:
            return [GLOBAL_DOMAIN]
        return [value]
    out: list[str] = []
    for item in as_list(value):
        if isinstance(item, str) and item.lower() in {"*", "global", "all"}:
            out.append(GLOBAL_DOMAIN)
        else:
            out.append(str(item))
    return out


def domains_survive_loss(domains: Iterable[str] | None, lost: str | None) -> bool:
    if lost is None:
        return True
    if domains is None:
        return True
    ds = set(domains)
    if not ds:
        return False
    if GLOBAL_DOMAIN in ds:
        return True
    return any(d != lost for d in ds)


def local_image_has_domains(domains: Iterable[str] | None, recovery_domain: str) -> bool:
    if domains is None:
        return True
    ds = set(domains)
    return GLOBAL_DOMAIN in ds or recovery_domain in ds


def _index_records(value: Any, id_field: str = "id") -> dict[str, dict[str, Any]]:
    if isinstance(value, dict):
        out: dict[str, dict[str, Any]] = {}
        for key, rec in value.items():
            if not isinstance(rec, dict):
                rec = {"value": rec}
            rec = copy.deepcopy(rec)
            rec.setdefault(id_field, str(key))
            out[str(rec[id_field])] = rec
        return out
    out = {}
    for rec in as_list(value):
        if not isinstance(rec, dict):
            raise CaseError(f"record must be an object: {rec!r}")
        rec = copy.deepcopy(rec)
        if id_field not in rec:
            raise CaseError(f"record is missing {id_field!r}: {rec}")
        out[str(rec[id_field])] = rec
    return out


def normalize_case(raw: dict[str, Any]) -> dict[str, Any]:
    if not isinstance(raw, dict):
        raise CaseError("case root must be a JSON object")
    if raw.get("schema") not in (None, SCHEMA):
        # Forward-compatible acceptance: the v1 semantics are a small stable
        # core.  A different major schema should be rejected explicitly.
        schema = str(raw.get("schema"))
        if schema.split("/")[-1].startswith("v") and not schema.endswith("/v1"):
            raise CaseError(f"unsupported schema {schema!r}; expected {SCHEMA}")

    case_id = str(raw.get("case_id") or raw.get("id") or "eraseanchor-case")

    raw_domains = raw.get("domains", [])
    if not raw_domains:
        domains: list[str] = []
    elif isinstance(raw_domains[0], dict):
        domains = [str(d["id"]) for d in raw_domains]
    else:
        domains = [str(d) for d in raw_domains]
    if len(domains) > MAX_DOMAINS:
        raise CaseError(f"at most {MAX_DOMAINS} failure domains are supported")
    if len(set(domains)) != len(domains):
        raise CaseError("domain ids must be unique")

    policy_raw = raw.get("policy", {})
    if not isinstance(policy_raw, dict):
        raise CaseError("policy must be an object")
    recovery_domains = domain_list(policy_raw.get("recovery_domains"), domains)
    commit_domains = domain_list(policy_raw.get("commit_domains"), domains)
    policy = {
        "hold_survives_domain_loss": bool(policy_raw.get("hold_survives_domain_loss", False)),
        "recovery_domains": [d for d in recovery_domains if d != GLOBAL_DOMAIN] or domains,
        "commit_domains": [d for d in commit_domains if d != GLOBAL_DOMAIN] or domains,
        "snapshot_anchor_revocations": bool(policy_raw.get("snapshot_anchor_revocations", True)),
        "apply_persistent_tombstones_in_snapshots": bool(
            policy_raw.get("apply_persistent_tombstones_in_snapshots", True)
        ),
    }

    roots = _index_records(raw.get("roots", []))
    for rid, root in roots.items():
        root["id"] = rid
        root["persisted"] = bool(root.get("persisted", True))
        root["domains"] = domain_list(root.get("domains"), [GLOBAL_DOMAIN])

    ciphertexts = _index_records(raw.get("ciphertexts", raw.get("blocks", {})))
    for cid, ct in ciphertexts.items():
        ct["id"] = cid
        ct["content_id"] = str(ct.get("content_id") or ct.get("content") or cid)
        if "key_ids" in ct:
            ct["key_ids"] = [str(k) for k in as_list(ct["key_ids"])]
        else:
            key_id = ct.get("key_id") or ct.get("key") or ct.get("dek") or f"dek:{cid}"
            ct["key_ids"] = [str(key_id)]
        ct["complete"] = bool(ct.get("complete", True))
        ct["domains"] = domain_list(ct.get("domains", ct.get("domain")), [GLOBAL_DOMAIN])

    envelopes = _index_records(raw.get("envelopes", []))
    for eid, env in envelopes.items():
        env["id"] = eid
        env["wrapper"] = str(env.get("wrapper") or env.get("wraps_key") or env.get("by") or "")
        env["wrapped"] = str(env.get("wrapped") or env.get("wrapped_key") or env.get("key") or "")
        if not env["wrapper"] or not env["wrapped"]:
            raise CaseError(f"envelope {eid!r} requires wrapper and wrapped key ids")
        env["domains"] = domain_list(env.get("domains", env.get("domain")), [GLOBAL_DOMAIN])

    snapshots_raw = raw.get("snapshots", {})
    snapshots = _index_records(snapshots_raw)
    for sid, snap in snapshots.items():
        snap["id"] = sid
        snap["parent"] = snap.get("parent") or snap.get("parent_snapshot")
        names = snap.get("names", snap.get("directory", {}))
        if names is None:
            names = {}
        if not isinstance(names, dict):
            raise CaseError(f"snapshot {sid!r} names must be an object")
        norm_names: dict[str, dict[str, Any] | None] = {}
        for path, value in names.items():
            if value is None:
                norm_names[str(path)] = None
            elif isinstance(value, str):
                norm_names[str(path)] = {"ciphertext": value}
            elif isinstance(value, dict):
                if value.get("deleted") or value.get("tombstone"):
                    norm_names[str(path)] = None
                else:
                    cid = value.get("ciphertext") or value.get("id") or value.get("block")
                    if not cid:
                        raise CaseError(f"name {path!r} in {sid!r} lacks ciphertext id")
                    v = copy.deepcopy(value)
                    v["ciphertext"] = str(cid)
                    norm_names[str(path)] = v
            else:
                raise CaseError(f"invalid directory entry {path!r} in snapshot {sid!r}")
        snap["names"] = norm_names

    tickets = _normalize_tickets(raw.get("tickets", []), snapshots)

    actions_raw = raw.get("actions", raw.get("candidate_actions", []))
    if not isinstance(actions_raw, list):
        raise CaseError("actions must be a list")
    if len(actions_raw) > MAX_ACTIONS:
        raise CaseError(f"at most {MAX_ACTIONS} candidate actions are supported")
    actions = [_normalize_action(a, policy) for a in actions_raw]
    ids = [a["id"] for a in actions]
    if len(ids) != len(set(ids)):
        raise CaseError("action ids must be unique")
    for action in actions:
        if action["type"] == "migrate_ciphertext" and action["ciphertext_id"] not in ciphertexts:
            raise CaseError(
                f"action {action['id']!r} references unknown ciphertext "
                f"{action['ciphertext_id']!r}"
            )
    actions.sort(key=lambda a: a["id"])

    case = {
        "schema": raw.get("schema", SCHEMA),
        "case_id": case_id,
        "domains": domains,
        "policy": policy,
        "roots": roots,
        "ciphertexts": ciphertexts,
        "envelopes": envelopes,
        "snapshots": snapshots,
        "tickets": tickets,
        "actions": actions,
        "raw": raw,
    }
    case["action_by_id"] = {a["id"]: a for a in actions}
    return case


def _normalize_tickets(raw_tickets: Any, snapshots: dict[str, dict[str, Any]]) -> list[dict[str, Any]]:
    if isinstance(raw_tickets, dict):
        tickets: list[dict[str, Any]] = []
        for kind, recs in raw_tickets.items():
            for rec in as_list(recs):
                if isinstance(rec, str):
                    rec = {"snapshot": rec}
                rec = copy.deepcopy(rec)
                rec["kind"] = kind
                tickets.append(rec)
    else:
        tickets = []
        for t in as_list(raw_tickets):
            if isinstance(t, str):
                t = {"id": t, "snapshot": t}
            tickets.append(copy.deepcopy(t))

    # Snapshot-local convenience fields.
    for sid, snap in snapshots.items():
        kind = snap.get("ticket") or snap.get("hold") or snap.get("disposition")
        if kind:
            tickets.append(
                {
                    "id": str(snap.get("ticket_id") or f"ticket-{sid}"),
                    "kind": str(kind),
                    "snapshot": sid,
                }
            )

    out = []
    seen = set()
    for idx, t in enumerate(tickets):
        kind = str(t.get("kind") or t.get("type") or "").lower()
        if kind in {"preserve", "preservation", "hold", "legal_hold"}:
            kind = "preserve"
        elif kind in {"erase", "erasure", "destroy", "crypto_erase"}:
            kind = "erase"
        else:
            raise CaseError(f"ticket {t!r} has unknown preserve/erase kind")
        sid = str(t.get("snapshot") or t.get("snapshot_id") or "")
        if sid not in snapshots:
            raise CaseError(f"ticket references unknown snapshot {sid!r}")
        tid = str(t.get("id") or f"{kind}-{sid}-{idx + 1}")
        if tid in seen:
            tid = f"{tid}-{idx + 1}"
        seen.add(tid)
        paths = t.get("paths", t.get("names", t.get("path")))
        if paths is not None:
            paths = [str(p) for p in as_list(paths)]
        cts = t.get("ciphertexts", t.get("targets"))
        if cts is not None:
            cts = [str(c) for c in as_list(cts)]
        out.append(
            {
                "id": tid,
                "kind": kind,
                "snapshot": sid,
                "paths": paths,
                "ciphertexts": cts or [],
            }
        )
    return out


def _normalize_action(a: dict[str, Any], policy: dict[str, Any]) -> dict[str, Any]:
    if not isinstance(a, dict):
        raise CaseError(f"action must be object: {a!r}")
    aid = str(a.get("id") or "")
    atype = str(a.get("type") or a.get("kind") or "")
    known = {"migrate_ciphertext", "add_envelope", "delete_envelope", "revoke_root"}
    aliases = {
        "migrate": "migrate_ciphertext",
        "ciphertext_migration": "migrate_ciphertext",
        "add_authorized_envelope": "add_envelope",
        "envelope_add": "add_envelope",
        "delete_old_envelope": "delete_envelope",
        "envelope_delete": "delete_envelope",
        "revoke_root_key": "revoke_root",
        "root_revocation": "revoke_root",
    }
    atype = aliases.get(atype, atype)
    if atype not in known:
        raise CaseError(f"action {aid!r} has unsupported type {atype!r}")
    if not aid:
        raise CaseError("action is missing id")
    try:
        cost = a.get("cost", 1)
        cost = float(cost) if isinstance(cost, str) else cost
        if cost < 0:
            raise ValueError
        if float(cost).is_integer():
            cost = int(cost)
    except (TypeError, ValueError) as exc:
        raise CaseError(f"action {aid!r} has invalid cost {a.get('cost')!r}") from exc

    out = copy.deepcopy(a)
    out["id"] = aid
    out["type"] = atype
    out["cost"] = cost
    requires_raw = a.get(
        "requires",
        a.get("after", a.get("depends_on", a.get("dependencies", []))),
    )
    out["requires"] = [str(x) for x in as_list(requires_raw)]
    migration_raw = a.get(
        "migration_dependencies",
        a.get(
            "dependent_migrations",
            a.get("depends_on_migrations", a.get("migration_dependency", a.get("migration"))),
        ),
    )
    dep_migs = [str(x) for x in as_list(migration_raw)]
    out["migration_dependencies"] = dep_migs
    out["requires"].extend(dep_migs)
    out["requires"] = list(dict.fromkeys(out["requires"]))
    out["record_domains"] = domain_list(
        a.get("record_domains", a.get("commit_domains", a.get("journal_domains"))),
        policy["commit_domains"],
    )
    default_irreversible = atype in {"delete_envelope", "revoke_root"}
    out["irreversible"] = bool(
        a.get("irreversible", default_irreversible)
    )

    if atype == "migrate_ciphertext":
        cid = a.get("ciphertext") or a.get("ciphertext_id") or a.get("block")
        if not cid:
            raise CaseError(f"action {aid!r} migrate requires ciphertext")
        out["ciphertext_id"] = str(cid)
        out["add_domains"] = domain_list(
            a.get("add_domains", a.get("to_domain", a.get("to"))), []
        )
        out["remove_domains"] = domain_list(
            a.get("remove_domains", a.get("from_domain", a.get("from"))), []
        )
        out["write_domains"] = domain_list(
            a.get("write_domains", out["add_domains"]), out["add_domains"]
        )
        if not out["add_domains"] and not out["remove_domains"]:
            raise CaseError(f"migrate action {aid!r} needs add/to or remove/from domains")
        if "irreversible" not in a and out["remove_domains"]:
            out["irreversible"] = True
    elif atype == "add_envelope":
        env = a.get("envelope") if isinstance(a.get("envelope"), dict) else {}
        eid = a.get("envelope_id") or env.get("id") or f"{aid}:env"
        out["envelope_id"] = str(eid)
        out["envelope"] = {
            "id": str(eid),
            "wrapper": str(a.get("wrapper") or env.get("wrapper") or env.get("by") or ""),
            "wrapped": str(a.get("wrapped") or env.get("wrapped") or env.get("wrapped_key") or ""),
            "domains": domain_list(
                a.get("envelope_domains", env.get("domains", env.get("domain"))),
                out["record_domains"],
            ),
            "authorized": bool(a.get("authorized", env.get("authorized", True))),
        }
        if not out["envelope"]["wrapper"] or not out["envelope"]["wrapped"]:
            raise CaseError(f"add_envelope action {aid!r} requires wrapper and wrapped")
    elif atype == "delete_envelope":
        eid = a.get("envelope_id") or a.get("envelope")
        if isinstance(eid, dict):
            eid = eid.get("id")
        if not eid:
            raise CaseError(f"delete_envelope action {aid!r} requires envelope_id")
        out["envelope_id"] = str(eid)
        out["persistent_anchor"] = bool(a.get("persistent_anchor", a.get("anchor", False)))
    elif atype == "revoke_root":
        rid = a.get("root_id") or a.get("root")
        if not rid:
            raise CaseError(f"revoke_root action {aid!r} requires root_id")
        out["root_id"] = str(rid)
        out["revocation_id"] = str(a.get("revocation_id") or f"revocation:{rid}:{aid}")
    return out


def resolve_snapshot(case: dict[str, Any], snapshot_id: str, _stack: set[str] | None = None) -> dict[str, str]:
    """Resolve a COW snapshot chain to path -> ciphertext id."""

    if _stack is None:
        _stack = set()
    if snapshot_id in _stack:
        raise CaseError(f"snapshot parent cycle at {snapshot_id!r}")
    if snapshot_id not in case["snapshots"]:
        raise CaseError(f"unknown snapshot {snapshot_id!r}")
    _stack.add(snapshot_id)
    snap = case["snapshots"][snapshot_id]
    resolved: dict[str, str] = {}
    parent = snap.get("parent")
    if parent:
        resolved.update(resolve_snapshot(case, str(parent), _stack))
    for path, entry in snap["names"].items():
        if entry is None:
            resolved.pop(path, None)
        else:
            resolved[path] = entry["ciphertext"]
    return resolved


def build_refs(case: dict[str, Any]) -> list[dict[str, Any]]:
    refs: list[dict[str, Any]] = []
    for ticket in case["tickets"]:
        sid = ticket["snapshot"]
        resolved = resolve_snapshot(case, sid)
        paths = ticket["paths"]
        direct_cts = ticket.get("ciphertexts", [])
        if paths is None and not direct_cts:
            paths = sorted(resolved)
        if paths is None:
            paths = []
        for path in paths:
            cid = resolved.get(path)
            content_id = case["ciphertexts"].get(cid, {}).get("content_id") if cid else None
            refs.append(
                {
                    "ref_id": f"{ticket['id']}:{sid}:{path}",
                    "ticket_id": ticket["id"],
                    "kind": ticket["kind"],
                    "snapshot": sid,
                    "path": path,
                    "ciphertext_id": cid,
                    "content_id": content_id,
                }
            )
        for cid in direct_cts:
            ct = case["ciphertexts"].get(cid)
            refs.append(
                {
                    "ref_id": f"{ticket['id']}:{sid}:ct:{cid}",
                    "ticket_id": ticket["id"],
                    "kind": ticket["kind"],
                    "snapshot": sid,
                    "path": None,
                    "ciphertext_id": cid if ct else None,
                    "content_id": ct["content_id"] if ct else cid,
                }
            )
    return refs


class World:
    """Mutable committed/prefix state used by the readability oracle."""

    def __init__(self, case: dict[str, Any]):
        self.case = case
        self.roots = copy.deepcopy(case["roots"])
        for root in self.roots.values():
            root["revoked"] = False
        self.envelopes = copy.deepcopy(case["envelopes"])
        for env in self.envelopes.values():
            env["deleted"] = False
        self.cts: dict[str, dict[str, Any]] = {}
        for cid, ct in case["ciphertexts"].items():
            rec = copy.deepcopy(ct)
            rec["domains"] = set(ct["domains"])
            rec["pending_domains"] = set()
            self.cts[cid] = rec
        self.revocations: dict[str, dict[str, Any]] = {}
        self.tombstones: dict[str, dict[str, Any]] = {}
        self.migrations: list[dict[str, Any]] = []
        self.applied_action_ids: list[str] = []

    def clone(self) -> "World":
        w = World.__new__(World)
        w.case = self.case
        w.roots = copy.deepcopy(self.roots)
        w.envelopes = copy.deepcopy(self.envelopes)
        w.cts = copy.deepcopy(self.cts)
        # copy.deepcopy correctly clones sets, but normalize defensively.
        for ct in w.cts.values():
            ct["domains"] = set(ct.get("domains", []))
            ct["pending_domains"] = set(ct.get("pending_domains", []))
        w.revocations = copy.deepcopy(self.revocations)
        w.tombstones = copy.deepcopy(self.tombstones)
        w.migrations = copy.deepcopy(self.migrations)
        w.applied_action_ids = list(self.applied_action_ids)
        return w


def apply_action(world: World, action: dict[str, Any], stage: str = "commit") -> None:
    """Apply one action stage.

    ``stage='data_write'`` models the separate data-write boundary.  The bytes
    become physically present but are not yet a committed catalog placement.
    ``stage='commit'`` applies metadata effects.
    """

    aid = action["id"]
    atype = action["type"]

    if atype == "migrate_ciphertext":
        cid = action["ciphertext_id"]
        if cid not in world.cts:
            raise CaseError(f"action {aid} references unknown ciphertext {cid}")
        ct = world.cts[cid]
        if stage == "data_write":
            for d in action.get("write_domains", []):
                ct["domains"].add(d)
                ct["pending_domains"].add(d)
            return
        for d in action.get("write_domains", []):
            ct["domains"].add(d)
        for d in action.get("add_domains", []):
            ct["domains"].add(d)
            ct["pending_domains"].discard(d)
        for d in action.get("remove_domains", []):
            ct["domains"].discard(d)
        world.migrations.append(
            {
                "action_id": aid,
                "ciphertext_id": cid,
                "added": list(action.get("add_domains", [])),
                "removed": list(action.get("remove_domains", [])),
            }
        )

    elif atype == "add_envelope" and stage == "commit":
        env = copy.deepcopy(action["envelope"])
        eid = env["id"]
        env["deleted"] = False
        env["added_by_action"] = aid
        world.envelopes[eid] = env

    elif atype == "delete_envelope" and stage == "commit":
        eid = action["envelope_id"]
        if eid not in world.envelopes:
            raise CaseError(f"action {aid} deletes unknown envelope {eid}")
        world.envelopes[eid]["deleted"] = True
        world.tombstones[eid] = {
            "action_id": aid,
            "domains": list(action.get("record_domains", [GLOBAL_DOMAIN])),
            "persistent_anchor": bool(action.get("persistent_anchor", False)),
        }

    elif atype == "revoke_root" and stage == "commit":
        rid = action["root_id"]
        if rid not in world.roots:
            # A synthetic root record may still be referenced solely as a graph
            # start.  Create a minimal persisted record so the witness is clear.
            world.roots[rid] = {
                "id": rid,
                "persisted": True,
                "domains": [GLOBAL_DOMAIN],
            }
        world.roots[rid]["revoked"] = True
        world.revocations[rid] = {
            "action_id": aid,
            "revocation_id": action.get("revocation_id"),
            "domains": list(action.get("record_domains", [GLOBAL_DOMAIN])),
        }

    if stage == "commit":
        world.applied_action_ids.append(aid)


def apply_event(world: World, event: dict[str, Any]) -> None:
    action = event.get("action")
    if not isinstance(action, dict):
        aid = event.get("action_id")
        action = world.case.get("action_by_id", {}).get(aid)
    if action is None:
        if event.get("stage") in {"recovery", "commitment"}:
            return
        raise CaseError(f"event lacks action definition: {event.get('event_id')}")
    apply_action(world, action, stage=event.get("stage", "commit"))


def state_for_actions(case: dict[str, Any], action_ids: list[str]) -> World:
    w = World(case)
    for aid in action_ids:
        if aid not in case["action_by_id"]:
            raise CaseError(f"unknown action id {aid!r}")
        apply_action(w, case["action_by_id"][aid], "commit")
    return w


def _root_starts(
    world: World,
    lost_domain: str | None,
    anchor_revocations: dict[str, dict[str, Any]] | set[str] | None,
) -> tuple[list[str], list[dict[str, Any]]]:
    anchors = _anchor_map(anchor_revocations)
    starts: list[str] = []
    blocked: list[dict[str, Any]] = []
    for rid in sorted(world.roots):
        root = world.roots[rid]
        if not root.get("persisted", True):
            blocked.append({"root": rid, "reason": "not_persisted"})
            continue
        if not domains_survive_loss(root.get("domains"), lost_domain):
            blocked.append({"root": rid, "reason": "only_copy_in_lost_domain"})
            continue
        if root.get("revoked") or rid in anchors:
            rec = anchors.get(rid) or world.revocations.get(rid) or {}
            if domains_survive_loss(rec.get("domains"), lost_domain):
                blocked.append({"root": rid, "reason": "revoked"})
            else:
                blocked.append({"root": rid, "reason": "revocation_record_lost"})
            continue
        starts.append(rid)
    return starts, blocked


def _anchor_map(
    anchor_revocations: dict[str, dict[str, Any]] | set[str] | None,
) -> dict[str, dict[str, Any]]:
    if anchor_revocations is None:
        return {}
    if isinstance(anchor_revocations, set):
        return {rid: {"domains": [GLOBAL_DOMAIN]} for rid in anchor_revocations}
    return anchor_revocations


def find_key_path(
    world: World,
    key_ids: list[str],
    lost_domain: str | None = None,
    anchor_revocations: dict[str, dict[str, Any]] | set[str] | None = None,
    anchor_tombstones: set[str] | dict[str, Any] | None = None,
) -> dict[str, Any] | None:
    """BFS for a shortest rooted envelope path to one of ``key_ids``."""

    targets = set(key_ids)
    tombstones = set(anchor_tombstones or [])
    starts, blocked_roots = _root_starts(world, lost_domain, anchor_revocations)
    envelope_ids = sorted(world.envelopes)

    for start in starts:
        if start in targets:
            return {
                "root_id": start,
                "nodes": [start],
                "envelope_path": [],
                "length": 0,
            }

    queue = deque((rid, [rid], []) for rid in starts)
    visited = set(starts)
    reachable = set(starts)
    blocked_edges: list[dict[str, Any]] = []

    while queue:
        node, nodes, edges = queue.popleft()
        for eid in envelope_ids:
            env = world.envelopes[eid]
            if env.get("wrapper") != node:
                continue
            if env.get("deleted") or eid in tombstones:
                blocked_edges.append({"envelope": eid, "reason": "deleted"})
                continue
            if not domains_survive_loss(env.get("domains"), lost_domain):
                blocked_edges.append({"envelope": eid, "reason": "only_copy_in_lost_domain"})
                continue
            nxt = env.get("wrapped")
            if not nxt or nxt in visited:
                continue
            visited.add(nxt)
            reachable.add(nxt)
            new_nodes = nodes + [nxt]
            new_edges = edges + [eid]
            if nxt in targets:
                return {
                    "root_id": nodes[0],
                    "nodes": new_nodes,
                    "envelope_path": new_edges,
                    "length": len(new_edges),
                }
            queue.append((nxt, new_nodes, new_edges))

    return {
        "_not_found": True,
        "reachable_nodes": sorted(reachable),
        "blocked_roots": blocked_roots,
        "blocked_envelopes": blocked_edges[:20],
    }


def witness_ref(
    world: World,
    ref: dict[str, Any],
    lost_domain: str | None = None,
    recovery_domain: str | None = None,
    anchor_revocations: dict[str, dict[str, Any]] | set[str] | None = None,
    anchor_tombstones: set[str] | dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Return a JSON-safe readability witness for one ticket reference."""

    compact_ref = {
        "ref_id": ref["ref_id"],
        "ticket_id": ref["ticket_id"],
        "kind": ref["kind"],
        "snapshot": ref["snapshot"],
        "path": ref.get("path"),
    }
    base = {
        "ref": compact_ref,
        "lost_domain": lost_domain,
        "recovery_domain": recovery_domain,
    }
    if not ref.get("ciphertext_id") and not ref.get("content_id"):
        return {
            **base,
            "readable": False,
            "reason": "logical_name_absent_from_snapshot",
        }

    content_id = ref.get("content_id")
    if content_id is None and ref.get("ciphertext_id"):
        content_id = world.cts.get(ref["ciphertext_id"], {}).get("content_id")

    candidates = [
        cid
        for cid, ct in sorted(world.cts.items())
        if ct.get("content_id") == content_id or cid == ref.get("ciphertext_id")
    ]
    if not candidates and ref.get("ciphertext_id") in world.cts:
        candidates = [ref["ciphertext_id"]]

    failures: list[dict[str, Any]] = []
    best: dict[str, Any] | None = None

    for cid in candidates:
        ct = world.cts.get(cid)
        if ct is None:
            failures.append({"ciphertext_id": cid, "reason": "ciphertext_record_absent"})
            continue
        if not ct.get("complete", True):
            failures.append({"ciphertext_id": cid, "reason": "incomplete_ciphertext"})
            continue
        original_domains = sorted(ct.get("domains", set()))
        if lost_domain:
            surviving = sorted(d for d in ct.get("domains", set()) if d == GLOBAL_DOMAIN or d != lost_domain)
        else:
            surviving = original_domains
        if not domains_survive_loss(ct.get("domains", set()), lost_domain):
            failures.append(
                {
                    "ciphertext_id": cid,
                    "reason": "ciphertext_only_copy_in_lost_domain",
                    "domains": original_domains,
                }
            )
            continue
        path = find_key_path(
            world,
            ct["key_ids"],
            lost_domain=lost_domain,
            anchor_revocations=anchor_revocations,
            anchor_tombstones=anchor_tombstones,
        )
        if path and not path.get("_not_found"):
            witness = {
                **base,
                "readable": True,
                "content_id": content_id,
                "ciphertext_id": cid,
                "ciphertext_domains": original_domains,
                "surviving_domains": surviving,
                "complete": True,
                **path,
                "proof": _format_proof(path),
            }
            if best is None or witness["length"] < best["length"]:
                best = witness
        else:
            failures.append(
                {
                    "ciphertext_id": cid,
                    "reason": "no_rooted_envelope_path_to_content_key",
                    "ciphertext_domains": original_domains,
                    "key_ids": ct["key_ids"],
                    "graph": path,
                }
            )

    if best is not None:
        return best

    return {
        **base,
        "readable": False,
        "content_id": content_id,
        "reason": failures[0]["reason"] if failures else "no_complete_ciphertext",
        "candidates_tried": failures[:5],
    }


def _format_proof(path: dict[str, Any]) -> str:
    nodes = path.get("nodes", [])
    edges = path.get("envelope_path", [])
    parts = [nodes[0]] if nodes else []
    for i, eid in enumerate(edges):
        parts.append(f"--{eid}-->")
        if i + 1 < len(nodes):
            parts.append(nodes[i + 1])
    return " ".join(parts)


def witnesses_for_refs(
    world: World,
    refs: list[dict[str, Any]],
    lost_domain: str | None = None,
    recovery_domain: str | None = None,
    anchor_revocations: dict[str, dict[str, Any]] | set[str] | None = None,
    anchor_tombstones: set[str] | dict[str, Any] | None = None,
) -> list[dict[str, Any]]:
    return [
        witness_ref(
            world,
            ref,
            lost_domain=lost_domain,
            recovery_domain=recovery_domain,
            anchor_revocations=anchor_revocations,
            anchor_tombstones=anchor_tombstones,
        )
        for ref in refs
    ]


def compact_ref(ref: dict[str, Any]) -> dict[str, Any]:
    return {
        "ref_id": ref["ref_id"],
        "ticket_id": ref["ticket_id"],
        "kind": ref["kind"],
        "snapshot": ref["snapshot"],
        "path": ref.get("path"),
        "ciphertext_id": ref.get("ciphertext_id"),
        "content_id": ref.get("content_id"),
    }
