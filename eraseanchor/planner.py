"""Exhaustive subset/order planner for at most 18 candidate actions."""

from __future__ import annotations

from typing import Any

from . import PLAN_SCHEMA_VERSION
from .engine import irreversible_boundaries, verify_actions
from .model import CaseError, World, build_refs, witness_ref, witnesses_for_refs


def find_content_conflicts(case: dict[str, Any]) -> list[dict[str, Any]]:
    """Find erase/preserve references sharing identical logical content.

    Dedup makes this conflict unconditional: any rooted witness that keeps the
    preserved content readable is necessarily a witness for the erase target.
    """

    refs = build_refs(case)
    preserve: dict[str, list[dict[str, Any]]] = {}
    erase: dict[str, list[dict[str, Any]]] = {}
    for ref in refs:
        cid = ref.get("content_id")
        if cid is None:
            continue
        target = preserve if ref["kind"] == "preserve" else erase
        target.setdefault(cid, []).append(ref)

    add_actions = [a for a in case["actions"] if a["type"] == "add_envelope"]
    add_by_envelope = {a["envelope_id"]: a["id"] for a in add_actions}
    maximal_world = World(case)
    for action in add_actions:
        # Commit all authorized additions to expose the best key graph offered
        # by the finite menu.  Do not apply revocations/deletions here.
        from .model import apply_action

        apply_action(maximal_world, action, "commit")

    conflicts: list[dict[str, Any]] = []
    for content_id in sorted(set(preserve) & set(erase)):
        p_refs = preserve[content_id]
        e_refs = erase[content_id]
        proof = None
        blocking = None
        for pref in p_refs:
            w = witness_ref(maximal_world, pref)
            if w.get("readable"):
                proof = w
                break
            blocking = w

        erase_proof = None
        required_actions: list[str] = []
        if proof is not None:
            for eid in proof.get("envelope_path", []):
                if eid in add_by_envelope:
                    required_actions.append(add_by_envelope[eid])
            # Recompute the corresponding erase witness in the same maximal
            # world; BFS gives the shortest proof for that reference.
            for eref in e_refs:
                ew = witness_ref(maximal_world, eref)
                if ew.get("readable"):
                    erase_proof = ew
                    break

        ct_ids = sorted(cid for cid, ct in case["ciphertexts"].items() if ct.get("content_id") == content_id)
        conflicts.append(
            {
                "content_id": content_id,
                "ciphertext_ids": ct_ids,
                "preserve_refs": [_public_ref(r) for r in p_refs],
                "erase_refs": [_public_ref(r) for r in e_refs],
                "readable_proof": proof,
                "erase_readable_proof": erase_proof,
                "minimal_required_add_actions": sorted(set(required_actions)),
                "preservation_readable_with_menu": proof is not None,
                "blocking_witness": None if proof is not None else blocking,
                "reason": (
                    "preserve and erase tickets bind the same deduplicated logical content; "
                    "any complete ciphertext plus rooted key witness for preservation also "
                    "makes the erase target readable"
                ),
            }
        )
    return conflicts


def _public_ref(ref: dict[str, Any]) -> dict[str, Any]:
    return {
        "ref_id": ref["ref_id"],
        "ticket_id": ref["ticket_id"],
        "kind": ref["kind"],
        "snapshot": ref["snapshot"],
        "path": ref.get("path"),
        "ciphertext_id": ref.get("ciphertext_id"),
        "content_id": ref.get("content_id"),
    }


class FastNormalGoal:
    """Bitset reachability pre-filter for final normal-state goals.

    The full witness/verifier remains authoritative.  This lets the exhaustive
    2^18 search skip subsets that cannot even satisfy ordinary readability.
    """

    def __init__(self, case: dict[str, Any], refs: list[dict[str, Any]]):
        self.case = case
        self.refs = refs
        node_ids: set[str] = set()
        for rid, root in case["roots"].items():
            node_ids.add(rid)
        for env in case["envelopes"].values():
            node_ids.add(env["wrapper"])
            node_ids.add(env["wrapped"])
        for ct in case["ciphertexts"].values():
            node_ids.update(ct["key_ids"])
        for a in case["actions"]:
            if a["type"] == "add_envelope":
                node_ids.add(a["envelope"]["wrapper"])
                node_ids.add(a["envelope"]["wrapped"])
            elif a["type"] == "revoke_root":
                node_ids.add(a["root_id"])
        self.node_index = {nid: i for i, nid in enumerate(sorted(node_ids))}

        self.eid_bit: dict[str, int] = {}
        edges: list[tuple[int, int, int]] = []
        eids = set(case["envelopes"])
        for a in case["actions"]:
            if a["type"] == "add_envelope":
                eids.add(a["envelope_id"])
        for bit_index, eid in enumerate(sorted(eids)):
            self.eid_bit[eid] = 1 << bit_index

        for eid, env in case["envelopes"].items():
            self._add_edge(edges, eid, env["wrapper"], env["wrapped"])
        for a in case["actions"]:
            if a["type"] == "add_envelope":
                env = a["envelope"]
                self._add_edge(edges, a["envelope_id"], env["wrapper"], env["wrapped"])

        self.adjacency: dict[int, list[tuple[int, int]]] = {}
        for u, v, ebit in edges:
            self.adjacency.setdefault(u, []).append((v, ebit))

        self.root_start_bits = 0
        for rid, root in case["roots"].items():
            if root.get("persisted", True):
                self.root_start_bits |= self._node_bit(rid)
        for a in case["actions"]:
            if a["type"] == "revoke_root":
                rid = a["root_id"]
                baseline_root = case["roots"].get(rid)
                if baseline_root is None or baseline_root.get("persisted", True):
                    self.root_start_bits |= self._node_bit(rid)

        self.content_key_bits: dict[str, int] = {}
        for ct in case["ciphertexts"].values():
            if not ct.get("complete", True):
                continue
            bits = 0
            for kid in ct["key_ids"]:
                bits |= self._node_bit(kid)
            self.content_key_bits[ct["content_id"]] = (
                self.content_key_bits.get(ct["content_id"], 0) | bits
            )

    def _node_bit(self, node_id: str) -> int:
        if node_id not in self.node_index:
            idx = len(self.node_index)
            self.node_index[node_id] = idx
        return 1 << self.node_index[node_id]

    def _add_edge(self, edges: list[tuple[int, int, int]], eid: str, wrapper: str, wrapped: str) -> None:
        ebit = self.eid_bit[eid]
        u = self.node_index[wrapper]
        v = self.node_index[wrapped]
        edges.append((u, v, ebit))

    def _reachable(self, active_envelopes: int, start_bits: int) -> int:
        reached = start_bits
        queue = []
        bits = start_bits
        while bits:
            bit = bits & -bits
            queue.append(bit.bit_length() - 1)
            bits -= bit
        seen_nodes = reached
        while queue:
            u = queue.pop()
            for v, ebit in self.adjacency.get(u, []):
                if not (active_envelopes & ebit):
                    continue
                vbit = 1 << v
                if reached & vbit:
                    continue
                reached |= vbit
                if not (seen_nodes & vbit):
                    queue.append(v)
                    seen_nodes |= vbit
        return reached

    def goal_ok(self, order: tuple[int, ...]) -> bool:
        active_envelopes = 0
        for eid in self.case["envelopes"]:
            active_envelopes |= self.eid_bit[eid]
        start_bits = self.root_start_bits

        actions = self.case["actions"]
        for i in order:
            a = actions[i]
            atype = a["type"]
            if atype == "add_envelope":
                active_envelopes |= self.eid_bit[a["envelope_id"]]
            elif atype == "delete_envelope":
                active_envelopes &= ~self.eid_bit[a["envelope_id"]]
            elif atype == "revoke_root":
                start_bits &= ~self._node_bit(a["root_id"])

        reached = self._reachable(active_envelopes, start_bits)
        for ref in self.refs:
            content_id = ref.get("content_id")
            if content_id is None:
                readable = False
            else:
                key_bits = self.content_key_bits.get(content_id, 0)
                readable = bool(key_bits & reached)
            if ref["kind"] == "preserve" and not readable:
                return False
            if ref["kind"] == "erase" and readable:
                return False
        return True


def diagnose_infeasibility(case: dict[str, Any]) -> dict[str, Any]:
    """Provide baseline witnesses for an exhaustively proven no-plan result."""

    refs = build_refs(case)
    world = World(case)
    witnesses = witnesses_for_refs(world, refs)
    preserve_proofs = [w for w in witnesses if w["ref"]["kind"] == "preserve" and w.get("readable")]
    preserve_failures = [w for w in witnesses if w["ref"]["kind"] == "preserve" and not w.get("readable")]
    erase_proofs = [w for w in witnesses if w["ref"]["kind"] == "erase" and w.get("readable")]

    shared_nodes: set[str] = set()
    shared_envelopes: set[str] = set()
    for pw in preserve_proofs:
        pnodes = set(pw.get("nodes", []))
        pedges = set(pw.get("envelope_path", []))
        for ew in erase_proofs:
            shared_nodes.update(pnodes & set(ew.get("nodes", [])))
            shared_envelopes.update(pedges & set(ew.get("envelope_path", [])))

    return {
        "kind": "no_feasible_candidate_sequence",
        "statement": (
            "The finite action menu was exhaustively searched. The baseline "
            "witnesses below identify the protected and erase targets; shared "
            "nodes/edges explain why a root or envelope action can expose both."
        ),
        "shared_proof_nodes": sorted(shared_nodes),
        "shared_envelope_ids": sorted(shared_envelopes),
        "preserve_readable_proofs": preserve_proofs[:5],
        "preservation_unreadable_proofs": preserve_failures[:5],
        "erase_readable_proofs": erase_proofs[:5],
    }


def _dependency_masks(case: dict[str, Any]) -> list[int]:
    ids = {a["id"]: i for i, a in enumerate(case["actions"])}
    masks = [0] * len(case["actions"])
    for i, a in enumerate(case["actions"]):
        mask = 0
        for req in a.get("requires", []):
            if req not in ids:
                raise CaseError(f"action {a['id']!r} requires unknown action {req!r}")
            mask |= 1 << ids[req]
        masks[i] = mask
    return masks


def _natural_allowed(
    action: dict[str, Any],
    prev_mask: int,
    ctx: dict[str, Any],
) -> bool:
    atype = action["type"]
    if atype == "delete_envelope":
        eid = action["envelope_id"]
        exists_baseline = eid in ctx["baseline_envelopes"]
        added = bool(prev_mask & ctx["add_envelope_masks"].get(eid, 0))
        deleted_before = bool(prev_mask & ctx["delete_envelope_masks"].get(eid, 0))
        if deleted_before:
            return False
        return exists_baseline or added
    if atype == "revoke_root":
        rid = action["root_id"]
        return not bool(prev_mask & ctx["revoke_root_masks"].get(rid, 0))
    if atype == "add_envelope":
        eid = action["envelope_id"]
        if eid in ctx["baseline_envelopes"] and not action.get("or_exists", False):
            # Re-adding after an explicitly ordered deletion is a legal state
            # transition, though unusual.
            return bool(prev_mask & ctx["delete_envelope_masks"].get(eid, 0))
        return True
    return True


def enumerate_orders(case: dict[str, Any]) -> tuple[list[tuple[int, ...] | None], dict[str, Any]]:
    actions = case["actions"]
    n = len(actions)
    req_masks = _dependency_masks(case)

    add_env_masks: dict[str, int] = {}
    delete_env_masks: dict[str, int] = {}
    revoke_root_masks: dict[str, int] = {}
    for i, a in enumerate(actions):
        bit = 1 << i
        if a["type"] == "add_envelope":
            add_env_masks[a["envelope_id"]] = add_env_masks.get(a["envelope_id"], 0) | bit
        elif a["type"] == "delete_envelope":
            delete_env_masks[a["envelope_id"]] = delete_env_masks.get(a["envelope_id"], 0) | bit
        elif a["type"] == "revoke_root":
            revoke_root_masks[a["root_id"]] = revoke_root_masks.get(a["root_id"], 0) | bit

    ctx = {
        "baseline_envelopes": set(case["envelopes"]),
        "add_envelope_masks": add_env_masks,
        "delete_envelope_masks": delete_env_masks,
        "revoke_root_masks": revoke_root_masks,
    }

    size = 1 << n
    dp: list[tuple[int, ...] | None] = [None] * size
    dp[0] = ()
    for mask in range(1, size):
        best: tuple[int, ...] | None = None
        bits = mask
        while bits:
            bit = bits & -bits
            i = bit.bit_length() - 1
            prev = mask ^ bit
            prefix = dp[prev]
            if prefix is not None:
                deps_ok = (req_masks[i] & prev) == req_masks[i]
                if deps_ok and _natural_allowed(actions[i], prev, ctx):
                    candidate = prefix + (i,)
                    if best is None or candidate < best:
                        best = candidate
            bits -= bit
        dp[mask] = best
    return dp, ctx


def _plan_document(
    case: dict[str, Any],
    action_ids: list[str],
    *,
    rank: int,
    total_cost: float | int,
    verdict: dict[str, Any],
) -> dict[str, Any]:
    refs = build_refs(case)
    boundaries = irreversible_boundaries(case, action_ids, refs)
    ordered_actions = [_public_action(case["action_by_id"][aid]) for aid in action_ids]
    return {
        "plan_id": f"plan-{rank:04d}-" + "-".join(action_ids),
        "rank": rank,
        "action_ids": list(action_ids),
        "actions": ordered_actions,
        "total_cost": total_cost,
        "action_count": len(action_ids),
        "ranking_key": [total_cost, len(action_ids), list(action_ids)],
        "irreversible_boundary_count": len(boundaries),
        "irreversible_boundaries": boundaries,
        "robustness": {
            "ok": verdict["ok"],
            "checks": verdict.get("checks", {}),
        },
        "final_witnesses": verdict.get("final_witnesses", []),
        "power_boundaries": verdict.get("power_boundaries", []),
    }


def _public_action(action: dict[str, Any]) -> dict[str, Any]:
    keys = [
        "id",
        "type",
        "cost",
        "requires",
        "migration_dependencies",
        "ciphertext_id",
        "add_domains",
        "remove_domains",
        "write_domains",
        "envelope_id",
        "envelope",
        "root_id",
        "revocation_id",
        "record_domains",
        "persistent_anchor",
        "irreversible",
    ]
    return {k: action[k] for k in keys if k in action}


def plan_case(
    case: dict[str, Any],
    *,
    plan_limit: int = 1,
    rank_limit: int = 25,
    verify: bool = True,
) -> dict[str, Any]:
    conflicts = find_content_conflicts(case)
    actions = case["actions"]
    n = len(actions)

    if conflicts:
        return {
            "schema": PLAN_SCHEMA_VERSION,
            "case_id": case["case_id"],
            "ok": True,
            "feasible": False,
            "status": "conflict",
            "candidate_action_count": n,
            "order_valid_plan_count": 0,
            "ranking": [],
            "conflicts": conflicts,
            "optimal": None,
            "plans": [],
            "stats": {
                "subsets_examined": 1 << n,
                "order_valid_plans": 0,
                "robust_plans_verified": 0,
            },
            "message": "preservation/erasure conflict has a minimal readability proof",
        }

    dp, _ctx = enumerate_orders(case)

    rankings: list[dict[str, Any]] = []
    for mask, order in enumerate(dp):
        if order is None:
            continue
        aids = [actions[i]["id"] for i in order]
        cost = sum(actions[i]["cost"] for i in order)
        rankings.append(
            {
                "mask": mask,
                "action_ids": aids,
                "total_cost": cost,
                "action_count": len(aids),
                "ranking_key": [cost, len(aids), aids],
            }
        )
    rankings.sort(key=lambda r: (r["total_cost"], r["action_count"], tuple(r["action_ids"])))

    top_ranking = [
        {k: v for k, v in r.items() if k != "mask"} for r in rankings[: max(0, rank_limit)]
    ]

    base = {
        "schema": PLAN_SCHEMA_VERSION,
        "case_id": case["case_id"],
        "candidate_action_count": n,
        "order_valid_plan_count": len(rankings),
        "ranking": top_ranking,
        "conflicts": conflicts,
    }

    feasible_plans: list[dict[str, Any]] = []
    verified = 0
    normal_goal_candidates = 0
    first_failure: dict[str, Any] | None = None
    refs = build_refs(case)
    fast_goal = FastNormalGoal(case, refs)
    for rank, candidate in enumerate(rankings, 1):
        aids = candidate["action_ids"]
        order = dp[candidate["mask"]]
        assert order is not None
        if not fast_goal.goal_ok(order):
            continue
        normal_goal_candidates += 1
        if verify:
            verdict = verify_actions(case, aids, early_on_goal_failure=True)
            verified += 1
            if not verdict["ok"]:
                if first_failure is None:
                    first_failure = {
                        "action_ids": aids,
                        "total_cost": candidate["total_cost"],
                        "violation_count": verdict["violation_count"],
                        "violations": verdict["violations"][:10],
                    }
                continue
        else:
            verdict = {"ok": True, "checks": {}, "final_witnesses": [], "power_boundaries": []}
        doc = _plan_document(
            case,
            aids,
            rank=len(feasible_plans) + 1,
            total_cost=candidate["total_cost"],
            verdict=verdict,
        )
        feasible_plans.append(doc)
        if len(feasible_plans) >= plan_limit:
            break

    if feasible_plans:
        optimal = feasible_plans[0]
        return {
            **base,
            "ok": True,
            "feasible": True,
            "status": "feasible",
            "optimal": optimal,
            "plans": feasible_plans,
            "stats": {
                "subsets_examined": 1 << n,
                "order_valid_plans": len(rankings),
                "normal_goal_candidates": normal_goal_candidates,
                "robust_plans_verified": verified,
            },
        }

    if first_failure is None:
        baseline_verdict = verify_actions(case, [], early_on_goal_failure=True)
        first_failure = {
            "action_ids": [],
            "total_cost": 0,
            "violation_count": baseline_verdict["violation_count"],
            "violations": baseline_verdict["violations"][:10],
            "note": "no action subset reached the normal readability goal",
        }

    return {
        **base,
        "ok": True,
        "feasible": False,
        "status": "infeasible",
        "optimal": None,
        "plans": [],
        "first_failure": first_failure,
        "infeasibility_proof": diagnose_infeasibility(case),
        "stats": {
            "subsets_examined": 1 << n,
            "order_valid_plans": len(rankings),
            "normal_goal_candidates": normal_goal_candidates,
            "robust_plans_verified": verified,
        },
        "message": "no candidate subset/order satisfies preservation and robust erasure",
    }
