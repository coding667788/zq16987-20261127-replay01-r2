from __future__ import annotations

import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from eraseanchor.engine import (  # noqa: E402
    domain_scan,
    replay_all_boundaries,
    simulate_boundary,
    verify_actions,
)
from eraseanchor.model import (  # noqa: E402
    World,
    build_refs,
    load_json_file,
    normalize_case,
    resolve_snapshot,
    state_for_actions,
    witnesses_for_refs,
)
from eraseanchor.planner import plan_case  # noqa: E402

FIXTURES = ROOT / "fixtures"


def case(name: str):
    return normalize_case(load_json_file(FIXTURES / name))


class ModelTests(unittest.TestCase):
    def test_cow_snapshot_inheritance_and_logical_deletion(self):
        c = case("cow_hold_erase.json")
        base = resolve_snapshot(c, "snap-base")
        weekly = resolve_snapshot(c, "snap-weekly")
        daily = resolve_snapshot(c, "snap-daily")
        current = resolve_snapshot(c, "snap-current")

        self.assertEqual(base["/accounts.dat"], "ct-accounts")
        self.assertEqual(weekly["/accounts.dat"], "ct-accounts")
        self.assertEqual(weekly["/stale.log"], "ct-stale")
        self.assertEqual(daily["/temp.log"], "ct-temp")
        # A COW tombstone masks the inherited name in this version.
        self.assertNotIn("/stale.log", daily)
        # Deleting the logical name in current does not erase daily's version.
        self.assertNotIn("/temp.log", current)
        self.assertEqual(daily["/temp.log"], "ct-temp")
        # Content deduplication is explicit through shared ciphertext IDs.
        self.assertEqual(base["/accounts.dat"], weekly["/accounts.dat"])

    def test_envelope_cycle_with_and_without_root_entry(self):
        c = case("key_cycle.json")
        refs = build_refs(c)
        w = World(c)
        witnesses = witnesses_for_refs(w, refs)
        by_kind_path = {(x["ref"]["kind"], x["ref"]["path"]): x for x in witnesses}

        reachable = by_kind_path[("preserve", "/reachable-cycle.bin")]
        isolated = by_kind_path[("erase", "/isolated-cycle.bin")]

        self.assertTrue(reachable["readable"], reachable)
        self.assertEqual(reachable["root_id"], "root-entry")
        self.assertIn("env-a-b", reachable["envelope_path"])
        self.assertFalse(isolated["readable"])
        self.assertEqual(isolated["reason"], "no_rooted_envelope_path_to_content_key")
        graph = isolated["candidates_tried"][0]["graph"]
        self.assertNotIn("key-x", graph["reachable_nodes"])
        self.assertNotIn("key-y", graph["reachable_nodes"])


class PlannerTests(unittest.TestCase):
    def test_cow_optimal_plan_and_sorting(self):
        c = case("cow_hold_erase.json")
        result = plan_case(c)
        self.assertEqual(result["status"], "feasible")
        self.assertTrue(result["feasible"])
        ids = result["optimal"]["action_ids"]
        self.assertEqual(ids, ["a01-migrate-accounts", "a03-delete-temp-safe"])
        self.assertEqual(result["optimal"]["total_cost"], 5)

        keys = [tuple(r["ranking_key"]) for r in result["ranking"]]
        self.assertEqual(keys, sorted(keys))

        boundaries = result["optimal"]["irreversible_boundaries"]
        self.assertEqual(len(boundaries), 1)
        b = boundaries[0]
        self.assertEqual(b["action_id"], "a03-delete-temp-safe")
        self.assertTrue(b["before_all_holds_readable"])
        self.assertTrue(b["after_all_holds_readable"])
        self.assertTrue(b["after_all_erase_targets_unreadable"])

    def test_root_revocation_uses_safe_anchor_and_dependency_order(self):
        c = case("root_revocation.json")
        result = plan_case(c)
        self.assertEqual(result["status"], "feasible", result.get("first_failure"))
        ids = result["optimal"]["action_ids"]
        self.assertEqual(
            ids,
            ["a01-migrate-keep", "a02-add-keep-envelope", "a03-revoke-shared-safe"],
        )
        positions = {aid: i for i, aid in enumerate(ids)}
        self.assertLess(positions["a01-migrate-keep"], positions["a03-revoke-shared-safe"])
        self.assertLess(positions["a02-add-keep-envelope"], positions["a03-revoke-shared-safe"])

        verdict = verify_actions(c, ids)
        self.assertTrue(verdict["ok"], verdict["violations"][:3])

        bad_order = ["a03-revoke-shared-safe", "a01-migrate-keep", "a02-add-keep-envelope"]
        bad = verify_actions(c, bad_order)
        self.assertFalse(bad["ok"])
        codes = {v["code"] for v in bad["violations"]}
        self.assertIn("missing_dependency_order", codes)

    def test_unsafe_single_domain_revocation_is_rejected(self):
        c = case("root_revocation.json")
        unsafe_ids = ["a01-migrate-keep", "a02-add-keep-envelope", "a04-revoke-shared-unsafe"]
        verdict = verify_actions(c, unsafe_ids)
        self.assertFalse(verdict["ok"])
        codes = {v["code"] for v in verdict["violations"]}
        self.assertIn("revocation_record_does_not_survive_domain_loss", codes)

    def test_all_envelope_paths_must_be_severed_with_tie_order(self):
        c = case("multiple_paths.json")
        result = plan_case(c)
        self.assertEqual(result["status"], "feasible", result.get("first_failure"))
        self.assertEqual(
            result["optimal"]["action_ids"],
            ["a01-delete-path-a", "a02-delete-path-b-dek"],
        )
        # Deleting only the shortest direct path leaves the second path live.
        one_path = verify_actions(c, ["a01-delete-path-a"])
        self.assertFalse(one_path["ok"])
        self.assertTrue(
            any(v["code"] == "erase_target_readable" for v in one_path["violations"])
        )

    def test_shared_dedup_conflict_has_minimal_proof(self):
        c = case("shared_block_conflict.json")
        result = plan_case(c)
        self.assertEqual(result["status"], "conflict")
        self.assertFalse(result["feasible"])
        self.assertIsNone(result["optimal"])
        conflict = result["conflicts"][0]
        self.assertEqual(conflict["content_id"], "same-logical-record-9")
        proof = conflict["readable_proof"]
        self.assertTrue(proof["readable"])
        self.assertEqual(proof["root_id"], "root-a")
        self.assertEqual(proof["envelope_path"], ["env-root-shared"])
        self.assertTrue(conflict["erase_readable_proof"]["readable"])
        self.assertGreaterEqual(len(conflict["preserve_refs"]), 1)
        self.assertGreaterEqual(len(conflict["erase_refs"]), 1)


class ReplayFaultTests(unittest.TestCase):
    def test_every_power_boundary_with_real_journal_files(self):
        c = case("root_revocation.json")
        ids = ["a01-migrate-keep", "a02-add-keep-envelope", "a03-revoke-shared-safe"]
        events_count = 5  # data_write + commit + add + revoke + commitment

        with tempfile.TemporaryDirectory(prefix="eraseanchor-test-") as td:
            root = Path(td)
            for boundary in range(events_count + 1):
                journal = root / f"b{boundary}.jsonl"
                r = simulate_boundary(c, ids, boundary, journal)
                self.assertTrue(r["ok"], r["violations"])
                self.assertTrue(r["hash_chain_valid"])
                self.assertTrue(journal.exists())
                lines = [ln for ln in journal.read_text(encoding="utf-8").splitlines() if ln]
                self.assertGreater(len(lines), 0)
                for line in lines:
                    json.loads(line)

            all_r = replay_all_boundaries(c, ids, root / "all")
            self.assertTrue(all_r["ok"])
            self.assertEqual(all_r["boundary_count"], events_count + 1)

    def test_remove_each_single_failure_domain(self):
        c = case("root_revocation.json")
        ids = ["a01-migrate-keep", "a02-add-keep-envelope", "a03-revoke-shared-safe"]
        refs = build_refs(c)
        w = state_for_actions(c, ids)

        for domain in c["domains"]:
            witnesses = witnesses_for_refs(w, refs, lost_domain=domain)
            for wit in witnesses:
                if wit["ref"]["kind"] == "preserve":
                    self.assertTrue(wit["readable"], (domain, wit))
                else:
                    self.assertFalse(wit["readable"], (domain, wit))

        scan = domain_scan(c, ids, refs)
        self.assertEqual(scan["violations"], [])
        self.assertGreater(scan["recovery_image_count"], len(c["domains"]))

    def test_cow_fixture_survives_power_and_domain_removal(self):
        c = case("cow_hold_erase.json")
        ids = ["a01-migrate-accounts", "a03-delete-temp-safe"]
        verdict = verify_actions(c, ids)
        self.assertTrue(verdict["ok"], verdict["violations"][:5])

    def test_maximum_sizes_respected(self):
        for name in [
            "cow_hold_erase.json",
            "root_revocation.json",
            "shared_block_conflict.json",
            "key_cycle.json",
        ]:
            c = case(name)
            self.assertLessEqual(len(c["actions"]), 18)
            self.assertLessEqual(len(c["domains"]), 6)


class CliTests(unittest.TestCase):
    def run_cli(self, *args: Path | str) -> subprocess.CompletedProcess[str]:
        return subprocess.run(
            [sys.executable, "-m", "eraseanchor", *map(str, args)],
            cwd=ROOT,
            capture_output=True,
            text=True,
            encoding="utf-8",
            check=False,
        )

    def test_plan_replay_verify_json_cli(self):
        with tempfile.TemporaryDirectory(prefix="eraseanchor-cli-") as td:
            td = Path(td)
            case_path = FIXTURES / "cow_hold_erase.json"
            plan_path = td / "plan.json"
            replay_path = td / "replay.json"
            verify_path = td / "verify.json"
            journal_dir = td / "journals"

            p = self.run_cli("plan", "--case", case_path, "--out", plan_path)
            self.assertEqual(p.returncode, 0, p.stderr)
            plan = json.loads(p.stdout)
            self.assertTrue(plan["feasible"])
            self.assertTrue(plan_path.exists())

            r = self.run_cli(
                "replay",
                "--case",
                case_path,
                "--plan",
                plan_path,
                "--all-boundaries",
                "--journal-dir",
                journal_dir,
                "--out",
                replay_path,
            )
            self.assertEqual(r.returncode, 0, r.stderr)
            replay = json.loads(r.stdout)
            self.assertTrue(replay["ok"])
            self.assertTrue(replay_path.exists())

            v = self.run_cli(
                "verify",
                "--case",
                case_path,
                "--plan",
                plan_path,
                "--replay",
                replay_path,
                "--out",
                verify_path,
            )
            self.assertEqual(v.returncode, 0, v.stderr)
            verified = json.loads(v.stdout)
            self.assertTrue(verified["ok"], verified.get("violations"))

            journals = list(journal_dir.glob("*.jsonl"))
            self.assertGreater(len(journals), 0)

    def test_manual_crash_and_resume_journal(self):
        with tempfile.TemporaryDirectory(prefix="eraseanchor-manual-") as td:
            td = Path(td)
            journal = td / "manual.jsonl"
            actions = ",".join(
                [
                    "a01-migrate-keep",
                    "a02-add-keep-envelope",
                    "a03-revoke-shared-safe",
                ]
            )
            crash = self.run_cli(
                "replay",
                "--case",
                FIXTURES / "root_revocation.json",
                "--actions",
                actions,
                "--crash-after",
                "1",
                "--journal",
                journal,
            )
            self.assertEqual(crash.returncode, 0, crash.stderr)
            crash_doc = json.loads(crash.stdout)
            self.assertEqual(crash_doc["status"], "power_lost")
            self.assertEqual(len(journal.read_text(encoding="utf-8").splitlines()), 1)

            resume = self.run_cli(
                "replay",
                "--case",
                FIXTURES / "root_revocation.json",
                "--actions",
                actions,
                "--resume",
                "--journal",
                journal,
            )
            self.assertEqual(resume.returncode, 0, resume.stderr)
            doc = json.loads(resume.stdout)
            self.assertTrue(doc["ok"], doc.get("violations"))
            self.assertIn("a01-migrate-keep", doc["pending_data_writes_at_recovery"])
            self.assertGreater(len(journal.read_text(encoding="utf-8").splitlines()), 1)

    def test_conflict_verify_cli(self):
        with tempfile.TemporaryDirectory(prefix="eraseanchor-conflict-") as td:
            plan_path = Path(td) / "conflict-plan.json"
            p = self.run_cli(
                "plan",
                "--case",
                FIXTURES / "shared_block_conflict.json",
                "--out",
                plan_path,
            )
            self.assertEqual(p.returncode, 0, p.stderr)
            v = self.run_cli(
                "verify",
                "--case",
                FIXTURES / "shared_block_conflict.json",
                "--plan",
                plan_path,
            )
            self.assertEqual(v.returncode, 0, v.stderr)
            doc = json.loads(v.stdout)
            self.assertEqual(doc["status"], "conflict_verified")
            self.assertTrue(doc["ok"])


if __name__ == "__main__":
    unittest.main(verbosity=2)
