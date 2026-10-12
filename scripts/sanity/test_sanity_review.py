"""Offline tests for sanity_review.py (no API calls). Run:
python3 -m unittest discover -s scripts/sanity
"""

import json
import unittest
from unittest import mock

import sanity_review as sr


def resp(out, stop="end_turn"):
    return {"stop_reason": stop, "model": "m", "usage": {"input_tokens": 1, "output_tokens": 1},
            "content": [{"type": "thinking", "thinking": ""},
                        {"type": "text", "text": json.dumps(out) if isinstance(out, dict) else out}]}


def finding(sev):
    return {"severity": sev, "location": "a.go:1", "issue": "x"}


class ParseResponse(unittest.TestCase):
    def test_block_needs_a_block_finding(self):
        s = sr.parse_response(resp({"findings": [finding("WARN")], "verdict": "BLOCK"}))
        self.assertEqual(s["verdict"], "WARN")

    def test_block_finding_blocks_even_if_verdict_disagrees(self):
        s = sr.parse_response(resp({"findings": [finding("BLOCK")], "verdict": "WARN"}))
        self.assertEqual(s["verdict"], "BLOCK")

    def test_no_findings_is_pass(self):
        s = sr.parse_response(resp({"findings": [], "verdict": "PASS"}))
        self.assertEqual((s["verdict"], s["status"]), ("PASS", "ok"))

    def test_refusal_and_bad_json_are_ai_errors(self):
        self.assertEqual(sr.parse_response(resp({}, stop="refusal"))["status"], "ai_error")
        self.assertEqual(sr.parse_response(resp("not json"))["status"], "ai_error")

    def test_legacy_reads_last_verdict_line(self):
        s = sr.parse_response(resp("VERDICT: BLOCK\nno wait\nVERDICT: PASS"), legacy=True)
        self.assertEqual(s["verdict"], "PASS")


class BuildMessages(unittest.TestCase):
    def test_diff_is_inline_and_fenced(self):
        system, user = sr.build_messages("criteria", "diff --git a/x b/x\n+1\n", ["go.sum"], "o/r", 3)
        self.assertTrue(system.startswith("criteria"))
        self.assertIn("untrusted data", system)
        self.assertIn("<diff>\ndiff --git a/x b/x\n+1\n</diff>", user)
        self.assertIn("- go.sum", user)

    def test_diff_is_capped(self):
        _, user = sr.build_messages("c", "+" + "x" * (sr.MAX_DIFF_BYTES + 10), [], "o/r", 1)
        self.assertIn("[diff truncated at", user)

    def test_request_shape_per_model(self):
        b = sr.build_request("claude-sonnet-5-5", "s", "u", effort="medium")
        self.assertEqual(b["output_config"]["effort"], "medium")
        self.assertEqual(b["output_config"]["format"]["type"], "json_schema")
        self.assertNotIn("temperature", b)
        b = sr.build_request("claude-haiku-4-5", "s", "u", effort="medium", temperature=0.0)
        self.assertEqual(b["temperature"], 0.0)
        self.assertNotIn("effort", b["output_config"])


class ConfirmBlock(unittest.TestCase):
    def run_with(self, verdicts, confirm=True):
        samples = [{"verdict": v, "status": "ok", "findings": [], "usage": {}} for v in verdicts]
        with mock.patch.object(sr, "review_once", side_effect=samples) as m:
            out = sr.review("claude-sonnet-5-5", "s", "u", "k", confirm_block=confirm)
        return out["verdict"], m.call_count

    def test_off_by_default_single_call(self):
        self.assertEqual(self.run_with(["BLOCK"], confirm=False), ("BLOCK", 1))

    def test_confirmed_block(self):
        self.assertEqual(self.run_with(["BLOCK", "BLOCK"]), ("BLOCK", 2))

    def test_split_goes_to_third_sample(self):
        self.assertEqual(self.run_with(["BLOCK", "WARN", "BLOCK"]), ("BLOCK", 3))
        self.assertEqual(self.run_with(["BLOCK", "PASS", "WARN"]), ("WARN", 3))

    def test_pass_needs_one_call(self):
        self.assertEqual(self.run_with(["PASS"]), ("PASS", 1))


if __name__ == "__main__":
    unittest.main()
