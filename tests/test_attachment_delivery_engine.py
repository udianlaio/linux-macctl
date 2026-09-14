import hashlib
import json
from pathlib import Path
import tempfile
import unittest

from attachment_delivery_engine import (
    AdapterCapability,
    CHATGPT_CONVERSATION_FILE_RELAY,
    GRADE_A,
    GRADE_B,
    GRADE_C,
    GRADE_D,
    choose_adapter,
    delivery_probe,
    runtime_adapters_from_config,
)


def _write_live_grade_a_evidence(root: str) -> tuple[str, str]:
    obj = {
        "schema": "macctl-pm3-grade-a-live-qualification/v2",
        "status": "CLOSED_PASS_LIVE_GRADE_A_USER_VISIBLE_ATTACHMENT",
        "adapter": CHATGPT_CONVERSATION_FILE_RELAY,
        "surface": "chatgpt-ordinary-chat",
        "r1_evaluator": {
            "qualification_state": "GRADE_A_NATIVE_ATTACHMENT_QUALIFIED",
            "qualified": True,
            "production_grade_a_ready": True,
            "exact_host_receipt": True,
            "exact_redownload": True,
            "grade_a_blockers": [],
        },
        "user_visible_attachment": {
            "confirmed": True,
            "downloadable_attachment_visible": True,
            "explicit_user_feedback": True,
        },
    }
    path = Path(root) / "grade-a-evidence.json"
    data = json.dumps(obj, sort_keys=True, separators=(",", ":")).encode("utf-8")
    path.write_bytes(data)
    return str(path), hashlib.sha256(data).hexdigest()


class AttachmentDeliveryTests(unittest.TestCase):
    def test_default_production_is_truthfully_not_qualified(self):
        probe = delivery_probe()
        self.assertFalse(probe["production_grade_a_ready"])
        self.assertEqual(probe["current_production_state"], "NOT_YET_QUALIFIED")
        self.assertTrue(probe["debug_emergency_grade_a_ready"])

    def test_runtime_profile_stays_fail_closed_without_evidence(self):
        adapters = runtime_adapters_from_config({
            CHATGPT_CONVERSATION_FILE_RELAY: {
                "enabled": True,
                "surface": "chatgpt-ordinary-chat",
                "qualification_state": "GRADE_A_USER_VISIBLE_ATTACHMENT_QUALIFIED",
                "qualification_evidence_sha256": "bad",
            }
        })
        probe = delivery_probe(adapters)
        relay = next(a for a in adapters if a.name == CHATGPT_CONVERSATION_FILE_RELAY)
        self.assertTrue(relay.available)
        self.assertFalse(relay.qualified)
        self.assertFalse(probe["production_grade_a_ready"])

    def test_runtime_profile_live_grade_a_evidence_enables_production(self):
        with tempfile.TemporaryDirectory() as root:
            evidence_file, evidence_sha = _write_live_grade_a_evidence(root)
            adapters = runtime_adapters_from_config({
                CHATGPT_CONVERSATION_FILE_RELAY: {
                    "enabled": True,
                    "surface": "chatgpt-ordinary-chat",
                    "qualification_state": "GRADE_A_USER_VISIBLE_ATTACHMENT_QUALIFIED",
                    "qualification_evidence_file": evidence_file,
                    "qualification_evidence_sha256": evidence_sha,
                }
            }, evidence_root=root)
            probe = delivery_probe(adapters)
            plan = choose_adapter(adapters=adapters, presentation="attachment", original_required=True)
            self.assertTrue(probe["production_grade_a_ready"])
            self.assertEqual(probe["current_production_state"], "READY")
            self.assertEqual(plan["selected_adapter"], CHATGPT_CONVERSATION_FILE_RELAY)
            self.assertEqual(plan["success_grade"], GRADE_A)

    def test_backend_native_v1_evidence_never_enables_production_without_user_visible_confirmation(self):
        with tempfile.TemporaryDirectory() as root:
            evidence_file, _ = _write_live_grade_a_evidence(root)
            obj = json.loads(Path(evidence_file).read_text(encoding="utf-8"))
            obj["schema"] = "macctl-pm3-grade-a-live-qualification/v1"
            obj["status"] = "CLOSED_PASS_LIVE_GRADE_A_NATIVE_ATTACHMENT"
            obj.pop("user_visible_attachment", None)
            data = json.dumps(obj, sort_keys=True, separators=(",", ":")).encode("utf-8")
            Path(evidence_file).write_bytes(data)
            adapters = runtime_adapters_from_config({
                CHATGPT_CONVERSATION_FILE_RELAY: {
                    "enabled": True,
                    "surface": "chatgpt-ordinary-chat",
                    "qualification_state": "GRADE_A_USER_VISIBLE_ATTACHMENT_QUALIFIED",
                    "qualification_evidence_file": evidence_file,
                    "qualification_evidence_sha256": hashlib.sha256(data).hexdigest(),
                }
            }, evidence_root=root)
            self.assertFalse(delivery_probe(adapters)["production_grade_a_ready"])

    def test_v2_evidence_without_explicit_user_visible_feedback_fails_closed(self):
        with tempfile.TemporaryDirectory() as root:
            evidence_file, _ = _write_live_grade_a_evidence(root)
            obj = json.loads(Path(evidence_file).read_text(encoding="utf-8"))
            obj["user_visible_attachment"]["confirmed"] = False
            obj["user_visible_attachment"]["downloadable_attachment_visible"] = False
            obj["user_visible_attachment"]["explicit_user_feedback"] = True
            data = json.dumps(obj, sort_keys=True, separators=(",", ":")).encode("utf-8")
            Path(evidence_file).write_bytes(data)
            adapters = runtime_adapters_from_config({
                CHATGPT_CONVERSATION_FILE_RELAY: {
                    "enabled": True,
                    "surface": "chatgpt-ordinary-chat",
                    "qualification_state": "GRADE_A_USER_VISIBLE_ATTACHMENT_QUALIFIED",
                    "qualification_evidence_file": evidence_file,
                    "qualification_evidence_sha256": hashlib.sha256(data).hexdigest(),
                }
            }, evidence_root=root)
            self.assertFalse(delivery_probe(adapters)["production_grade_a_ready"])

    def test_runtime_profile_wrong_surface_does_not_qualify(self):
        with tempfile.TemporaryDirectory() as root:
            evidence_file, evidence_sha = _write_live_grade_a_evidence(root)
            adapters = runtime_adapters_from_config({
                CHATGPT_CONVERSATION_FILE_RELAY: {
                    "enabled": True,
                    "surface": "not-ordinary-chat",
                    "qualification_state": "GRADE_A_USER_VISIBLE_ATTACHMENT_QUALIFIED",
                    "qualification_evidence_file": evidence_file,
                    "qualification_evidence_sha256": evidence_sha,
                }
            }, evidence_root=root)
            probe = delivery_probe(adapters)
            self.assertFalse(probe["production_grade_a_ready"])

    def test_runtime_profile_tampered_evidence_fails_closed(self):
        with tempfile.TemporaryDirectory() as root:
            evidence_file, evidence_sha = _write_live_grade_a_evidence(root)
            Path(evidence_file).write_text("{}", encoding="utf-8")
            adapters = runtime_adapters_from_config({
                CHATGPT_CONVERSATION_FILE_RELAY: {
                    "enabled": True,
                    "surface": "chatgpt-ordinary-chat",
                    "qualification_state": "GRADE_A_USER_VISIBLE_ATTACHMENT_QUALIFIED",
                    "qualification_evidence_file": evidence_file,
                    "qualification_evidence_sha256": evidence_sha,
                }
            }, evidence_root=root)
            self.assertFalse(delivery_probe(adapters)["production_grade_a_ready"])

    def test_native_file_ref_is_preferred_when_qualified(self):
        adapters = (
            AdapterCapability("NATIVE", True, True, GRADE_A, inline_image=True, exact_original=True),
            AdapterCapability("RESOURCE", True, True, GRADE_C, exact_original=True),
        )
        plan = choose_adapter(adapters=adapters, presentation="both", original_required=True)
        self.assertEqual(plan["status"], "READY")
        self.assertEqual(plan["selected_adapter"], "NATIVE")
        self.assertTrue(plan["single_source_bytes"])
        self.assertFalse(plan["duplicate_full_payload_required"])

    def test_inline_only_cannot_satisfy_exact_original(self):
        adapters = (AdapterCapability("IMAGE", True, True, GRADE_B, inline_image=True, exact_original=False),)
        plan = choose_adapter(adapters=adapters, presentation="both", original_required=True)
        self.assertEqual(plan["status"], "NOT_YET_QUALIFIED")

    def test_attachment_presentation_never_accepts_grade_b_even_without_original_requirement(self):
        adapters = (AdapterCapability("IMAGE", True, True, GRADE_B, inline_image=True, exact_original=False),)
        plan = choose_adapter(adapters=adapters, presentation="attachment", original_required=False)
        self.assertEqual(plan["status"], "NOT_YET_QUALIFIED")

    def test_both_presentation_never_accepts_resource_link_even_without_original_requirement(self):
        adapters = (AdapterCapability("RESOURCE", True, True, GRADE_C, exact_original=True),)
        plan = choose_adapter(adapters=adapters, presentation="both", original_required=False)
        self.assertEqual(plan["status"], "NOT_YET_QUALIFIED")

    def test_inline_without_original_requirement_can_use_grade_b(self):
        adapters = (AdapterCapability("IMAGE", True, True, GRADE_B, inline_image=True, exact_original=False),)
        plan = choose_adapter(adapters=adapters, presentation="inline", original_required=False)
        self.assertEqual(plan["status"], "READY")
        self.assertEqual(plan["selected_adapter"], "IMAGE")
        self.assertEqual(plan["success_grade"], GRADE_B)

    def test_resource_link_does_not_magically_become_native_attachment(self):
        adapters = (AdapterCapability("RESOURCE", True, True, GRADE_C, exact_original=True),)
        plan = choose_adapter(adapters=adapters, presentation="attachment", original_required=True)
        self.assertEqual(plan["status"], "NOT_YET_QUALIFIED")

    def test_link_only_is_not_attachment_success(self):
        adapters = (AdapterCapability("HTTPS", True, True, GRADE_D, exact_original=True),)
        plan = choose_adapter(adapters=adapters, presentation="attachment", original_required=True)
        self.assertEqual(plan["status"], "NOT_YET_QUALIFIED")

    def test_debug_fallback_requires_explicit_opt_in(self):
        adapters = (AdapterCapability("PRIVATE_GITHUB_ACTIONS_ARTIFACT", True, True, GRADE_A, inline_image=True, exact_original=True),)
        blocked = choose_adapter(adapters=adapters, allow_debug_fallback=False)
        allowed = choose_adapter(adapters=adapters, allow_debug_fallback=True)
        self.assertEqual(blocked["status"], "NOT_YET_QUALIFIED")
        self.assertEqual(allowed["status"], "READY")


if __name__ == "__main__":
    unittest.main()
