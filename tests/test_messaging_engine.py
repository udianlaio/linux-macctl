from pathlib import Path
import os
import tempfile
import unittest

from linux_macctl.messaging_engine import (
    MessagingError,
    MessagingStore,
    binding_id,
    build_binding,
    build_draft,
    contact_sha256,
    evaluate_action,
    detect_provider_login_state,
    exact_text_candidates,
    load_message_file,
    token_region_evidence,
    visual_token_matches,
    visible_region_texts,
    public_binding,
    select_header_candidate,
    validate_message_bytes,
    validate_selected_contact,
    vision_box_to_screen,
)


class MessagingContractTests(unittest.TestCase):
    def test_binding_is_stable_and_provider_scoped(self):
        a = build_binding("wechat", "测试联系人甲", allow_send=True, created_at=1)
        b = build_binding("wechat", "测试联系人甲", allow_send=True, created_at=2)
        self.assertEqual(a["binding_id"], b["binding_id"])
        self.assertTrue(a["binding_id"].startswith("msgb_"))
        self.assertNotEqual(contact_sha256("wechat", "测试联系人甲"), contact_sha256("feishu", "测试联系人甲"))

    def test_message_body_is_never_in_draft_record(self):
        body = "R5 测试消息 ✅".encode()
        meta = validate_message_bytes(body)
        binding = build_binding("wechat", "测试联系人甲", allow_send=True, created_at=1)
        draft = build_draft(binding, meta, created_at=2)
        self.assertEqual(draft["message_sha256"], meta["sha256"])
        self.assertNotIn("text", draft)
        self.assertNotIn("message", {k for k in draft if k == "message"})
        self.assertNotIn(body.decode(), str(draft))

    def test_send_requires_binding_scope_exact_contact_confirmation_and_dedupe(self):
        binding = build_binding("wechat", "测试联系人甲", allow_send=True, created_at=1)
        sha = "a" * 64
        self.assertFalse(evaluate_action(binding, "send", selected_contact="测试联系人甲", confirm=False, message_sha256=sha)["allowed"])
        self.assertFalse(evaluate_action(binding, "send", selected_contact="别人", confirm=True, message_sha256=sha)["allowed"])
        self.assertFalse(evaluate_action(binding, "send", selected_contact="测试联系人甲", confirm=True, message_sha256=sha, prior_sent_sha256={sha})["allowed"])
        self.assertTrue(evaluate_action(binding, "send", selected_contact="测试联系人甲", confirm=True, message_sha256=sha, prior_sent_sha256=set())["allowed"])

    def test_read_draft_send_are_independently_scoped(self):
        binding = build_binding("wechat", "测试联系人甲", allow_read=True, allow_draft=True, allow_send=False)
        self.assertTrue(evaluate_action(binding, "read", selected_contact="测试联系人甲")["allowed"])
        self.assertTrue(evaluate_action(binding, "draft", selected_contact="测试联系人甲")["allowed"])
        self.assertFalse(evaluate_action(binding, "send", selected_contact="测试联系人甲", confirm=True, message_sha256="b"*64)["allowed"])

    def test_send_rate_limit_blocks_after_threshold(self):
        binding = build_binding("wechat", "测试联系人甲", allow_send=True, created_at=1)
        sha = "c" * 64
        blocked = evaluate_action(binding, "send", selected_contact="测试联系人甲", confirm=True, message_sha256=sha, recent_send_count=5, rate_limit_count=5)
        self.assertFalse(blocked["allowed"])
        self.assertEqual(blocked["reason"], "send_rate_limit_blocked")
        allowed = evaluate_action(binding, "send", selected_contact="测试联系人甲", confirm=True, message_sha256=sha, recent_send_count=4, rate_limit_count=5)
        self.assertTrue(allowed["allowed"])

    def test_public_binding_has_no_secret_payload(self):
        b = public_binding(build_binding("wechat", "测试联系人甲", allow_send=True))
        self.assertEqual(b["contact"], "测试联系人甲")
        self.assertNotIn("password", str(b).lower())
        self.assertNotIn("token", str(b).lower())


class MessageFileTests(unittest.TestCase):
    def test_message_file_must_be_private_utf8_regular_and_bounded(self):
        with tempfile.TemporaryDirectory() as td:
            p = Path(td) / "m.txt"
            p.write_text("测试", encoding="utf-8")
            os.chmod(p, 0o600)
            data, meta = load_message_file(p)
            self.assertEqual(data.decode(), "测试")
            self.assertEqual(meta["chars"], 2)
            os.chmod(p, 0o644)
            with self.assertRaisesRegex(MessagingError, "permissions"):
                load_message_file(p)

    def test_nul_and_oversize_fail_closed(self):
        with self.assertRaisesRegex(MessagingError, "nul"):
            validate_message_bytes(b"a\x00b")
        with self.assertRaisesRegex(MessagingError, "too_large"):
            validate_message_bytes(b"x" * 16385)


class VisionBindingTests(unittest.TestCase):
    def test_wechat_login_required_is_detected_before_conversation_binding(self):
        items = [{"text": "你已退出微信"}, {"text": "登录"}, {"text": "切换账号"}]
        self.assertEqual(detect_provider_login_state("wechat", items), "LOGIN_REQUIRED")
        self.assertEqual(detect_provider_login_state("wechat", [{"text": "测试联系人甲"}]), "SESSION_PRESENT_OR_UNKNOWN")

    def test_vision_conversion_and_window_filter(self):
        item = {"text": "测试联系人甲", "confidence": 1.0, "box": {"x": 0.4, "y": 0.7, "width": 0.05, "height": 0.02}}
        rect = vision_box_to_screen(item, screen_width=1920, screen_height=1080)
        self.assertAlmostEqual(rect["cx"], 816, delta=1)
        self.assertAlmostEqual(rect["cy"], 313.2, delta=2)
        window = {"x": 520, "y": 220, "width": 880, "height": 640}
        cands = exact_text_candidates([item], "测试联系人甲", screen_width=1920, screen_height=1080, window=window)
        self.assertEqual(len(cands), 1)

    def test_selected_header_requires_exactly_one_header_candidate(self):
        window = {"x": 520, "y": 220, "width": 880, "height": 640}
        good = {"text": "测试联系人甲", "rect": {"cx": 850, "cy": 250}}
        side = {"text": "测试联系人甲", "rect": {"cx": 630, "cy": 300}}
        self.assertEqual(select_header_candidate([good, side], window), good)
        with self.assertRaisesRegex(MessagingError, "header_not_unique"):
            select_header_candidate([good, {"text":"测试联系人甲","rect":{"cx":900,"cy":260}}], window)

    def test_token_regions_separate_composer_history_and_preview_with_ocr_confusable(self):
        self.assertTrue(visual_token_matches("R5 微信自动化测试 R5TO10537", "R5T010537"))
        self.assertTrue(visual_token_matches("R5 微信修复后资格测试 R5TES灭88888", "修复后资格测试"))
        window = {"x": 520, "y": 220, "width": 880, "height": 640}
        items = [
            {"text":"R5T010537", "box":{"x":0.54,"y":0.68,"width":0.06,"height":0.02}},  # history
            {"text":"R5TO10537", "box":{"x":0.54,"y":0.29,"width":0.06,"height":0.02}},  # composer
            {"text":"R5T010537", "box":{"x":0.32,"y":0.70,"width":0.06,"height":0.02}},  # preview
        ]
        ev = token_region_evidence(items, "R5T010537", screen_width=1920, screen_height=1080, window=window)
        self.assertEqual(ev["counts"]["HISTORY"], 1)
        self.assertEqual(ev["counts"]["COMPOSER"], 1)
        self.assertEqual(ev["counts"]["LEFT_PREVIEW"], 1)
        self.assertNotIn("R5T010537", str(ev))
        visible = visible_region_texts(items, region="HISTORY", screen_width=1920, screen_height=1080, window=window, limit=10)
        self.assertEqual(len(visible), 1)
        self.assertEqual(visible[0]["text"], "R5T010537")


class MessagingStoreTests(unittest.TestCase):
    def test_store_is_hash_only_for_draft_and_receipt(self):
        with tempfile.TemporaryDirectory() as td:
            store = MessagingStore(td)
            binding = build_binding("wechat", "测试联系人甲", allow_send=True, created_at=1)
            store.save_binding(binding)
            self.assertEqual(store.load_binding(binding["binding_id"])["contact"], "测试联系人甲")
            meta = validate_message_bytes("hello".encode())
            draft = build_draft(binding, meta, created_at=2)
            store.save_draft(draft)
            loaded = store.load_draft(draft["draft_id"])
            self.assertEqual(loaded["message_sha256"], meta["sha256"])
            self.assertNotIn("hello", str(loaded))
            store.save_receipt(draft, result="SENT_VERIFIED", sent_at=3)
            self.assertIn(meta["sha256"], store.sent_hashes(binding["binding_id"]))
            self.assertEqual(store.recent_sent_count(binding["binding_id"], window_seconds=10, now=5), 1)
            self.assertEqual(store.recent_sent_count(binding["binding_id"], window_seconds=1, now=5), 0)


if __name__ == "__main__":
    unittest.main()
