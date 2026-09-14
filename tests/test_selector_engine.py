import unittest

from linux_macctl.selector_engine import (
    SELECTOR_SCHEMA_VERSION,
    choose_ranked_match,
    normalize_text,
    rank_ax_inventory,
    text_score,
)


def inventory(*nodes):
    return {
        "application": "Finder",
        "bundle_id": "com.apple.finder",
        "pid": 123,
        "node_count": len(nodes),
        "max_nodes": 120,
        "max_depth": 3,
        "truncated": False,
        "windows": list(nodes),
    }


def node(ref, *, role="AXButton", subrole="", title="", description="", value="", truncated=False):
    return {
        "ref": ref,
        "role": role,
        "subrole": subrole,
        "title": title,
        "description": description,
        "value": value,
        "value_truncated": truncated,
        "focused": False,
        "frame": {},
        "actions": ["AXPress"],
    }


class SelectorTextTests(unittest.TestCase):
    def test_nfkc_case_and_whitespace_normalization(self):
        self.assertEqual(normalize_text("  ＡＢＣ\tDef  "), "abc def")
        self.assertEqual(text_score("ＡＢＣ Def", "abc   def"), (100, "exact"))

    def test_quality_ladder(self):
        self.assertEqual(text_score("最近使用", "最近"), (90, "prefix"))
        self.assertEqual(text_score("打开最近使用项目", "最近使用"), (82, "contains"))
        self.assertEqual(text_score("alpha xx beta", "alpha beta"), (76, "tokens"))
        score, quality = text_score("settings", "setings")
        self.assertEqual(quality, "similar")
        self.assertGreaterEqual(score, 70)
        self.assertEqual(text_score("completely different", "target"), (-1, "none"))


class SelectorRankingTests(unittest.TestCase):
    def test_bundle_mismatch_and_missing_selector_fail_closed(self):
        p = inventory(node("w0", title="最近使用"))
        mismatch = rank_ax_inventory(p, {"bundle": "com.apple.TextEdit", "title": "最近"})
        self.assertEqual(mismatch["status"], "FAIL")
        self.assertEqual(mismatch["reason"], "frontmost_bundle_mismatch")
        missing = rank_ax_inventory(p, {"bundle": "com.apple.finder"})
        self.assertEqual(missing["reason"], "missing_selector")

    def test_role_subrole_and_threshold_filtering(self):
        p = inventory(
            node("w0/c1", role="AXButton", subrole="AXCloseButton", description="关闭"),
            node("w0/c2", role="AXButton", subrole="AXSearchField", description="搜索"),
        )
        ranked = rank_ax_inventory(
            p,
            {"bundle": "com.apple.finder", "role": "AXButton", "subrole": "AXSearchField", "description": "搜"},
            min_score=90,
        )
        self.assertEqual(ranked["schema"], SELECTOR_SCHEMA_VERSION)
        self.assertEqual(ranked["match_count"], 1)
        self.assertEqual(ranked["matches"][0]["ref"], "w0/c2")
        self.assertEqual(ranked["matches"][0]["score"], 90)

    def test_deterministic_order_for_equal_scores(self):
        p = inventory(
            node("w0/c9", title="相同"),
            node("w0/c2", title="相同"),
            node("w0/c5", title="相同"),
        )
        ranked = rank_ax_inventory(p, {"title": "相同"})
        self.assertEqual([m["ref"] for m in ranked["matches"]], ["w0/c2", "w0/c5", "w0/c9"])

    def test_min_score_removes_weak_match(self):
        p = inventory(node("w0", title="打开最近使用项目"))
        ranked = rank_ax_inventory(p, {"title": "最近使用"}, min_score=90)
        self.assertEqual(ranked["match_count"], 0)


class RankedPressDecisionTests(unittest.TestCase):
    def test_tie_is_ambiguous_and_fail_closed(self):
        p = inventory(node("w0/c1", title="搜索"), node("w0/c2", title="搜索"))
        ranked = rank_ax_inventory(p, {"role": "AXButton", "title": "搜"}, min_score=70, min_margin=10)
        decision = choose_ranked_match(ranked, min_margin=10)
        self.assertEqual(decision["status"], "FAIL")
        self.assertEqual(decision["reason"], "ambiguous_ranked_selector")
        self.assertEqual(decision["score_margin"], 0)
        self.assertEqual(decision["exit_code"], 65)

    def test_clear_winner_is_selected(self):
        p = inventory(node("w0/c1", title="搜索"), node("w0/c2", title="搜索高级设置"))
        ranked = rank_ax_inventory(p, {"title": "搜索"}, min_score=70)
        decision = choose_ranked_match(ranked, min_margin=10)
        self.assertEqual(decision["status"], "PASS")
        self.assertEqual(decision["top"]["ref"], "w0/c1")
        self.assertGreaterEqual(decision["score_margin"], 10)

    def test_no_match_and_truncated_value_are_rejected(self):
        empty = choose_ranked_match({"matches": []}, min_margin=10)
        self.assertEqual(empty["reason"], "no_ranked_match")
        p = inventory(node("w0", role="AXTextField", value="abcdef", truncated=True))
        ranked = rank_ax_inventory(p, {"role": "AXTextField", "value": "abcdef"})
        truncated = choose_ranked_match(ranked, min_margin=10, value_requested=True)
        self.assertEqual(truncated["reason"], "ranked_value_truncated")
        self.assertEqual(truncated["exit_code"], 65)

    def test_invalid_threshold_is_a_contract_failure(self):
        result = rank_ax_inventory(inventory(node("w0", title="x")), {"title": "x"}, min_score=101)
        self.assertEqual(result["status"], "FAIL")
        self.assertEqual(result["reason"], "invalid_rank_threshold")


if __name__ == "__main__":
    unittest.main()
