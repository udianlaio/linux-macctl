import unittest
from linux_macctl.browser_automation_engine import (
    BrowserAutomationError, dom_extract_expression, dom_focus_expression,
    dom_select_expression, dom_search_probe_expression, dom_wait_probe_expression, dom_value_equals_expression, history_target,
    normalize_extract_request, normalize_key_event, normalize_wait_request,
)

class BrowserAutomationEngineTests(unittest.TestCase):
    def test_extract_defaults(self):
        r=normalize_extract_request()
        self.assertEqual(r["mode"],"summary")
        self.assertIsNone(r["selector"])
    def test_document_extract_uses_body_for_visible_text(self):
        x=dom_extract_expression(mode="text")
        self.assertIn("document.body||document.documentElement",x)

    def test_extract_rejects_bad_mode(self):
        with self.assertRaises(BrowserAutomationError): normalize_extract_request(mode="raw-js")
    def test_extract_bounds(self):
        with self.assertRaises(BrowserAutomationError): normalize_extract_request(max_chars=10)
        with self.assertRaises(BrowserAutomationError): normalize_extract_request(max_items=501)
    def test_extract_expression_is_bounded(self):
        x=dom_extract_expression(mode="full",selector="main",max_chars=4096,max_items=12)
        self.assertIn("maxChars=4096",x); self.assertIn("maxItems=12",x); self.assertIn("querySelector",x)
    def test_wait_visible_text(self):
        r=normalize_wait_request(selector="#status",state="visible",expect_text="Ready")
        self.assertEqual(r["state"],"visible")
        x=dom_wait_probe_expression(selector="#status",state="visible",expect_text="Ready")
        self.assertIn("satisfied",x)
    def test_wait_absent_value_forbidden(self):
        with self.assertRaises(BrowserAutomationError): normalize_wait_request(selector="#x",state="absent",expect_text="x")
    def test_search_probe_requires_get_search_surface(self):
        expr=dom_search_probe_expression("#q")
        self.assertIn("search_input_required",expr)
        self.assertIn("search_get_form_required",expr)
        self.assertIn("method!=='get'",expr)
        self.assertIn("u.origin+u.pathname",expr)

    def test_select_exact(self):
        x=dom_select_expression("#country","TW")
        self.assertIn("element_not_select",x); self.assertIn("option_value_not_found",x)
    def test_focus_exact(self):
        self.assertIn("selector_not_unique",dom_focus_expression("#q"))
    def test_key_whitelist(self):
        r=normalize_key_event("Enter",["cmd","shift"])
        self.assertEqual(r["modifier_bits"],12)
        self.assertEqual(r["cdp"]["windowsVirtualKeyCode"],13)
    def test_key_denies_arbitrary(self):
        with self.assertRaises(BrowserAutomationError): normalize_key_event("F13",[])
    def test_key_modifier_denies_unknown(self):
        with self.assertRaises(BrowserAutomationError): normalize_key_event("Enter",["hyper"])
    def test_history_back(self):
        h={"currentIndex":1,"entries":[{"id":10,"url":"https://a.test/"},{"id":11,"url":"https://a.test/b"}]}
        r=history_target(h,"back")
        self.assertEqual(r["entry_id"],10)
    def test_history_boundary(self):
        with self.assertRaises(BrowserAutomationError): history_target({"currentIndex":0,"entries":[{"id":1,"url":"x"}]},"back")

    def test_extract_redacts_sensitive_values_and_url_queries(self):
        expr=dom_extract_expression(mode="full")
        self.assertIn("valueRedacted",expr)
        self.assertIn("t==='password'",expr)
        self.assertIn("t==='hidden'",expr)
        self.assertIn("u.origin+u.pathname",expr)
        self.assertNotIn("u.search",expr)
    def test_wait_redacts_sensitive_value_but_can_compare(self):
        expr=dom_wait_probe_expression(selector="#secret",expect_value="probe-secret")
        self.assertIn("valueRedacted",expr)
        self.assertIn("value===ev",expr)
        self.assertIn("sensitive)?null",expr)
    def test_value_equals_returns_boolean_not_value(self):
        expr=dom_value_equals_expression("#secret","probe-secret")
        self.assertIn("matches:",expr)
        self.assertNotIn("value:e.value",expr)
        self.assertNotIn("value:String(e.value)",expr)

if __name__=='__main__': unittest.main()
