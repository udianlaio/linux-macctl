import unittest
from browser_control_router import plan_control_route

class BrowserControlRouterTests(unittest.TestCase):
    def test_chrome_isolated_prefers_cdp(self):
        r=plan_control_route(browser="chrome",context="isolated",action="extract")
        self.assertEqual(r["routes"][0],"CDP_DOM")
        self.assertEqual(r["status"],"PASS")
    def test_existing_chrome_never_uses_default_profile_cdp(self):
        r=plan_control_route(browser="chrome",context="existing_session",action="click",authenticated=True)
        self.assertNotIn("CDP_DOM",r["routes"])
        self.assertEqual(r["default_profile_cdp"],"FORBIDDEN")
        self.assertTrue(r["requires_site_specific_policy"])
    def test_search_is_supported_as_input_route(self):
        r=plan_control_route(browser="chrome",context="isolated",action="search")
        self.assertEqual(r["status"],"PASS")
        self.assertEqual(r["routes"][0],"CDP_DOM")

    def test_safari_native_ax_vision(self):
        r=plan_control_route(browser="safari",context="existing_session",action="observe")
        self.assertEqual(r["routes"],["AX_SEMANTIC","SCREENCAPTUREKIT_VISION"])
    def test_native_upload_not_overclaimed(self):
        r=plan_control_route(browser="safari",context="existing_session",action="upload")
        self.assertEqual(r["status"],"NOT_QUALIFIED")
    def test_no_route_blocks(self):
        r=plan_control_route(browser="safari",context="existing_session",action="query",ax_available=False,vision_available=False)
        self.assertEqual(r["status"],"BLOCKED")
