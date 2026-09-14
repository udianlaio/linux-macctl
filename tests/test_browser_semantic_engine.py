import unittest
from linux_macctl.browser_semantic_engine import analyze_extracted_page

class BrowserSemanticTests(unittest.TestCase):
    def test_login_classification_and_no_secret_return(self):
        e={"ok":True,"title":"Sign in","url":"https://example.com/login","text":"Sign in","links":[],"forms":[{"id":"f"}],"interactive":[{"tag":"INPUT","type":"password","id":"pw","value":None,"valueRedacted":True}]}
        r=analyze_extracted_page(e)
        self.assertEqual(r["page_type"],"login")
        self.assertIn("AUTHENTICATION_SURFACE",r["risk_hints"])
        self.assertFalse(r["credential_values_returned"])
    def test_upload_and_search_classification(self):
        u={"ok":True,"title":"U","url":"https://e/u","text":"Upload","links":[],"forms":[],"interactive":[{"tag":"INPUT","type":"file","id":"f"}]}
        self.assertEqual(analyze_extracted_page(u)["page_type"],"upload")
        q={"ok":True,"title":"S","url":"https://e/s","text":"Search","links":[],"forms":[],"interactive":[{"tag":"INPUT","type":"search","id":"q"}]}
        self.assertEqual(analyze_extracted_page(q)["page_type"],"search")
    def test_article_and_listing(self):
        article={"ok":True,"text":"x"*1300,"links":[],"forms":[],"interactive":[]}
        self.assertEqual(analyze_extracted_page(article)["page_type"],"article")
        listing={"ok":True,"text":"short","links":[{}]*12,"forms":[],"interactive":[]}
        self.assertEqual(analyze_extracted_page(listing)["page_type"],"listing")
    def test_invalid_contract(self):
        with self.assertRaises(ValueError): analyze_extracted_page({"ok":False})
