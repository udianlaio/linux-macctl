import json
import unittest
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1]
class PublicDistributionTests(unittest.TestCase):
    def test_installer_verifies_release_checksum(self):
        s=(ROOT/'install.sh').read_text()
        self.assertIn('sha256sum -c',s)
        self.assertIn("--proto '=https'",s)
        self.assertNotIn('curl -k',s)
    def test_host_key_never_auto_accepts(self):
        s=(ROOT/'setup-target.sh').read_text()
        self.assertIn('StrictHostKeyChecking=yes',s)
        self.assertIn('[[ "$confirmed" == YES ]]',s)
        self.assertNotIn('StrictHostKeyChecking=no',s)
        self.assertNotIn('accept-new',s)
    def test_default_config_blocks_macos_updates(self):
        d=json.loads((ROOT/'config.example.json').read_text())
        self.assertFalse(d['allow_macos_system_update'])
        self.assertFalse(d['allow_macos_major_upgrade'])
        self.assertEqual(d['host'],'CHANGE_ME')
        self.assertEqual(d['user'],'CHANGE_ME')
    def test_public_provenance_exports_no_private_history(self):
        d=json.loads((ROOT/'PUBLIC_PROVENANCE.json').read_text())
        self.assertFalse(d['history_exported'])
        self.assertFalse(d['runtime_secrets_exported'])
    def test_uninstall_is_non_destructive_by_default(self):
        s=(ROOT/'uninstall.sh').read_text()
        self.assertIn('if ((PURGE))',s)
        self.assertIn('/etc/macctl',s)
        self.assertIn('已保留',s)
if __name__=='__main__': unittest.main()
