#!/usr/bin/env python3
import unittest

from execution_backend import (
    AUTO,
    LOCAL_MACOS,
    REMOTE_SSH,
    BackendError,
    local_macos_shell_argv,
    normalize_mode,
    remote_command_string,
    remote_rsync_argv,
    remote_scp_argv,
    remote_shell_argv,
    remote_ssh_argv,
    resolve_backend_mode,
)


class ExecutionBackendTests(unittest.TestCase):
    def test_default_mode_preserves_remote_ssh(self):
        self.assertEqual(normalize_mode(None), REMOTE_SSH)

    def test_unknown_mode_fail_closed(self):
        with self.assertRaisesRegex(BackendError, "unknown_execution_backend"):
            normalize_mode("magic")

    def test_auto_linux_stays_remote_even_for_self(self):
        r = resolve_backend_mode(AUTO, host_os="Linux", target_is_self=True)
        self.assertEqual(r.selected, REMOTE_SSH)
        self.assertEqual(r.reason, "auto_remote_ssh_fallback")

    def test_auto_darwin_self_selects_local(self):
        r = resolve_backend_mode(AUTO, host_os="Darwin", target_is_self=True)
        self.assertEqual(r.selected, LOCAL_MACOS)
        self.assertEqual(r.reason, "auto_local_macos_self")

    def test_local_requires_darwin_and_self(self):
        with self.assertRaisesRegex(BackendError, "requires_darwin"):
            resolve_backend_mode(LOCAL_MACOS, host_os="Linux", target_is_self=True)
        with self.assertRaisesRegex(BackendError, "explicit_self"):
            resolve_backend_mode(LOCAL_MACOS, host_os="Darwin", target_is_self=False)

    def test_remote_ssh_argv_exact_baseline(self):
        self.assertEqual(
            remote_ssh_argv(ssh_config="/etc/macctl/ssh_config", target="macmini", remote="echo ok"),
            ["ssh", "-F", "/etc/macctl/ssh_config", "macmini", "echo ok"],
        )

    def test_remote_ssh_fresh_and_control_op(self):
        self.assertEqual(
            remote_ssh_argv(
                ssh_config="/etc/macctl/ssh_config",
                target="macmini",
                fresh=True,
                op="check",
            ),
            [
                "ssh", "-F", "/etc/macctl/ssh_config",
                "-o", "ControlMaster=no", "-o", "ControlPath=none",
                "-O", "check", "macmini",
            ],
        )

    def test_remote_shell_preserves_sudo_contract(self):
        argv = remote_shell_argv("id -u", sudo=True, shell="/bin/zsh", remote_timeout=8)
        self.assertEqual(argv[:2], ["/usr/bin/sudo", "-n"])
        self.assertIn("/usr/bin/perl", argv)
        self.assertEqual(argv[-3:], ["/bin/zsh", "-lc", "id -u"])

    def test_remote_command_string_is_shell_quoted(self):
        s = remote_command_string("printf 'a b'", shell="/bin/zsh", remote_timeout=None)
        self.assertIn("/bin/zsh -lc", s)
        self.assertIn("printf", s)

    def test_local_argv_has_no_remote_timeout_wrapper(self):
        self.assertEqual(
            local_macos_shell_argv("printf OK", sudo=False),
            ["/bin/zsh", "-lc", "printf OK"],
        )
        self.assertEqual(
            local_macos_shell_argv("id -u", sudo=True),
            ["/usr/bin/sudo", "-n", "/bin/zsh", "-lc", "id -u"],
        )

    def test_scp_push_pull_exact_baseline(self):
        self.assertEqual(
            remote_scp_argv(
                ssh_config="/etc/macctl/ssh_config", target="macmini",
                local_path="/tmp/a", remote_path="/tmp/b",
                direction="push", recursive=False,
            ),
            ["scp", "-F", "/etc/macctl/ssh_config", "-q", "/tmp/a", "macmini:/tmp/b"],
        )
        self.assertEqual(
            remote_scp_argv(
                ssh_config="/etc/macctl/ssh_config", target="macmini",
                local_path="/tmp/a", remote_path="/tmp/b",
                direction="pull", recursive=True,
            ),
            ["scp", "-F", "/etc/macctl/ssh_config", "-q", "-r", "macmini:/tmp/b", "/tmp/a"],
        )

    def test_rsync_push_exact_baseline(self):
        self.assertEqual(
            remote_rsync_argv(
                ssh_config="/etc/macctl/ssh_config", target="macmini",
                local_path="src/", remote_path="dst/", direction="push",
                delete=True, dry_run=True,
            ),
            [
                "rsync", "-a", "--partial-dir=.macctl-partial", "--stats", "-e",
                "ssh -F /etc/macctl/ssh_config", "--delete", "--dry-run",
                "src/", "macmini:dst/",
            ],
        )

    def test_transfer_direction_fail_closed(self):
        with self.assertRaisesRegex(BackendError, "invalid_scp_direction"):
            remote_scp_argv(
                ssh_config="/x", target="m", local_path="a", remote_path="b", direction="sideways"
            )
        with self.assertRaisesRegex(BackendError, "invalid_rsync_direction"):
            remote_rsync_argv(
                ssh_config="/x", target="m", local_path="a", remote_path="b", direction="sideways"
            )


if __name__ == "__main__":
    unittest.main()
