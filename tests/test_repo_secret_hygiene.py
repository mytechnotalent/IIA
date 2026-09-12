"""Tests that enforce secret hygiene across the tracked repository."""

import importlib.util
import os
import subprocess

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SCANNER_PATH = os.path.join(
    ROOT, ".opencode", "skills", "repo-secret-hygiene", "scan_secrets.py"
)


def _load_scanner():
    """
    Load the hygiene scanner module from its file path.

    Parameters
    ----------
    None

    Returns
    -------
    module
        The imported scanner module.
    """
    spec = importlib.util.spec_from_file_location("scan_secrets", SCANNER_PATH)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


scan = _load_scanner()


def _tracked_files():
    """
    List repository-tracked files.

    Parameters
    ----------
    None

    Returns
    -------
    list
        Relative paths tracked by git.
    """
    result = subprocess.run(
        ["git", "-C", ROOT, "ls-files"], capture_output=True, text=True
    )
    return [name for name in result.stdout.splitlines() if name]


class TestDetection:
    def test_private_key_detected(self):
        payload = "-----BEGIN RSA " + "PRIVATE KEY-----"
        hard, _ = scan.scan_text(payload, "x")
        assert hard >= 1

    def test_github_token_detected(self):
        payload = "token = 'ghp_" + "b" * 36 + "'"
        hard, _ = scan.scan_text(payload, "x")
        assert hard >= 1

    def test_generic_secret_detected(self):
        payload = "pass" + "word = " + '"' + "hunter2hunter2" + '"'
        hard, _ = scan.scan_text(payload, "x")
        assert hard >= 1

    def test_placeholder_ignored(self):
        hard, _ = scan.scan_text('token = "<secret>"', "x")
        assert hard == 0

    def test_placeholder_ip_ignored(self):
        _, soft = scan.scan_text("host 192.168.1.50", "x", strict=True)
        assert soft == 0

    def test_soft_only_under_strict(self):
        _, soft = scan.scan_text("host 192.168.1.9", "x", strict=False)
        assert soft == 0


class TestTrackedTreeClean:
    def test_no_hard_findings_in_tracked_files(self):
        hard = 0
        for rel in _tracked_files():
            path = os.path.join(ROOT, rel)
            text = scan._read(path)
            if text is None:
                continue
            hard += scan.scan_text(text, rel, strict=False)[0]
        assert hard == 0
