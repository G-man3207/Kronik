"""fleet-controller.py: OpenSSL's configuration and its fixed diagnostic codes."""
import os
from pathlib import Path
import runpy
import unittest
from unittest import mock

CONTROLLER = runpy.run_path(str(Path(__file__).resolve().parents[1] / "fleet-controller.py"))
openssl_environment = CONTROLLER["openssl_environment"]
openssl_error_code = CONTROLLER["openssl_error_code"]


class DiagnosticTests(unittest.TestCase):
    def test_missing_guest_default_config_uses_empty_fixture_config(self):
        with mock.patch.object(os.path, "isfile", return_value=False) as exists:
            self.assertEqual(openssl_environment(),
                             {"PATH": "/usr/bin:/bin", "OPENSSL_CONF": "/dev/null"})
            exists.assert_called_once_with("/usr/lib/ssl/openssl.cnf")

    def test_existing_guest_default_config_is_not_overridden(self):
        with mock.patch.object(os.path, "isfile", return_value=True):
            self.assertEqual(openssl_environment(), {"PATH": "/usr/bin:/bin"})

    def test_diagnostics_are_fixed_codes_and_bounded(self):
        self.assertEqual(openssl_error_code(b"Can't open /usr/lib/ssl/openssl.cnf: No such file"),
                         "OPENSSL_CONFIG_MISSING")
        self.assertEqual(openssl_error_code(b"Certificate request self-signature verify failure"),
                         "OPENSSL_CSR_SIGNATURE_INVALID")
        self.assertEqual(openssl_error_code(b"private-credential unknown-tool-output"),
                         "OPENSSL_EXECUTION_FAILED")
        self.assertEqual(openssl_error_code(b"x" * 8192 + b" openssl.cnf: No such file"),
                         "OPENSSL_EXECUTION_FAILED")
