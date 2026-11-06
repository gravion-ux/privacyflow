import io
import json
import sys
import tempfile
import unittest
from contextlib import redirect_stdout
from pathlib import Path
sys.path.insert(0, str(Path(__file__).parents[1] / "src"))
import privacyflow
from privacyflow.cli import main

PROFILE = "[Interface]\nPrivateKey = AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8=\nAddress = 10.0.0.2/32\n[Peer]\nPublicKey = ICEiIyQlJicoKSorLC0uLzAxMjM0NTY3ODk6Ozw9Pj8=\nEndpoint = vpn.example.net:51820\nAllowedIPs = 0.0.0.0/0, ::/0\n"


class PrivacyflowCliTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.base = Path(self.temp.name)
        (self.base / "vpn.conf").write_text(PROFILE)
        self.config = self.base / "veil.toml"
        self.config.write_text('profiles = ["vpn.conf"]\n[rotation]\ninterval_seconds=300\nrequire_kill_switch=true\n')

    def tearDown(self):
        self.temp.cleanup()

    def run_cli(self, argv):
        buffer = io.StringIO()
        with redirect_stdout(buffer):
            code = main(argv)
        return code, buffer.getvalue()

    def test_validate_accepts_a_valid_configuration(self):
        code, output = self.run_cli(["validate", str(self.config)])
        self.assertEqual(code, 0)
        self.assertIn("Valid configuration", output)

    def test_rotation_plan_is_dry_run_only(self):
        code, output = self.run_cli(["rotation-plan", str(self.config)])
        self.assertEqual(code, 0)
        report = json.loads(output)
        self.assertEqual(report["mode"], "DRY_RUN_ONLY")
        self.assertEqual(len(report["steps"]), 1)

    def test_a_missing_configuration_is_reported_without_a_traceback(self):
        code, _ = self.run_cli(["validate", str(self.base / "absent.toml")])
        self.assertEqual(code, 2)

    def test_an_invalid_configuration_is_reported_without_a_traceback(self):
        self.config.write_text('profiles = ["vpn.conf"]\n[rotation]\ninterval_seconds=5\n')
        code, _ = self.run_cli(["validate", str(self.config)])
        self.assertEqual(code, 2)

    def test_the_command_can_be_called_with_an_argument_list(self):
        code, output = self.run_cli(["validate", str(self.config)])
        self.assertEqual(code, 0)
        self.assertIn("1 WireGuard profile(s)", output)


class PrivacyflowPublicApiTests(unittest.TestCase):
    def test_the_package_exposes_the_public_api(self):
        self.assertTrue(privacyflow.__version__)
        for name in ("load_config", "validate_wireguard_profile", "rotation_plan", "ConfigError", "PrivacyflowConfig"):
            self.assertIn(name, privacyflow.__all__)
            self.assertTrue(hasattr(privacyflow, name))

    def test_the_exported_functions_are_the_config_module_functions(self):
        from privacyflow.config import load_config, rotation_plan, validate_wireguard_profile
        self.assertIs(privacyflow.load_config, load_config)
        self.assertIs(privacyflow.rotation_plan, rotation_plan)
        self.assertIs(privacyflow.validate_wireguard_profile, validate_wireguard_profile)
