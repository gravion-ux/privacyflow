import sys
import tempfile
import unittest
from pathlib import Path
sys.path.insert(0, str(Path(__file__).parents[1] / "src"))
from privacyflow.config import ConfigError, PrivacyflowConfig, load_config, rotation_plan

PROFILE = """[Interface]\nPrivateKey = AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8=\nAddress = 10.0.0.2/32\n[Peer]\nPublicKey = ICEiIyQlJicoKSorLC0uLzAxMjM0NTY3ODk6Ozw9Pj8=\nEndpoint = vpn.example.net:51820\nAllowedIPs = 0.0.0.0/0, ::/0\n"""


def profile_with_endpoint(endpoint):
    return PROFILE.replace("vpn.example.net:51820", endpoint)


class PrivacyflowRotationPlanTests(unittest.TestCase):
    def setUp(self): self.temp = tempfile.TemporaryDirectory(); self.base = Path(self.temp.name)
    def tearDown(self): self.temp.cleanup()

    def make_config(self, files, entries, interval=300):
        for relative, content in files.items():
            path = self.base / relative
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(content)
        cfg = self.base / "plan.toml"
        listed = ", ".join(f'"{entry}"' for entry in entries)
        rotation = "" if interval is None else f"\n[rotation]\ninterval_seconds = {interval}\n"
        cfg.write_text(f"profiles = [{listed}]{rotation}\n")
        return cfg

    def test_plan_preserves_config_order_and_numbers_steps_from_one(self):
        files = {
            "one.conf": profile_with_endpoint("a.example.net:51820"),
            "two.conf": profile_with_endpoint("b.example.net:51820"),
            "three.conf": profile_with_endpoint("c.example.net:51820"),
        }
        cfg = self.make_config(files, ["three.conf", "one.conf", "two.conf"], interval=900)
        plan = rotation_plan(load_config(cfg))
        self.assertEqual([step["step"] for step in plan], [1, 2, 3])
        self.assertEqual([step["profile"] for step in plan], ["three", "one", "two"])
        self.assertTrue(all(step["interval_seconds"] == 900 for step in plan))
        self.assertTrue(all(step["action"] == "would-switch-after-health-check" for step in plan))

    def test_plan_uses_the_default_interval_when_the_rotation_table_is_omitted(self):
        cfg = self.make_config({"a.conf": PROFILE}, ["a.conf"], interval=None)
        plan = rotation_plan(load_config(cfg))
        self.assertEqual(plan[0]["interval_seconds"], 1800)

    def test_accepts_the_minimum_interval_boundary(self):
        cfg = self.make_config({"a.conf": PROFILE}, ["a.conf"], interval=60)
        self.assertEqual(rotation_plan(load_config(cfg))[0]["interval_seconds"], 60)

    def test_accepts_the_maximum_interval_boundary(self):
        cfg = self.make_config({"a.conf": PROFILE}, ["a.conf"], interval=86400)
        self.assertEqual(rotation_plan(load_config(cfg))[0]["interval_seconds"], 86400)

    def test_rejects_an_interval_just_below_the_minimum(self):
        cfg = self.make_config({"a.conf": PROFILE}, ["a.conf"], interval=59)
        with self.assertRaisesRegex(ConfigError, "60 to 86400"):
            load_config(cfg)

    def test_rejects_an_interval_just_above_the_maximum(self):
        cfg = self.make_config({"a.conf": PROFILE}, ["a.conf"], interval=86401)
        with self.assertRaisesRegex(ConfigError, "60 to 86400"):
            load_config(cfg)

    def test_profiles_sharing_an_endpoint_are_both_planned(self):
        # Only duplicate paths are rejected; two distinct profile files may
        # point at the same Peer.Endpoint and both appear in the plan.
        cfg = self.make_config({"a.conf": PROFILE, "b.conf": PROFILE}, ["a.conf", "b.conf"])
        plan = rotation_plan(load_config(cfg))
        self.assertEqual([step["profile"] for step in plan], ["a", "b"])

    def test_same_named_profiles_in_different_directories_produce_identical_step_names(self):
        # Plan steps identify profiles by file stem only, so two profiles with
        # the same file name in different directories are indistinguishable.
        files = {"x/wg0.conf": PROFILE, "y/wg0.conf": PROFILE}
        cfg = self.make_config(files, ["x/wg0.conf", "y/wg0.conf"])
        plan = rotation_plan(load_config(cfg))
        self.assertEqual([step["profile"] for step in plan], ["wg0", "wg0"])
        self.assertEqual([step["step"] for step in plan], [1, 2])

    def test_rejects_the_same_profile_reached_through_a_parent_relative_path(self):
        cfg = self.make_config({"a.conf": PROFILE, "sub/keep.txt": "x"}, ["a.conf", "sub/../a.conf"])
        with self.assertRaisesRegex(ConfigError, "duplicate paths"):
            load_config(cfg)

    def test_a_profile_with_multiple_peers_produces_one_plan_step(self):
        second_peer = "\n[Peer]\nPublicKey = ICEiIyQlJicoKSorLC0uLzAxMjM0NTY3ODk6Ozw9Pj8=\nEndpoint = vpn2.example.net:51821\nAllowedIPs = 10.20.0.0/16\n"
        cfg = self.make_config({"a.conf": PROFILE + second_peer}, ["a.conf"])
        plan = rotation_plan(load_config(cfg))
        self.assertEqual(len(plan), 1)
        self.assertEqual(plan[0]["profile"], "a")

    def test_plan_step_names_come_from_the_file_stem(self):
        cfg = self.make_config({"wg0.home.conf": PROFILE}, ["wg0.home.conf"])
        plan = rotation_plan(load_config(cfg))
        self.assertEqual(plan[0]["profile"], "wg0.home")

    def test_rotation_plan_for_a_config_with_no_profiles_is_empty(self):
        # load_config never returns an empty profile list, but rotation_plan
        # itself is a public function and yields no steps for one.
        config = PrivacyflowConfig(interval_seconds=300, require_kill_switch=True, profiles=())
        self.assertEqual(rotation_plan(config), [])


if __name__ == "__main__": unittest.main()
