"""Exercise the upgrade test without installing packages or changing the host."""

import json
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest.mock import patch

import gdm_upgrade


class UpgradeTest(unittest.TestCase):
    def setUp(self):
        directory = tempfile.TemporaryDirectory()
        self.addCleanup(directory.cleanup)
        root = Path(directory.name)
        self.profile = root / "profile"
        self.system_profile = root / "system-profile"
        self.database = root / "greeter-defaults"
        self.database.touch()
        self.system_profile.write_text(f"user-db:user\nfile-db:{self.database}\n")
        self.candidate = root / "adsys_candidate.deb"
        self.candidate.touch()
        self.report = root / "report.json"
        self.installed = gdm_upgrade.BASELINE_VERSION
        self.candidate_version = "0.16.4ubuntu1.2"
        self.baseline_fixed = False
        self.candidate_broken = False
        self.policy_failure = False
        self.lost_lock = False
        self.installations = []
        self.legacy = "user-db:user\nsystem-db:gdm\nsystem-db:machine"
        self.fixed = self.system_profile.read_text() + "system-db:gdm\nsystem-db:machine"
        self.real_run = subprocess.run
        patches = [
            patch.multiple(
                gdm_upgrade, PROFILE=self.profile,
                SYSTEM_PROFILES=(self.system_profile,),
                CANDIDATES=root, REPORT=self.report,
            ),
            patch("gdm_upgrade.subprocess.check_output", side_effect=self.output),
            patch("gdm_upgrade.subprocess.run", side_effect=self.command),
        ]
        for item in patches:
            item.start()
            self.addCleanup(item.stop)

    def output(self, args, **kwargs):
        if args[0] == "dpkg-query":
            return self.installed
        if args[0] == "dpkg-deb":
            return "adsys" if args[-1] == "Package" else self.candidate_version
        self.assertEqual(args[0], "gsettings")
        if args[-1] == "session-name":
            vendor = kwargs["env"]["DCONF_PROFILE"] == str(self.system_profile)
            return "'gnome-login'" if vendor or self.profile.read_text() == self.fixed else "'ubuntu'"
        if args[-1] == "banner-message-text":
            if args[1] == "writable":
                return "true" if self.lost_lock and self.installed == self.candidate_version else "false"
            return "'Sample banner text'"
        self.fail(f"unexpected query: {args}")

    def command(self, args, **kwargs):
        if args[0] == "dpkg":
            return self.real_run(args, **kwargs)
        if args[0] == "adsysctl":
            if self.policy_failure:
                raise subprocess.CalledProcessError(1, args)
            if self.installed == gdm_upgrade.BASELINE_VERSION:
                content = self.fixed if self.baseline_fixed else self.legacy
            else:
                content = self.legacy if self.candidate_broken else self.fixed
            self.profile.write_text(content)
        elif args[0] == "apt-get":
            # The upgrade must receive the real legacy profile, not a clean slate.
            self.assertEqual(self.profile.read_text(), self.legacy)
            self.assertEqual(args[-1], str(self.candidate))
            self.installations.append(self.candidate)
            self.installed = self.candidate_version
        else:
            self.assertEqual(args, ["systemctl", "restart", "adsysd"])
        return subprocess.CompletedProcess(args, 0)

    def evidence(self):
        return json.loads(self.report.read_text())

    def test_confirms_old_failure_then_repairs_the_same_profile(self):
        self.assertEqual(gdm_upgrade.main(), 0)
        report = self.evidence()
        self.assertEqual(report["before"]["adsys_version"], gdm_upgrade.BASELINE_VERSION)
        self.assertEqual(len(report["before"]["problems"]), 2)
        self.assertEqual(report["after"]["adsys_version"], self.candidate_version)
        self.assertEqual(report["after"]["problems"], [])
        self.assertFalse(report["graphical_logins_tested"])
        self.assertEqual(self.installations, [self.candidate])

    def test_rejects_a_baseline_that_is_already_fixed(self):
        self.baseline_fixed = True
        self.assertEqual(gdm_upgrade.main(), 1)
        self.assertIn("legacy profile", self.evidence()["error"])
        self.assertEqual(self.installations, [])

    def test_command_failure_is_not_an_expected_regression(self):
        self.policy_failure = True
        self.assertEqual(gdm_upgrade.main(), 1)
        self.assertIn("non-zero exit status", self.evidence()["error"])
        self.assertEqual(self.installations, [])

    def test_rejects_a_candidate_that_keeps_the_bug(self):
        self.candidate_broken = True
        self.assertEqual(gdm_upgrade.main(), 1)
        self.assertIn("did not repair", self.evidence()["error"])
        self.assertTrue(self.evidence()["after"]["problems"])

    def test_rejects_a_missing_vendor_database(self):
        self.database.unlink()
        self.assertEqual(gdm_upgrade.main(), 1)
        self.assertIn("vendor greeter database", self.evidence()["error"])
        self.assertEqual(self.installations, [])

    def test_requires_an_actual_package_upgrade(self):
        self.candidate_version = gdm_upgrade.BASELINE_VERSION
        self.assertEqual(gdm_upgrade.main(), 1)
        self.assertEqual(self.installations, [])

    def test_rejects_lost_policy_enforcement_after_upgrade(self):
        self.lost_lock = True
        self.assertEqual(gdm_upgrade.main(), 1)
        self.assertIn("GPO was not applied and locked", self.evidence()["error"])


if __name__ == "__main__":
    unittest.main()
