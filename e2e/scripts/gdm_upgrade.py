#!/usr/bin/python3
"""Reproduce the released GDM profile bug, then verify an in-place upgrade."""

import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile


BASELINE_VERSION = "0.16.4ubuntu1.1"
PROFILE = Path("/etc/dconf/profile/gdm")
SYSTEM_PROFILES = (
    Path("/usr/local/share/dconf/profile/gdm"),
    Path("/usr/share/dconf/profile/gdm"),
)
CANDIDATES = Path("/debs")
REPORT = Path("/root/adsys-gdm-upgrade.json")


def output(*args: str, **kwargs) -> str:
    """Run a command; command failures are never expected regression results."""
    return subprocess.check_output(args, text=True, **kwargs).strip()


def sources(profile: str) -> list[str]:
    """Read active sources, ignoring comments and whitespace."""
    return [
        line.strip()
        for line in profile.splitlines()
        if line.strip() and not line.lstrip().startswith("#")
    ]


def snapshot() -> dict:
    """Capture the real profile, defaults and a machine GPO's value and lock."""
    system_profile = next((p for p in SYSTEM_PROFILES if p.is_file()), None)
    if system_profile is None:
        raise RuntimeError("no vendor GDM profile: cannot reproduce this regression")
    system_sources = sources(system_profile.read_text())
    databases = [s.removeprefix("file-db:") for s in system_sources if s.startswith("file-db:")]
    if not databases or not all(Path(p).is_file() for p in databases):
        raise RuntimeError("vendor greeter database is missing")

    with tempfile.TemporaryDirectory(prefix="adsys-gdm-defaults-") as config:
        # A fresh greeter has no saved user settings overriding these defaults.
        env = dict(os.environ, XDG_CONFIG_HOME=config, GSETTINGS_BACKEND="dconf")
        vendor_session = output(
            "gsettings", "get", "org.gnome.desktop.session", "session-name",
            env=dict(env, DCONF_PROFILE=str(system_profile)),
        )
        env["DCONF_PROFILE"] = "gdm"
        return {
            "adsys_version": output("dpkg-query", "-W", "-f=${Version}", "adsys"),
            "profile": PROFILE.read_text(),
            "system_profile": str(system_profile),
            "system_sources": system_sources,
            "vendor_session_name": vendor_session,
            "session_name": output("gsettings", "get", "org.gnome.desktop.session", "session-name", env=env),
            "banner": output("gsettings", "get", "org.gnome.login-screen", "banner-message-text", env=env),
            "banner_writable": output("gsettings", "writable", "org.gnome.login-screen", "banner-message-text", env=env),
        }


def greeter_problems(state: dict) -> list[str]:
    """Apply the same healthy-defaults check to both package versions."""
    problems = []
    missing = [s for s in state["system_sources"] if s not in sources(state["profile"])]
    if missing:
        problems.append("missing vendor sources: " + ", ".join(missing))
    if state["session_name"] != "'gnome-login'":
        problems.append("session-name is " + state["session_name"] + ", expected 'gnome-login'")
    return problems


def require_policy(state: dict) -> None:
    """Prove machine policy application and enforcement, not just file creation."""
    if state["banner"] != "'Sample banner text'" or state["banner_writable"] != "false":
        raise RuntimeError("the banner GPO was not applied and locked")
    if state["vendor_session_name"] != "'gnome-login'":
        raise RuntimeError("the vendor profile itself does not select gnome-login")


def upgrade(report: dict) -> None:
    """Require the precise old failure before installing and checking the candidate."""
    installed = output("dpkg-query", "-W", "-f=${Version}", "adsys")
    if installed != BASELINE_VERSION:
        raise RuntimeError(f"expected released baseline {BASELINE_VERSION}, got {installed}")

    candidates = list(CANDIDATES.glob("adsys_*.deb"))
    if len(candidates) != 1:
        raise RuntimeError("expected exactly one candidate adsys package in /debs")
    candidate = candidates[0]
    if output("dpkg-deb", "-f", str(candidate), "Package") != "adsys":
        raise RuntimeError("candidate is not an adsys package")
    version = output("dpkg-deb", "-f", str(candidate), "Version")
    subprocess.run(["dpkg", "--compare-versions", version, "gt", installed], check=True)
    report["candidate_version"] = version

    subprocess.run(["systemctl", "restart", "adsysd"], check=True)
    subprocess.run(["adsysctl", "policy", "update", "-m"], check=True)
    before = snapshot()
    report["before"] = before
    require_policy(before)
    legacy = ["user-db:user", "system-db:gdm", "system-db:machine"]
    if before["adsys_version"] != BASELINE_VERSION or sources(before["profile"]) != legacy:
        raise RuntimeError("baseline did not generate the expected legacy profile")
    if before["session_name"] != "'ubuntu'":
        raise RuntimeError("baseline did not reproduce the incorrect ubuntu session default")
    problems = greeter_problems(before)
    before["problems"] = problems
    if not any(s.startswith("file-db:") and s not in legacy for s in before["system_sources"]) or not problems:
        raise RuntimeError("baseline did not reproduce the missing greeter database")
    print(f"Confirmed regression with {installed}: {'; '.join(problems)}", flush=True)

    # Keep the generated profile and policy cache in place throughout the upgrade.
    subprocess.run(
        ["apt-get", "install", "-y", "-o", "Dpkg::Options::=--force-confdef",
         "-o", "Dpkg::Options::=--force-confold", str(candidate)],
        check=True, env=dict(os.environ, DEBIAN_FRONTEND="noninteractive"),
    )
    subprocess.run(["systemctl", "restart", "adsysd"], check=True)
    subprocess.run(["adsysctl", "policy", "update", "-m"], check=True)
    after = snapshot()
    report["after"] = after
    if after["adsys_version"] != version:
        raise RuntimeError("the candidate package was not installed")
    require_policy(after)
    after["problems"] = greeter_problems(after)
    if after["problems"]:
        raise RuntimeError("candidate did not repair greeter defaults: " + "; ".join(after["problems"]))
    print(f"Verified upgrade to {version}: vendor defaults and GPO locks preserved", flush=True)


def main() -> int:
    """Save partial evidence even if setup, reproduction or upgrade fails."""
    report = {"baseline_version": BASELINE_VERSION, "graphical_logins_tested": False}
    try:
        upgrade(report)
    except (OSError, RuntimeError, subprocess.CalledProcessError) as error:
        report["error"] = str(error)
        print(str(error), file=sys.stderr)
        return 1
    finally:
        REPORT.write_text(json.dumps(report, indent=2) + "\n")
    return 0


if __name__ == "__main__":
    sys.exit(main())
