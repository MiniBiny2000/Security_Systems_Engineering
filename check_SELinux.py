#!/usr/bin/env python3

import os
import subprocess
import json


def run_command(cmd):
    try:
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True
        )
        if result.returncode == 0:
            return result.stdout.strip(), None
        return None, result.stderr.strip() or f"Command failed: {' '.join(cmd)}"
    except FileNotFoundError:
        return None, f"Command not found: {cmd[0]}"
    except Exception as e:
        return None, str(e)


# ---------------- SELinux ----------------

def check_selinux():
    selinux_fs = "/sys/fs/selinux"
    enforce_file = "/sys/fs/selinux/enforce"

    result = {
        "status": None,
        "getenforce": None,
        "error": None
    }

    if not os.path.exists(selinux_fs):
        result["status"] = "SELinux not installed or disabled in kernel"
        ge, ge_err = run_command(["getenforce"])
        result["getenforce"] = ge
        if ge_err:
            result["error"] = ge_err
        return result

    try:
        with open(enforce_file) as f:
            value = f.read().strip()

        if value == "1":
            result["status"] = "SELinux enabled (enforcing)"
        elif value == "0":
            result["status"] = "SELinux enabled (permissive)"
        else:
            result["status"] = "SELinux status unknown"
    except Exception as e:
        result["status"] = "SELinux filesystem present but cannot read enforcement status"
        result["error"] = str(e)

    ge, ge_err = run_command(["getenforce"])
    result["getenforce"] = ge
    if ge_err and not result["error"]:
        result["error"] = ge_err

    return result


# ---------------- AppArmor ----------------

def check_apparmor():
    enabled_file = "/sys/module/apparmor/parameters/enabled"
    profiles_file = "/sys/kernel/security/apparmor/profiles"

    result = {
        "kernel_module": "not detected",
        "enabled": "unknown",
        "profiles_loaded": "unknown",
        "aa_status": None,
        "error": None,
    }

    errors = []

    if os.path.exists(enabled_file):
        result["kernel_module"] = "detected"
        try:
            with open(enabled_file) as f:
                value = f.read().strip()
            result["enabled"] = "yes" if value.upper().startswith("Y") else "no"
        except Exception as e:
            result["enabled"] = "unreadable"
            errors.append(str(e))

    if os.path.exists(profiles_file):
        try:
            with open(profiles_file) as f:
                profiles = [line.strip() for line in f if line.strip()]
            result["profiles_loaded"] = len(profiles)
        except Exception as e:
            result["profiles_loaded"] = "unreadable"
            errors.append(str(e))

    aa_status, aa_err = run_command(["aa-status"])
    if aa_status:
        result["aa_status"] = aa_status
    elif aa_err:
        errors.append(aa_err)

    if errors:
        result["error"] = errors

    return result


# ---------------- ASLR ----------------

def check_aslr():
    aslr_file = "/proc/sys/kernel/randomize_va_space"

    result = {
        "status": None,
        "error": None
    }

    if not os.path.exists(aslr_file):
        result["status"] = "ASLR setting not available"
        return result

    try:
        with open(aslr_file) as f:
            value = f.read().strip()

        if value == "0":
            result["status"] = "Disabled"
        elif value == "1":
            result["status"] = "Enabled (conservative)"
        elif value == "2":
            result["status"] = "Enabled (full)"
        else:
            result["status"] = f"Unknown value: {value}"

    except Exception as e:
        result["status"] = "Could not read ASLR setting"
        result["error"] = str(e)

    return result


# ---------------- Sandbox indicators ----------------

def check_sandboxing():
    result = {
        "flatpak_installed": False,
        "snap_installed": False,
        "firejail_installed": False,
        "bubblewrap_installed": False,
        "user_namespaces": None,
        "seccomp_supported": "unknown",
        "error": None
    }

    errors = []

    for tool in ["flatpak", "snap", "firejail", "bwrap"]:
        out, err = run_command(["which", tool])
        if tool == "flatpak":
            result["flatpak_installed"] = out is not None
        elif tool == "snap":
            result["snap_installed"] = out is not None
        elif tool == "firejail":
            result["firejail_installed"] = out is not None
        elif tool == "bwrap":
            result["bubblewrap_installed"] = out is not None

        if err and "Command not found" not in err:
            errors.append(err)

    userns_file = "/proc/sys/kernel/unprivileged_userns_clone"
    if os.path.exists(userns_file):
        try:
            with open(userns_file) as f:
                value = f.read().strip()
            result["user_namespaces"] = "enabled" if value == "1" else "disabled"
        except Exception as e:
            result["user_namespaces"] = "unreadable"
            errors.append(str(e))

    seccomp_file = "/boot/config-" + os.uname().release
    if os.path.exists(seccomp_file):
        try:
            with open(seccomp_file) as f:
                cfg = f.read()
            result["seccomp_supported"] = "yes" if "CONFIG_SECCOMP=y" in cfg else "no"
        except Exception as e:
            result["seccomp_supported"] = "unreadable"
            errors.append(str(e))

    if errors:
        result["error"] = errors

    return result


# ---------------- Containerization ----------------

def check_containerization():
    result = {
        "docker_installed": False,
        "podman_installed": False,
        "lxc_installed": False,
        "systemd_nspawn_installed": False,
        "running_in_container": "no",
        "error": None
    }

    errors = []

    for tool, key in [
        ("docker", "docker_installed"),
        ("podman", "podman_installed"),
        ("lxc-info", "lxc_installed"),
        ("systemd-nspawn", "systemd_nspawn_installed")
    ]:
        out, err = run_command(["which", tool])
        result[key] = out is not None
        if err and "Command not found" not in err:
            errors.append(err)

    if os.path.exists("/.dockerenv"):
        result["running_in_container"] = "yes (Docker)"

    container_env = os.environ.get("container")
    if container_env:
        result["running_in_container"] = f"yes ({container_env})"

    cgroup_info, _ = run_command(["cat", "/proc/1/cgroup"])
    if cgroup_info:
        if any(x in cgroup_info.lower() for x in ["docker", "podman", "containerd", "lxc"]):
            result["running_in_container"] = "yes (cgroup indication)"

    if errors:
        result["error"] = errors

    return result


# ---------------- SCORING ----------------

def compute_security_score(data):
    score = 0.0

    # SELinux
    selinux = data.get("selinux", {})
    status = (selinux.get("status") or "").lower()

    if "enforcing" in status:
        score += 0.35
    elif "permissive" in status:
        score += 0.2

    # AppArmor
    apparmor = data.get("apparmor", {})
    enabled = (apparmor.get("enabled") or "").lower()
    profiles = apparmor.get("profiles_loaded")

    if enabled == "yes":
        if isinstance(profiles, int) and profiles > 0:
            score += 0.35
        else:
            score += 0.2

    # ASLR
    aslr = data.get("aslr", {})
    status = (aslr.get("status") or "").lower()

    if "full" in status:
        score += 0.2
    elif "conservative" in status:
        score += 0.1

    # Sandboxing / Containers
    sandbox = data.get("sandboxing", {})
    container = data.get("containerization", {})

    if any([
        sandbox.get("flatpak_installed"),
        sandbox.get("snap_installed"),
        sandbox.get("firejail_installed"),
        sandbox.get("bubblewrap_installed"),
        container.get("docker_installed"),
        container.get("podman_installed")
    ]):
        score += 0.1

    return round(score, 2)


# ---------------- MAIN ----------------

def main():
    output = {
        "selinux": None,
        "apparmor": None,
        "aslr": None,
        "sandboxing": None,
        "containerization": None,
        "security_score": 0.0,
        "error": None}

    try:
        output["selinux"] = check_selinux()
        output["apparmor"] = check_apparmor()
        output["aslr"] = check_aslr()
        output["sandboxing"] = check_sandboxing()
        output["containerization"] = check_containerization()

        output["security_score"] = compute_security_score(output)

    except Exception as e:
        output["error"] = str(e)

    print(json.dumps(output, indent=2))


if __name__ == "__main__":
    main()
