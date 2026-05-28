#!/usr/bin/env python3

import os
import subprocess
import json


def run(cmd):
    try:
        return subprocess.check_output(cmd, stderr=subprocess.DEVNULL, text=True).strip(), None
    except FileNotFoundError:
        return None, f"Command not found: {cmd[0]}"
    except Exception as e:
        return None, str(e)


def detect_compositor_protocol():
    result = {
        "protocol": "Unknown",
        "details": None,
        "error": None
    }

    xdg_session_type = os.environ.get("XDG_SESSION_TYPE")
    wayland_display = os.environ.get("WAYLAND_DISPLAY")
    display = os.environ.get("DISPLAY")
    xdg_session_id = os.environ.get("XDG_SESSION_ID")

    result["details"] = {
        "XDG_SESSION_TYPE": xdg_session_type,
        "WAYLAND_DISPLAY": wayland_display,
        "DISPLAY": display,
        "XDG_SESSION_ID": xdg_session_id
    }

    # Primary detection
    if xdg_session_type:
        if xdg_session_type.lower() == "wayland":
            result["protocol"] = "Wayland"
        elif xdg_session_type.lower() in ("x11", "xorg"):
            result["protocol"] = "X11/Xorg"

    elif wayland_display:
        result["protocol"] = "Wayland"

    elif display:
        result["protocol"] = "X11/Xorg"

    elif xdg_session_id:
        loginctl, err = run(["loginctl", "show-session", xdg_session_id, "-p", "Type"])
        if loginctl:
            if "Type=wayland" in loginctl:
                result["protocol"] = "Wayland"
            elif "Type=x11" in loginctl:
                result["protocol"] = "X11/Xorg"
        if err:
            result["error"] = err

    return result


# ---------------- SCORING ----------------

def compute_protocol_score(detection):
    details = detection.get("details", {}) or {}

    has_wayland = bool(details.get("WAYLAND_DISPLAY"))
    has_x11 = bool(details.get("DISPLAY"))

    # Pure Wayland
    if has_wayland and not has_x11:
        return 0.0

    # Wayland + XWayland
    if has_wayland and has_x11:
        return 0.5

    # Pure X11
    if has_x11 and not has_wayland:
        return 1.0

    # Unknown fallback
    return 0.5


# ---------------- MAIN ----------------

def main():
    output = {
        "protocol": None,
        "details": None,
        "score": None,
        "error": None
    }

    try:
        detection = detect_compositor_protocol()

        output["protocol"] = detection["protocol"]
        output["details"] = detection["details"]
        output["error"] = detection["error"]

        # 🔥 compute score
        output["score"] = compute_protocol_score(detection)

    except Exception as e:
        output["error"] = str(e)

    print(json.dumps(output, indent=2))


if __name__ == "__main__":
    main()
