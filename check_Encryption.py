import subprocess
import json


def get_root_device():
    result = subprocess.run(
        ["findmnt", "-n", "-o", "SOURCE", "/"],
        capture_output=True,
        text=True,
        check=True
    )
    return result.stdout.strip()


def is_luks(device):
    result = subprocess.run(
        ["cryptsetup", "isLuks", device],
        capture_output=True
    )
    return result.returncode == 0


def check_mapper(device):
    return device.startswith("/dev/mapper/")


def main():
    output = {
        "root_filesystem_device": None,
        "mapped_through_dev_mapper": False,
        "underlying_device": None,
        "storage_encryption_detected": False,
        "encryption_type": None,
        "score": None,
        "error": None
    }

    try:
        root_device = get_root_device()
        output["root_filesystem_device"] = root_device

        if not root_device:
            output["error"] = "Could not determine root filesystem device."
            output["score"] = -1
            print(json.dumps(output, indent=4))
            return

        # --- Case 1: device-mapper (common for LUKS) ---
        if check_mapper(root_device):
            output["mapped_through_dev_mapper"] = True

            underlying = subprocess.run(
                ["lsblk", "-no", "PKNAME", root_device],
                capture_output=True,
                text=True,
                check=True
            ).stdout.strip()

            if underlying:
                underlying_device = "/dev/" + underlying
                output["underlying_device"] = underlying_device

                if is_luks(underlying_device):
                    output["storage_encryption_detected"] = True
                    output["encryption_type"] = "LUKS"
                    output["score"] = 0.0
                    print(json.dumps(output, indent=4))
                    return

        # --- Case 2: direct device ---
        if is_luks(root_device):
            output["storage_encryption_detected"] = True
            output["encryption_type"] = "LUKS"
            output["score"] = 0.0

        # --- Default: no encryption detected ---
        if output["score"] is None:
            output["score"] = 1.0

    except FileNotFoundError as e:
        output["error"] = f"Required command not found: {e.filename}"
        output["score"] = -1

    except subprocess.CalledProcessError as e:
        cmd = " ".join(e.cmd) if e.cmd else "unknown command"
        output["error"] = f"Command failed: {cmd}"
        output["score"] = -1

    except Exception as e:
        output["error"] = str(e)
        output["score"] = -1

    print(json.dumps(output, indent=4))


if __name__ == "__main__":
    main()
