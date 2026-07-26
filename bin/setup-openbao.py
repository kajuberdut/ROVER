#!/usr/bin/env python3
"""bin/setup-openbao.py: Initialize OpenBao with AppRole auth.

Safe to re-run; skips if openbao_keys.json already exists in project root.
"""

from __future__ import annotations

import contextlib
import json
import shutil
import subprocess
import sys
import time
from pathlib import Path

# ── helpers ──────────────────────────────────────────────────────────────────

RED = "\033[0;31m"
GREEN = "\033[0;32m"
YELLOW = "\033[1;33m"
NC = "\033[0m"


def info(msg: str) -> None:
    print(f"{GREEN}[rover]{NC} {msg}")


def warn(msg: str) -> None:
    print(f"{YELLOW}[warn]{NC}  {msg}")


def error(msg: str) -> None:
    print(f"{RED}[error]{NC} {msg}")
    sys.exit(1)


def require(cmd: str) -> None:
    if shutil.which(cmd) is None:
        error(f"'{cmd}' is required but not found in PATH.")


# ── main ─────────────────────────────────────────────────────────────────────


def main() -> None:
    require("docker")
    require("jq")

    repo_root = Path(__file__).resolve().parent.parent
    keys_file = repo_root / "openbao_keys.json"
    data_dir = repo_root / "openbao" / "data"
    config_dir = repo_root / "openbao" / "config"

    if keys_file.exists():
        warn("openbao_keys.json already exists. Skipping OpenBao initialization.")
        return

    info("Initializing OpenBao persistent storage and AppRole...")

    data_dir.mkdir(parents=True, exist_ok=True)
    config_dir.mkdir(parents=True, exist_ok=True)
    data_dir.chmod(0o777)
    config_dir.chmod(0o777)

    # ── clean stale data ─────────────────────────────────────────────────
    if list(data_dir.iterdir()):
        with contextlib.suppress(Exception):
            for child in data_dir.iterdir():
                if child.is_dir():
                    shutil.rmtree(child, ignore_errors=True)
                else:
                    child.unlink(missing_ok=True)

        # Fall back to ephemeral docker container to clean container-owned files
        if list(data_dir.iterdir()):
            subprocess.run(
                [
                    "docker",
                    "run",
                    "--rm",
                    "-v",
                    f"{data_dir}:/data",
                    "alpine",
                    "sh",
                    "-c",
                    "rm -rf /data/* /data/.* 2>/dev/null || true",
                ],
                check=False,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
            )

    # ── write config ─────────────────────────────────────────────────────
    config_file = config_dir / "config.hcl"
    config_file.write_text(
        """\
storage "file" {
  path = "/vault/file"
}
listener "tcp" {
  address     = "0.0.0.0:8200"
  tls_disable = 1
}
disable_mlock = true
"""
    )

    # ── start temp container ─────────────────────────────────────────────
    info("Starting temporary OpenBao container...")
    subprocess.run(
        ["docker", "rm", "-f", "temp_bao"],
        check=False,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )

    subprocess.run(
        [
            "docker",
            "run",
            "-d",
            "--name",
            "temp_bao",
            "-v",
            f"{data_dir}:/vault/file",
            "-v",
            f"{config_dir}:/vault/config",
            "openbao/openbao:latest",
            "server",
            "-config=/vault/config/config.hcl",
        ],
        check=True,
        stdout=subprocess.DEVNULL,
    )

    # ── wait for ready ───────────────────────────────────────────────────
    info("Waiting for OpenBao to become ready...")
    max_retries = 30
    for count in range(1, max_retries + 1):
        result = subprocess.run(
            [
                "docker",
                "exec",
                "-e",
                "BAO_ADDR=http://127.0.0.1:8200",
                "temp_bao",
                "bao",
                "status",
            ],
            capture_output=True,
            text=True,
        )
        if "Initialized" in result.stdout or "Initialized" in result.stderr:
            print()
            info(f"OpenBao ready after {count}s.")
            break
        print(" .", end="", flush=True)
        time.sleep(1)
    else:
        print()
        error("OpenBao failed to start in time.")
        subprocess.run(["docker", "rm", "-f", "temp_bao"], check=False)
        return

    # ── initialize ───────────────────────────────────────────────────────
    info("Performing initialization and configuration...")

    result = subprocess.run(
        [
            "docker",
            "exec",
            "-e",
            "BAO_ADDR=http://127.0.0.1:8200",
            "temp_bao",
            "bao",
            "operator",
            "init",
            "-key-shares=1",
            "-key-threshold=1",
            "-format=json",
        ],
        capture_output=True,
        text=True,
    )
    if result.returncode != 0:
        error(f"OpenBao init failed:\n{result.stderr}")
        subprocess.run(["docker", "rm", "-f", "temp_bao"], check=False)
        return

    keys = json.loads(result.stdout)
    unseal_key = keys["unseal_keys_b64"][0]
    root_token = keys["root_token"]

    # Write unseal key for the auto-unseal sidecar container
    unseal_file = config_dir / "unseal_key.txt"
    unseal_file.write_text(unseal_key + "\n")

    # Save keys file without root_token for security hygiene
    keys_to_save = dict(keys)
    if "root_token" in keys_to_save:
        del keys_to_save["root_token"]
    keys_file.write_text(json.dumps(keys_to_save, indent=2) + "\n")

    # ── unseal + configure in a single session ──────────────────────────
    setup_script = f"""\
bao operator unseal {unseal_key} > /dev/null
bao secrets enable -version=2 kv > /dev/null
bao auth enable approle > /dev/null
cat <<'EOF' > /tmp/rover.hcl
path "kv/data/rover/*" {{ capabilities = ["create", "read", "update", "delete"] }}
path "kv/metadata/rover/*" {{ capabilities = ["list", "delete"] }}
path "kv/data/scanner/*" {{ capabilities = ["create", "read", "update", "delete"] }}
path "kv/data/registry/*" {{ capabilities = ["create", "read", "update", "delete"] }}
EOF
bao policy write rover-web /tmp/rover.hcl > /dev/null
bao write auth/approle/role/rover-web token_policies="rover-web" token_ttl="24h" token_max_ttl="720h" secret_id_ttl="0" > /dev/null
echo "===ROLE_ID_START==="
bao read -format=json auth/approle/role/rover-web/role-id
echo "===ROLE_ID_END==="
echo "===SECRET_ID_START==="
bao write -f -format=json auth/approle/role/rover-web/secret-id
echo "===SECRET_ID_END==="
"""

    tmp_script = repo_root / ".bao-setup-temp.sh"
    tmp_script.write_text(setup_script)
    try:
        subprocess.run(
            ["docker", "cp", str(tmp_script), "temp_bao:/tmp/bao-setup.sh"],
            check=True,
            stdout=subprocess.DEVNULL,
        )
        result = subprocess.run(
            [
                "docker",
                "exec",
                "-e",
                "BAO_ADDR=http://127.0.0.1:8200",
                "-e",
                f"BAO_TOKEN={root_token}",
                "temp_bao",
                "sh",
                "/tmp/bao-setup.sh",
            ],
            capture_output=True,
            text=True,
        )
        if result.returncode != 0:
            error(f"OpenBao configuration failed:\n{result.stderr}")
            subprocess.run(["docker", "rm", "-f", "temp_bao"], check=False)
            return
    finally:
        tmp_script.unlink(missing_ok=True)

    # ── parse credentials ────────────────────────────────────────────────
    info("Extracting credentials...")
    role_id = secret_id = ""
    stdout = result.stdout

    if "===ROLE_ID_START===" in stdout and "===ROLE_ID_END===" in stdout:
        role_json_str = (
            stdout.split("===ROLE_ID_START===")[1].split("===ROLE_ID_END===")[0].strip()
        )
        try:
            role_id = json.loads(role_json_str)["data"]["role_id"]
        except Exception as e:
            error(f"Failed to parse role_id JSON: {e}\n{role_json_str}")

    if "===SECRET_ID_START===" in stdout and "===SECRET_ID_END===" in stdout:
        secret_json_str = (
            stdout.split("===SECRET_ID_START===")[1]
            .split("===SECRET_ID_END===")[0]
            .strip()
        )
        try:
            secret_id = json.loads(secret_json_str)["data"]["secret_id"]
        except Exception as e:
            error(f"Failed to parse secret_id JSON: {e}\n{secret_json_str}")

    if not role_id or not secret_id:
        error(f"Failed to extract credentials. Output:\n{result.stdout}")
        subprocess.run(["docker", "rm", "-f", "temp_bao"], check=False)
        return

    # ── write to .env.local ──────────────────────────────────────────────
    env_file = repo_root / ".env.local"
    env_file.write_text(
        env_file.read_text(encoding="utf-8", errors="replace")
        + f"OPENBAO_ROLE_ID={role_id}\n"
        f"OPENBAO_SECRET_ID={secret_id}\n"
        f"BAO_ROLE_ID={role_id}\n"
        f"BAO_SECRET_ID={secret_id}\n"
    )

    # ── cleanup ──────────────────────────────────────────────────────────
    info("Cleaning up temporary container...")
    subprocess.run(["docker", "rm", "-f", "temp_bao"], check=False)
    info("OpenBao credentials written to .env.local. Keep openbao_keys.json secure.")


if __name__ == "__main__":
    main()
