import argparse
import json
import os
import ssl
import sys
import urllib.error
import urllib.parse
import urllib.request


def _read_response_body(stream) -> str:
    """Safely reads and decodes bytes or string from an HTTP response or error stream."""
    if not stream:
        return ""
    try:
        raw = stream.read()
        if isinstance(raw, bytes):
            return raw.decode("utf-8")
        return str(raw)
    except Exception:
        return ""


def _get_ssl_context(args) -> ssl.SSLContext | None:
    """Constructs an unverified SSL context if --insecure flag or ROVER_INSECURE env var is set."""
    insecure_flag = getattr(args, "insecure", False)
    env_insecure = os.environ.get("ROVER_INSECURE", "").lower() in ("1", "true", "yes")
    env_skip_verify = os.environ.get("ROVER_SKIP_TLS_VERIFY", "").lower() in (
        "1",
        "true",
        "yes",
    )

    if insecure_flag or env_insecure or env_skip_verify:
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        return ctx
    return None


def handle_publish_metadata(args):
    """Handles the publish-metadata command."""
    token = args.token or os.environ.get("ROVER_API_TOKEN")
    if not token:
        print(
            "Error: ROVER_API_TOKEN environment variable or --token flag is required.",
            file=sys.stderr,
        )
        sys.exit(1)

    url = args.url or os.environ.get("ROVER_URL", "http://localhost:8000")
    endpoint = f"{url.rstrip('/')}/api/ci/image-metadata"

    # Parse metadata if provided
    metadata_dict = {}
    if args.metadata:
        try:
            metadata_dict = json.loads(args.metadata)
        except json.JSONDecodeError as e:
            print(f"Error: Invalid JSON provided for --metadata: {e}", file=sys.stderr)
            sys.exit(1)

    # Parse tags
    tags = [t.strip() for t in args.tags.split(",")] if args.tags else []

    payload = {
        "image_hash": args.hash,
        "repo_uri": args.repo,
        "commit_hash": args.commit,
        "metadata": metadata_dict,
        "image_tags": tags,
    }
    if args.job_url:
        payload["ci_job_url"] = args.job_url

    data = json.dumps(payload).encode("utf-8")

    req = urllib.request.Request(
        endpoint,
        data=data,
        headers={
            "Content-Type": "application/json",
            "Authorization": f"Bearer {token}",
        },
        method="POST",
    )

    ssl_ctx = _get_ssl_context(args)

    try:
        with urllib.request.urlopen(req, context=ssl_ctx) as response:
            resp_body = _read_response_body(response)
            print(f"Success ({response.status}): {resp_body}")
    except urllib.error.HTTPError as e:
        resp_body = _read_response_body(e)
        print(f"HTTP Error {e.code}: {e.reason}", file=sys.stderr)
        if resp_body:
            print(resp_body, file=sys.stderr)
        sys.exit(1)
    except urllib.error.URLError as e:
        print(f"Connection Error: {e.reason}", file=sys.stderr)
        sys.exit(1)


def handle_audit_logs(args):
    """Handles the audit-logs command."""
    token = args.token or os.environ.get("ROVER_API_TOKEN")
    if not token:
        print(
            "Error: ROVER_API_TOKEN environment variable or --token flag is required.",
            file=sys.stderr,
        )
        sys.exit(1)

    url = args.url or os.environ.get("ROVER_URL", "http://localhost:8000")
    base_endpoint = f"{url.rstrip('/')}/api/admin/audit_logs"

    params = {}
    if args.action:
        params["action"] = args.action
    if args.resource_type:
        params["resource_type"] = args.resource_type
    if args.resource_id:
        params["resource_id"] = args.resource_id
    if args.user_sub:
        params["user_sub"] = args.user_sub
    if args.limit is not None:
        params["limit"] = str(args.limit)
    if args.offset is not None:
        params["offset"] = str(args.offset)

    if params:
        query_string = urllib.parse.urlencode(params)
        endpoint = f"{base_endpoint}?{query_string}"
    else:
        endpoint = base_endpoint

    req = urllib.request.Request(
        endpoint,
        headers={
            "Accept": "application/json",
            "Authorization": f"Bearer {token}",
        },
        method="GET",
    )

    ssl_ctx = _get_ssl_context(args)

    try:
        with urllib.request.urlopen(req, context=ssl_ctx) as response:
            resp_body = _read_response_body(response)
            data = json.loads(resp_body) if resp_body else {}
            if args.json:
                print(json.dumps(data, indent=2))
            else:
                logs = data.get("audit_logs", [])
                count = data.get("count", len(logs))
                print(f"Audit Logs ({count} total matching entries):\n")
                if not logs:
                    print("No audit log records found.")
                    return

                header_fmt = "{:<24} {:<24} {:<24} {:<20} {:<15}"
                print(
                    header_fmt.format(
                        "TIMESTAMP",
                        "ACTION",
                        "USER (EMAIL/SUB)",
                        "RESOURCE",
                        "IP ADDRESS",
                    )
                )
                print("-" * 110)
                for entry in logs:
                    ts = str(entry.get("created_at", ""))[:19].replace("T", " ")
                    action = str(entry.get("action", ""))
                    user_str = (
                        entry.get("user_email") or entry.get("user_sub") or "system"
                    )
                    res_type = entry.get("resource_type") or ""
                    res_id = entry.get("resource_id") or ""
                    res_str = f"{res_type}/{res_id}" if res_type or res_id else "n/a"
                    ip = entry.get("ip_address") or "n/a"
                    print(
                        header_fmt.format(
                            ts[:24],
                            action[:24],
                            str(user_str)[:24],
                            res_str[:20],
                            str(ip)[:15],
                        )
                    )
    except urllib.error.HTTPError as e:
        resp_body = _read_response_body(e)
        print(f"HTTP Error {e.code}: {e.reason}", file=sys.stderr)
        if resp_body:
            print(resp_body, file=sys.stderr)
        sys.exit(1)
    except urllib.error.URLError as e:
        print(f"Connection Error: {e.reason}", file=sys.stderr)
        sys.exit(1)


def main():
    parser = argparse.ArgumentParser(description="ROVER Command Line Interface")
    parser.add_argument(
        "--url",
        help="ROVER server URL (defaults to ROVER_URL env var or http://localhost:8000)",
    )
    parser.add_argument(
        "--token",
        help="ROVER API Token (defaults to ROVER_API_TOKEN env var)",
    )
    parser.add_argument(
        "--insecure",
        "-k",
        action="store_true",
        help="Allow insecure SSL connections (skip TLS certificate verification)",
    )

    subparsers = parser.add_subparsers(
        dest="command", required=True, help="Available commands"
    )

    # publish-metadata command
    publish_parser = subparsers.add_parser(
        "publish-metadata", help="Publish CI image metadata to ROVER"
    )
    publish_parser.add_argument(
        "--hash", required=True, help="The image hash (e.g., sha256:...)"
    )
    publish_parser.add_argument(
        "--repo", required=True, help="The source repository URI"
    )
    publish_parser.add_argument("--commit", required=True, help="The git commit hash")
    publish_parser.add_argument(
        "--job-url", help="The URL to the CI job that built this image"
    )
    publish_parser.add_argument("--tags", help="Comma-separated list of image tags")
    publish_parser.add_argument(
        "--metadata", help="Additional metadata as a JSON string"
    )

    # audit-logs command
    audit_parser = subparsers.add_parser(
        "audit-logs",
        aliases=["audit_logs", "audit"],
        help="Retrieve and filter historical audit logs (requires system_admin role)",
    )
    audit_parser.add_argument(
        "--action", help="Filter logs by audit action (e.g. user.invite_create)"
    )
    audit_parser.add_argument(
        "--resource-type",
        dest="resource_type",
        help="Filter logs by resource type (e.g. user_invite, release_asset)",
    )
    audit_parser.add_argument(
        "--resource-id",
        dest="resource_id",
        help="Filter logs by resource ID",
    )
    audit_parser.add_argument(
        "--user-sub",
        dest="user_sub",
        help="Filter logs by user sub UUID",
    )
    audit_parser.add_argument(
        "--limit",
        type=int,
        default=100,
        help="Maximum number of log entries to return (default 100)",
    )
    audit_parser.add_argument(
        "--offset",
        type=int,
        default=0,
        help="Pagination offset (default 0)",
    )
    audit_parser.add_argument(
        "--json",
        action="store_true",
        help="Output raw JSON response",
    )

    args = parser.parse_args()

    if args.command == "publish-metadata":
        handle_publish_metadata(args)
    elif args.command in ("audit-logs", "audit_logs", "audit"):
        handle_audit_logs(args)


if __name__ == "__main__":
    main()
