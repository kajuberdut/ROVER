import argparse
import json
import os
import sys
import urllib.error
import urllib.request


def handle_publish_metadata(args):
    """Handles the publish-metadata command."""
    token = args.token or os.environ.get("ROVER_API_TOKEN")
    if not token:
        print("Error: ROVER_API_TOKEN environment variable or --token flag is required.", file=sys.stderr)
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

    try:
        with urllib.request.urlopen(req) as response:
            resp_body = response.read().decode("utf-8")
            print(f"Success ({response.status}): {resp_body}")
    except urllib.error.HTTPError as e:
        resp_body = e.read().decode("utf-8") if e.fp else ""
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

    subparsers = parser.add_subparsers(dest="command", required=True, help="Available commands")

    # publish-metadata command
    publish_parser = subparsers.add_parser("publish-metadata", help="Publish CI image metadata to ROVER")
    publish_parser.add_argument("--hash", required=True, help="The image hash (e.g., sha256:...)")
    publish_parser.add_argument("--repo", required=True, help="The source repository URI")
    publish_parser.add_argument("--commit", required=True, help="The git commit hash")
    publish_parser.add_argument("--job-url", help="The URL to the CI job that built this image")
    publish_parser.add_argument("--tags", help="Comma-separated list of image tags")
    publish_parser.add_argument("--metadata", help="Additional metadata as a JSON string")

    args = parser.parse_args()

    if args.command == "publish-metadata":
        handle_publish_metadata(args)


if __name__ == "__main__":
    main()
