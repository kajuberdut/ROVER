import json
import logging
import subprocess
import tempfile
import urllib.error
import urllib.request

# ruff: noqa: S603, S607
from testcontainers.core.container import DockerContainer  # type: ignore

logger = logging.getLogger(__name__)


from typing import Any, cast

from rover import scan_queue


def run_major_component_scan(
    target_name: str, target_version: str
) -> tuple[dict[str, Any], str, str | None]:
    """
    Fetches the end of life date for a given component and version.
    Utilizes a 28-day database cache to avoid rate limiting.
    """
    logger.info(f"Checking EOL data for {target_name} version {target_version}")

    cached_json = scan_queue.get_cached_eol_data(target_name, target_version)
    if cached_json:
        logger.info(f"Using cached EOL data for {target_name} v{target_version}")
        return json.loads(cached_json), "eol_cache", "cached"

    url = f"https://endoflife.date/api/{target_name}/{target_version}.json"
    req = urllib.request.Request(url, headers={"User-Agent": "RoverScanner/1.0"})  # noqa: S310

    try:
        with urllib.request.urlopen(req) as response:  # noqa: S310
            data = response.read().decode("utf-8")
            parsed_data = json.loads(data)

            # Store the raw validated json exactly into our cache
            scan_queue.set_cached_eol_data(
                target_name, target_version, json.dumps(parsed_data)
            )

            return parsed_data, "eol_api", "fresh"
    except urllib.error.HTTPError as e:
        logger.error(f"HTTP error fetching EOL data: {e.code} - {e.reason}")
        if e.code == 404:
            raise Exception(f"EOL data not found for {target_name} v{target_version}")
        raise Exception(f"Failed to fetch EOL data: {e.reason}")
    except Exception as e:
        logger.error(f"Error fetching EOL data: {e}")
        raise Exception("Failed to retrieve EOL data from endoflife.date API")


def extract_oci_annotations(image_name: str) -> dict[str, str | None]:
    """
    Uses skopeo inspect to pull OCI annotations like source and revision.
    Returns a dictionary of found annotations.
    """
    logger.info(f"Extracting OCI annotations for image {image_name}")
    try:
        # TODO(auth): For private registries, pass `--creds user:token` to skopeo
        # or mount a Docker credential store / authfile via `--authfile <path>`.
        # Credentials could be stored per-image in the database and injected here.
        url = f"docker://{image_name}"
        res = subprocess.run(  # noqa: S603, S607
            ["skopeo", "inspect", url],
            capture_output=True,
            text=True,
            timeout=15,
            check=True,
        )
        data = json.loads(res.stdout)
        labels = data.get("Labels") or {}

        return {
            "source": labels.get("org.opencontainers.image.source"),
            "revision": labels.get("org.opencontainers.image.revision"),
        }
    except subprocess.TimeoutExpired:
        logger.warning(f"Timeout extracting OCI annotations for {image_name}")
    except subprocess.CalledProcessError as e:
        logger.warning(
            f"Failed to extract OCI annotations for {image_name}: {e.stderr}"
        )
    except Exception as e:
        logger.warning(f"Error parsing Skopeo output for {image_name}: {e}")

    return {"source": None, "revision": None}


def run_trivy_scan(
    target_url: str, git_ref: str | None = None, target_type: str = "repo"
) -> tuple[dict[str, Any], str, str | None]:
    """
    Runs a Trivy CVE scan against a git repository or Docker image using Testcontainers.
    """
    logger.info(
        f"Starting Trivy scan for {target_type} {target_url} (ref {git_ref or 'HEAD'})"
    )

    with tempfile.TemporaryDirectory() as tmpdir:
        commit_hash = "latest"
        tags_str = None

        if target_type == "repo":
            # Clone the repository locally
            # TODO(auth): For private Git repositories (GitHub, Bitbucket, GitLab, etc.),
            # inject an oauth token or deploy key via the clone URL:
            #   https://oauth-token@github.com/org/repo
            # Credentials should be stored per-repository in the database and
            # substituted into the URL here. Never log the substituted URL.
            try:
                subprocess.run(  # noqa: S603, S607
                    ["git", "clone", target_url, tmpdir],
                    check=True,
                    capture_output=True,
                )
            except subprocess.CalledProcessError as e:
                logger.error(f"Failed to clone repository: {e.stderr.decode('utf-8')}")
                raise Exception("Failed to clone target repository")

            if git_ref:
                try:
                    subprocess.run(  # noqa: S603, S607
                        ["git", "checkout", git_ref],
                        cwd=tmpdir,
                        check=True,
                        capture_output=True,
                    )
                except subprocess.CalledProcessError as e:
                    logger.error(
                        f"Failed to checkout ref {git_ref}: {e.stderr.decode('utf-8')}"
                    )
                    raise Exception(f"Failed to checkout git reference: {git_ref}")

            # Capture metadata
            try:
                res = subprocess.run(  # noqa: S603, S607
                    ["git", "rev-parse", "HEAD"],
                    cwd=tmpdir,
                    check=True,
                    capture_output=True,
                    text=True,
                )
                commit_hash = res.stdout.strip()

                res = subprocess.run(  # noqa: S603, S607
                    ["git", "tag", "--points-at", "HEAD"],
                    cwd=tmpdir,
                    check=True,
                    capture_output=True,
                    text=True,
                )
                tags = [t.strip() for t in res.stdout.split("\n") if t.strip()]
                tags_str = ", ".join(tags) if tags else None
            except subprocess.CalledProcessError as e:
                logger.warning(f"Failed to capture git metadata: {e}")
                commit_hash = "unknown"
                tags_str = None
        elif target_type == "image":
            # If git_ref is provided, use it as the image tag, unless target_url already has a tag
            image_target = target_url
            if git_ref and ":" not in image_target.split("/")[-1]:
                image_target = f"{target_url}:{git_ref}"
            tags_str = image_target
            commit_hash = "latest"  # Images don't have git commits in the same way

        # Pinned to specific sha256 digest to prevent supply chain attacks on mutable tags
        # TODO(auth): For private Docker registries (GHCR, ECR, private Docker Hub),
        # Trivy requires `TRIVY_USERNAME` / `TRIVY_PASSWORD` environment variables,
        # or a registry config file at `~/.docker/config.json` inside the container.
        # These should be injected as per-image credentials stored in the database:
        #   container.with_env("TRIVY_USERNAME", creds.username)
        #   container.with_env("TRIVY_PASSWORD", creds.token)  # noqa: S106
        container = DockerContainer(
            # Pinned to aquasec/trivy:0.69.3 linux/amd64 digest to prevent supply chain attacks.
            "aquasec/trivy@sha256:bcc376de8d77cfe086a917230e818dc9f8528e3c852f7b1aff648949b6258d1c"
        )

        # Configure Trivy database cache using an ephemeral named volume
        container.with_env("TRIVY_CACHE_DIR", "/trivy-cache")
        container.with_volume_mapping(
            "trivy-vulnerability-db-cache", "/trivy-cache", "rw"
        )
        # Mount the Docker socket so Trivy can scan images
        container.with_volume_mapping(
            "/var/run/docker.sock", "/var/run/docker.sock", "ro"
        )

        if target_type == "repo":
            # Tell the container to execute the repo scan and output json for the specific commit we resolved
            container.with_command(f"repo {target_url} --commit {commit_hash} -f json")
        else:
            # Tell the container to execute the image scan
            container.with_command(f"image {image_target} -f json")

        try:
            container.start()

            # Wait for the container to exit and get the logs
            client = container.get_docker_client()
            result = client.client.containers.get(container.get_wrapped_container().id)

            exit_code = result.wait()["StatusCode"]

            logs = container.get_logs()
            stdout = logs[0].decode("utf-8")
            stderr = logs[1].decode("utf-8")

            logger.info(f"Trivy stdout (first 200 chars): {stdout[:200]}")
            logger.info(f"Trivy stderr: {stderr}")

            if exit_code != 0:
                logger.warning(
                    f"Trivy scan exited with code {exit_code}. Stderr: {stderr}"
                )

            try:
                json_start = stdout.find("{")
                json_end = stdout.rfind("}") + 1
                if json_start >= 0 and json_end > json_start:
                    json_str = stdout[json_start:json_end]
                    scan_results = cast(dict[str, Any], json.loads(json_str))
                else:
                    if exit_code != 0:
                        raise Exception(f"Trivy failed with exit code {exit_code}")
                    scan_results = {"Results": []}

                return scan_results, commit_hash, tags_str

            except json.JSONDecodeError as e:
                logger.error(f"Failed to parse Trivy JSON output. Error: {e}")
                logger.error(f"Raw output: {stdout}")
                raise Exception("Failed to parse vulnerability report")

        finally:
            container.stop()


def run_semgrep_scan(
    target_url: str, git_ref: str | None = None
) -> tuple[dict[str, Any], str, str | None]:
    """
    Runs a Semgrep SAST scan against a cloned git repository using Testcontainers.

    Because ROVER itself runs inside Docker (accessed via a mounted socket), sibling
    containers launched from the host daemon cannot see ROVER's local filesystem.
    We solve this by cloning into a *named Docker volume* — volumes live on the host
    daemon and are mountable by any container, including the Semgrep sibling.

    Returns (results_dict, resolved_commit_hash, resolved_tags_str).
    """
    import uuid as _uuid

    import docker as _docker  # type: ignore

    logger.info(
        f"Starting Semgrep scan for repo {target_url} (ref {git_ref or 'HEAD'})"
    )

    docker_client = _docker.from_env()
    volume_name = f"rover-semgrep-clone-{_uuid.uuid4().hex[:12]}"

    try:
        # Create an ephemeral named volume on the host daemon
        docker_client.volumes.create(name=volume_name)
        logger.info(f"Created Docker volume {volume_name} for semgrep clone")

        # Detect whether git_ref is a commit hash (hex-only, 7–40 chars) or a branch/tag name.
        # git clone --branch only works with branch/tag names; commit hashes require a
        # separate checkout step after cloning the full history.
        import re as _re

        is_commit = bool(git_ref and _re.fullmatch(r"[0-9a-f]{7,40}", git_ref))

        if is_commit:
            # Full clone (no --depth) so the specific commit is reachable, then checkout.
            clone_args = ["clone", target_url, "/src"]
        elif git_ref:
            # Branch or tag: shallow clone is safe and much faster.
            clone_args = [
                "clone",
                "--branch",
                git_ref,
                "--depth",
                "1",
                target_url,
                "/src",
            ]
        else:
            # Default branch, shallow.
            clone_args = ["clone", "--depth", "1", target_url, "/src"]

        # TODO(auth): For private Git repositories injected tokens must be passed
        # through to the alpine/git container. The safest approach is to rewrite
        # the clone URL to embed credentials (e.g. https://token@host/repo) and
        # ensure the container never echoes the URL to logs. Alternatively, mount
        # a pre-populated `.netrc` file or SSH key via a Docker secret/volume.
        docker_client.containers.run(
            "alpine/git",
            command=clone_args,
            volumes={volume_name: {"bind": "/src", "mode": "rw"}},
            remove=True,
            stdout=True,
            stderr=True,
        )

        if is_commit:
            # Check out the specific commit now that the full history is available.
            docker_client.containers.run(
                "alpine/git",
                command=["-C", "/src", "checkout", git_ref],
                volumes={volume_name: {"bind": "/src", "mode": "rw"}},
                remove=True,
                stdout=True,
                stderr=True,
            )
            logger.info(f"Checked out commit {git_ref} in volume {volume_name}")

        logger.info(
            f"Cloned {target_url} (ref={git_ref or 'default'}) into volume {volume_name}"
        )

        # --- Resolve commit hash and tags via another transient container ---
        commit_hash = "unknown"
        tags_str = None
        try:
            rev = docker_client.containers.run(
                "alpine/git",
                command=["-C", "/src", "rev-parse", "HEAD"],
                volumes={volume_name: {"bind": "/src", "mode": "ro"}},
                remove=True,
                stdout=True,
                stderr=False,
            )
            commit_hash = rev.decode("utf-8").strip()

            tag_out = docker_client.containers.run(
                "alpine/git",
                command=["-C", "/src", "tag", "--points-at", "HEAD"],
                volumes={volume_name: {"bind": "/src", "mode": "ro"}},
                remove=True,
                stdout=True,
                stderr=False,
            )
            tags = [t.strip() for t in tag_out.decode("utf-8").split("\n") if t.strip()]
            tags_str = ", ".join(tags) if tags else None
        except Exception as e:
            logger.warning(f"Failed to capture git metadata: {e}")

        # --- Run Semgrep against the volume ---
        # Pinned to specific sha256 digest to prevent supply chain attacks on mutable tags
        container = DockerContainer(
            "semgrep/semgrep@sha256:3dab091ee3247fce7e4ed3df9f92b3bd72692c083295f53cec3f135b86404db1"
        )
        container.with_volume_mapping(volume_name, "/src", "ro")
        # --config auto: auto-detect languages and pull matching rules from semgrep.dev
        container.with_command("semgrep scan /src --json --no-git-ignore --config auto")

        try:
            container.start()

            client = container.get_docker_client()
            result = client.client.containers.get(container.get_wrapped_container().id)
            exit_code = result.wait()["StatusCode"]

            logs = container.get_logs()
            stdout = logs[0].decode("utf-8")
            stderr = logs[1].decode("utf-8")

            logger.info(f"Semgrep stdout (first 200 chars): {stdout[:200]}")
            logger.info(f"Semgrep stderr: {stderr[:500]}")

            # Semgrep exits with code 1 when findings are found — that is not an error
            if exit_code not in (0, 1):
                logger.warning(
                    f"Semgrep scan exited with code {exit_code}. Stderr: {stderr}"
                )

            try:
                json_start = stdout.find("{")
                json_end = stdout.rfind("}") + 1
                if json_start >= 0 and json_end > json_start:
                    scan_results = cast(
                        dict[str, Any], json.loads(stdout[json_start:json_end])
                    )
                else:
                    if exit_code not in (0, 1):
                        raise Exception(f"Semgrep failed with exit code {exit_code}")
                    scan_results = {"results": [], "errors": []}

                return scan_results, commit_hash, tags_str

            except json.JSONDecodeError as e:
                logger.error(f"Failed to parse Semgrep JSON output. Error: {e}")
                logger.error(f"Raw output: {stdout[:500]}")
                raise Exception("Failed to parse Semgrep report")

        finally:
            container.stop()

    finally:
        # Always clean up the ephemeral volume
        try:
            vol = docker_client.volumes.get(volume_name)
            vol.remove(force=True)
            logger.info(f"Removed Docker volume {volume_name}")
        except Exception as e:
            logger.warning(f"Failed to remove volume {volume_name}: {e}")


def fetch_helm_chart_versions(repo_url: str) -> dict[str, list[str]]:
    """
    Spawns an ephemeral alpine/helm container to interrogate a remote Helm repository.
    Returns a dictionary mapping chart names to a list of available versions.

    Supports two URL schemes:
    - HTTP/HTTPS Helm repos (e.g. https://charts.bitnami.com/bitnami):
      Uses `helm repo add` + `helm search repo -l` to list all charts and versions.
    - OCI registries (e.g. oci://registry-1.docker.io/bitnamicharts/nginx):
      Uses `helm show chart` to fetch the chart name and latest available version.
      Tag enumeration requires registry auth which is not available without credentials,
      so only the current latest version is returned.
    """
    import docker

    docker_client = docker.from_env()
    logger.info(f"Interrogating helm repo {repo_url} for charts and versions")

    is_oci = repo_url.startswith("oci://")

    try:
        if is_oci:
            return _fetch_oci_chart_versions(docker_client, repo_url)
        else:
            return _fetch_http_repo_versions(docker_client, repo_url)
    except Exception as e:
        logger.error(f"Failed to fetch helm chart versions for {repo_url}: {e}")
        return {}


_HELM_IMAGE = "alpine/helm@sha256:a572075a78666ad6fb1f40cb477a9e2eabbc46f3739beeb81904a6121f6ef027"


def _fetch_oci_chart_versions(
    docker_client: "Any", oci_url: str
) -> dict[str, list[str]]:
    """
    For OCI Helm registries: runs `helm show chart <oci_url>` in an ephemeral container
    and parses the YAML output to extract chart name and version.
    """

    import yaml  # type: ignore[import-untyped]

    client = docker_client  # type: ignore[assignment]
    logger.info(f"Using OCI path for {oci_url}")

    # TODO(auth): For private OCI Helm registries (private Docker Hub namespaces,
    # GHCR, JFrog Artifactory, etc.), `helm show chart` / `helm pull` require
    # registry credentials. Pass them via environment variables inside the container:
    #   env=["HELM_REGISTRY_CONFIG=/tmp/config.json"] with a mounted credential file,
    # or inject --username / --password flags (marked noqa: S106 to suppress secrets lint).
    # Credentials could be stored per-registry in the database and mounted via tmpfs.
    output_bytes = client.containers.run(
        _HELM_IMAGE,
        command=["-c", f"helm show chart {oci_url} 2>&1"],
        entrypoint="sh",
        remove=True,
        stdout=True,
        stderr=False,
    )
    output = output_bytes.decode("utf-8")

    # The first few lines may be pull progress messages; find the YAML start.
    yaml_start = output.find("apiVersion:")
    if yaml_start == -1:
        # Fall back to annotations block start
        yaml_start = output.find("annotations:")
    if yaml_start == -1:
        yaml_start = 0

    chart_data = yaml.safe_load(output[yaml_start:])
    chart_name = chart_data.get("name") or oci_url.rstrip("/").split("/")[-1]
    version = chart_data.get("version", "latest")
    return {chart_name: [version]}


def _fetch_http_repo_versions(
    docker_client: "Any", repo_url: str
) -> dict[str, list[str]]:
    """
    For standard HTTP/HTTPS Helm repos: uses `helm repo add` + `helm search repo -l -o json`
    to enumerate all charts and every published version.
    """

    # TODO(auth): For private HTTP Helm repos protected by basic auth or bearer tokens,
    # `helm repo add` supports `--username` / `--password` (and `--pass-credentials`
    # for cross-origin chart dependencies). These should be looked up per-repo from
    # the database and injected into the shell command string — but take care to
    # never write credentials to container logs or Docker inspect output.
    output_bytes = docker_client.containers.run(
        _HELM_IMAGE,
        command=[
            "-c",
            f"helm repo add temp {repo_url} > /dev/null 2>&1 && helm search repo temp -l -o json",
        ],
        entrypoint="sh",
        remove=True,
        stdout=True,
        stderr=False,
    )
    output_json = output_bytes.decode("utf-8")

    # Sometimes helm emits warnings to stdout before the JSON array.
    json_start = output_json.find("[")
    if json_start != -1:
        output_json = output_json[json_start:]

    raw_data = json.loads(output_json)

    chart_catalog: dict[str, list[str]] = {}
    for entry in raw_data:
        raw_name = entry.get("name", "")
        chart_name = raw_name[5:] if raw_name.startswith("temp/") else raw_name
        version = entry.get("version")
        if chart_name and version:
            if chart_name not in chart_catalog:
                chart_catalog[chart_name] = []
            chart_catalog[chart_name].append(version)
    return chart_catalog


def run_helm_ingestion(
    repo_url: str, chart_name: str, chart_version: str | None = None
) -> list[str]:
    """
    Renders a Helm chart using an ephemeral alpine/helm container and extracts all container images.
    Returns a list of image identifiers.
    """
    import yaml  # type: ignore[import-untyped]

    logger.info(
        f"Starting Helm ingestion for {repo_url} / {chart_name} (version: {chart_version or 'latest'})"
    )

    is_oci = repo_url.startswith("oci://")
    if is_oci:
        # For OCI registries the full reference is the chart argument itself:
        #   helm template <release-name> <oci-url> [--version <ver>]
        cmd = f"template {chart_name} {repo_url}"
        if chart_version:
            cmd += f" --version {chart_version}"
    else:
        # For HTTP repos use the --repo flag:
        #   helm template <release-name> <chart-name> --repo <repo-url> [--version <ver>]
        cmd = f"template {chart_name} {chart_name} --repo {repo_url}"
        if chart_version:
            cmd += f" --version {chart_version}"
    # TODO(auth): For OCI Helm chart ingestion from private registries, `helm template`
    # needs the same registry credentials as `helm show chart`. Inject them via
    # HELM_REGISTRY_CONFIG or --username/--password flags before the template command.

    container = DockerContainer(
        "alpine/helm@sha256:a572075a78666ad6fb1f40cb477a9e2eabbc46f3739beeb81904a6121f6ef027"
    ).with_command(cmd)

    try:
        container.start()

        client = container.get_docker_client()
        result = client.client.containers.get(container.get_wrapped_container().id)
        exit_code = result.wait()["StatusCode"]

        logs = container.get_logs()
        stdout = logs[0].decode("utf-8")
        stderr = logs[1].decode("utf-8")

        if exit_code != 0:
            logger.error(
                f"Helm template failed with code {exit_code}. Stderr: {stderr}"
            )
            raise Exception(f"Failed to ingest helm chart: {stderr}")

        images = set()

        # Parse the multi-document YAML stream
        docs = yaml.safe_load_all(stdout)

        def find_images(obj: Any) -> None:
            if isinstance(obj, dict):
                for k, v in obj.items():
                    if k == "image" and isinstance(v, str):
                        images.add(v)
                    else:
                        find_images(v)
            elif isinstance(obj, list):
                for item in obj:
                    find_images(item)

        for doc in docs:
            if doc:
                find_images(doc)

        logger.info(f"Successfully extracted {len(images)} images from Helm chart")
        return list(images)

    except Exception as e:
        logger.error(f"Error during helm ingestion: {e}")
        raise
    finally:
        container.stop()
