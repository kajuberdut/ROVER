"""src/rover/plugins/eol.py — End-of-life component scanner plugin."""

import json
import logging
import urllib.error
import urllib.request
from typing import Any

from rover import db
from rover.plugins.base import ScanResult

logger = logging.getLogger(__name__)


class EolComponentScannerPlugin:
    """Scanner plugin that fetches end-of-life dates for components via endoflife.date API."""

    name: str = "major_component"
    supported_asset_types: set[str] = {"major_component"}

    def can_handle(self, target_type: str) -> bool:
        return target_type in self.supported_asset_types

    def scan(
        self,
        target_url: str,
        git_ref: str | None = None,
        target_type: str = "major_component",
        db_module: Any | None = None,
        url_opener: Any | None = None,
    ) -> ScanResult:
        """Fetches EOL data for target_url (component name) and git_ref (version string)."""
        target_name = target_url
        target_version = git_ref or ""

        db_ref = db_module or db

        logger.info(f"Checking EOL data for {target_name} version {target_version}")

        cached_json = db_ref.get_cached_eol_data(target_name, target_version)
        if cached_json:
            logger.info(f"Using cached EOL data for {target_name} v{target_version}")
            return ScanResult(
                results=json.loads(cached_json),
                source="eol_cache",
                status="cached",
            )

        url = f"https://endoflife.date/api/{target_name}/{target_version}.json"
        req = urllib.request.Request(url, headers={"User-Agent": "RoverScanner/1.0"})  # noqa: S310

        try:
            open_fn = url_opener or urllib.request.urlopen
            with open_fn(req) as response:  # noqa: S310
                data = response.read().decode("utf-8")
                parsed_data = json.loads(data)

                db_ref.set_cached_eol_data(
                    target_name, target_version, json.dumps(parsed_data)
                )

                return ScanResult(
                    results=parsed_data,
                    source="eol_api",
                    status="fresh",
                )
        except urllib.error.HTTPError as e:
            logger.error(f"HTTP error fetching EOL data: {e.code} - {e.reason}")
            if e.code == 404:
                raise Exception(
                    f"EOL data not found for {target_name} v{target_version}"
                )
            raise Exception(f"Failed to fetch EOL data: {e.reason}")
        except Exception as e:
            logger.error(f"Error fetching EOL data: {e}")
            raise Exception("Failed to retrieve EOL data from endoflife.date API")
