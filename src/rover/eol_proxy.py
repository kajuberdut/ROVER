import asyncio
import json
import urllib.error
import urllib.request

import falcon.asgi

from rover import db


def _fetch_url(url: str) -> str:
    req_url = urllib.request.Request(  # noqa: S310
        url,
        headers={"User-Agent": "ROVER Scanner"},
    )
    with urllib.request.urlopen(req_url, timeout=10) as response:  # noqa: S310
        content: bytes = response.read()
        return content.decode("utf-8")


class EolProxyAllResource:
    async def on_get(
        self, req: falcon.asgi.Request, resp: falcon.asgi.Response
    ) -> None:
        """Proxies and caches the master list of all EOL component names."""

        # Check cache
        cached = db.get_cached_eol_data("ALL", "list")
        if cached:
            resp.text = cached
            resp.content_type = falcon.MEDIA_JSON
            return

        # Fetch, cache, and serve
        try:
            data = await asyncio.to_thread(
                _fetch_url, "https://endoflife.date/api/all.json"
            )

            # Verify it's valid JSON before caching
            json.loads(data)

            db.set_cached_eol_data("ALL", "list", data)

            resp.text = data
            resp.content_type = falcon.MEDIA_JSON

        except urllib.error.HTTPError as e:
            if e.code == 404:
                raise falcon.HTTPNotFound(
                    title="API Not Found", description="All components list not found"
                )
            raise falcon.HTTPBadGateway(
                title="Upstream API Error", description=f"HTTP Error {e.code}"
            )
        except urllib.error.URLError as e:
            raise falcon.HTTPBadGateway(
                title="Upstream Connection Error",
                description=f"Could not connect to endoflife.date: {e.reason}",
            )
        except TimeoutError:
            raise falcon.HTTPGatewayTimeout(
                title="Upstream Timeout",
                description="Request to endoflife.date timed out",
            )
        except Exception as e:
            raise falcon.HTTPInternalServerError(
                title="API Fetch Failed", description=str(e)
            )


class EolProxyProductResource:
    async def on_get(
        self, req: falcon.asgi.Request, resp: falcon.asgi.Response, product: str
    ) -> None:
        """Proxies and caches the version list for a specific EOL component."""

        # Check cache
        cached = db.get_cached_eol_data(product, "cycles")
        if cached:
            resp.text = cached
            resp.content_type = falcon.MEDIA_JSON
            return

        # Fetch, cache, and serve
        try:
            data = await asyncio.to_thread(
                _fetch_url, f"https://endoflife.date/api/{product}.json"
            )

            # Verify it's valid JSON before caching
            json.loads(data)

            db.set_cached_eol_data(product, "cycles", data)

            resp.text = data
            resp.content_type = falcon.MEDIA_JSON

        except urllib.error.HTTPError as e:
            if e.code == 404:
                raise falcon.HTTPNotFound(
                    title="Component Not Found",
                    description=f"The component '{product}' was not found on endoflife.date",
                )
            raise falcon.HTTPBadGateway(
                title="Upstream API Error", description=f"HTTP Error {e.code}"
            )
        except urllib.error.URLError as e:
            raise falcon.HTTPBadGateway(
                title="Upstream Connection Error",
                description=f"Could not connect to endoflife.date: {e.reason}",
            )
        except TimeoutError:
            raise falcon.HTTPGatewayTimeout(
                title="Upstream Timeout",
                description="Request to endoflife.date timed out",
            )
        except Exception as e:
            raise falcon.HTTPInternalServerError(
                title="API Fetch Failed", description=str(e)
            )


eol_proxy_app = falcon.asgi.App()
eol_proxy_app.add_route("/all", EolProxyAllResource())
eol_proxy_app.add_route("/{product}", EolProxyProductResource())
