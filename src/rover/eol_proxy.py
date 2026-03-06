import json
import urllib.error
import urllib.request

import falcon.asgi

from rover import scan_queue


class EolProxyAllResource:
    async def on_get(
        self, req: falcon.asgi.Request, resp: falcon.asgi.Response
    ) -> None:
        """Proxies and caches the master list of all EOL component names."""

        # Check cache
        cached = scan_queue.get_cached_eol_data("ALL", "list")
        if cached:
            resp.text = cached
            resp.content_type = falcon.MEDIA_JSON
            return

        # Fetch, cache, and serve
        try:
            req_url = urllib.request.Request(
                "https://endoflife.date/api/all.json",
                headers={"User-Agent": "ROVER Scanner"},
            )
            with urllib.request.urlopen(req_url) as response:  # noqa: S310
                data = response.read().decode("utf-8")

                # Verify it's valid JSON before caching
                json.loads(data)

                scan_queue.set_cached_eol_data("ALL", "list", data)

                resp.text = data
                resp.content_type = falcon.MEDIA_JSON

        except urllib.error.HTTPError as e:
            raise falcon.HTTPNotFound(
                title="API Error", description=f"HTTP Error {e.code}"
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
        cached = scan_queue.get_cached_eol_data(product, "cycles")
        if cached:
            resp.text = cached
            resp.content_type = falcon.MEDIA_JSON
            return

        # Fetch, cache, and serve
        try:
            req_url = urllib.request.Request(
                f"https://endoflife.date/api/{product}.json",
                headers={"User-Agent": "ROVER Scanner"},
            )
            with urllib.request.urlopen(req_url) as response:  # noqa: S310
                data = response.read().decode("utf-8")

                # Verify it's valid JSON before caching
                json.loads(data)

                scan_queue.set_cached_eol_data(product, "cycles", data)

                resp.text = data
                resp.content_type = falcon.MEDIA_JSON

        except urllib.error.HTTPError as e:
            if e.code == 404:
                raise falcon.HTTPNotFound(
                    title="Component Not Found",
                    description=f"The component '{product}' was not found on endoflife.date",
                )
            raise falcon.HTTPBadGateway(
                title="API Error", description=f"HTTP Error {e.code}"
            )
        except Exception as e:
            raise falcon.HTTPInternalServerError(
                title="API Fetch Failed", description=str(e)
            )


eol_proxy_app = falcon.asgi.App()
eol_proxy_app.add_route("/all", EolProxyAllResource())
eol_proxy_app.add_route("/{product}", EolProxyProductResource())
