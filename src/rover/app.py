"""rover/app.py: ASGI application entry point.

Assembles the Falcon app via ``rover.routes.create_app()`` and starts
the background worker thread. Import this module to get the ``app``
object that ASGI servers (uvicorn, gunicorn+uvicorn) expect.

Route definitions and resource classes live in ``rover/routes/``.
"""

import asyncio
import threading

from rover import worker
from rover.routes import create_app

app = create_app()


def start_worker() -> None:
    """Run the async worker loop inside a dedicated background thread."""
    loop = asyncio.new_event_loop()
    asyncio.set_event_loop(loop)
    loop.run_until_complete(worker.worker_loop())


worker_thread = threading.Thread(target=start_worker, daemon=True)
worker_thread.start()
