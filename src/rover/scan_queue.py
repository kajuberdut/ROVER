# This file is retained for backwards compatibility during refactoring
# It re-exports the newly decomposed database layer.
from rover.db import *

# Ensure tables are created on startup (same behavior as before)
init_db()
