FROM python:3.12-slim

# Install uv
COPY --from=ghcr.io/astral-sh/uv:latest /uv /uvx /bin/

# Install git and skopeo
RUN apt-get update && apt-get install -y git skopeo && rm -rf /var/lib/apt/lists/*

WORKDIR /app

# Copy dependency files
ENV UV_COMPILE_BYTECODE=1
ENV UV_NO_CACHE=1
COPY pyproject.toml uv.lock ./

# Install dependencies
RUN uv sync --frozen --no-install-project --no-dev

# Copy application code
COPY src ./src
COPY tests ./tests
COPY README.md ./

# Sync project
RUN uv sync --frozen --no-dev

# Run the application
CMD ["/app/.venv/bin/uvicorn", "rover.app:app", "--host", "0.0.0.0", "--port", "8000"]
