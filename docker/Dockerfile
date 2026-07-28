# Stage 1: Build Starlight documentation site
FROM node:24-alpine AS docs-builder
WORKDIR /app/docs/starlight
COPY docs/starlight/package*.json ./
RUN npm ci
COPY docs/starlight ./
RUN npm run build

# Stage 2: Main application container
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

# Copy application code and documentation
COPY src ./src
COPY tests ./tests
COPY migrations ./migrations
COPY README.md ./
COPY docs ./docs
COPY --from=docs-builder /app/docs/starlight/dist ./docs/starlight/dist

# Sync project
RUN uv sync --frozen --no-dev

# Run the application
CMD ["/app/.venv/bin/uvicorn", "rover.app:app", "--host", "0.0.0.0", "--port", "8000"]
