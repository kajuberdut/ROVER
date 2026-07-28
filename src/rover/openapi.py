"""rover/openapi.py: OpenAPI 3.0 specification builder and interactive documentation views for R.O.V.E.R."""

from typing import Any


def get_openapi_schema() -> dict[str, Any]:
    """Generates the OpenAPI 3.0 JSON specification dictionary for R.O.V.E.R. public API."""
    return {
        "openapi": "3.0.3",
        "info": {
            "title": "R.O.V.E.R. Security & Release Management API",
            "version": "1.0.0",
            "description": (
                "Public REST & Machine-to-Machine API for R.O.V.E.R. (Release & Vulnerability Evaluation Engine). "
                "Allows CI/CD pipelines, security automation scripts, and external tools to trigger scans, "
                "ingest CI metadata, manage scan schedules, and inspect vulnerability reports."
            ),
            "contact": {
                "name": "R.O.V.E.R. Engineering Team",
                "url": "https://rover.local",
            },
        },
        "servers": [
            {"url": "https://rover.local", "description": "Local HTTPS Server"},
            {"url": "http://localhost:8000", "description": "Development Server"},
        ],
        "components": {
            "securitySchemes": {
                "BearerAuth": {
                    "type": "http",
                    "scheme": "bearer",
                    "bearerFormat": "API-Token",
                    "description": "Bearer token authentication header (Authorization: Bearer <token>).",
                },
                "CookieAuth": {
                    "type": "apiKey",
                    "in": "cookie",
                    "name": "rover_session",
                    "description": "Session cookie for authenticated web users.",
                },
            },
            "schemas": {
                "CiImageMetadataInput": {
                    "type": "object",
                    "required": ["image_hash", "repo_uri", "commit_hash"],
                    "properties": {
                        "image_hash": {
                            "type": "string",
                            "example": "sha256:abc123def456...",
                        },
                        "repo_uri": {
                            "type": "string",
                            "example": "https://github.com/example/repo.git",
                        },
                        "commit_hash": {"type": "string", "example": "a1b2c3d4e5f6..."},
                        "metadata": {
                            "type": "object",
                            "example": {
                                "build_id": "1042",
                                "builder": "github-actions",
                            },
                        },
                        "image_tags": {
                            "type": "array",
                            "items": {"type": "string"},
                            "example": ["latest", "v1.0.0"],
                        },
                        "ci_job_url": {
                            "type": "string",
                            "example": "https://github.com/example/repo/actions/runs/12345",
                        },
                    },
                },
                "ScheduledScanInput": {
                    "type": "object",
                    "required": ["name", "cron_expression"],
                    "properties": {
                        "name": {"type": "string", "example": "Nightly Security Audit"},
                        "cron_expression": {"type": "string", "example": "0 2 * * *"},
                        "release_id": {
                            "type": "string",
                            "nullable": True,
                            "example": "rel_uuid_123",
                        },
                        "enabled": {"type": "boolean", "default": True},
                    },
                },
                "ScheduledScan": {
                    "type": "object",
                    "properties": {
                        "id": {"type": "string"},
                        "name": {"type": "string"},
                        "product_id": {"type": "string"},
                        "release_id": {"type": "string", "nullable": True},
                        "cron_expression": {"type": "string"},
                        "enabled": {"type": "boolean"},
                        "last_run_at": {
                            "type": "string",
                            "format": "date-time",
                            "nullable": True,
                        },
                        "next_run_at": {
                            "type": "string",
                            "format": "date-time",
                            "nullable": True,
                        },
                        "last_status": {"type": "string"},
                        "created_at": {"type": "string", "format": "date-time"},
                    },
                },
                "ScheduleExecutionLog": {
                    "type": "object",
                    "properties": {
                        "id": {"type": "string"},
                        "schedule_id": {"type": "string"},
                        "triggered_at": {"type": "string", "format": "date-time"},
                        "status": {"type": "string", "example": "success"},
                        "jobs_created_count": {"type": "integer", "example": 10},
                        "error_message": {"type": "string", "nullable": True},
                    },
                },
            },
        },
        "security": [
            {"BearerAuth": []},
            {"CookieAuth": []},
        ],
        "paths": {
            "/api/ci/image-metadata": {
                "post": {
                    "summary": "Ingest CI Container Image Metadata",
                    "description": "Machine-to-machine endpoint for CI/CD pipelines to record image hashes, repository URIs, commit SHAs, and pipeline URLs.",
                    "operationId": "ingestCiImageMetadata",
                    "requestBody": {
                        "required": True,
                        "content": {
                            "application/json": {
                                "schema": {
                                    "$ref": "#/components/schemas/CiImageMetadataInput"
                                }
                            }
                        },
                    },
                    "responses": {
                        "201": {"description": "Metadata recorded successfully"},
                        "400": {
                            "description": "Invalid JSON or missing required fields"
                        },
                        "401": {"description": "Unauthorized or missing API token"},
                        "409": {
                            "description": "Image metadata for this hash already exists"
                        },
                    },
                }
            },
            "/api/products/{product_id}/schedules": {
                "get": {
                    "summary": "List Product Scheduled Scans",
                    "description": "Retrieves all automated scan schedules configured for a given product.",
                    "operationId": "listProductSchedules",
                    "parameters": [
                        {
                            "name": "product_id",
                            "in": "path",
                            "required": True,
                            "schema": {"type": "string"},
                            "description": "UUID of the target product",
                        }
                    ],
                    "responses": {
                        "200": {
                            "description": "List of scheduled scans",
                            "content": {
                                "application/json": {
                                    "schema": {
                                        "type": "object",
                                        "properties": {
                                            "schedules": {
                                                "type": "array",
                                                "items": {
                                                    "$ref": "#/components/schemas/ScheduledScan"
                                                },
                                            }
                                        },
                                    }
                                }
                            },
                        },
                        "403": {"description": "Insufficient permissions"},
                    },
                },
                "post": {
                    "summary": "Create Scheduled Scan",
                    "description": "Creates a new automated background scan schedule for a product.",
                    "operationId": "createScheduledScan",
                    "parameters": [
                        {
                            "name": "product_id",
                            "in": "path",
                            "required": True,
                            "schema": {"type": "string"},
                        }
                    ],
                    "requestBody": {
                        "required": True,
                        "content": {
                            "application/json": {
                                "schema": {
                                    "$ref": "#/components/schemas/ScheduledScanInput"
                                }
                            }
                        },
                    },
                    "responses": {
                        "201": {"description": "Schedule created successfully"},
                        "400": {
                            "description": "Invalid payload or invalid cron pattern"
                        },
                        "403": {"description": "Insufficient write permissions"},
                    },
                },
            },
            "/api/schedules/{schedule_id}": {
                "post": {
                    "summary": "Trigger or Toggle Schedule",
                    "description": "Performs actions on a schedule (action=trigger to run immediately, action=toggle to pause/enable).",
                    "operationId": "manageScheduleAction",
                    "parameters": [
                        {
                            "name": "schedule_id",
                            "in": "path",
                            "required": True,
                            "schema": {"type": "string"},
                        },
                        {
                            "name": "action",
                            "in": "query",
                            "required": False,
                            "schema": {
                                "type": "string",
                                "enum": ["toggle", "trigger"],
                                "default": "toggle",
                            },
                        },
                    ],
                    "responses": {
                        "200": {"description": "Action executed successfully"},
                        "404": {"description": "Schedule not found"},
                    },
                },
                "delete": {
                    "summary": "Delete Schedule",
                    "description": "Deletes a scheduled scan.",
                    "operationId": "deleteSchedule",
                    "parameters": [
                        {
                            "name": "schedule_id",
                            "in": "path",
                            "required": True,
                            "schema": {"type": "string"},
                        }
                    ],
                    "responses": {
                        "200": {"description": "Schedule deleted"},
                        "404": {"description": "Schedule not found"},
                    },
                },
            },
            "/api/schedules/{schedule_id}/logs": {
                "get": {
                    "summary": "Get Schedule Audit Logs",
                    "description": "Retrieves execution audit history logs for a schedule.",
                    "operationId": "getScheduleLogs",
                    "parameters": [
                        {
                            "name": "schedule_id",
                            "in": "path",
                            "required": True,
                            "schema": {"type": "string"},
                        }
                    ],
                    "responses": {
                        "200": {
                            "description": "List of schedule execution audit logs",
                            "content": {
                                "application/json": {
                                    "schema": {
                                        "type": "object",
                                        "properties": {
                                            "logs": {
                                                "type": "array",
                                                "items": {
                                                    "$ref": "#/components/schemas/ScheduleExecutionLog"
                                                },
                                            }
                                        },
                                    }
                                }
                            },
                        }
                    },
                }
            },
            "/api/eol/all": {
                "get": {
                    "summary": "Get All End-Of-Life Proxy Data",
                    "description": "Retrieves cached software component EOL lifecycle data.",
                    "operationId": "getAllEolData",
                    "responses": {
                        "200": {"description": "JSON map of components and EOL cycles"}
                    },
                }
            },
            "/api/eol/{product}": {
                "get": {
                    "summary": "Get Component EOL Cycles",
                    "description": "Retrieves EOL cycles for a specific component (e.g., python, postgres, ubuntu).",
                    "operationId": "getComponentEolCycles",
                    "parameters": [
                        {
                            "name": "product",
                            "in": "path",
                            "required": True,
                            "schema": {"type": "string"},
                            "example": "python",
                        }
                    ],
                    "responses": {
                        "200": {"description": "Array of EOL cycle release records"}
                    },
                }
            },
            "/api/helm/repo/charts": {
                "get": {
                    "summary": "Discover Remote Helm Charts",
                    "description": "Fetches and parses a remote Helm repository index.yaml to discover chart releases.",
                    "operationId": "discoverHelmCharts",
                    "parameters": [
                        {
                            "name": "repo_url",
                            "in": "query",
                            "required": True,
                            "schema": {"type": "string"},
                            "example": "https://charts.bitnami.com/bitnami",
                        }
                    ],
                    "responses": {
                        "200": {
                            "description": "List of available Helm charts in repository"
                        }
                    },
                }
            },
        },
    }


SWAGGER_UI_HTML = """<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>R.O.V.E.R. API Documentation - Swagger UI</title>
    <link rel="stylesheet" type="text/css" href="https://cdn.jsdelivr.net/npm/swagger-ui-dist@5.11.0/swagger-ui.css" />
    <style>
        html { box-sizing: border-box; overflow: -moz-scrollbars-vertical; overflow-y: scroll; }
        *, *:before, *:after { box-sizing: inherit; }
        body { margin: 0; background: #fafafa; }
        .swagger-ui .topbar { display: none; }
    </style>
</head>
<body>
    <div id="swagger-ui"></div>
    <script src="https://cdn.jsdelivr.net/npm/swagger-ui-dist@5.11.0/swagger-ui-bundle.js" charset="UTF-8"></script>
    <script src="https://cdn.jsdelivr.net/npm/swagger-ui-dist@5.11.0/swagger-ui-standalone-preset.js" charset="UTF-8"></script>
    <script>
    window.onload = function() {
        const ui = SwaggerUIBundle({
            url: "/api/openapi.json",
            dom_id: '#swagger-ui',
            deepLinking: true,
            presets: [
                SwaggerUIBundle.presets.apis,
                SwaggerUIStandalonePreset
            ],
            plugins: [
                SwaggerUIBundle.plugins.DownloadUrl
            ],
            layout: "StandaloneLayout"
        });
        window.ui = ui;
    };
    </script>
</body>
</html>
"""
