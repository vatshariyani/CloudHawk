"""
CloudHawk OpenAPI 3.0 specification + Swagger UI (T20)

Served at:
  GET /api/docs/          — Swagger UI
  GET /api/docs/openapi.json — machine-readable spec
"""

from flask import Blueprint, jsonify, render_template_string

swagger_bp = Blueprint("swagger", __name__, url_prefix="/api/docs")

_SWAGGER_UI = """<!DOCTYPE html>
<html>
<head>
  <title>CloudHawk API Docs</title>
  <link rel="stylesheet" href="https://unpkg.com/swagger-ui-dist@5/swagger-ui.css">
</head>
<body>
  <div id="swagger-ui"></div>
  <script src="https://unpkg.com/swagger-ui-dist@5/swagger-ui-bundle.js"></script>
  <script>
    SwaggerUIBundle({
      url: '/api/docs/openapi.json',
      dom_id: '#swagger-ui',
      deepLinking: true,
      presets: [SwaggerUIBundle.presets.apis, SwaggerUIBundle.SwaggerUIStandalonePreset],
      layout: 'BaseLayout'
    });
  </script>
</body>
</html>"""


@swagger_bp.route("/")
def swagger_ui():
    return render_template_string(_SWAGGER_UI)


@swagger_bp.route("/openapi.json")
def openapi_spec():
    return jsonify(_SPEC)


# ---------------------------------------------------------------------------
# OpenAPI 3.0 spec — kept as a plain dict so it's easy to diff and extend
# ---------------------------------------------------------------------------

_alert_schema = {
    "type": "object",
    "properties": {
        "id":          {"type": "string"},
        "cloud":       {"type": "string", "enum": ["aws", "gcp", "azure"]},
        "source":      {"type": "string"},
        "resource_id": {"type": "string"},
        "event_type":  {"type": "string"},
        "severity":    {"type": "string", "enum": ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]},
        "description": {"type": "string"},
        "timestamp":   {"type": "string", "format": "date-time"},
    },
}

_paginated_response = lambda items_schema, items_key: {   # noqa: E731
    "type": "object",
    "properties": {
        items_key:  {"type": "array", "items": items_schema},
        "total":    {"type": "integer"},
        "limit":    {"type": "integer"},
        "offset":   {"type": "integer"},
        "has_more": {"type": "boolean"},
    },
}

_rule_schema = {
    "type": "object",
    "required": ["id", "title", "description", "condition", "severity"],
    "properties": {
        "id":          {"type": "string"},
        "title":       {"type": "string"},
        "description": {"type": "string"},
        "condition":   {"type": "string"},
        "severity":    {"type": "string", "enum": ["CRITICAL", "HIGH", "MEDIUM", "LOW"]},
        "service":     {"type": "string"},
        "owasp":       {"type": "string"},
        "remediation": {"type": "string"},
    },
}

_security = [{"ApiKeyAuth": []}, {"BearerAuth": []}]

_SPEC = {
    "openapi": "3.0.3",
    "info": {
        "title": "CloudHawk Security API",
        "description": (
            "REST API for CloudHawk multi-cloud security monitoring. "
            "Authenticate with an API key (`X-API-Key` header) or a "
            "Bearer JWT obtained from `POST /api/v1/auth/token`."
        ),
        "version": "1.0.0",
        "contact": {"name": "CloudHawk"},
        "license": {"name": "MIT", "url": "https://opensource.org/licenses/MIT"},
    },
    "servers": [
        {"url": "/api/v1", "description": "Current server"},
    ],
    "components": {
        "securitySchemes": {
            "ApiKeyAuth": {
                "type": "apiKey",
                "in": "header",
                "name": "X-API-Key",
                "description": "API key issued by POST /api/v1/auth/api-key",
            },
            "BearerAuth": {
                "type": "http",
                "scheme": "bearer",
                "bearerFormat": "JWT",
                "description": "JWT token issued by POST /api/v1/auth/token",
            },
        },
        "schemas": {
            "Alert": _alert_schema,
            "Rule":  _rule_schema,
            "Error": {
                "type": "object",
                "properties": {"error": {"type": "string"}},
            },
        },
        "parameters": {
            "limit": {
                "name": "limit", "in": "query",
                "schema": {"type": "integer", "default": 100, "minimum": 1, "maximum": 1000},
                "description": "Max items to return",
            },
            "offset": {
                "name": "offset", "in": "query",
                "schema": {"type": "integer", "default": 0, "minimum": 0},
                "description": "Number of items to skip",
            },
        },
    },
    "paths": {
        # ------------------------------------------------------------------ health
        "/health": {
            "get": {
                "tags": ["System"],
                "summary": "Health check",
                "responses": {
                    "200": {
                        "description": "API is healthy",
                        "content": {"application/json": {"schema": {
                            "type": "object",
                            "properties": {
                                "status":    {"type": "string"},
                                "timestamp": {"type": "string"},
                                "version":   {"type": "string"},
                                "services":  {"type": "object"},
                            },
                        }}},
                    },
                },
            },
        },
        # ------------------------------------------------------------------ auth/token
        "/auth/token": {
            "post": {
                "tags": ["Authentication"],
                "summary": "Issue JWT token",
                "requestBody": {
                    "required": True,
                    "content": {"application/json": {"schema": {
                        "type": "object",
                        "required": ["user_id"],
                        "properties": {
                            "user_id":     {"type": "string"},
                            "permissions": {"type": "array", "items": {"type": "string"}},
                        },
                    }}},
                },
                "responses": {
                    "200": {"description": "Token issued", "content": {"application/json": {"schema": {
                        "type": "object",
                        "properties": {
                            "token":       {"type": "string"},
                            "expires_in":  {"type": "integer"},
                            "permissions": {"type": "array", "items": {"type": "string"}},
                        },
                    }}}},
                    "400": {"description": "Bad request"},
                },
            },
        },
        # ------------------------------------------------------------------ auth/api-key
        "/auth/api-key": {
            "post": {
                "tags": ["Authentication"],
                "summary": "Issue API key (admin only)",
                "security": _security,
                "requestBody": {
                    "required": True,
                    "content": {"application/json": {"schema": {
                        "type": "object",
                        "properties": {
                            "name":        {"type": "string"},
                            "permissions": {"type": "array", "items": {"type": "string"}},
                        },
                    }}},
                },
                "responses": {
                    "200": {"description": "API key issued"},
                    "401": {"description": "Unauthorised"},
                    "403": {"description": "Forbidden"},
                },
            },
        },
        # ------------------------------------------------------------------ scans
        "/scans": {
            "get": {
                "tags": ["Scans"],
                "summary": "List scan result files",
                "security": _security,
                "responses": {
                    "200": {"description": "Scan list", "content": {"application/json": {"schema": {
                        "type": "object",
                        "properties": {
                            "scans": {"type": "array", "items": {"type": "object"}},
                            "total": {"type": "integer"},
                        },
                    }}}},
                    "401": {"description": "Unauthorised"},
                },
            },
            "post": {
                "tags": ["Scans"],
                "summary": "Trigger a live cloud scan",
                "security": _security,
                "requestBody": {
                    "required": True,
                    "content": {"application/json": {"schema": {
                        "type": "object",
                        "required": ["cloud_provider"],
                        "properties": {
                            "cloud_provider":  {"type": "string", "enum": ["AWS", "GCP", "Azure"]},
                            "region":          {"type": "string", "description": "AWS region"},
                            "project_id":      {"type": "string", "description": "GCP project"},
                            "subscription_id": {"type": "string", "description": "Azure subscription"},
                            "max_events":      {"type": "integer", "default": 1000},
                        },
                    }}},
                },
                "responses": {
                    "201": {"description": "Scan completed"},
                    "400": {"description": "Bad request"},
                    "401": {"description": "Unauthorised"},
                    "500": {"description": "Scan failed"},
                },
            },
        },
        "/scans/{scan_id}": {
            "get": {
                "tags": ["Scans"],
                "summary": "Get scan details",
                "security": _security,
                "parameters": [
                    {"name": "scan_id", "in": "path", "required": True, "schema": {"type": "string"}},
                    {"$ref": "#/components/parameters/limit"},
                    {"$ref": "#/components/parameters/offset"},
                ],
                "responses": {
                    "200": {"description": "Scan detail"},
                    "404": {"description": "Not found"},
                },
            },
        },
        # ------------------------------------------------------------------ alerts
        "/alerts": {
            "get": {
                "tags": ["Alerts"],
                "summary": "List alerts (paginated)",
                "security": _security,
                "parameters": [
                    {
                        "name": "severity", "in": "query",
                        "schema": {"type": "string", "enum": ["CRITICAL", "HIGH", "MEDIUM", "LOW"]},
                    },
                    {"name": "service", "in": "query", "schema": {"type": "string"}},
                    {"name": "source",  "in": "query", "schema": {"type": "string"}},
                    {"name": "cloud",   "in": "query",
                     "schema": {"type": "string", "enum": ["aws", "gcp", "azure"]}},
                    {"$ref": "#/components/parameters/limit"},
                    {"$ref": "#/components/parameters/offset"},
                ],
                "responses": {
                    "200": {
                        "description": "Paginated alerts",
                        "content": {"application/json": {"schema": _paginated_response(
                            {"$ref": "#/components/schemas/Alert"}, "alerts"
                        )}},
                    },
                    "401": {"description": "Unauthorised"},
                },
            },
        },
        "/alerts/{alert_id}": {
            "get": {
                "tags": ["Alerts"],
                "summary": "Get single alert",
                "security": _security,
                "parameters": [
                    {"name": "alert_id", "in": "path", "required": True, "schema": {"type": "string"}},
                ],
                "responses": {
                    "200": {"description": "Alert detail",
                            "content": {"application/json": {"schema": {"$ref": "#/components/schemas/Alert"}}}},
                    "404": {"description": "Not found"},
                },
            },
        },
        # ------------------------------------------------------------------ rules
        "/rules": {
            "get": {
                "tags": ["Rules"],
                "summary": "List detection rules",
                "security": _security,
                "parameters": [
                    {"name": "service",  "in": "query", "schema": {"type": "string"}},
                    {"name": "severity", "in": "query",
                     "schema": {"type": "string", "enum": ["CRITICAL", "HIGH", "MEDIUM", "LOW"]}},
                ],
                "responses": {
                    "200": {"description": "Rules list"},
                    "404": {"description": "Rules file not found"},
                },
            },
            "post": {
                "tags": ["Rules"],
                "summary": "Create a new detection rule",
                "security": _security,
                "requestBody": {
                    "required": True,
                    "content": {"application/json": {"schema": {"$ref": "#/components/schemas/Rule"}}},
                },
                "responses": {
                    "201": {"description": "Rule created"},
                    "400": {"description": "Validation error"},
                    "409": {"description": "Duplicate rule ID"},
                },
            },
        },
        # ------------------------------------------------------------------ stats
        "/stats": {
            "get": {
                "tags": ["System"],
                "summary": "System statistics",
                "security": _security,
                "responses": {
                    "200": {"description": "Stats", "content": {"application/json": {"schema": {
                        "type": "object",
                        "properties": {
                            "total_alerts":       {"type": "integer"},
                            "total_scans":        {"type": "integer"},
                            "severity_breakdown": {"type": "object"},
                            "cloud_breakdown":    {"type": "object"},
                            "api_version":        {"type": "string"},
                            "timestamp":          {"type": "string"},
                        },
                    }}}},
                },
            },
        },
    },
}
