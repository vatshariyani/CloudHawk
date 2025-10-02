"""
CloudHawk API Swagger/OpenAPI Documentation
"""

from flask import Blueprint, jsonify, render_template_string
import json

swagger_bp = Blueprint('swagger', __name__, url_prefix='/api/docs')

# Swagger UI HTML template
SWAGGER_UI_HTML = """
<!DOCTYPE html>
<html>
<head>
    <title>CloudHawk API Documentation</title>
    <link rel="stylesheet" type="text/css" href="https://unpkg.com/swagger-ui-dist@4.15.5/swagger-ui.css" />
    <style>
        html { box-sizing: border-box; overflow: -moz-scrollbars-vertical; overflow-y: scroll; }
        *, *:before, *:after { box-sizing: inherit; }
        body { margin:0; background: #fafafa; }
    </style>
</head>
<body>
    <div id="swagger-ui"></div>
    <script src="https://unpkg.com/swagger-ui-dist@4.15.5/swagger-ui-bundle.js"></script>
    <script src="https://unpkg.com/swagger-ui-dist@4.15.5/swagger-ui-standalone-preset.js"></script>
    <script>
        window.onload = function() {
            const ui = SwaggerUIBundle({
                url: '/api/docs/swagger.json',
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
        };
    </script>
</body>
</html>
"""

@swagger_bp.route('/')
def swagger_ui():
    """Serve Swagger UI"""
    return render_template_string(SWAGGER_UI_HTML)

@swagger_bp.route('/swagger.json')
def swagger_json():
    """Return OpenAPI specification"""
    return jsonify({
        "openapi": "3.0.0",
        "info": {
            "title": "CloudHawk Security API",
            "description": "Comprehensive REST API for CloudHawk multi-cloud security monitoring",
            "version": "2.0.0",
            "contact": {
                "name": "CloudHawk Support",
                "email": "support@cloudhawk.dev"
            },
            "license": {
                "name": "MIT",
                "url": "https://opensource.org/licenses/MIT"
            }
        },
        "servers": [
            {
                "url": "http://localhost:5000/api/v1",
                "description": "Development server"
            }
        ],
        "security": [
            {
                "ApiKeyAuth": []
            },
            {
                "BearerAuth": []
            }
        ],
        "paths": {
            "/health": {
                "get": {
                    "tags": ["System"],
                    "summary": "Health Check",
                    "description": "Check API health status",
                    "responses": {
                        "200": {
                            "description": "API is healthy",
                            "content": {
                                "application/json": {
                                    "schema": {
                                        "type": "object",
                                        "properties": {
                                            "status": {"type": "string"},
                                            "timestamp": {"type": "string"},
                                            "version": {"type": "string"},
                                            "services": {"type": "object"}
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
            },
            "/auth/token": {
                "post": {
                    "tags": ["Authentication"],
                    "summary": "Generate JWT Token",
                    "description": "Generate JWT token for API access",
                    "requestBody": {
                        "required": True,
                        "content": {
                            "application/json": {
                                "schema": {
                                    "type": "object",
                                    "properties": {
                                        "user_id": {"type": "string"},
                                        "permissions": {
                                            "type": "array",
                                            "items": {"type": "string"}
                                        }
                                    },
                                    "required": ["user_id"]
                                }
                            }
                        }
                    },
                    "responses": {
                        "200": {
                            "description": "Token generated successfully",
                            "content": {
                                "application/json": {
                                    "schema": {
                                        "type": "object",
                                        "properties": {
                                            "token": {"type": "string"},
                                            "expires_in": {"type": "integer"},
                                            "permissions": {"type": "array"}
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
            },
            "/scans": {
                "get": {
                    "tags": ["Scans"],
                    "summary": "List Scans",
                    "description": "Get list of available security scans",
                    "security": [{"ApiKeyAuth": []}, {"BearerAuth": []}],
                    "responses": {
                        "200": {
                            "description": "List of scans",
                            "content": {
                                "application/json": {
                                    "schema": {
                                        "type": "object",
                                        "properties": {
                                            "scans": {
                                                "type": "array",
                                                "items": {
                                                    "type": "object",
                                                    "properties": {
                                                        "id": {"type": "string"},
                                                        "filename": {"type": "string"},
                                                        "created_at": {"type": "string"},
                                                        "size": {"type": "integer"},
                                                        "type": {"type": "string"}
                                                    }
                                                }
                                            },
                                            "total": {"type": "integer"}
                                        }
                                    }
                                }
                            }
                        }
                    }
                },
                "post": {
                    "tags": ["Scans"],
                    "summary": "Create Scan",
                    "description": "Create a new security scan",
                    "security": [{"ApiKeyAuth": []}, {"BearerAuth": []}],
                    "requestBody": {
                        "required": True,
                        "content": {
                            "application/json": {
                                "schema": {
                                    "type": "object",
                                    "properties": {
                                        "cloud_provider": {
                                            "type": "string",
                                            "enum": ["AWS", "GCP", "Azure"]
                                        },
                                        "region": {"type": "string"},
                                        "max_events": {"type": "integer"},
                                        "project_id": {"type": "string"},
                                        "subscription_id": {"type": "string"}
                                    },
                                    "required": ["cloud_provider"]
                                }
                            }
                        }
                    },
                    "responses": {
                        "200": {
                            "description": "Scan created successfully",
                            "content": {
                                "application/json": {
                                    "schema": {
                                        "type": "object",
                                        "properties": {
                                            "scan_id": {"type": "string"},
                                            "cloud_provider": {"type": "string"},
                                            "events_collected": {"type": "integer"},
                                            "alerts_generated": {"type": "integer"},
                                            "status": {"type": "string"},
                                            "created_at": {"type": "string"}
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
            },
            "/scans/{scan_id}": {
                "get": {
                    "tags": ["Scans"],
                    "summary": "Get Scan Details",
                    "description": "Get details of a specific scan",
                    "security": [{"ApiKeyAuth": []}, {"BearerAuth": []}],
                    "parameters": [
                        {
                            "name": "scan_id",
                            "in": "path",
                            "required": True,
                            "schema": {"type": "string"}
                        }
                    ],
                    "responses": {
                        "200": {
                            "description": "Scan details",
                            "content": {
                                "application/json": {
                                    "schema": {
                                        "type": "object",
                                        "properties": {
                                            "scan_id": {"type": "string"},
                                            "total_events": {"type": "integer"},
                                            "severity_breakdown": {"type": "object"},
                                            "source_breakdown": {"type": "object"},
                                            "created_at": {"type": "string"},
                                            "events": {"type": "array"}
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
            },
            "/alerts": {
                "get": {
                    "tags": ["Alerts"],
                    "summary": "Get Alerts",
                    "description": "Get security alerts with filtering",
                    "security": [{"ApiKeyAuth": []}, {"BearerAuth": []}],
                    "parameters": [
                        {
                            "name": "severity",
                            "in": "query",
                            "schema": {"type": "string", "enum": ["CRITICAL", "HIGH", "MEDIUM", "LOW"]}
                        },
                        {
                            "name": "service",
                            "in": "query",
                            "schema": {"type": "string"}
                        },
                        {
                            "name": "limit",
                            "in": "query",
                            "schema": {"type": "integer", "default": 100}
                        },
                        {
                            "name": "offset",
                            "in": "query",
                            "schema": {"type": "integer", "default": 0}
                        }
                    ],
                    "responses": {
                        "200": {
                            "description": "List of alerts",
                            "content": {
                                "application/json": {
                                    "schema": {
                                        "type": "object",
                                        "properties": {
                                            "alerts": {"type": "array"},
                                            "total": {"type": "integer"},
                                            "limit": {"type": "integer"},
                                            "offset": {"type": "integer"},
                                            "has_more": {"type": "boolean"}
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
            },
            "/rules": {
                "get": {
                    "tags": ["Rules"],
                    "summary": "Get Security Rules",
                    "description": "Get all security rules",
                    "security": [{"ApiKeyAuth": []}, {"BearerAuth": []}],
                    "responses": {
                        "200": {
                            "description": "List of security rules",
                            "content": {
                                "application/json": {
                                    "schema": {
                                        "type": "object",
                                        "properties": {
                                            "rules": {"type": "array"}
                                        }
                                    }
                                }
                            }
                        }
                    }
                },
                "post": {
                    "tags": ["Rules"],
                    "summary": "Create Security Rule",
                    "description": "Create a new security rule",
                    "security": [{"ApiKeyAuth": []}, {"BearerAuth": []}],
                    "requestBody": {
                        "required": True,
                        "content": {
                            "application/json": {
                                "schema": {
                                    "type": "object",
                                    "properties": {
                                        "id": {"type": "string"},
                                        "title": {"type": "string"},
                                        "description": {"type": "string"},
                                        "condition": {"type": "string"},
                                        "severity": {"type": "string"},
                                        "service": {"type": "string"},
                                        "remediation": {"type": "string"}
                                    },
                                    "required": ["id", "title", "description", "condition", "severity"]
                                }
                            }
                        }
                    },
                    "responses": {
                        "200": {
                            "description": "Rule created successfully",
                            "content": {
                                "application/json": {
                                    "schema": {
                                        "type": "object",
                                        "properties": {
                                            "message": {"type": "string"},
                                            "rule_id": {"type": "string"}
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
            },
            "/stats": {
                "get": {
                    "tags": ["Statistics"],
                    "summary": "Get System Statistics",
                    "description": "Get system statistics and metrics",
                    "security": [{"ApiKeyAuth": []}, {"BearerAuth": []}],
                    "responses": {
                        "200": {
                            "description": "System statistics",
                            "content": {
                                "application/json": {
                                    "schema": {
                                        "type": "object",
                                        "properties": {
                                            "total_alerts": {"type": "integer"},
                                            "total_scans": {"type": "integer"},
                                            "severity_breakdown": {"type": "object"},
                                            "api_version": {"type": "string"},
                                            "timestamp": {"type": "string"}
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
            }
        },
        "components": {
            "securitySchemes": {
                "ApiKeyAuth": {
                    "type": "apiKey",
                    "in": "header",
                    "name": "X-API-Key"
                },
                "BearerAuth": {
                    "type": "http",
                    "scheme": "bearer",
                    "bearerFormat": "JWT"
                }
            }
        }
    })
