"""
ApexVault AI Platform - Interactive Local Command Server
==========================================================
Lightweight, Zero-Dependency HTTP Server using Python Standard Library.
Binds strictly to 127.0.0.1:8000 (Localhost only) for maximum OpSec.
"""

import sys
import os
import json
from http.server import HTTPServer, BaseHTTPRequestHandler
from urllib.parse import urlparse

# Ensure project root is in sys.path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from gateway_app.apex_pipeline import ApexVaultMasterPipeline, ApexExecutionResult

HOST = "127.0.0.1"
PORT = 8000
STATIC_DIR = os.path.join(os.path.dirname(__file__), "static")

# Initialize Global Singleton Pipeline
apex_platform = ApexVaultMasterPipeline(db_path="data/apex_vault.db")


class ApexVaultHTTPHandler(BaseHTTPRequestHandler):
    """Handles REST API calls and serves the Framer-grade modern web frontend."""

    def _set_headers(self, content_type: str = "application/json", status: int = 200):
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Access-Control-Allow-Origin", "http://127.0.0.1:8000")
        self.send_header("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
        self.send_header("Access-Control-Allow-Headers", "Content-Type")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.end_headers()

    def do_OPTIONS(self):
        self._set_headers(status=204)

    def do_GET(self):
        parsed = urlparse(self.path)
        path = parsed.path

        if path in ("/", "/index.html"):
            index_path = os.path.join(STATIC_DIR, "index.html")
            if os.path.exists(index_path):
                with open(index_path, "rb") as f:
                    content = f.read()
                self._set_headers("text/html; charset=utf-8", 200)
                self.wfile.write(content)
            else:
                self._set_headers("text/plain", 404)
                self.wfile.write(b"index.html not found.")
            return

        elif path.endswith(".js"):
            file_name = os.path.basename(path)
            js_path = os.path.join(STATIC_DIR, file_name)
            if os.path.exists(js_path):
                with open(js_path, "rb") as f:
                    content = f.read()
                self._set_headers("application/javascript; charset=utf-8", 200)
                self.wfile.write(content)
            else:
                self._set_headers("text/plain", 404)
                self.wfile.write(b"JavaScript file not found.")
            return

        elif path == "/api/health":
            mcp_alive = apex_platform.mcp_client.is_alive()
            mcp_health = apex_platform.mcp_client.call_tool("get_database_health", {}) if mcp_alive else {}
            health_data = {
                "status": "HEALTHY",
                "version": "2.0.0",
                "platform": "ApexVault AI Autonomous Financial Operations",
                "pillars_active": [
                    "Pillar 1: Orchestration Core (1.1 - 1.5)",
                    "Pillar 2: Edge Guardrails (2.1 - 2.6)",
                    "Pillar 3: Zero-Trust Data Tier & MCP (3.1 - 3.5)"
                ],
                "mcp_server": {
                    "is_alive": mcp_alive,
                    "pid": apex_platform.mcp_client.process.pid if mcp_alive else None,
                    "info": mcp_health
                }
            }
            self._set_headers("application/json", 200)
            self.wfile.write(json.dumps(health_data, indent=2).encode("utf-8"))
            return

        else:
            self._set_headers("text/plain", 404)
            self.wfile.write(b"404 Not Found")

    def do_POST(self):
        parsed = urlparse(self.path)
        path = parsed.path

        if path == "/api/execute":
            content_length = int(self.headers.get("Content-Length", 0))
            body_bytes = self.rfile.read(content_length)

            try:
                data = json.loads(body_bytes.decode("utf-8"))
            except Exception:
                self._set_headers("application/json", 400)
                self.wfile.write(json.dumps({"error": "Invalid JSON body"}).encode("utf-8"))
                return

            prompt = data.get("prompt", "")
            tenant_id = data.get("tenant_id", "org_alpha")
            bypass_cache = bool(data.get("bypass_cache", False))

            result: ApexExecutionResult = apex_platform.process(prompt, tenant_id=tenant_id, bypass_cache=bypass_cache)

            response_payload = {
                "is_success": result.is_success,
                "is_blocked": result.is_blocked,
                "block_reason": result.block_reason,
                "was_cached": result.was_cached,
                "route_taken": result.route_taken,
                "tenant_id": result.tenant_id,
                "final_output": result.final_output,
                "total_latency_ms": round(result.total_latency_ms, 3),
                "data_payload": result.data_payload,
                "stages": [
                    {
                        "stage_number": s.stage_number,
                        "stage_name": s.stage_name,
                        "pillar": s.pillar,
                        "status": s.status,
                        "latency_ms": round(s.latency_ms, 3),
                        "details": s.details
                    }
                    for s in result.stages
                ]
            }

            self._set_headers("application/json", 200)
            self.wfile.write(json.dumps(response_payload, indent=2).encode("utf-8"))
            return

        elif path == "/api/mcp_restart":
            # Allows UI to test subprocess crash & recovery
            apex_platform.mcp_client.close()
            apex_platform.mcp_client.start()
            self._set_headers("application/json", 200)
            self.wfile.write(json.dumps({
                "status": "RESTARTED",
                "pid": apex_platform.mcp_client.process.pid if apex_platform.mcp_client.is_alive() else None
            }).encode("utf-8"))
            return

        else:
            self._set_headers("text/plain", 404)
            self.wfile.write(b"404 Not Found")

    def log_message(self, format, *args):
        """Clean minimal logging."""
        sys.stderr.write(f"[ApexVault Gateway HTTP] {self.address_string()} - {format % args}\n")


def run_server(port: int = PORT):
    server_address = (HOST, port)
    httpd = HTTPServer(server_address, ApexVaultHTTPHandler)
    print("=" * 80)
    print(f"🏛️  ApexVault AI: Level-4 Multi-Tenant Treasury Platform")
    print(f"🔗  Console URL: http://{HOST}:{port}")
    print(f"🛡️  Zero-Trust MCP Subprocess: ACTIVE (PID: {apex_platform.mcp_client.process.pid})")
    print(f"🔒  Database: data/apex_vault.db (Physical mode=ro enabled)")
    print("=" * 80)
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        print("\n[!] Shutting down ApexVault server...")
        apex_platform.mcp_client.close()
        httpd.server_close()


if __name__ == "__main__":
    port_arg = int(sys.argv[1]) if len(sys.argv) > 1 else PORT
    run_server(port_arg)
