"""
Enterprise MCP Client & Subprocess Lifecycle Manager (Topic 3.5)
=================================================================
Protocol: Model Context Protocol (MCP) Standard - JSON-RPC 2.0 over stdio
Compliance: Process Isolation, Graceful Fault Recovery & Blast Radius Containment
"""

import sys
import os
import json
import subprocess
import threading
from typing import Dict, Any, List, Optional


class EnterpriseMCPClient:
    """
    Gateway-side client that communicates with the isolated Database MCP Server
    via OS standard input/output pipes.
    """

    def __init__(self, db_path: str = "data/ecommerce.db", server_script: Optional[str] = None):
        self.db_path = os.path.abspath(db_path)
        self.repo_root = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
        self.server_script = server_script or os.path.abspath(
            os.path.join(os.path.dirname(__file__), "db_server.py")
        )
        self.process: Optional[subprocess.Popen] = None
        self._request_counter = 0
        self._lock = threading.Lock()

    def start(self, timeout_seconds: float = 5.0) -> Dict[str, Any]:
        """
        Launches the MCP Server as an isolated operating system subprocess.
        Performs the initial MCP 'initialize' handshake.
        """
        with self._lock:
            if self.process is not None and self.process.poll() is None:
                return {"status": "ALREADY_RUNNING", "pid": self.process.pid}

            # Configure clean subprocess environment with PYTHONPATH pointing to repository root
            env = os.environ.copy()
            existing_pythonpath = env.get("PYTHONPATH", "")
            env["PYTHONPATH"] = (
                f"{self.repo_root}{os.pathsep}{existing_pythonpath}"
                if existing_pythonpath else self.repo_root
            )

            # Launch isolated subprocess with clean stdio pipes
            self.process = subprocess.Popen(
                [sys.executable, self.server_script, self.db_path],
                cwd=self.repo_root,
                env=env,
                stdin=subprocess.PIPE,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                bufsize=1  # Line buffered
            )

        # Execute MCP Initialize Handshake outside lock to prevent deadlock
        init_res = self._send_request(
            "initialize",
            {
                "protocolVersion": "2024-11-05",
                "capabilities": {},
                "clientInfo": {"name": "enterprise-ai-gateway", "version": "1.0.0"}
            },
            timeout_seconds=timeout_seconds
        )
        return init_res

    def is_alive(self) -> bool:
        """Verifies if the server subprocess is actively running."""
        return self.process is not None and self.process.poll() is None

    def list_tools(self, timeout_seconds: float = 5.0) -> List[Dict[str, Any]]:
        """Queries the server for registered tools schema."""
        response = self._send_request("tools/list", {}, timeout_seconds=timeout_seconds)
        result = response.get("result", {})
        return result.get("tools", [])

    def call_tool(
        self,
        name: str,
        arguments: Dict[str, Any],
        timeout_seconds: float = 5.0
    ) -> Dict[str, Any]:
        """
        Invokes a tool on the isolated server over JSON-RPC 2.0.
        """
        response = self._send_request(
            "tools/call",
            {"name": name, "arguments": arguments},
            timeout_seconds=timeout_seconds
        )
        if "error" in response:
            return {"is_error": True, "error": response["error"]}

        result = response.get("result", {})
        content = result.get("content", [])
        if content and content[0].get("type") == "text":
            try:
                return json.loads(content[0]["text"])
            except json.JSONDecodeError:
                return {"is_error": False, "raw_text": content[0]["text"]}
        return result

    def close(self):
        """Gracefully terminates the MCP server subprocess."""
        with self._lock:
            if self.process is not None:
                try:
                    if self.process.poll() is None:
                        self.process.terminate()
                        self.process.wait(timeout=2.0)
                except Exception:
                    self.process.kill()
                finally:
                    self.process = None

    def _send_request(
        self,
        method: str,
        params: Dict[str, Any],
        timeout_seconds: float = 5.0
    ) -> Dict[str, Any]:
        """Sends a JSON-RPC 2.0 line and waits for the single-line JSON response."""
        with self._lock:
            if not self.is_alive():
                return {
                    "jsonrpc": "2.0",
                    "id": None,
                    "error": {
                        "code": -32000,
                        "message": "MCP Server subprocess is not running."
                    }
                }

            self._request_counter += 1
            req_id = self._request_counter

            payload = {
                "jsonrpc": "2.0",
                "id": req_id,
                "method": method,
                "params": params
            }

            try:
                msg = json.dumps(payload) + "\n"
                self.process.stdin.write(msg)
                self.process.stdin.flush()

                # Read line response from server stdout
                line = self.process.stdout.readline()
                if not line:
                    exit_code = self.process.poll()
                    return {
                        "jsonrpc": "2.0",
                        "id": req_id,
                        "error": {
                            "code": -32001,
                            "message": f"MCP Server closed stdout unexpectedly. Exit code: {exit_code}"
                        }
                    }
                return json.loads(line.strip())
            except Exception as e:
                return {
                    "jsonrpc": "2.0",
                    "id": req_id,
                    "error": {"code": -32000, "message": f"Subprocess IPC Error: {str(e)}"}
                }
