"""
Enterprise Decoupled Database MCP Server (Topic 3.5)
=====================================================
Protocol: Model Context Protocol (MCP) Standard - JSON-RPC 2.0 over stdio
Compliance: Process-Level Isolation, Principle of Least Privilege (PoLP)
Role:
  - Runs in an isolated OS subprocess completely separated from the AI Gateway.
  - Implements full Pillar 3 Defense Stack:
      1. Multi-Tenant RLS (Topic 3.4)
      2. AST SQL Validation & LIMIT Auto-Clamping (Topic 3.3)
      3. Physical Read-Only Mode & OS Locks (Topic 3.2)
      4. Low-Level C-Authorizer (Topic 3.1)
"""

import sys
import json
import os
import sqlite3
from typing import Dict, Any, List, Optional
from src.guardrails.c_authorizer import EnterpriseCAuthorizer
from src.guardrails.read_only_vault import EnterpriseReadOnlyVault
from src.guardrails.ast_sql_validator import EnterpriseASTSQLValidator
from src.guardrails.multi_tenant_rls import EnterpriseMultiTenantRLS


class DatabaseMCPServer:
    """
    Decoupled MCP Server that exposes secure database tools over standard I/O (stdio).
    """

    PROTOCOL_VERSION = "2024-11-05"
    SERVER_NAME = "enterprise-database-mcp"
    SERVER_VERSION = "1.0.0"

    def __init__(self, db_path: str = "data/ecommerce.db"):
        self.db_path = db_path
        self.rls_engine = EnterpriseMultiTenantRLS()
        self.ast_validator = EnterpriseASTSQLValidator(max_limit=100)
        self.read_only_vault = EnterpriseReadOnlyVault()

    def get_tool_definitions(self) -> List[Dict[str, Any]]:
        """Returns MCP-compliant tool specifications."""
        return [
            {
                "name": "query_database",
                "description": "Executes a secure, isolated read-only query against the enterprise warehouse.",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "sql": {
                            "type": "string",
                            "description": "SQL query to execute."
                        },
                        "tenant_id": {
                            "type": "string",
                            "description": "Authenticated enterprise tenant ID (e.g. org_alpha)."
                        }
                    },
                    "required": ["sql", "tenant_id"]
                }
            },
            {
                "name": "get_database_health",
                "description": "Returns security profile telemetry confirming read-only and RLS isolation status.",
                "inputSchema": {
                    "type": "object",
                    "properties": {}
                }
            }
        ]

    def execute_query_database(self, arguments: Dict[str, Any]) -> Dict[str, Any]:
        """
        Executes query through the multi-stage Pillar 3 Zero-Trust defense pipeline.
        """
        sql = arguments.get("sql", "")
        tenant_id = arguments.get("tenant_id", "")

        # 1. Row-Level Security (Topic 3.4)
        rls_result = self.rls_engine.enforce_isolation(sql, authenticated_tenant_id=tenant_id)
        if not rls_result.is_safe:
            return {
                "is_error": True,
                "error_stage": "ROW_LEVEL_SECURITY_GATE",
                "violations": rls_result.violations,
                "message": "Query rejected by Multi-Tenant Isolation Gate."
            }

        # 2. AST Validation & Auto-Clamping (Topic 3.3)
        ast_result = self.ast_validator.validate_and_sanitize(rls_result.isolated_sql)
        if not ast_result.is_valid:
            return {
                "is_error": True,
                "error_stage": "AST_VALIDATION_GATE",
                "violations": ast_result.violations,
                "message": "Query rejected by AST Syntax Validator."
            }

        executable_sql = ast_result.sanitized_sql

        # 3 & 4. Physical Read-Only Mode (Topic 3.2) & C-Authorizer (Topic 3.1)
        if not os.path.exists(self.db_path):
            return {
                "is_error": True,
                "error_stage": "STORAGE_ACCESS",
                "message": f"Database file not found: {self.db_path}"
            }

        try:
            conn = self.read_only_vault.connect_physical_readonly(self.db_path, attach_c_authorizer=True)
            cursor = conn.cursor()
            cursor.execute(executable_sql)
            cols = [d[0] for d in cursor.description] if cursor.description else []
            rows = [dict(zip(cols, r)) for r in cursor.fetchall()]
            conn.close()

            return {
                "is_error": False,
                "row_count": len(rows),
                "columns": cols,
                "data": rows,
                "applied_limit": ast_result.applied_limit,
                "was_clamped": ast_result.was_clamped,
                "tables_isolated": rls_result.tables_isolated
            }
        except (sqlite3.DatabaseError, sqlite3.OperationalError) as db_err:
            return {
                "is_error": True,
                "error_stage": "DATABASE_ENGINE_GATE",
                "message": f"Execution halted by database engine: {str(db_err)}"
            }

    def execute_get_health(self) -> Dict[str, Any]:
        """Telemetry check."""
        return {
            "status": "HEALTHY",
            "server": self.SERVER_NAME,
            "version": self.SERVER_VERSION,
            "database_exists": os.path.exists(self.db_path),
            "physical_mode": "ro",
            "pid": os.getpid()
        }

    def handle_request(self, request: Dict[str, Any]) -> Dict[str, Any]:
        """Dispatches incoming JSON-RPC 2.0 requests."""
        req_id = request.get("id")
        method = request.get("method")
        params = request.get("params", {})

        if method == "initialize":
            return {
                "jsonrpc": "2.0",
                "id": req_id,
                "result": {
                    "protocolVersion": self.PROTOCOL_VERSION,
                    "capabilities": {"tools": {}},
                    "serverInfo": {
                        "name": self.SERVER_NAME,
                        "version": self.SERVER_VERSION
                    }
                }
            }

        elif method == "tools/list":
            return {
                "jsonrpc": "2.0",
                "id": req_id,
                "result": {
                    "tools": self.get_tool_definitions()
                }
            }

        elif method == "tools/call":
            tool_name = params.get("name")
            arguments = params.get("arguments", {})

            if tool_name == "query_database":
                content = self.execute_query_database(arguments)
                return {
                    "jsonrpc": "2.0",
                    "id": req_id,
                    "result": {
                        "content": [{"type": "text", "text": json.dumps(content)}]
                    }
                }
            elif tool_name == "get_database_health":
                content = self.execute_get_health()
                return {
                    "jsonrpc": "2.0",
                    "id": req_id,
                    "result": {
                        "content": [{"type": "text", "text": json.dumps(content)}]
                    }
                }
            else:
                return {
                    "jsonrpc": "2.0",
                    "id": req_id,
                    "error": {"code": -32601, "message": f"Tool not found: {tool_name}"}
                }

        elif method == "ping":
            return {"jsonrpc": "2.0", "id": req_id, "result": {}}

        return {
            "jsonrpc": "2.0",
            "id": req_id,
            "error": {"code": -32601, "message": f"Method not found: {method}"}
        }

    def run_stdio(self):
        """Standard I/O event loop reading JSON-RPC 2.0 requests from stdin."""
        for line in sys.stdin:
            line = line.strip()
            if not line:
                continue
            try:
                request = json.loads(line)
                response = self.handle_request(request)
            except json.JSONDecodeError as err:
                response = {
                    "jsonrpc": "2.0",
                    "id": None,
                    "error": {"code": -32700, "message": f"Parse error: {str(err)}"}
                }
            
            sys.stdout.write(json.dumps(response) + "\n")
            sys.stdout.flush()


if __name__ == "__main__":
    target_db = sys.argv[1] if len(sys.argv) > 1 else "data/ecommerce.db"
    server = DatabaseMCPServer(db_path=target_db)
    server.run_stdio()
