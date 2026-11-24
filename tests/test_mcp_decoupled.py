"""
Red Team Adversarial Tests for Decoupled MCP Server (Topic 3.5)
================================================================
Validates:
  1. Subprocess launch and JSON-RPC 2.0 initialize handshake.
  2. Tool discovery (tools/list) returning standard JSON schemas.
  3. Clean read query execution through the decoupled process boundary.
  4. Multi-Tenant RLS enforcement across the MCP boundary (blocking BOLA).
  5. AST SQL mutation blocking (DROP TABLE) across the MCP boundary.
  6. Low-level C-Authorizer column protection (email exfiltration block).
  7. Process crash isolation (killing the subprocess does not crash the gateway).
"""

import os
import sqlite3
import pytest
from src.mcp.client import EnterpriseMCPClient


@pytest.fixture
def mcp_test_db(tmp_path):
    """Sets up an isolated test database for MCP testing."""
    db_file = str(tmp_path / "mcp_warehouse.db")
    conn = sqlite3.connect(db_file)
    cursor = conn.cursor()
    cursor.execute("""
        CREATE TABLE accounts (
            account_id TEXT PRIMARY KEY,
            tenant_id TEXT NOT NULL,
            owner_name TEXT NOT NULL,
            balance REAL NOT NULL
        );
    """)
    cursor.execute("""
        CREATE TABLE customers (
            customer_id TEXT PRIMARY KEY,
            tenant_id TEXT NOT NULL,
            customer_name TEXT NOT NULL,
            email TEXT NOT NULL
        );
    """)
    cursor.execute("""
        INSERT INTO accounts VALUES
        ('ACC_1', 'org_alpha', 'Alice Corp', 15000.00),
        ('ACC_2', 'org_beta', 'Competitor Corp', 85000.00);
    """)
    cursor.execute("""
        INSERT INTO customers VALUES
        ('CUST_1', 'org_alpha', 'Alice Client', 'secret_alice@alpha.com'),
        ('CUST_2', 'org_beta', 'Competitor Client', 'secret_beta@beta.com');
    """)
    conn.commit()
    conn.close()
    return db_file


@pytest.fixture
def mcp_client(mcp_test_db):
    """Provides an active, connected EnterpriseMCPClient."""
    client = EnterpriseMCPClient(db_path=mcp_test_db)
    client.start()
    yield client
    client.close()


def test_mcp_server_handshake_and_tool_discovery(mcp_client):
    """
    Test 1 & 2: Subprocess starts and responds to tools/list with query_database.
    """
    assert mcp_client.is_alive() is True
    tools = mcp_client.list_tools()

    tool_names = [t["name"] for t in tools]
    assert "query_database" in tool_names
    assert "get_database_health" in tool_names


def test_mcp_query_database_benign_execution(mcp_client):
    """
    Test 3: Valid query executed through subprocess and RLS returns only org_alpha data.
    """
    args = {
        "sql": "SELECT account_id, owner_name, balance FROM accounts;",
        "tenant_id": "org_alpha"
    }
    result = mcp_client.call_tool("query_database", args)

    assert result["is_error"] is False
    assert result["row_count"] == 1
    assert result["data"][0]["owner_name"] == "Alice Corp"
    assert result["data"][0]["balance"] == 15000.00


def test_mcp_blocks_cross_tenant_bola_attack(mcp_client):
    """
    Test 4: Hostile query attempting to read org_beta data is trapped by RLS gate.
    """
    args = {
        "sql": "SELECT * FROM accounts WHERE tenant_id = 'org_beta';",
        "tenant_id": "org_alpha"
    }
    result = mcp_client.call_tool("query_database", args)

    assert result["is_error"] is True
    assert result["error_stage"] == "ROW_LEVEL_SECURITY_GATE"
    assert any("BOLA_ATTACK_DETECTED" in v for v in result["violations"])


def test_mcp_blocks_mutation_via_ast_gate(mcp_client):
    """
    Test 5: Destructive DDL query (DROP TABLE) is trapped by the AST validator.
    """
    args = {
        "sql": "DROP TABLE accounts;",
        "tenant_id": "org_alpha"
    }
    result = mcp_client.call_tool("query_database", args)

    assert result["is_error"] is True
    assert result["error_stage"] in ("ROW_LEVEL_SECURITY_GATE", "AST_VALIDATION_GATE")


def test_mcp_blocks_sensitive_column_via_c_authorizer(mcp_client):
    """
    Test 6: Query for sensitive 'email' column is trapped by the low-level C-Authorizer.
    """
    args = {
        "sql": "SELECT customer_name, email FROM customers;",
        "tenant_id": "org_alpha"
    }
    result = mcp_client.call_tool("query_database", args)

    assert result["is_error"] is True
    assert result["error_stage"] == "DATABASE_ENGINE_GATE"
    assert "prohibited" in result["message"].lower() or "not authorized" in result["message"].lower()


def test_mcp_subprocess_crash_containment(mcp_test_db):
    """
    Test 7: CRITICAL BLAST RADIUS TEST -
    If the server subprocess is violently killed (SIGKILL / terminate),
    the client process catches the failure safely without crashing.
    """
    client = EnterpriseMCPClient(db_path=mcp_test_db)
    client.start()
    assert client.is_alive() is True

    # Violently kill the server process
    client.process.kill()
    client.process.wait()

    assert client.is_alive() is False

    # Calling tool on dead process must raise or return graceful error, not crash the test
    res = client.call_tool("get_database_health", {})
    assert "error" in res or res.get("is_error") is True

    # Verify client can cleanly recover and restart
    client.start()
    assert client.is_alive() is True
    health = client.call_tool("get_database_health", {})
    assert health.get("status") == "HEALTHY"

    client.close()
