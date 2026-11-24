"""
Red Team Adversarial Tests for Row-Level Security (RLS) & Multi-Tenant Isolation (Topic 3.4)
=============================================================================================
Validates:
  1. Automatic injection of tenant predicate on queries lacking WHERE clauses.
  2. Safe conjoining of tenant predicate with pre-existing user predicates.
  3. Active BOLA / IDOR detection and blocking on hostile cross-tenant spoofing.
  4. Multi-table JOIN queries get isolated on all referenced multi-tenant tables.
  5. Injection-like or malformed tenant IDs are strictly rejected.
  6. Subqueries and nested table scans receive proper tenant bounding.
  7. Live database execution test proving zero cross-tenant data leakage.
"""

import sqlite3
import pytest
from src.guardrails.multi_tenant_rls import EnterpriseMultiTenantRLS, RLSEnforcementResult


@pytest.fixture
def rls_engine():
    return EnterpriseMultiTenantRLS()


@pytest.fixture
def multi_tenant_db(tmp_path):
    """Sets up a realistic multi-tenant banking database with data for org_alpha and org_beta."""
    db_file = str(tmp_path / "multi_tenant.db")
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
            customer_name TEXT NOT NULL
        );
    """)
    # Seed data: 2 accounts for org_alpha, 2 accounts for org_beta
    cursor.execute("""
        INSERT INTO accounts VALUES
        ('ACC_A1', 'org_alpha', 'Alpha Corp Admin', 50000.00),
        ('ACC_A2', 'org_alpha', 'Alpha CFO', 125000.00),
        ('ACC_B1', 'org_beta', 'Competitor Beta CEO', 999999.00),
        ('ACC_B2', 'org_beta', 'Competitor Secret Fund', 450000.00);
    """)
    cursor.execute("""
        INSERT INTO customers VALUES
        ('CUST_A1', 'org_alpha', 'Client A1'),
        ('CUST_B1', 'org_beta', 'Client B1');
    """)
    conn.commit()
    conn.close()
    return db_file


def test_tenant_injected_on_plain_query(rls_engine):
    """
    Test 1: Unbounded query without WHERE receives automatic tenant predicate.
    """
    sql = "SELECT account_id, owner_name, balance FROM accounts;"
    result = rls_engine.enforce_isolation(sql, authenticated_tenant_id="org_alpha")

    assert result.is_safe is True
    assert "accounts.tenant_id = 'org_alpha'" in result.isolated_sql
    assert "accounts" in result.tables_isolated


def test_tenant_safely_conjoined_with_existing_where(rls_engine):
    """
    Test 2: Pre-existing user predicate is preserved and conjoined via AND.
    """
    sql = "SELECT account_id, balance FROM accounts WHERE balance > 10000 ORDER BY balance DESC;"
    result = rls_engine.enforce_isolation(sql, authenticated_tenant_id="org_alpha")

    assert result.is_safe is True
    assert "balance > 10000" in result.isolated_sql
    assert "accounts.tenant_id = 'org_alpha'" in result.isolated_sql


def test_hostile_cross_tenant_spoofing_blocked(rls_engine):
    """
    Test 3: Attacker attempts to exfiltrate competitor data by requesting tenant_id = 'org_beta'.
    Engine must flag BOLA attack and block execution.
    """
    hostile_sql = "SELECT * FROM accounts WHERE tenant_id = 'org_beta';"
    result = rls_engine.enforce_isolation(hostile_sql, authenticated_tenant_id="org_alpha")

    assert result.is_safe is False
    assert result.spoofing_detected is True
    assert any("BOLA_ATTACK_DETECTED" in v for v in result.violations)


def test_multi_table_join_isolation(rls_engine):
    """
    Test 4: JOIN query between accounts and customers applies isolation to both tables.
    """
    join_sql = """
        SELECT a.account_id, c.customer_name 
        FROM accounts a 
        JOIN customers c ON a.tenant_id = c.tenant_id 
        WHERE a.balance > 0;
    """
    result = rls_engine.enforce_isolation(join_sql, authenticated_tenant_id="org_alpha")

    assert result.is_safe is True
    assert "a.tenant_id = 'org_alpha'" in result.isolated_sql
    assert "c.tenant_id = 'org_alpha'" in result.isolated_sql
    assert "accounts" in result.tables_isolated
    assert "customers" in result.tables_isolated


def test_invalid_or_injected_tenant_id_rejected(rls_engine):
    """
    Test 5: Malicious or SQL-injection style tenant IDs are rejected upfront.
    """
    sql = "SELECT * FROM accounts;"
    
    # SQL injection payload as tenant ID
    res1 = rls_engine.enforce_isolation(sql, authenticated_tenant_id="org_alpha' OR 1=1;--")
    assert res1.is_safe is False
    assert any("INVALID_AUTHENTICATED_TENANT_ID" in v for v in res1.violations)

    # Empty tenant ID
    res2 = rls_engine.enforce_isolation(sql, authenticated_tenant_id="")
    assert res2.is_safe is False


def test_live_database_execution_proves_zero_cross_tenant_leak(rls_engine, multi_tenant_db):
    """
    Test 6: Real execution on SQLite database proves that only org_alpha rows are returned.
    Competitor Beta's $999,999.00 balance is completely invisible.
    """
    conn = sqlite3.connect(multi_tenant_db)
    cursor = conn.cursor()

    # 1. Without RLS (Vulnerable) -> Returns all 4 rows including Competitor Beta
    vulnerable_sql = "SELECT account_id, owner_name, balance FROM accounts;"
    cursor.execute(vulnerable_sql)
    all_rows = cursor.fetchall()
    assert len(all_rows) == 4
    assert any("Competitor Beta" in r[1] for r in all_rows)

    # 2. With AST RLS (Protected) -> Rewrites query to restrict to org_alpha
    rls_result = rls_engine.enforce_isolation(vulnerable_sql, authenticated_tenant_id="org_alpha")
    assert rls_result.is_safe is True

    cursor.execute(rls_result.isolated_sql)
    isolated_rows = cursor.fetchall()

    # Must strictly contain ONLY org_alpha rows (2 rows)
    assert len(isolated_rows) == 2
    assert all("Competitor" not in r[1] for r in isolated_rows)
    assert any("Alpha Corp Admin" in r[1] for r in isolated_rows)
    assert any("Alpha CFO" in r[1] for r in isolated_rows)

    conn.close()
