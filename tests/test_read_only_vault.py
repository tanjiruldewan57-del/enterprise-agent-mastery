"""
Red Team Adversarial Tests for Physical Read-Only URI Mode (Topic 3.2)
======================================================================
Validates Defense-in-Depth Storage Isolation:
  1. Safe URI generation across Windows & POSIX environments.
  2. Physical OS/Engine write rejection EVEN IF C-Authorizer is detached.
  3. PRAGMA query_only = ON active enforcement.
  4. Ephemeral in-memory sandbox isolation (zero disk touch).
  5. Live database security profile inspection & telemetry.
"""

import os
import sqlite3
import pytest
from src.guardrails.read_only_vault import EnterpriseReadOnlyVault, DatabaseIsolationProfile


@pytest.fixture
def sample_db(tmp_path):
    """Creates a sample physical SQLite database with initial customer data."""
    db_file = str(tmp_path / "production_vault.db")
    conn = sqlite3.connect(db_file)
    cursor = conn.cursor()
    cursor.execute("""
        CREATE TABLE accounts (
            account_id TEXT PRIMARY KEY,
            owner_name TEXT NOT NULL,
            balance REAL NOT NULL
        );
    """)
    cursor.execute("""
        INSERT INTO accounts VALUES
        ('ACC_101', 'Alice Stark', 7500.00),
        ('ACC_102', 'Bruce Wayne', 98000.00);
    """)
    conn.commit()
    conn.close()
    return db_file


def test_safe_uri_formatting():
    """
    Test 1: URI generator creates standard RFC-compliant paths with mode=ro.
    """
    vault = EnterpriseReadOnlyVault()
    uri = vault.format_safe_sqlite_uri("data/my_store.db", mode="ro", immutable=True)
    
    assert "mode=ro" in uri
    assert "immutable=1" in uri
    assert uri.startswith("file:")


def test_physical_write_fails_even_without_authorizer(sample_db):
    """
    Test 2: CRITICAL TEST - Even if an attacker or bug detaches the C-Authorizer
    (conn.set_authorizer(None)), attempting to write to mode=ro physical connection
    MUST be rejected by the OS / SQLite engine layer.
    """
    vault = EnterpriseReadOnlyVault()
    conn = vault.connect_physical_readonly(sample_db, attach_c_authorizer=False)

    # Confirm authorizer is completely disabled
    conn.set_authorizer(None)

    cursor = conn.cursor()
    
    # Read queries must succeed
    cursor.execute("SELECT COUNT(*) FROM accounts;")
    assert cursor.fetchone()[0] == 2

    # Mutation attempt MUST fail with OperationalError: attempt to write a readonly database
    with pytest.raises(sqlite3.OperationalError) as exc_info:
        cursor.execute("INSERT INTO accounts VALUES ('ACC_999', 'Hacker', 1000000.00);")

    err = str(exc_info.value).lower()
    assert "readonly" in err or "read-only" in err or "cannot" in err

    conn.close()


def test_query_only_pragma_enforcement(sample_db):
    """
    Test 3: Validates that PRAGMA query_only is active and trusted_schema is OFF.
    """
    vault = EnterpriseReadOnlyVault()
    conn = vault.connect_physical_readonly(sample_db)
    cursor = conn.cursor()

    cursor.execute("PRAGMA query_only;")
    assert cursor.fetchone()[0] == 1

    cursor.execute("PRAGMA trusted_schema;")
    assert cursor.fetchone()[0] == 0

    conn.close()


def test_ephemeral_in_memory_sandbox_isolation(sample_db):
    """
    Test 4: In-memory clone allows high-speed querying with absolute zero disk exposure.
    """
    vault = EnterpriseReadOnlyVault()
    mem_conn = vault.create_ephemeral_sandbox(sample_db)

    cursor = mem_conn.cursor()
    cursor.execute("SELECT owner_name, balance FROM accounts WHERE balance > 10000;")
    rows = cursor.fetchall()
    assert len(rows) == 1
    assert rows[0][0] == "Bruce Wayne"

    # Verify query_only is also set on the sandbox
    cursor.execute("PRAGMA query_only;")
    assert cursor.fetchone()[0] == 1

    mem_conn.close()


def test_security_profile_telemetry(sample_db):
    """
    Test 5: Live inspection telemetry provides verifiable zero-trust confirmation.
    """
    vault = EnterpriseReadOnlyVault()
    conn = vault.connect_physical_readonly(sample_db)

    profile = vault.inspect_security_profile(conn, db_path=sample_db)
    assert profile.is_physical_readonly is True
    assert profile.query_only_pragma_active is True
    assert profile.trusted_schema_disabled is True
    assert profile.is_ephemeral_memory is False

    conn.close()
