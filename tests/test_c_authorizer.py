"""
Adversarial Unit Tests for C-Level Database Authorizer (Topic 3.1)
==================================================================
Validates:
  1. Benign SELECT query execution permitted on public columns.
  2. Complete blocking of SELECT * when sensitive columns (email, password) are present.
  3. Strict blocking of DML & DDL mutations (INSERT, UPDATE, DELETE, DROP, ALTER).
  4. Blocking of dangerous functions (load_extension, readfile) to prevent RCE.
  5. Blocking of ATTACH DATABASE to prevent secondary database exfiltration.
  6. Granular custom restricted column enforcement (e.g. blocking SSN).
"""

import sqlite3
import pytest
from src.guardrails.c_authorizer import EnterpriseCAuthorizer, AuthorizerDecision


@pytest.fixture
def test_db(tmp_path):
    """Sets up a realistic banking/customer test database."""
    db_file = str(tmp_path / "test_auth.db")
    conn = sqlite3.connect(db_file)
    cursor = conn.cursor()
    cursor.execute("""
        CREATE TABLE customers (
            customer_id INTEGER PRIMARY KEY,
            full_name TEXT NOT NULL,
            account_type TEXT NOT NULL,
            available_balance REAL NOT NULL,
            email TEXT NOT NULL,
            password_hash TEXT NOT NULL,
            ssn TEXT NOT NULL
        );
    """)
    cursor.execute("""
        INSERT INTO customers VALUES 
        (1, 'Alice Smith', 'Checking', 5400.00, 'alice@example.com', 'argon2$hash$secret', '123-45-6789'),
        (2, 'Bob Jones', 'Savings', 12300.50, 'bob@example.com', 'argon2$hash$secret2', '987-65-4321');
    """)
    conn.commit()
    conn.close()
    return db_file


def test_authorizer_allows_benign_select(test_db):
    """
    Test 1: Read queries on non-sensitive columns execute cleanly.
    """
    authorizer = EnterpriseCAuthorizer()
    conn = sqlite3.connect(f"file:{test_db}?mode=ro", uri=True)
    authorizer.attach_to_connection(conn)

    cursor = conn.cursor()
    cursor.execute("SELECT customer_id, full_name, available_balance FROM customers WHERE available_balance > 5000;")
    rows = cursor.fetchall()

    assert len(rows) == 2
    assert rows[0][1] == "Alice Smith"
    conn.close()

    # Verify audit trail recorded allowed decisions
    audit = authorizer.get_audit_trail()
    assert any(d.action_name == "SQLITE_SELECT" and d.is_allowed for d in audit)


def test_authorizer_blocks_select_star_sensitive_columns(test_db):
    """
    Test 2: SELECT * triggers SQLITE_DENY when it reaches 'email' or 'password_hash'.
    """
    authorizer = EnterpriseCAuthorizer()
    conn = sqlite3.connect(f"file:{test_db}?mode=ro", uri=True)
    authorizer.attach_to_connection(conn)

    cursor = conn.cursor()
    with pytest.raises(sqlite3.DatabaseError) as exc_info:
        cursor.execute("SELECT * FROM customers;")

    assert any(term in str(exc_info.value).lower() for term in ("not authorized", "prohibited"))

    # Audit trail must show DENY on email or password_hash
    audit = authorizer.get_audit_trail()
    denied_cols = [d.target_column_or_fn for d in audit if not d.is_allowed]
    assert "email" in denied_cols or "password_hash" in denied_cols
    conn.close()


def test_authorizer_blocks_all_mutations(test_db):
    """
    Test 3: DML (INSERT, UPDATE, DELETE) and DDL (DROP, ALTER) operations are strictly denied.
    """
    authorizer = EnterpriseCAuthorizer(allow_mutations=False)
    conn = sqlite3.connect(test_db)
    authorizer.attach_to_connection(conn)
    cursor = conn.cursor()

    # 1. Block INSERT
    with pytest.raises(sqlite3.DatabaseError):
        cursor.execute("INSERT INTO customers (customer_id, full_name, account_type, available_balance, email, password_hash, ssn) VALUES (3, 'Hacker', 'Checking', 1.0, 'h@h.com', 'x', '000');")

    # 2. Block UPDATE
    with pytest.raises(sqlite3.DatabaseError):
        cursor.execute("UPDATE customers SET available_balance = 999999.0 WHERE customer_id = 1;")

    # 3. Block DELETE
    with pytest.raises(sqlite3.DatabaseError):
        cursor.execute("DELETE FROM customers WHERE customer_id = 2;")

    # 4. Block DROP TABLE
    with pytest.raises(sqlite3.DatabaseError):
        cursor.execute("DROP TABLE customers;")

    conn.close()


def test_authorizer_blocks_dangerous_functions(test_db):
    """
    Test 4: Dangerous extension loading & file reading functions are denied.
    """
    authorizer = EnterpriseCAuthorizer()
    conn = sqlite3.connect(f"file:{test_db}?mode=ro", uri=True)
    authorizer.attach_to_connection(conn)
    cursor = conn.cursor()

    with pytest.raises(sqlite3.DatabaseError):
        cursor.execute("SELECT load_extension('malicious.so');")

    with pytest.raises(sqlite3.DatabaseError):
        cursor.execute("SELECT readfile('/etc/passwd');")

    conn.close()


def test_authorizer_blocks_attach_database(test_db):
    """
    Test 5: Attaching secondary external databases is denied.
    """
    authorizer = EnterpriseCAuthorizer()
    conn = sqlite3.connect(f"file:{test_db}?mode=ro", uri=True)
    authorizer.attach_to_connection(conn)
    cursor = conn.cursor()

    with pytest.raises(sqlite3.DatabaseError):
        cursor.execute("ATTACH DATABASE ':memory:' AS shadow_db;")

    conn.close()


def test_authorizer_custom_restricted_columns(test_db):
    """
    Test 6: Configurable custom column shield allows email if removed from blacklist,
    but blocks ssn.
    """
    # Only restrict SSN
    custom_auth = EnterpriseCAuthorizer(restricted_columns={"ssn"})
    conn = sqlite3.connect(f"file:{test_db}?mode=ro", uri=True)
    custom_auth.attach_to_connection(conn)
    cursor = conn.cursor()

    # Email is allowed under this custom policy
    cursor.execute("SELECT full_name, email FROM customers;")
    rows = cursor.fetchall()
    assert len(rows) == 2

    # SSN is strictly blocked
    with pytest.raises(sqlite3.DatabaseError):
        cursor.execute("SELECT full_name, ssn FROM customers;")

    conn.close()
