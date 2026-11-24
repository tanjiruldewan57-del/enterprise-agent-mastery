"""
Red Team Adversarial Tests for AST SQL Validator (Topic 3.3)
=============================================================
Validates:
  1. Benign SELECT query validation and auto-injection of LIMIT 100.
  2. Excessive LIMIT (e.g. 50,000) clamped down to policy maximum (100).
  3. Pre-existing safe LIMIT (e.g. 10) preserved without unnecessary clamping.
  4. Semicolon piggyback multi-statement attacks blocked.
  5. Direct DDL & DML mutations (DROP, INSERT, UPDATE, DELETE, ALTER) rejected.
  6. Access to internal/forbidden catalog tables (sqlite_master) blocked.
  7. Malformed SQL syntax error handling.
  8. Compound queries (UNION) handled cleanly with limit injection.
"""

import pytest
from src.guardrails.ast_sql_validator import EnterpriseASTSQLValidator, ASTValidationResult


@pytest.fixture
def validator():
    return EnterpriseASTSQLValidator(dialect="sqlite", max_limit=100)


def test_benign_select_valid_and_auto_clamped(validator):
    """
    Test 1: Legitimate query without LIMIT is accepted and auto-clamped to LIMIT 100.
    """
    sql = "SELECT customer_id, full_name, available_balance FROM customers WHERE available_balance > 1000;"
    result = validator.validate_and_sanitize(sql)

    assert result.is_valid is True
    assert result.was_clamped is True
    assert result.applied_limit == 100
    assert "LIMIT 100" in result.sanitized_sql.upper()
    assert "customers" in result.tables_referenced


def test_excessive_limit_clamped_down(validator):
    """
    Test 2: A query asking for 50,000 rows (potential OOM bomb) is clamped down to 100.
    """
    sql = "SELECT * FROM transactions LIMIT 50000;"
    result = validator.validate_and_sanitize(sql)

    assert result.is_valid is True
    assert result.was_clamped is True
    assert result.applied_limit == 100
    assert "LIMIT 100" in result.sanitized_sql.upper()
    assert "50000" not in result.sanitized_sql


def test_valid_reasonable_limit_preserved(validator):
    """
    Test 3: A query with LIMIT 25 (below ceiling) is preserved as-is.
    """
    sql = "SELECT id, name FROM products ORDER BY price DESC LIMIT 25;"
    result = validator.validate_and_sanitize(sql)

    assert result.is_valid is True
    assert result.was_clamped is False
    assert result.applied_limit == 25
    assert "LIMIT 25" in result.sanitized_sql.upper()


def test_semicolon_piggyback_attack_blocked(validator):
    """
    Test 4: Chained multi-statement attack (SELECT ... ; DROP TABLE) is blocked.
    """
    sql = "SELECT balance FROM accounts WHERE id = 1; DROP TABLE audit_log;"
    result = validator.validate_and_sanitize(sql)

    assert result.is_valid is False
    assert result.sanitized_sql is None
    assert any("MULTI_STATEMENT_PIGGYBACK_DETECTED" in v for v in result.violations)


@pytest.mark.parametrize("mutation_query", [
    "DROP TABLE customers;",
    "INSERT INTO customers (id, name) VALUES (99, 'Hacker');",
    "DELETE FROM accounts WHERE balance < 0;",
    "UPDATE users SET is_admin = 1;",
    "ALTER TABLE customers ADD COLUMN secret TEXT;",
    "CREATE TABLE backdoor (cmd TEXT);",
])
def test_direct_mutations_blocked(validator, mutation_query):
    """
    Test 5: DDL/DML statements cannot disguise as legitimate queries.
    """
    result = validator.validate_and_sanitize(mutation_query)

    assert result.is_valid is False
    assert result.sanitized_sql is None
    assert any("MUTATION_STATEMENT_FORBIDDEN" in v for v in result.violations)


def test_disallowed_table_blocked(validator):
    """
    Test 6: Query attempting to scrape sqlite_master schema metadata is rejected.
    """
    sql = "SELECT sql FROM sqlite_master WHERE type = 'table';"
    result = validator.validate_and_sanitize(sql)

    assert result.is_valid is False
    assert any("DISALLOWED_TABLE_ACCESS" in v for v in result.violations)


def test_malformed_syntax_gracefully_rejected(validator):
    """
    Test 7: Unparseable, broken SQL syntax is trapped cleanly.
    """
    sql = "SELECT FROM WHERE GROUP BY ORDER;"
    result = validator.validate_and_sanitize(sql)

    assert result.is_valid is False
    assert any("MALFORMED_SQL_SYNTAX" in v for v in result.violations)


def test_union_compound_query_with_limit(validator):
    """
    Test 8: Compound UNION queries are validated and clamped appropriately.
    """
    sql = "SELECT account_id FROM accounts UNION SELECT customer_id FROM customers;"
    result = validator.validate_and_sanitize(sql)

    assert result.is_valid is True
    assert result.applied_limit == 100
    assert "UNION" in result.sanitized_sql.upper()
    assert "LIMIT 100" in result.sanitized_sql.upper()
