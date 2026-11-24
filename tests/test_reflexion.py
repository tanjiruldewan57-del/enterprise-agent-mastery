"""
Adversarial Unit Tests for Cognitive Reflexion & Self-Correction (Topic 1.5)
===========================================================================
Validates:
  1. Fast-path termination without invoking reflector on clean execution.
  2. Multi-turn self-healing loop: recovers from database error on Turn 2.
  3. Bounded termination at max_retries without runaway recursion.
  4. Anti-ping-pong history injection in reflector diagnostic prompt.
"""

import os
import pytest
from src.core.reflexion_engine import (
    execute_self_healing_cycle,
    build_reflector_prompt,
    build_healing_generator_prompt
)


@pytest.fixture
def test_db_path():
    db_path = os.path.abspath(
        os.path.join(os.path.dirname(__file__), "..", "data", "ecommerce.db")
    )
    assert os.path.exists(db_path), f"Database not found at {db_path}"
    return db_path


@pytest.fixture
def mock_schema():
    return """
    CREATE TABLE products (
        product_id INTEGER PRIMARY KEY,
        product_name TEXT,
        price REAL,
        category TEXT
    );
    """


def test_reflexion_immediate_success(test_db_path, mock_schema):
    """
    Test 1: Query succeeds on Turn 1. Reflector must NOT be called!
    """
    generator_fn = lambda p: "SELECT COUNT(*) as total FROM products"
    reflector_called = False

    def mock_reflector(p):
        nonlocal reflector_called
        reflector_called = True
        return "Should not be called"

    state = execute_self_healing_cycle(
        db_path=test_db_path,
        user_query="Total products",
        schema_ddl=mock_schema,
        generator_fn=generator_fn,
        reflector_fn=mock_reflector,
        max_retries=3
    )

    assert state["is_success"] is True
    assert state["execution_status"] == "SUCCESS"
    assert state["retry_count"] == 0
    assert len(state["attempt_history"]) == 1
    assert reflector_called is False, "Efficiency failure: Reflector was called on successful query!"


def test_reflexion_heals_typo_on_turn_2(test_db_path, mock_schema):
    """
    Test 2 (The Self-Healing Core):
    Turn 1 fails with typo 'producst'.
    Reflector diagnoses typo.
    Turn 2 generator fixes typo and succeeds!
    """
    turn = 0
    reflector_call_count = 0

    def mock_generator(prompt: str) -> str:
        nonlocal turn
        turn += 1
        if turn == 1:
            # Turn 1: Typo in table name
            return "SELECT * FROM producst LIMIT 2"
        else:
            # Turn 2: Fixed table name based on diagnosis
            return "SELECT * FROM products LIMIT 2"

    def mock_reflector(prompt: str) -> str:
        nonlocal reflector_call_count
        reflector_call_count += 1
        return "Diagnosis: Table 'producst' does not exist. Use 'products'."

    state = execute_self_healing_cycle(
        db_path=test_db_path,
        user_query="Show 2 products",
        schema_ddl=mock_schema,
        generator_fn=mock_generator,
        reflector_fn=mock_reflector,
        max_retries=3
    )

    # Assertions
    assert state["is_success"] is True
    assert state["execution_status"] == "SUCCESS"
    assert state["retry_count"] == 1
    assert len(state["attempt_history"]) == 2
    assert reflector_call_count == 1
    assert state["attempt_history"][0]["is_valid"] is False
    assert state["attempt_history"][1]["is_valid"] is True
    assert "no such table: producst" in state["attempt_history"][0]["error"]


def test_reflexion_bounded_failure_on_persistent_error(test_db_path, mock_schema):
    """
    Test 3: Persistent error halts cleanly at max_retries without infinite loop.
    """
    mock_generator = lambda p: "SELECT invalid_col FROM products"
    mock_reflector = lambda p: "Diagnosis: invalid_col does not exist."

    state = execute_self_healing_cycle(
        db_path=test_db_path,
        user_query="Broken query",
        schema_ddl=mock_schema,
        generator_fn=mock_generator,
        reflector_fn=mock_reflector,
        max_retries=3
    )

    assert state["is_success"] is False
    assert state["execution_status"] == "FAILED_MAX_RETRIES"
    assert state["retry_count"] == 3
    assert len(state["attempt_history"]) == 3


def test_anti_ping_pong_history_injection(mock_schema):
    """
    Test 4: Reflector prompt includes past failed attempts to prevent ping-pong loops.
    """
    past_attempts = [
        {"generated_sql": "SELECT * FROM orders_v1", "is_valid": False},
        {"generated_sql": "SELECT * FROM orders_v2", "is_valid": False},
    ]
    prompt = build_reflector_prompt(
        user_query="Show orders",
        failed_sql="SELECT * FROM orders_v3",
        error_message="no such table: orders_v3",
        schema_ddl=mock_schema,
        past_attempts=past_attempts
    )

    assert "PAST FAILED ATTEMPTS (DO NOT REPEAT THESE):" in prompt
    assert "SELECT * FROM orders_v1" in prompt
    assert "SELECT * FROM orders_v2" in prompt
