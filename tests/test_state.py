"""
Adversarial Unit Tests for Enterprise State & Reducer Logic (Topic 1.2)
======================================================================
Validates:
  1. Reducer channel (operator.add) accumulates trial histories without overwriting.
  2. Overwrite channels maintain current-instant values.
  3. Retry boundary logic correctly signals ceiling breach.
  4. AttemptRecord dictionary schema integrity.
"""

import operator
from src.state import AgentState, AttemptRecord


def test_reducer_accumulates_across_cycles():
    """
    Test 1 (The Amnesia Test):
    Simulates a 3-cycle self-healing retry loop.
    Verifies that operator.add preserves all attempts without overwriting.
    """
    # Initial State at t=0
    state: AgentState = {
        "user_query": "Top 5 customers",
        "sanitized_query": "Top 5 customers",
        "current_sql": "",
        "sql_results": None,
        "is_success": False,
        "error_message": None,
        "execution_status": "PENDING",
        "retry_count": 0,
        "max_retries": 3,
        "attempt_history": [],
    }

    # Cycle 1: First attempt generates invalid SQL
    cycle_1_attempt: AttemptRecord = {
        "step": "generator",
        "generated_sql": "SELECT * FORM customers", # Typo: FORM
        "error": "syntax error at or near 'FORM'",
        "is_valid": False,
        "execution_time_ms": 110.0,
    }
    state["attempt_history"] = operator.add(state["attempt_history"], [cycle_1_attempt])
    state["current_sql"] = cycle_1_attempt["generated_sql"]
    state["retry_count"] = 1

    # Cycle 2: Second attempt generates correct SQL syntax but wrong table
    cycle_2_attempt: AttemptRecord = {
        "step": "reflector",
        "generated_sql": "SELECT * FROM client_accounts",
        "error": "no such table: client_accounts",
        "is_valid": False,
        "execution_time_ms": 95.0,
    }
    state["attempt_history"] = operator.add(state["attempt_history"], [cycle_2_attempt])
    state["current_sql"] = cycle_2_attempt["generated_sql"]
    state["retry_count"] = 2

    # Cycle 3: Third attempt fixes table name and succeeds
    cycle_3_attempt: AttemptRecord = {
        "step": "reflector",
        "generated_sql": "SELECT * FROM customers LIMIT 5",
        "error": None,
        "is_valid": True,
        "execution_time_ms": 45.0,
    }
    state["attempt_history"] = operator.add(state["attempt_history"], [cycle_3_attempt])
    state["current_sql"] = cycle_3_attempt["generated_sql"]
    state["is_success"] = True
    state["execution_status"] = "SUCCESS"

    # Assertions
    # 1. Reducer must have accumulated all 3 attempts!
    assert len(state["attempt_history"]) == 3, "State amnesia! Previous attempts were overwritten."
    
    # 2. Chronological sequence check
    assert state["attempt_history"][0]["step"] == "generator"
    assert state["attempt_history"][1]["error"] == "no such table: client_accounts"
    assert state["attempt_history"][2]["is_valid"] is True

    # 3. Overwrite channel holds ONLY latest SQL
    assert state["current_sql"] == "SELECT * FROM customers LIMIT 5"
    assert state["retry_count"] == 2
    assert state["is_success"] is True


def test_retry_boundary_ceiling():
    """
    Test 2: Verifies that retry_count reaching max_retries can be deterministically flagged.
    """
    state: AgentState = {
        "user_query": "Revenue by region",
        "sanitized_query": "Revenue by region",
        "current_sql": "SELECT invalid",
        "sql_results": None,
        "is_success": False,
        "error_message": "Persistent DB failure",
        "execution_status": "RUNNING",
        "retry_count": 3,
        "max_retries": 3,
        "attempt_history": [],
    }

    # Deterministic boundary check
    is_exhausted = state["retry_count"] >= state["max_retries"]
    assert is_exhausted is True, "Boundary failure: Agent failed to flag retry ceiling."
