"""
Adversarial Unit Tests for Single-Pass Baseline Engine (Topic 1.3)
=================================================================
Validates:
  1. Markdown cleaning and conversational fluff stripping.
  2. Multilingual intent handling and execution.
  3. Graceful exception containment (no unhandled server crashes).
"""

import os
import pytest
from src.baseline_v0 import clean_sql_output, run_baseline_v0, build_baseline_prompt


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


def test_v0_single_pass_success(test_db_path, mock_schema):
    """
    Test 1: Model returns markdown code fence with conversational prefix.
    Verifies regex cleaning and clean database execution.
    """
    messy_llm_response = """
    Here is the SQL Query:
    ```sql
    SELECT COUNT(*) as total FROM products;
    ```
    """
    mock_llm = lambda prompt: messy_llm_response

    state = run_baseline_v0(
        db_path=test_db_path,
        user_query="How many total products exist?",
        schema_ddl=mock_schema,
        llm_callable=mock_llm
    )

    assert state["current_sql"] == "SELECT COUNT(*) as total FROM products"
    assert state["is_success"] is True
    assert state["execution_status"] == "SUCCESS"
    assert state["sql_results"] is not None
    assert len(state["sql_results"]) == 1
    assert len(state["attempt_history"]) == 1
    assert state["attempt_history"][0]["is_valid"] is True


def test_v0_single_pass_bengali_detection(test_db_path, mock_schema):
    """
    Test 2: Verifies multilingual prompt wrapping and clean execution.
    """
    bengali_query = "আমাদের মোট কয়টি প্রোডাক্ট আছে?"
    prompt = build_baseline_prompt(mock_schema, bengali_query)
    
    assert "Bengali, or Banglish" in prompt
    assert bengali_query in prompt

    mock_llm = lambda p: "SELECT COUNT(*) as cnt FROM products"
    state = run_baseline_v0(
        db_path=test_db_path,
        user_query=bengali_query,
        schema_ddl=mock_schema,
        llm_callable=mock_llm
    )

    assert state["is_success"] is True
    assert state["sql_results"][0]["cnt"] > 0


def test_v0_single_pass_fails_without_retry(test_db_path, mock_schema):
    """
    Test 3: Model hallucinates a non-existent column.
    Verifies exception containment without unhandled crash, and no retry.
    """
    hallucinated_sql = "SELECT non_existent_col FROM products"
    mock_llm = lambda p: hallucinated_sql

    state = run_baseline_v0(
        db_path=test_db_path,
        user_query="Show secret columns",
        schema_ddl=mock_schema,
        llm_callable=mock_llm
    )

    assert state["is_success"] is False
    assert state["execution_status"] == "FAILED"
    assert "no such column: non_existent_col" in state["error_message"]
    assert state["retry_count"] == 0
    assert len(state["attempt_history"]) == 1
