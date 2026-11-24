"""
Deterministic Single-Pass Baseline Engine (V0)
==============================================
Architecture: Single-Pass Text-to-SQL without Self-Correction Loops
Purpose: Provides benchmark performance baseline (EX metric) and fast-path execution.
"""

import re
import time
import sqlite3
from typing import Dict, Any, Callable, Optional, List
from src.state import AgentState, AttemptRecord


def clean_sql_output(raw_llm_response: str) -> str:
    """
    Strips markdown code fences (```sql ... ```), surrounding quotes, 
    and leading/trailing conversational prose.
    """
    if not raw_llm_response:
        return ""

    text = raw_llm_response.strip()

    # 1. Extract content inside ```sql ... ``` or ``` ... ```
    code_block_match = re.search(r"```(?:sql)?\s*(.*?)\s*```", text, re.DOTALL | re.IGNORECASE)
    if code_block_match:
        text = code_block_match.group(1).strip()

    # 2. Remove common conversational lead-ins (e.g. "Here is the SQL:")
    text = re.sub(r"^(?:Here\s+is\s+the\s+(?:sql|query)|SQL\s+Query|Query)\s*:\s*", "", text, flags=re.IGNORECASE)

    # 3. Strip trailing semicolons and normalize whitespace
    text = text.rstrip(";").strip()
    return text


def build_baseline_prompt(schema_ddl: str, user_query: str) -> str:
    """
    Builds a strict, unambiguous prompt injecting schema DDL and handling multilingual intent.
    """
    return f"""You are a precise SQLite SQL expert.
Given the following database schema, generate ONLY an executable SQLite SQL query to answer the user question.

### DATABASE SCHEMA:
{schema_ddl}

### INSTRUCTIONS:
1. Return ONLY the raw SQL query. Do NOT include markdown code blocks, explanations, or prose.
2. The user query may be in English, Bengali, or Banglish. Correctly understand the analytical intent.
3. Use only the tables and columns present in the schema.

### USER QUESTION:
{user_query}

SQL:"""


def run_baseline_v0(
    db_path: str,
    user_query: str,
    schema_ddl: str,
    llm_callable: Callable[[str], str]
) -> AgentState:
    """
    Executes a single-pass Text-to-SQL baseline without retries.
    Returns a standardized AgentState snapshot.
    """
    start_time = time.perf_counter()
    prompt = build_baseline_prompt(schema_ddl, user_query)
    
    # 1. Call LLM
    raw_response = llm_callable(prompt)
    extracted_sql = clean_sql_output(raw_response)

    # 2. Execute SQL with defensive try-except
    is_success = False
    error_message: Optional[str] = None
    results: Optional[List[Dict[str, Any]]] = None

    try:
        conn = sqlite3.connect(f"file:{db_path}?mode=ro", uri=True)
        conn.row_factory = sqlite3.Row
        cursor = conn.cursor()
        cursor.execute(extracted_sql)
        rows = cursor.fetchall()
        results = [dict(row) for row in rows]
        is_success = True
        conn.close()
    except Exception as exc:
        is_success = False
        error_message = str(exc)

    duration_ms = (time.perf_counter() - start_time) * 1000

    # 3. Build Attempt Record
    attempt: AttemptRecord = {
        "step": "baseline_v0",
        "generated_sql": extracted_sql,
        "error": error_message,
        "is_valid": is_success,
        "execution_time_ms": round(duration_ms, 2),
    }

    # 4. Return Standardized AgentState
    return {
        "user_query": user_query,
        "sanitized_query": user_query,
        "current_sql": extracted_sql,
        "sql_results": results,
        "is_success": is_success,
        "error_message": error_message,
        "execution_status": "SUCCESS" if is_success else "FAILED",
        "retry_count": 0,
        "max_retries": 0,  # Single-pass has 0 retries
        "attempt_history": [attempt],
    }
