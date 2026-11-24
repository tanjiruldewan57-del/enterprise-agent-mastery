"""
Cognitive Reflexion & Self-Correction Engine (Topic 1.5)
=======================================================
Architecture: Verbal Reinforcement Reflexion Loop (NeurIPS 2023)
Compliance: Bounded Cyclic Self-Healing with Anti-Ping-Pong State Tracking
"""

import time
import sqlite3
from typing import Dict, Any, Callable, Optional, List
from dataclasses import dataclass
from src.state import AgentState, AttemptRecord
from src.baseline_v0 import clean_sql_output


@dataclass(frozen=True)
class ReflexionDiagnosis:
    """Structured diagnostic feedback produced by the Reflector agent."""
    root_cause: str
    failed_sql: str
    db_error: str
    prescribed_fix: str


def build_reflector_prompt(
    user_query: str,
    failed_sql: str,
    error_message: str,
    schema_ddl: str,
    past_attempts: List[Dict[str, Any]]
) -> str:
    """
    Constructs the diagnostic prompt for the Reflector (Critic).
    Enforces anti-apology and anti-ping-pong rules.
    """
    # Extract past failed queries to avoid ping-pong cycles
    past_failed_sqls = [
        att.get("generated_sql") for att in past_attempts 
        if att.get("generated_sql") and not att.get("is_valid")
    ]
    past_history_block = "\n".join(f"- Attempt: {s}" for s in past_failed_sqls) if past_failed_sqls else "None"

    return f"""You are a Database Debugging Specialist & SQL Critic.
A Text-to-SQL query failed against the database. Diagnose the exact root cause and prescribe a fix.

### DATABASE SCHEMA:
{schema_ddl}

### USER INTENT:
{user_query}

### FAILED SQL:
{failed_sql}

### DATABASE ERROR MESSAGE:
{error_message}

### PAST FAILED ATTEMPTS (DO NOT REPEAT THESE):
{past_history_block}

### INSTRUCTIONS:
1. Explain WHY the SQL failed based on the schema and error message.
2. Prescribe the exact table or column correction needed.
3. Do NOT apologize. Do NOT write pleasantries. Provide a concise, highly technical diagnosis.

DIAGNOSIS:"""


def build_healing_generator_prompt(
    user_query: str,
    schema_ddl: str,
    diagnosis: str,
    failed_sql: str
) -> str:
    """
    Constructs the correction prompt for the Generator, injecting the critic's diagnosis.
    """
    return f"""You are a precise SQLite SQL expert.
Your previous SQL query failed, and a database critic has provided diagnostic feedback.
Generate ONLY the corrected executable SQLite SQL query.

### DATABASE SCHEMA:
{schema_ddl}

### USER QUESTION:
{user_query}

### PREVIOUS FAILED SQL:
{failed_sql}

### CRITIC'S DIAGNOSTIC FEEDBACK:
{diagnosis}

### INSTRUCTIONS:
1. Follow the critic's prescribed fix to resolve the error.
2. Return ONLY the raw SQL query. Do NOT include markdown code blocks, explanations, or prose.

CORRECTED SQL:"""


def execute_self_healing_cycle(
    db_path: str,
    user_query: str,
    schema_ddl: str,
    generator_fn: Callable[[str], str],
    reflector_fn: Callable[[str], str],
    max_retries: int = 3
) -> AgentState:
    """
    Executes a bounded Cognitive Reflexion loop (Generator -> Evaluator -> Reflector).
    Terminates on SUCCESS or when max_retries is reached.
    """
    state: AgentState = {
        "user_query": user_query,
        "sanitized_query": user_query,
        "current_sql": "",
        "sql_results": None,
        "is_success": False,
        "error_message": None,
        "execution_status": "RUNNING",
        "retry_count": 0,
        "max_retries": max_retries,
        "attempt_history": [],
    }

    current_prompt = f"""You are a precise SQLite SQL expert.
Generate ONLY an executable SQLite SQL query for:
Schema:
{schema_ddl}

Question:
{user_query}

SQL:"""

    latest_diagnosis: Optional[str] = None

    while state["retry_count"] < state["max_retries"]:
        start_time = time.perf_counter()
        
        # 1. Generator Actor generates/corrects SQL
        raw_sql_response = generator_fn(current_prompt)
        current_sql = clean_sql_output(raw_sql_response)
        state["current_sql"] = current_sql

        # 2. Evaluator Environment executes in Sandboxed DB
        db_success = False
        db_error: Optional[str] = None
        db_results: Optional[List[Dict[str, Any]]] = None

        try:
            conn = sqlite3.connect(f"file:{db_path}?mode=ro", uri=True)
            conn.row_factory = sqlite3.Row
            cursor = conn.cursor()
            cursor.execute(current_sql)
            rows = cursor.fetchall()
            db_results = [dict(row) for row in rows]
            db_success = True
            conn.close()
        except Exception as exc:
            db_success = False
            db_error = str(exc)

        duration_ms = (time.perf_counter() - start_time) * 1000

        # Record Attempt immutably
        attempt: AttemptRecord = {
            "step": "generator" if state["retry_count"] == 0 else "reflector_retry",
            "generated_sql": current_sql,
            "error": db_error,
            "is_valid": db_success,
            "execution_time_ms": round(duration_ms, 2)
        }
        state["attempt_history"].append(attempt)

        # 3. Decision Gate
        if db_success:
            state["is_success"] = True
            state["sql_results"] = db_results
            state["error_message"] = None
            state["execution_status"] = "SUCCESS"
            return state

        # If Failed: Increment retry and trigger Reflector Critic
        state["retry_count"] += 1
        state["error_message"] = db_error

        # 4. Reflector Critic produces diagnosis
        reflector_prompt = build_reflector_prompt(
            user_query=user_query,
            failed_sql=current_sql,
            error_message=db_error,
            schema_ddl=schema_ddl,
            past_attempts=state["attempt_history"]
        )
        latest_diagnosis = reflector_fn(reflector_prompt)

        # 5. Prepare prompt for next generator turn with corrective feedback
        current_prompt = build_healing_generator_prompt(
            user_query=user_query,
            schema_ddl=schema_ddl,
            diagnosis=latest_diagnosis,
            failed_sql=current_sql
        )

    # If loop exits without success, mark as FAILED_MAX_RETRIES
    state["execution_status"] = "FAILED_MAX_RETRIES"
    state["is_success"] = False
    return state


class ReflexionEngine:
    """Enterprise class wrapper for the cognitive reflexion self-healing loop."""

    @staticmethod
    def build_diagnosis_prompt(
        user_query: str,
        failed_sql: str,
        error_message: str,
        schema_ddl: str,
        past_attempts: List[Dict[str, Any]]
    ) -> str:
        return build_reflector_prompt(user_query, failed_sql, error_message, schema_ddl, past_attempts)

    @staticmethod
    def execute(
        state: AgentState,
        generator_fn: Callable[[str], str],
        reflector_fn: Callable[[str], str],
        db_path: str,
        schema_ddl: str,
        max_retries: int = 3
    ) -> AgentState:
        return execute_self_healing_cycle(state, generator_fn, reflector_fn, db_path, schema_ddl, max_retries)

