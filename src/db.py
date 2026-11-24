import os
import sqlite3
import time
from typing import List, Dict, Any, Tuple, Optional
from src.guardrails.c_authorizer import EnterpriseCAuthorizer, default_c_authorizer
from src.guardrails.read_only_vault import EnterpriseReadOnlyVault, default_read_only_vault

def authorizer_callback(action: int, arg1: Optional[str], arg2: Optional[str], dbname: Optional[str], source: Optional[str]) -> int:
    """
    Defense-in-depth SQLite authorizer.
    Delegates to the EnterpriseCAuthorizer engine.
    """
    return default_c_authorizer.callback(action, arg1, arg2, dbname, source)

def get_db_connection(
    db_path: str = "data/ecommerce.db",
    read_only: bool = False,
    in_memory_clone: bool = False,
    timeout_ms: int = 5000
) -> sqlite3.Connection:
    """
    Returns an SQLite connection configured with defense-in-depth security.
    Uses EnterpriseReadOnlyVault for physical OS-level and engine-level isolation.
    """
    if in_memory_clone:
        if os.path.exists(db_path):
            return default_read_only_vault.create_ephemeral_sandbox(db_path, attach_c_authorizer=read_only)
        else:
            conn = sqlite3.connect(":memory:", uri=True)
            if read_only:
                conn.execute("PRAGMA query_only = ON;")
                conn.set_authorizer(authorizer_callback)
            return conn
    elif read_only:
        return default_read_only_vault.connect_physical_readonly(db_path, attach_c_authorizer=True)
    else:
        return sqlite3.connect(db_path)

def execute_query_safe(
    conn: sqlite3.Connection,
    sql: str,
    timeout_ms: int = 5000
) -> Tuple[List[Dict[str, Any]], List[str]]:
    """
    Executes a query with a per-query monotonic timeout deadline.
    Returns (list_of_row_dicts, column_names).
    """
    deadline = time.monotonic() + (timeout_ms / 1000.0)

    def check_deadline() -> int:
        if time.monotonic() > deadline:
            return 1  # Non-zero aborts the query with OperationalError
        return 0

    # Set progress handler to check every 100 opcodes
    conn.set_progress_handler(check_deadline, 100)

    try:
        cursor = conn.cursor()
        cursor.execute(sql)
        cols = [desc[0] for desc in cursor.description] if cursor.description else []
        rows = [dict(zip(cols, row)) for row in cursor.fetchall()]
        return rows, cols
    finally:
        # Reset progress handler so future queries don't inherit old deadline
        conn.set_progress_handler(None, 0)

def get_schema_ddl(conn: sqlite3.Connection, include_distinct_values: bool = True) -> str:
    """
    Extracts table schemas from sqlite_master and augments low-cardinality categorical
    columns with their exact distinct values to prevent casing/spelling traps.
    Also appends canonical enterprise business metric formulas.
    """
    cursor = conn.cursor()
    cursor.execute("SELECT name, sql FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%';")
    tables = cursor.fetchall()
    
    ddl_parts = [
        "-- ENTERPRISE DATA WAREHOUSE SCHEMA (SQLite Dialect)",
        "-- BUSINESS DEFINITIONS:",
        "-- Revenue = SUM(order_items.quantity * order_items.unit_price * (1.0 - COALESCE(order_items.discount_pct, 0.0)))",
        "-- Active/Valid Orders = orders WHERE status NOT IN ('CANCELLED', 'REFUNDED')",
        "-- Net Sales = Revenue of orders WHERE status IN ('DELIVERED', 'delivered', 'SHIPPED')",
        ""
    ]

    for table_name, create_sql in tables:
        ddl_parts.append(f"{create_sql};")
        
        if include_distinct_values:
            try:
                # Find TEXT columns
                cursor.execute(f"PRAGMA table_info({table_name});")
                columns = cursor.fetchall()
                for col in columns:
                    col_name, col_type = col[1], col[2]
                    if "TEXT" in col_type.upper() or "VARCHAR" in col_type.upper():
                        # Exclude freeform text or sensitive columns
                        if col_name.lower() in ("email", "full_name", "product_name", "password"):
                            continue
                        cursor.execute(f"SELECT DISTINCT {col_name} FROM {table_name} WHERE {col_name} IS NOT NULL LIMIT 12;")
                        distinct_vals = [r[0] for r in cursor.fetchall()]
                        if 1 <= len(distinct_vals) <= 10:
                            ddl_parts.append(f"-- DISTINCT VALUES for {table_name}.{col_name}: {distinct_vals}")
            except Exception:
                pass
        ddl_parts.append("")

    return "\n".join(ddl_parts).strip()