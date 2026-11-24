"""
Enterprise C-Level Database Authorizer & VDBE Interceptor (Topic 3.1)
=====================================================================
Compliance: Zero-Trust Database Access, Principle of Least Privilege (PoLP)
Architecture: C-Level Engine Hook for Granular Column-Level Read Enforcement
"""

import sqlite3
import time
from typing import Dict, Any, List, Optional, Set, Tuple
from dataclasses import dataclass, field


# Human-readable mapping of SQLite C-Action Opcodes
SQLITE_ACTION_NAMES: Dict[int, str] = {
    1: "SQLITE_CREATE_INDEX",
    2: "SQLITE_CREATE_TABLE",
    3: "SQLITE_CREATE_TEMP_INDEX",
    4: "SQLITE_CREATE_TEMP_TABLE",
    5: "SQLITE_CREATE_TEMP_TRIGGER",
    6: "SQLITE_CREATE_TEMP_VIEW",
    7: "SQLITE_CREATE_TRIGGER",
    8: "SQLITE_CREATE_VIEW",
    9: "SQLITE_DELETE",
    10: "SQLITE_DROP_INDEX",
    11: "SQLITE_DROP_TABLE",
    12: "SQLITE_DROP_TEMP_INDEX",
    13: "SQLITE_DROP_TEMP_TABLE",
    14: "SQLITE_DROP_TEMP_TRIGGER",
    15: "SQLITE_DROP_TEMP_VIEW",
    16: "SQLITE_DROP_TRIGGER",
    17: "SQLITE_DROP_VIEW",
    18: "SQLITE_INSERT",
    19: "SQLITE_PRAGMA",
    20: "SQLITE_READ",
    21: "SQLITE_SELECT",
    22: "SQLITE_TRANSACTION",
    23: "SQLITE_UPDATE",
    24: "SQLITE_ATTACH",
    25: "SQLITE_DETACH",
    26: "SQLITE_ALTER_TABLE",
    27: "SQLITE_REINDEX",
    28: "SQLITE_ANALYZE",
    29: "SQLITE_CREATE_VTABLE",
    30: "SQLITE_DROP_VTABLE",
    31: "SQLITE_FUNCTION",
    32: "SQLITE_SAVEPOINT",
    33: "SQLITE_RECURSIVE",
}


@dataclass(frozen=True)
class AuthorizerDecision:
    """Immutable audit record for every action inspected by the C-Authorizer."""
    action_code: int
    action_name: str
    target_table: Optional[str]
    target_column_or_fn: Optional[str]
    is_allowed: bool
    decision_code: int  # sqlite3.SQLITE_OK (0) or sqlite3.SQLITE_DENY (1)
    timestamp: float


class EnterpriseCAuthorizer:
    """
    Sub-millisecond Deterministic C-Level Database Security Guard.
    Plugs directly into the SQLite Virtual Database Engine (VDBE).
    """

    DEFAULT_RESTRICTED_COLUMNS: Set[str] = {
        "email", "password", "password_hash", "salt", "secret",
        "token", "ssn", "credit_card", "api_key", "pin", "auth_key"
    }

    DANGEROUS_FUNCTIONS: Set[str] = {
        "load_extension", "readfile", "writefile", "system", "shell"
    }

    SAFE_READ_PRAGMAS: Set[str] = {
        "query_only", "table_info", "database_list", "table_xinfo",
        "trusted_schema", "schema_version", "foreign_key_list"
    }

    def __init__(
        self,
        restricted_columns: Optional[Set[str]] = None,
        allow_mutations: bool = False
    ):
        self.restricted_columns = {
            col.lower() for col in (restricted_columns or self.DEFAULT_RESTRICTED_COLUMNS)
        }
        self.allow_mutations = allow_mutations
        self._audit_log: List[AuthorizerDecision] = []

    def callback(
        self,
        action: int,
        arg1: Optional[str],
        arg2: Optional[str],
        dbname: Optional[str],
        source: Optional[str]
    ) -> int:
        """
        C-Level Engine Hook invoked for every opcode during SQL compilation.
        
        Parameters:
          action: SQLite Action Code (e.g. SQLITE_READ = 20, SQLITE_INSERT = 18)
          arg1: First argument (often table name or target name)
          arg2: Second argument (often column name or function name)
          dbname: Database name (main, temp)
          source: Inner context / trigger name
          
        Returns:
          sqlite3.SQLITE_OK (0): Operation permitted.
          sqlite3.SQLITE_DENY (1): Operation aborted; throws DatabaseError.
          sqlite3.SQLITE_IGNORE (2): Column read treated as NULL (silently suppressed).
        """
        now = time.time()
        action_name = SQLITE_ACTION_NAMES.get(action, f"UNKNOWN_ACTION_{action}")

        # 1. Allowed Read Actions Whitelist
        if action in (
            sqlite3.SQLITE_SELECT,
            sqlite3.SQLITE_READ,
            sqlite3.SQLITE_FUNCTION,
            sqlite3.SQLITE_RECURSIVE,
            sqlite3.SQLITE_PRAGMA
        ):
            # Check Column-Level Restrictions on SQLITE_READ
            if action == sqlite3.SQLITE_READ:
                # arg1 is table_name, arg2 is column_name
                if arg2 and arg2.lower() in self.restricted_columns:
                    self._record(action, action_name, arg1, arg2, False, sqlite3.SQLITE_DENY, now)
                    return sqlite3.SQLITE_DENY

            # Check Function Whitelist (Prevent RCE and File System Access)
            elif action == sqlite3.SQLITE_FUNCTION:
                # arg2 is function name
                if arg2 and arg2.lower() in self.DANGEROUS_FUNCTIONS:
                    self._record(action, action_name, arg1, arg2, False, sqlite3.SQLITE_DENY, now)
                    return sqlite3.SQLITE_DENY

            # Check PRAGMA Safety (Allow read-only metadata introspection, block mutations)
            elif action == sqlite3.SQLITE_PRAGMA:
                # arg1 is pragma name, arg2 is pragma value (None when reading pragma)
                if not (arg1 and arg1.lower() in self.SAFE_READ_PRAGMAS and arg2 is None):
                    self._record(action, action_name, arg1, arg2, False, sqlite3.SQLITE_DENY, now)
                    return sqlite3.SQLITE_DENY

            self._record(action, action_name, arg1, arg2, True, sqlite3.SQLITE_OK, now)
            return sqlite3.SQLITE_OK

        # 2. Mutation & DDL Operations Gate
        if self.allow_mutations and action in (
            sqlite3.SQLITE_INSERT,
            sqlite3.SQLITE_UPDATE,
            sqlite3.SQLITE_TRANSACTION,
            sqlite3.SQLITE_SAVEPOINT
        ):
            self._record(action, action_name, arg1, arg2, True, sqlite3.SQLITE_OK, now)
            return sqlite3.SQLITE_OK

        # Default Zero-Trust Policy: Deny all unapproved actions (DROP, DELETE, ALTER, ATTACH, PRAGMA)
        self._record(action, action_name, arg1, arg2, False, sqlite3.SQLITE_DENY, now)
        return sqlite3.SQLITE_DENY

    def _record(
        self,
        code: int,
        name: str,
        table: Optional[str],
        col_or_fn: Optional[str],
        is_allowed: bool,
        decision_code: int,
        t: float
    ):
        """Records immutable audit decision."""
        self._audit_log.append(AuthorizerDecision(
            action_code=code,
            action_name=name,
            target_table=table,
            target_column_or_fn=col_or_fn,
            is_allowed=is_allowed,
            decision_code=decision_code,
            timestamp=t
        ))

    def attach_to_connection(self, conn: sqlite3.Connection):
        """Attaches the C-level authorizer hook directly to the database connection."""
        conn.set_authorizer(self.callback)

    def get_audit_trail(self) -> List[AuthorizerDecision]:
        """Returns copy of the session audit trail."""
        return list(self._audit_log)

    def clear_audit_trail(self):
        """Purges audit history."""
        self._audit_log.clear()


# Global Singleton for Read-Only Analysis
default_c_authorizer = EnterpriseCAuthorizer()
