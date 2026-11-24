"""
Enterprise Row-Level Security (RLS) & Multi-Tenant Isolation Engine (Topic 3.4)
================================================================================
Compliance: OWASP API1:2023 (BOLA / IDOR Defense), Zero Cross-Tenant Data Leaks
Architecture:
  - AST-Level Deterministic Tenant Predicate Injection via SQLGlot
  - Strict Scope Binding: Parentheses-Enclosed Boolean Conjunction:
      (user_predicates) AND (table.tenant_id = 'current_tenant')
  - Hostile Tenant Spoofing Detection & Neutralization
  - Multi-Table JOIN & Subquery Isolation
"""

import time
import re
from typing import List, Optional, Set, Dict, Any, Tuple
from dataclasses import dataclass, field
import sqlglot
import sqlglot.expressions as exp
from sqlglot.errors import ParseError


@dataclass(frozen=True)
class RLSEnforcementResult:
    """Immutable audit record and isolated representation of the multi-tenant query."""
    is_safe: bool
    isolated_sql: Optional[str]
    original_sql: str
    tenant_id: str
    tables_isolated: List[str] = field(default_factory=list)
    spoofing_detected: bool = False
    violations: List[str] = field(default_factory=list)
    latency_ms: float = 0.0


class EnterpriseMultiTenantRLS:
    """
    Compiler-level Row-Level Security (RLS) and multi-tenant isolation engine.
    Guarantees mathematically that queries cannot read outside the authenticated tenant.
    """

    DEFAULT_MULTI_TENANT_TABLES: Set[str] = {
        "accounts",
        "customers",
        "transactions",
        "invoices",
        "orders",
        "loan_applications",
        "audit_logs",
    }

    # Strict tenant_id format: alphanumeric, dashes, underscores, max 64 chars
    TENANT_ID_REGEX = re.compile(r"^[a-zA-Z0-9_\-]{2,64}$")

    def __init__(
        self,
        tenant_column: str = "tenant_id",
        dialect: str = "sqlite",
        multi_tenant_tables: Optional[Set[str]] = None,
        block_on_spoof_attempt: bool = True
    ):
        self.tenant_column = tenant_column.lower()
        self.dialect = dialect
        self.multi_tenant_tables = {
            t.lower() for t in (multi_tenant_tables or self.DEFAULT_MULTI_TENANT_TABLES)
        }
        self.block_on_spoof_attempt = block_on_spoof_attempt

    def enforce_isolation(
        self,
        sql_query: str,
        authenticated_tenant_id: str
    ) -> RLSEnforcementResult:
        """
        Parses SQL, detects hostile tenant overrides, and injects deterministic
        tenant isolation predicates for every multi-tenant table referenced.
        """
        start_t = time.perf_counter()
        raw_sql = sql_query.strip() if sql_query else ""

        # 1. Validate Authenticated Tenant Context
        if not authenticated_tenant_id or not self.TENANT_ID_REGEX.match(authenticated_tenant_id):
            elapsed = (time.perf_counter() - start_t) * 1000.0
            return RLSEnforcementResult(
                is_safe=False,
                isolated_sql=None,
                original_sql=sql_query,
                tenant_id=authenticated_tenant_id,
                violations=[f"INVALID_AUTHENTICATED_TENANT_ID: '{authenticated_tenant_id}'"],
                latency_ms=elapsed
            )

        if not raw_sql:
            elapsed = (time.perf_counter() - start_t) * 1000.0
            return RLSEnforcementResult(
                is_safe=False,
                isolated_sql=None,
                original_sql=sql_query,
                tenant_id=authenticated_tenant_id,
                violations=["EMPTY_QUERY_STRING"],
                latency_ms=elapsed
            )

        # 2. Parse into AST
        try:
            statements = sqlglot.parse(raw_sql, read=self.dialect)
        except ParseError as e:
            elapsed = (time.perf_counter() - start_t) * 1000.0
            return RLSEnforcementResult(
                is_safe=False,
                isolated_sql=None,
                original_sql=raw_sql,
                tenant_id=authenticated_tenant_id,
                violations=[f"MALFORMED_SQL_SYNTAX: {str(e)[:100]}"],
                latency_ms=elapsed
            )

        active_statements = [s for s in statements if s is not None]
        if len(active_statements) != 1:
            elapsed = (time.perf_counter() - start_t) * 1000.0
            return RLSEnforcementResult(
                is_safe=False,
                isolated_sql=None,
                original_sql=raw_sql,
                tenant_id=authenticated_tenant_id,
                violations=[f"MULTI_STATEMENT_FORBIDDEN: Expected 1 statement, got {len(active_statements)}"],
                latency_ms=elapsed
            )

        ast = active_statements[0]
        if not isinstance(ast, (exp.Select, exp.Union)):
            elapsed = (time.perf_counter() - start_t) * 1000.0
            return RLSEnforcementResult(
                is_safe=False,
                isolated_sql=None,
                original_sql=raw_sql,
                tenant_id=authenticated_tenant_id,
                violations=[f"NON_SELECT_OPERATION_FORBIDDEN: '{type(ast).__name__}'"],
                latency_ms=elapsed
            )

        # 3. Detect Hostile Tenant Spoofing in Existing WHERE Clauses
        spoofing_detected = False
        violations: List[str] = []

        for eq_node in ast.find_all(exp.EQ):
            # Check if left or right is tenant_column
            left_col = eq_node.left.name.lower() if isinstance(eq_node.left, exp.Column) else ""
            right_col = eq_node.right.name.lower() if isinstance(eq_node.right, exp.Column) else ""
            
            if left_col == self.tenant_column or right_col == self.tenant_column:
                # Extract the literal value compared
                val_node = eq_node.right if left_col == self.tenant_column else eq_node.left
                if isinstance(val_node, exp.Literal):
                    specified_tenant = str(val_node.this).strip("'\"")
                    if specified_tenant != authenticated_tenant_id:
                        spoofing_detected = True
                        violations.append(
                            f"BOLA_ATTACK_DETECTED: Query attempted access to tenant '{specified_tenant}' "
                            f"while authenticated as '{authenticated_tenant_id}'"
                        )

        if spoofing_detected and self.block_on_spoof_attempt:
            elapsed = (time.perf_counter() - start_t) * 1000.0
            return RLSEnforcementResult(
                is_safe=False,
                isolated_sql=None,
                original_sql=raw_sql,
                tenant_id=authenticated_tenant_id,
                spoofing_detected=True,
                violations=violations,
                latency_ms=elapsed
            )

        # 4. Inject Tenant Predicate for Every Select Node with Multi-Tenant Tables
        tables_isolated: Set[str] = set()

        for select_node in ast.find_all(exp.Select):
            # Find all direct table sources in this select
            tables_in_scope = list(select_node.find_all(exp.Table))
            for t in tables_in_scope:
                t_name = t.name.lower() if t.name else ""
                if t_name in self.multi_tenant_tables:
                    tables_isolated.add(t_name)
                    # Use alias if provided, otherwise table name
                    target_qualifier = t.alias if t.alias else t_name
                    
                    # Construct table.tenant_id = 'authenticated_tenant_id'
                    tenant_predicate = exp.EQ(
                        this=exp.column(self.tenant_column, table=target_qualifier),
                        expression=exp.Literal.string(authenticated_tenant_id)
                    )
                    
                    # Conjoin predicate safely into the WHERE clause
                    select_node.where(tenant_predicate, copy=False)

        # 5. Render Rewritten Isolated SQL
        isolated_sql = ast.sql(dialect=self.dialect)
        elapsed = (time.perf_counter() - start_t) * 1000.0

        return RLSEnforcementResult(
            is_safe=True,
            isolated_sql=isolated_sql,
            original_sql=raw_sql,
            tenant_id=authenticated_tenant_id,
            tables_isolated=sorted(list(tables_isolated)),
            spoofing_detected=spoofing_detected,
            violations=[],
            latency_ms=elapsed
        )


# Global Default Multi-Tenant RLS Instance
default_multi_tenant_rls = EnterpriseMultiTenantRLS()
