"""
Enterprise Abstract Syntax Tree (AST) SQL Validator & Sanitizer (Topic 3.3)
=============================================================================
Compliance: Defense-in-Depth SQL Validation, Resource Exhaustion Guard (OOM)
Architecture:
  - Compiler Syntax Tree Deconstruction via SQLGlot
  - Strict Single-Statement Enforcement (Piggyback Semicolon Defense)
  - Whitelisted Root Operations (Only exp.Select / exp.Union)
  - Deep Tree Traversal (Prohibits Nested DDL/DML in CTEs or Subqueries)
  - Resource Protection: Deterministic LIMIT Clamping (Ceiling: 100)
"""

import time
from typing import List, Optional, Set, Dict, Any, Tuple
from dataclasses import dataclass, field
import sqlglot
import sqlglot.expressions as exp
from sqlglot.errors import ParseError


@dataclass(frozen=True)
class ASTValidationResult:
    """Immutable audit record and sanitized representation of the validated SQL query."""
    is_valid: bool
    sanitized_sql: Optional[str]
    original_sql: str
    violations: List[str] = field(default_factory=list)
    was_clamped: bool = False
    applied_limit: Optional[int] = None
    ast_root_type: Optional[str] = None
    tables_referenced: List[str] = field(default_factory=list)
    latency_ms: float = 0.0


class EnterpriseASTSQLValidator:
    """
    Production-grade Abstract Syntax Tree (AST) SQL Validator.
    Inspects queries at the syntactic compiler level before database execution.
    """

    PROHIBITED_EXPRESSIONS: Tuple[type, ...] = (
        exp.Insert,
        exp.Update,
        exp.Delete,
        exp.Drop,
        exp.Create,
        exp.Alter,
        exp.Command,
        exp.Pragma,
    )

    DEFAULT_DISALLOWED_TABLES: Set[str] = {
        "sqlite_master",
        "sqlite_temp_master",
        "sqlite_sequence",
        "sqlite_stat1",
        "sqlite_stat4",
        "admin_credentials",
        "secret_vault",
    }

    def __init__(
        self,
        dialect: str = "sqlite",
        max_limit: int = 100,
        enforce_single_statement: bool = True,
        disallowed_tables: Optional[Set[str]] = None
    ):
        self.dialect = dialect
        self.max_limit = max_limit
        self.enforce_single_statement = enforce_single_statement
        self.disallowed_tables = {
            t.lower() for t in (disallowed_tables or self.DEFAULT_DISALLOWED_TABLES)
        }

    def validate_and_sanitize(self, sql_query: str) -> ASTValidationResult:
        """
        Deconstructs SQL query into an AST, validates syntactic security policies,
        clamps unbounded LIMITs, and returns sanitized executable SQL.
        """
        start_t = time.perf_counter()
        raw_sql = sql_query.strip() if sql_query else ""

        # 1. Empty Check
        if not raw_sql:
            elapsed = (time.perf_counter() - start_t) * 1000.0
            return ASTValidationResult(
                is_valid=False,
                sanitized_sql=None,
                original_sql=sql_query,
                violations=["EMPTY_QUERY_STRING"],
                latency_ms=elapsed
            )

        # 2. Parse into Syntax Tree
        try:
            statements = sqlglot.parse(raw_sql, read=self.dialect)
        except ParseError as e:
            elapsed = (time.perf_counter() - start_t) * 1000.0
            return ASTValidationResult(
                is_valid=False,
                sanitized_sql=None,
                original_sql=raw_sql,
                violations=[f"MALFORMED_SQL_SYNTAX: {str(e)[:100]}"],
                latency_ms=elapsed
            )

        # Filter out empty or whitespace statements
        active_statements = [s for s in statements if s is not None]
        if not active_statements:
            elapsed = (time.perf_counter() - start_t) * 1000.0
            return ASTValidationResult(
                is_valid=False,
                sanitized_sql=None,
                original_sql=raw_sql,
                violations=["NO_ACTIONABLE_SQL_EXPRESSIONS"],
                latency_ms=elapsed
            )

        # 3. Single-Statement Policy (Piggyback Semicolon Defense)
        if self.enforce_single_statement and len(active_statements) > 1:
            elapsed = (time.perf_counter() - start_t) * 1000.0
            detected_types = [type(s).__name__ for s in active_statements]
            return ASTValidationResult(
                is_valid=False,
                sanitized_sql=None,
                original_sql=raw_sql,
                violations=[
                    f"MULTI_STATEMENT_PIGGYBACK_DETECTED: Query contains {len(active_statements)} chained statements ({', '.join(detected_types)})"
                ],
                latency_ms=elapsed
            )

        ast = active_statements[0]
        root_type = type(ast).__name__
        violations: List[str] = []

        # 4. Root Operation Policy (Must be Select or Union)
        if not isinstance(ast, (exp.Select, exp.Union)):
            elapsed = (time.perf_counter() - start_t) * 1000.0
            return ASTValidationResult(
                is_valid=False,
                sanitized_sql=None,
                original_sql=raw_sql,
                violations=[f"MUTATION_STATEMENT_FORBIDDEN: Root operator '{root_type}' is not a read query"],
                ast_root_type=root_type,
                latency_ms=elapsed
            )

        # 5. Deep AST Traversal (Verify no nested mutations in subqueries or CTEs)
        for node in ast.walk():
            if isinstance(node, self.PROHIBITED_EXPRESSIONS):
                violations.append(
                    f"NESTED_MUTATION_EXPRESSION_DETECTED: Forbidden '{type(node).__name__}' found inside query AST"
                )

        # 6. Table Access Enforcement (Detect sensitive or internal catalog tables)
        tables_found: Set[str] = set()
        for table_node in ast.find_all(exp.Table):
            t_name = table_node.name.lower() if table_node.name else ""
            if t_name:
                tables_found.add(t_name)
                if t_name in self.disallowed_tables:
                    violations.append(f"DISALLOWED_TABLE_ACCESS: Access to protected table '{t_name}' is forbidden")

        if violations:
            elapsed = (time.perf_counter() - start_t) * 1000.0
            return ASTValidationResult(
                is_valid=False,
                sanitized_sql=None,
                original_sql=raw_sql,
                violations=violations,
                ast_root_type=root_type,
                tables_referenced=sorted(list(tables_found)),
                latency_ms=elapsed
            )

        # 7. Deterministic LIMIT Clamping (Resource Exhaustion / OOM Defense)
        was_clamped = False
        applied_limit = self.max_limit

        limit_node = ast.args.get("limit")
        if limit_node is not None and limit_node.expression is not None:
            try:
                current_limit = int(limit_node.expression.this)
                if current_limit > self.max_limit:
                    limit_node.set("expression", exp.Literal.number(self.max_limit))
                    was_clamped = True
                    applied_limit = self.max_limit
                else:
                    applied_limit = current_limit
            except (ValueError, TypeError, AttributeError):
                # If LIMIT is an unparseable expression, clamp safely to ceiling
                limit_node.set("expression", exp.Literal.number(self.max_limit))
                was_clamped = True
                applied_limit = self.max_limit
        else:
            # Query has no LIMIT: Inject LIMIT ceiling
            ast = ast.limit(self.max_limit)
            was_clamped = True
            applied_limit = self.max_limit

        # 8. Render Clean Sanitized SQL
        sanitized_sql = ast.sql(dialect=self.dialect)
        elapsed = (time.perf_counter() - start_t) * 1000.0

        return ASTValidationResult(
            is_valid=True,
            sanitized_sql=sanitized_sql,
            original_sql=raw_sql,
            violations=[],
            was_clamped=was_clamped,
            applied_limit=applied_limit,
            ast_root_type=root_type,
            tables_referenced=sorted(list(tables_found)),
            latency_ms=elapsed
        )


# Global Default AST Validator Instance
default_ast_validator = EnterpriseASTSQLValidator()
