import re
from typing import Tuple, Optional
import sqlglot
from sqlglot import exp
from sqlglot.errors import ParseError

ALLOWED_ANONYMOUS_FUNCTIONS = {
    "strftime", "julianday", "date", "time", "datetime",
    "ifnull", "coalesce", "lower", "upper", "group_concat",
    "substr", "trim", "abs", "round", "nullif", "length",
    "replace", "char", "hex", "random", "printf"
}

DANGEROUS_FUNCTIONS = {
    "load_extension", "readfile", "writefile", "edit"
}

FORBIDDEN_EXPRESSIONS = (
    exp.Insert,
    exp.Update,
    exp.Delete,
    exp.Drop,
    exp.Alter,
    exp.Command,
    exp.Pragma,
    exp.Create
)

SENSITIVE_COLUMNS = {"email", "password", "token", "secret"}

def validate_and_sanitize_sql(
    sql_query: str,
    dialect: str = "sqlite"
) -> Tuple[bool, str, Optional[str], Optional[str]]:
    """
    Validates and sanitizes a SQL query using sqlglot AST parsing.
    Returns: (is_safe, category, sanitized_sql, reason)
    where category in {"VALID_SELECT", "SYNTAX_ERROR", "DESTRUCTIVE_MUTATION", "DATA_EXFILTRATION"}
    """
    cleaned_sql = sql_query.strip()
    if not cleaned_sql:
        return False, "SYNTAX_ERROR", None, "Empty SQL query."

    # 1. Parse AST
    try:
        statements = sqlglot.parse(cleaned_sql, read=dialect)
    except ParseError as e:
        return False, "SYNTAX_ERROR", None, f"SQL Parse Error: {str(e)}"
    except Exception as e:
        return False, "SYNTAX_ERROR", None, f"Syntax Analysis Error: {str(e)}"

    if not statements or statements[0] is None:
        return False, "SYNTAX_ERROR", None, "Unable to parse valid SQL statement."

    # Prevent multi-statement batch injection (e.g. SELECT 1; DROP TABLE orders;)
    if len(statements) > 1:
        return False, "DESTRUCTIVE_MUTATION", None, "Multiple SQL statements detected (batch queries prohibited)."

    stmt = statements[0]

    # 2. Check Root Statement Type: Must be Select or Union (including CTEs)
    if not isinstance(stmt, (exp.Select, exp.Union)):
        return False, "DESTRUCTIVE_MUTATION", None, f"Disallowed root statement type: {stmt.key}"

    # 3. Traverse entire AST for forbidden mutation nodes
    for node in stmt.find_all(exp.Expression):
        if isinstance(node, FORBIDDEN_EXPRESSIONS):
            return False, "DESTRUCTIVE_MUTATION", None, f"Disallowed DDL/DML operation: {type(node).__name__}"

        # Function check
        if isinstance(node, exp.Anonymous):
            fn_name = node.name.lower() if node.name else ""
            if fn_name in DANGEROUS_FUNCTIONS:
                return False, "DESTRUCTIVE_MUTATION", None, f"Dangerous function blocked: {fn_name}"
            if fn_name and fn_name not in ALLOWED_ANONYMOUS_FUNCTIONS:
                return False, "DESTRUCTIVE_MUTATION", None, f"Unrecognized/forbidden function call: {fn_name}"

        # Sensitive Column / Exfiltration check
        if isinstance(node, exp.Column):
            col_name = node.name.lower() if node.name else ""
            if col_name in SENSITIVE_COLUMNS:
                return False, "DATA_EXFILTRATION", None, f"Access to sensitive column '{col_name}' is prohibited."

    # 4. AST Limit Injection & Clamping (Capped at 100 directly in AST)
    current_limit = stmt.args.get("limit")
    if current_limit and hasattr(current_limit, "expression"):
        val_node = current_limit.expression
        if isinstance(val_node, exp.Literal) and val_node.is_number:
            try:
                val = int(val_node.this)
                if val > 100:
                    stmt = stmt.limit(100)
            except ValueError:
                stmt = stmt.limit(100)
        elif val_node is not None:
            stmt = stmt.limit(100)
    else:
        stmt = stmt.limit(100)

    # Compile sanitized query back to dialect SQL string
    sanitized_sql = stmt.sql(dialect=dialect)
    return True, "VALID_SELECT", sanitized_sql, None