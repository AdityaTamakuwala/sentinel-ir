"""Safe template interpolation and condition evaluation for declarative playbooks."""

from __future__ import annotations

import re
from typing import Any


def resolve_dotted_path(target: Any, path: str) -> Any:
    """Resolve a dot-separated path (e.g. 'incident.parameters.source_ip') from a context object/dict."""
    if not path:
        return ""

    parts = path.strip().split(".")
    current = target

    for part in parts:
        if current is None:
            return ""

        if isinstance(current, dict):
            current = current.get(part)
        elif hasattr(current, part):
            current = getattr(current, part)
        else:
            return ""

    return current if current is not None else ""


_TEMPLATE_PATTERN = re.compile(r"\{\{\s*([a-zA-Z0-9_\.]+)\s*\}\}")


def render_template(val: Any, context: dict[str, Any]) -> Any:
    """Recursively render template expressions `{{ var.path }}` in strings, lists, or dicts."""
    if isinstance(val, str):
        # If the string is EXACTLY a single template expression "{{ foo.bar }}", preserve native type (int, bool, dict, etc.)
        match = _TEMPLATE_PATTERN.fullmatch(val.strip())
        if match:
            expression = match.group(1)
            resolved = resolve_dotted_path(context, expression)
            return resolved

        # Otherwise replace all occurrences inside string
        def replace_match(m: re.Match[str]) -> str:
            resolved = resolve_dotted_path(context, m.group(1))
            return str(resolved) if resolved is not None else ""

        return _TEMPLATE_PATTERN.sub(replace_match, val)

    elif isinstance(val, dict):
        return {k: render_template(v, context) for k, v in val.items()}

    elif isinstance(val, list):
        return [render_template(item, context) for item in val]

    return val


def evaluate_condition(condition_str: str | None, context: dict[str, Any]) -> bool:
    """Safely evaluate a step condition expression against the context.

    Supported patterns:
    - None or empty string -> True
    - "a == b", "a != b", "a in b", "a > b", "a >= b", "a < b", "a <= b"
    - boolean literals "true", "false"
    """
    if not condition_str or not condition_str.strip():
        return True

    expr = condition_str.strip()
    if expr.lower() == "true":
        return True
    if expr.lower() == "false":
        return False

    # Check comparison operators: ==, !=, >=, <=, >, <, in
    operators = ["==", "!=", ">=", "<=", ">", "<", " in "]
    for op in operators:
        if op in expr:
            left_raw, right_raw = expr.split(op, 1)
            left_val = render_template(f"{{{{ {left_raw.strip()} }}}}", context)
            right_val = render_template(f"{{{{ {right_raw.strip()} }}}}", context)

            # Strip string quotes if present
            if isinstance(left_val, str) and left_val.startswith(("'", '"')) and left_val.endswith(("'", '"')):
                left_val = left_val[1:-1]
            if isinstance(right_val, str) and right_val.startswith(("'", '"')) and right_val.endswith(("'", '"')):
                right_val = right_val[1:-1]

            # Try numeric comparison if applicable
            try:
                left_num = float(left_val)  # type: ignore[arg-type]
                right_num = float(right_val)  # type: ignore[arg-type]
                left_val, right_val = left_num, right_num
            except (ValueError, TypeError):
                pass

            op_clean = op.strip()
            if op_clean == "==":
                return bool(str(left_val).lower() == str(right_val).lower() if isinstance(left_val, str) else left_val == right_val)
            elif op_clean == "!=":
                return bool(left_val != right_val)
            elif op_clean == ">=":
                return bool(left_val >= right_val)  # type: ignore[operator]
            elif op_clean == "<=":
                return bool(left_val <= right_val)  # type: ignore[operator]
            elif op_clean == ">":
                return bool(left_val > right_val)  # type: ignore[operator]
            elif op_clean == "<":
                return bool(left_val < right_val)  # type: ignore[operator]
            elif op_clean == "in":
                return bool(str(left_val) in str(right_val))

    # Single variable truthiness
    val = render_template(f"{{{{ {expr} }}}}", context)
    return bool(val)

