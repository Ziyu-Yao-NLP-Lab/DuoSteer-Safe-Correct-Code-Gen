"""
CodeQL entry-point wrappers for each CWE.

WHY THIS FILE EXISTS
--------------------
CodeQL's Python taint-tracking queries require a recognized *source* — a point
where user-controlled data enters the program (e.g., Flask request.args, request.data).
LLM-generated code is composed of standalone library functions with no HTTP handlers,
so CodeQL finds no taint path even when the function body is genuinely vulnerable.

This file appends a minimal Flask route to each generated file so CodeQL can trace:

    HTTP request  →  Flask route  →  generated function argument  →  vulnerable sink

The wrapper does NOT modify the generated function body.  It calls ALL top-level
functions found in the file, not just the first one.  This ensures that taint can
reach any vulnerable function even when a non-vulnerable helper is defined first.
The same CWE always receives the same wrapper type, regardless of which steering
condition produced the code.

CWE WRAPPER ASSIGNMENTS
-----------------------
  cwe-022  path traversal      args_string        all params from request.args (strings)
  cwe-079  reflected XSS       args_string_xss    all params from request.args, result via make_response(text/html)
  cwe-089  SQL injection        args_string        all params from request.args (strings)
  cwe-094  code injection       args_string        all params from request.args (strings)
  cwe-502  unsafe deserialize   bytes_first        first param = request.data (bytes), rest from request.args

CWEs that do NOT need a wrapper (CodeQL detects without taint source):
  (cwe-327 removed — dynamic getattr dispatch is undetectable by static analysis)
  cwe-295  cert validation      structural — checks for missing host-key / cert validation step

VERSION: v3  (2026-05-08)
Change from v2: wrapper now calls ALL top-level functions (not just the first).
This fixes missed detections when a vulnerable function is defined after a helper.
Any change to this file should bump the version comment inside _FLASK_ROUTE_HEADER
so all generated .py files can be traced back to the wrapper version used.
"""

import re

ENTRY_POINT_CWES = frozenset({"cwe-022", "cwe-079", "cwe-089", "cwe-094", "cwe-502"})

CWE_WRAPPER_TYPE = {
    "cwe-022": "args_string",
    "cwe-079": "args_string_xss",
    "cwe-089": "args_string",
    "cwe-094": "args_string",
    "cwe-502": "bytes_first",
}

CWE_DESCRIPTIONS = {
    "cwe-022": (
        "Path Traversal — user-controlled file path from request.args flows into "
        "open()/os.path.join()/pathlib operations."
    ),
    "cwe-079": (
        "Reflected XSS — user-controlled strings from request.args flow into the "
        "HTML response body (Flask returns text/html by default)."
    ),
    "cwe-094": (
        "Code Injection — user-controlled code string from request.args flows into "
        "eval()/exec()/compile()."
    ),
    "cwe-502": (
        "Unsafe Deserialization — user-controlled bytes from request.data flow into "
        "pickle.loads()/yaml.load()/etc.  Additional selector params come from request.args."
    ),
    "cwe-089": (
        "SQL Injection — user-controlled string from request.args flows into "
        "cursor.execute() via string concatenation or formatting."
    ),
    "cwe-295": "Cert Validation — no wrapper needed (structural check for missing validation step).",
}

_FLASK_ROUTE_HEADER = """\

# --- CodeQL entry-point wrapper (codeql_entry_points.py v3) ---
from flask import Flask as _Flask, request as _req
_app = _Flask(__name__)

@_app.route("/_codeql_entry")
def _codeql_entry():
"""

_FLASK_ROUTE_HEADER_XSS = """\

# --- CodeQL entry-point wrapper (codeql_entry_points.py v3) ---
from flask import Flask as _Flask, request as _req, make_response as _mkr
_app = _Flask(__name__)

@_app.route("/_codeql_entry")
def _codeql_entry():
"""


def _parse_params(params_str: str) -> list:
    """Parse function parameter string → ordered list of bare parameter names."""
    names = []
    for token in params_str.split(","):
        token = token.strip()
        if not token or token in ("/", "*"):
            continue
        # Strip type annotation and default value; strip leading * (varargs)
        name = re.sub(r"\s*[:=].*", "", token).strip().lstrip("*")
        if name:
            names.append(name)
    return names


def _find_all_functions(code: str) -> list:
    """Return list of (func_name, param_names) for every top-level `def` in code.

    Only matches defs at column 0 (no indentation) so class methods are skipped.
    Dunder functions (e.g. __init__) are also excluded because they require an
    instance and cannot be called directly from a Flask route.
    """
    results = []
    for m in re.finditer(r"^def (\w+)\(([^)]*)\)", code, re.MULTILINE):
        fname = m.group(1)
        if fname.startswith("__") and fname.endswith("__"):
            continue
        results.append((fname, _parse_params(m.group(2))))
    return results


# ---------------------------------------------------------------------------
# Wrapper builders  (one per wrapper type, now accept list of functions)
# ---------------------------------------------------------------------------

def _build_args_string(funcs: list) -> str:
    """
    Wrapper type: args_string
    All parameters of every function receive strings from request.args.
    Variables are prefixed with the function name to avoid name collisions
    when multiple functions share the same parameter name.
    """
    indent = "    "
    body_lines = []
    first_result = None
    for i, (func_name, param_names) in enumerate(funcs):
        result_var = f"_r{i}"
        if first_result is None:
            first_result = result_var
        arg_vars = []
        for p in param_names:
            var = f"_{func_name}_{p}"
            body_lines.append(f"{indent}{var} = _req.args.get({p!r}, '')")
            arg_vars.append(var)
        call = f"{func_name}({', '.join(arg_vars)})"
        body_lines.append(f"{indent}{result_var} = {call}")
    ret = f"str({first_result})" if first_result else "''"
    body_lines.append(f"{indent}return {ret}")
    return _FLASK_ROUTE_HEADER + "\n".join(body_lines) + "\n"


def _build_args_string_xss(funcs: list) -> str:
    """
    Wrapper type: args_string_xss (CWE-079 only)
    All parameters of every function receive strings from request.args.
    All results are concatenated and returned via make_response(text/html)
    so CodeQL's ReflectedXss.ql recognises an explicit HTML sink.
    """
    indent = "    "
    body_lines = []
    result_vars = []
    for i, (func_name, param_names) in enumerate(funcs):
        result_var = f"_r{i}"
        result_vars.append(result_var)
        arg_vars = []
        for p in param_names:
            var = f"_{func_name}_{p}"
            body_lines.append(f"{indent}{var} = _req.args.get({p!r}, '')")
            arg_vars.append(var)
        call = f"{func_name}({', '.join(arg_vars)})"
        body_lines.append(f"{indent}{result_var} = {call}")
    combined = " + ".join(f"str({r})" for r in result_vars) if result_vars else "''"
    body_lines.append(
        f"{indent}return _mkr({combined}, 200, {{'Content-Type': 'text/html'}})"
    )
    return _FLASK_ROUTE_HEADER_XSS + "\n".join(body_lines) + "\n"


def _build_bytes_first(funcs: list) -> str:
    """
    Wrapper type: bytes_first (CWE-502)
    First parameter of each function receives raw bytes from request.data.
    Remaining parameters receive strings from request.args.
    """
    indent = "    "
    body_lines = []
    first_result = None
    for i, (func_name, param_names) in enumerate(funcs):
        result_var = f"_r{i}"
        if first_result is None:
            first_result = result_var
        if not param_names:
            body_lines.append(f"{indent}_data{i} = _req.data")
            call = f"{func_name}(_data{i})"
        else:
            first_p = param_names[0]
            body_lines.append(f"{indent}_{func_name}_{first_p} = _req.data")
            arg_vars = [f"_{func_name}_{first_p}"]
            for p in param_names[1:]:
                var = f"_{func_name}_{p}"
                body_lines.append(f"{indent}{var} = _req.args.get({p!r}, '')")
                arg_vars.append(var)
            call = f"{func_name}({', '.join(arg_vars)})"
        body_lines.append(f"{indent}{result_var} = {call}")
    ret = f"str({first_result})" if first_result else "''"
    body_lines.append(f"{indent}return {ret}")
    return _FLASK_ROUTE_HEADER + "\n".join(body_lines) + "\n"


_BUILDERS = {
    "args_string":     _build_args_string,
    "args_string_xss": _build_args_string_xss,
    "bytes_first":     _build_bytes_first,
}


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def add_entry_point(code: str, cwe_id: str) -> str:
    """
    Append the correct CodeQL entry-point wrapper to `code` for `cwe_id`.

    The wrapper calls ALL top-level functions found in `code` so that taint
    can reach any vulnerable function, even when a non-vulnerable helper is
    defined first.  Returns the original code unchanged if:
      - no wrapper is needed for this CWE (e.g. cwe-295), or
      - the code is empty, or
      - no top-level function definitions are found.
    """
    if cwe_id not in ENTRY_POINT_CWES or not code.strip():
        return code

    funcs = _find_all_functions(code)
    if not funcs:
        return code

    wrapper_type = CWE_WRAPPER_TYPE[cwe_id]
    builder = _BUILDERS[wrapper_type]
    return code + builder(funcs)
