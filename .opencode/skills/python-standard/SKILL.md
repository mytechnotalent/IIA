---
name: python-standard
description: Python coding standard for all owned tooling in the iiatool (IIA) project.
---

# Python Standard (iiatool / IIA)

All owned Python files in the `iiatool/` package, tests under `tests/`, and any
future tooling must comply with strict PEP8, an eight-line executable
function-body limit, no blank lines inside function bodies, and complete
NumPy-style docstrings.

## Scope

Applies to every Python file inside `iiatool/` and `tests/`, plus any new
Python tools added to this repository. Vendored or third-party scripts are
excluded.

## Rules

- Use four spaces, no tabs, and `snake_case` names.
- Use `UPPER_SNAKE_CASE` module constants and `PascalCase` classes.
- Keep lines within 79 characters.
- Use standard-library imports before third-party imports.
- Use two blank lines between top-level definitions.
- Every module has a module docstring.
- Every function, including private and nested functions, has a NumPy-style
  docstring with purpose, `Parameters`, and `Returns` sections.
- Function executable bodies contain at most eight lines, except cryptographic
  algorithms.
- Function bodies contain no blank lines.
- Never log or hard-code credentials or secrets.

## Verification

Run `python3 -m flake8 <file.py>` when flake8 is available. Also run:

```bash
python3 -m pytest tests/ -q
```
