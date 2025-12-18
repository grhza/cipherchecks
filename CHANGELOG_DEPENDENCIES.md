# Dependency Updates Changelog

**Date:** 2025-12-18
**Author:** Antigravity

## Summary
To ensure the longevity and maintainability of the `cipherchecks` tool, the following dependencies and configuration settings have been updated to their latest stable versions.

## Changes

### [pyproject.toml](file:///Users/raydiation/Projects/cipherchecks/pyproject.toml)

| Dependency | Old Version | New Version | Reason |
| :--- | :--- | :--- | :--- |
| **flake8** | `^3.9.2` | `^7.3.0` | Major version update for latest linting rules and Python support. |
| **pylint** | `^2.9.3` | `^4.0.4` | Major version update for improved static analysis and Python 3.14 support. |
| **python** | `^3.11` | `^3.13` | Updated to 3.13 for `sslyze` compatibility. |

### [Dockerfile](file:///Users/raydiation/Projects/cipherchecks/Dockerfile)

| Environment Variable | Old Value | New Value | Reason |
| :--- | :--- | :--- | :--- |
| **POETRY_VERSION** | `1.7.0` | `2.2.1` | Update availability of latest Poetry features and bug fixes. |

## Next Steps for User
1. Run `poetry update` locally to update your `poetry.lock` file with the new versions.
2. Rebuild the Docker image to verify the new Poetry version:
   ```bash
   docker build . -t cipherchecks
   ```
