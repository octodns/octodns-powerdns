# Agent Guide for octoDNS PowerDNS Provider

This repository contains the PowerDNS provider for octoDNS.

> [!IMPORTANT]
> **Core Workflow and Guidelines**
>
> All agents working on this repository must read and follow the general instructions and workflow guidelines defined in the core octoDNS `AGENTS.md` file.
> - **Local check**: Look for the file at `../octodns/AGENTS.md`.
> - **Remote check**: If the local file is not available, fetch it from GitHub: [octoDNS Core AGENTS.md](https://github.com/octodns/octodns/raw/refs/heads/main/AGENTS.md).
>
> You must align your code structure, style, pull request guidelines, and overall development workflows with the instructions specified there.

## Repository & Module Information

### Key Components
- **Provider Class**: [PowerDnsProvider](file:///home/ross/octodns/octodns-powerdns/octodns_powerdns/__init__.py) (defined in [octodns_powerdns/__init__.py](file:///home/ross/octodns/octodns-powerdns/octodns_powerdns/__init__.py)).
- **Dynamic Record Support**: Implemented in [octodns_powerdns/dynamic.py](file:///home/ross/octodns/octodns-powerdns/octodns_powerdns/dynamic.py). PowerDNS LUA records are used to route dynamic queries (continent, country, region) via the GeoIP backend. A base64-encoded JSON blob containing the full dynamic payload is embedded in a leading LUA comment for round-trip populating.
- **Custom PowerDNS LUA Record**: Implemented in [octodns_powerdns/record.py](file:///home/ross/octodns/octodns-powerdns/octodns_powerdns/record.py).

### Development & Testing
- **Local Dev Server**: A [docker-compose.yml](file:///home/ross/octodns/octodns-powerdns/docker-compose.yml) file is provided to spin up a local PowerDNS server with API enabled for testing (default API key is `its@secret`).
- **Setup script**: Run `./script/bootstrap` to create a virtual environment, install runtime and development dependencies (including `black`, `isort`, `pyflakes`, and `pytest`), and configure pre-commit git hooks.
- **Test Suite**: Run tests using `pytest` (e.g., `pytest tests/`). Test files are located in [tests/](file:///home/ross/octodns/octodns-powerdns/tests).

### Key Constraints & Behaviors
- **Python Version**: Targets Python `>=3.9`.
- **Formatting**: Code formatting is enforced via `black` (version `>=26.0.0,<27.0.0`) and `isort`.
- **Dynamic Subnets**: Not supported (`SUPPORTS_DYNAMIC_SUBNETS=False`).
- **Pool Value Status**: Not supported (`SUPPORTS_POOL_VALUE_STATUS=False`).
