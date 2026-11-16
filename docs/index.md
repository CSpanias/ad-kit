# ad-kit

`ad-kit` is an automation toolkit designed to make Active Directory (AD) assessments more efficient.

It combines tool management, environment preparation, AD enumeration, domain data collection, NTDS extraction, and common security checks into a single command-line interface.

The toolkit is intended to provide a repeatable methodology for conducting AD security reviews and generating consistent assessment output.

## Features

- Tool installation and status verification
- Domain and Domain Controller enumeration
- Assessment session tracking and engagement metadata
- [netexec](https://github.com/Pennyw0rth/NetExec) [audit mode](https://www.netexec.wiki/getting-started/audit-mode) configuration
- Standard User and Domain Admin credential validation
- BloodHound data collection via [rusthound-ce](https://github.com/g0h4n/RustHound-CE)
- NTDS extraction via Impacket [secretsdump](https://github.com/fortra/impacket/blob/master/examples/secretsdump.py)
- SCP command generation for artefact retrieval
- Automated Active Directory security assessment checks
- Markdown finding generation with supporting evidence

## Installation

=== "UV (Recommended)"

    ```bash
    # Install UV
    curl -LsSf https://astral.sh/uv/install.sh | sh

    # Install ad-kit
    uv tool install git+https://github.com/CSpanias/ad-kit

    # Verify installation
    ad-kit -h

    # Update
    uv tool upgrade ad-kit
    ```

=== "Development"

    ```bash
    git clone https://github.com/CSpanias/ad-kit /opt/ad-kit
    cd /opt/ad-kit
    uv venv
    uv pip install -e .
    ad-kit -h
    ```

## Typical Workflow

A typical Active Directory assessment using `ad-kit` follows this workflow:

1. **Install Required Tools** (`ad-kit tools install all`)
2. **Enumerate Environment** (`ad-kit enum`)
   - Session metadata
   - Domain users
   - Domain controllers
   - Credential validation
   - BloodHound collection
   - NTDS extraction
3. **Security Assessment Checks** (`ad-kit check all`)
   - Findings
   - Evidence
   - Markdown reports
4. **Continue Engagement**

The generated artefacts can be consumed by other assessment tooling. For example, exported BloodHound collections (`.zip`) and NTDS dumps (`.ntds`) can be processed directly using [password-audit](https://github.com/CSpanias/password-audit).