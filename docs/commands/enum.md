# Enumerate Command

Bootstrap an Active Directory assessment.

```bash
ad-kit enum
```

## What it does

1. **Discover the target domain** — Identifies the Domain Controller and domain name from a DC IP address.
2. **Enumerate Domain Controllers** — Discovers all DCs and saves their hostnames and IP addresses.
3. **Configure NetExec's audit mode** — Ensures `audit_mode = *` is set in NetExec's configuration.
4. **Validate a Standard User account** — Prompts for and validates standard user credentials.
5. **Validate a Domain Admin account** — Prompts for and validates Domain Admin credentials (required for NTDS dump).
6. **Create user and machine account lists** — Exports domain users and computers to artefact files.
7. **Collect BloodHound data** — Runs RustHound-CE to collect AD graph data (optional).
8. **Dump NTDS** — Extracts NTDS.dit using Impacket secretsdump (optional, requires Domain Admin).

## Output

Artefacts are written to the `ad-kit/` directory:

| File | Description |
|------|-------------|
| `session.json` | Session metadata for subsequent checks |
| `domain.txt` | Target domain name |
| `dc-hostnames.txt` | Discovered Domain Controller hostnames |
| `dc-ips.txt` | Discovered Domain Controller IP addresses |
| `domain-users-filtered.txt` | Filtered domain user list |
| `domain-computers.txt` | Domain computer hostnames |
| `*.zip` | BloodHound collection (if enabled) |
| `*.ntds` | NTDS dump (if enabled) |

## Prerequisites

- NetExec (`netexec` or `nxc`) must be installed
- RustHound-CE (`rusthound-ce`) must be installed (for BloodHound)
- Impacket (`secretsdump.py`) must be installed (for NTDS dump)
- Valid Standard User and Domain Admin credentials