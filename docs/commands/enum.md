# Enumerate Command

Bootstrap an Active Directory assessment.

```bash
ad-kit enum
```

## What it does

1. **Discover the target domain**: Identifies the Domain Controller (DC) and domain name from a DC IP address.
2. **Enumerate Domain Controllers**: Discovers all DCs and saves their hostnames and IP addresses.
3. **Configure NetExec's audit mode**: Ensures `audit_mode = *` is set in NetExec's configuration.
4. **Validate a Standard User account**: Prompts for and validates standard user credentials.
5. **Validate a Domain Admin account**: Prompts for and validates Domain Admin credentials (required for NTDS dump).
6. **Create user and machine account lists**: Exports domain users and computers to artefact files.
7. **Collect BloodHound data**: Runs RustHound-CE to collect AD graph data (optional).
8. **Dump NTDS**: Extracts NTDS.dit using Impacket secretsdump (optional, requires Domain Admin).

Credential validation uses NetExec LDAP and reports the protocol in the
console. NetExec's `Pwn3d!` marker indicates membership in one of several
privileged groups, not necessarily Domain Admin membership or permission to
dump NTDS. The absence of that marker does not prove an account is
unprivileged.

If the Domain Admin account cannot be validated but the standard user was
validated, enumeration continues using the standard account. A requested NTDS
dump is skipped, and the session records that privileged validation failed.

For an NTDS dump, ad-kit tries the supplied DC first, then other discovered
DCs if necessary. Each attempt is isolated; failed or incomplete dumps are
not used for retrieval. Authentication failures stop further attempts to
reduce account-lockout risk. The successful DC is shown in the console.
Secretsdump runs with debug logging so that early failures, including its
preliminary SMB/RPC check, can be reported without retrying the dump on the
same DC. Only failure diagnostics are displayed, with the supplied password
and NTLM hashes redacted; raw debug output is not displayed.

User and computer exports are checked before being accepted. If collection
fails, existing files are not treated as this session's results; dependent
checks require a successful export. A computer export with no parsed hosts is
accepted as empty only when NetExec explicitly reports zero records.

When prompted to generate an SCP retrieval command, select a displayed
interface address reachable from your local machine. The command uses the
current OS username and absolute artefact path, and includes only ZIP and NTDS
files created or updated by this run. If the SSH username differs (for
example, when running ad-kit with `sudo`), adjust it before running the
command. Linux's `ip` command is required to list addresses.

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