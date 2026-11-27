# Enumerate Command

Bootstrap an Active Directory assessment.

```bash
ad-kit enum
```

## What it does

1. **Discover the target domain**: Identifies the Domain Controller (DC) and domain name from a DC IP address.
2. **Configure NetExec's audit mode**: Ensures `audit_mode = *` is set in NetExec's configuration.
3. **Validate a Standard User account**: Prompts for and validates standard user credentials.
4. **Validate a Domain Admin account**: Prompts for and validates Domain Admin credentials (required for NTDS dump).
5. **Enumerate Domain Controllers**: Discovers all DCs and saves their hostnames and IP addresses.
6. **Create user and machine account lists**: Exports domain users and computers to artefact files.
7. **Collect BloodHound data**: Runs RustHound-CE to collect AD graph data (optional).
8. **Dump NTDS**: Extracts NTDS.dit using Impacket secretsdump (optional, requires Domain Admin).

## Commands run

The following show the external commands run during enumeration. Placeholders
represent values supplied or discovered during the session; ad-kit passes
arguments directly rather than invoking a shell.

### Domain discovery and NetExec configuration

```bash
nxc ldap <dc-ip>
```

If `~/.nxc/nxc.conf` does not exist, ad-kit first runs `netexec --help` to
initialise it. It then sets `audit_mode = *` in the configuration file directly;
there is no separate command for that change.

### Credential validation and DC enumeration

For each account selected for validation, ad-kit runs:

```bash
nxc ldap <dc-ip> -u '<username>' -p '<password>'
```

It uses the validated standard user for subsequent LDAP operations, or the
validated privileged account if no standard user is available:

```bash
nxc ldap <dc-ip> -u '<username>' -p '<password>' --dc-list
```

### Domain data collection

```bash
nxc ldap <dc-ip> -u '<username>' -p '<password>' --users-export <temporary-users-file>
nxc ldap <dc-ip> -u '<username>' -p '<password>' --computers
```

The user export is staged in a temporary directory. Ad-kit filters the
testing accounts and writes the user and computer lists itself.

### BloodHound collection

If selected, RustHound runs in the artefacts directory:

```bash
rusthound-ce -d <domain> -u '<username>' -p '<password>' -i <dc-ip> -c LdapOnly -z
```

If the server requires stronger LDAP authentication, ad-kit retries with
`--ldaps`:

```bash
rusthound-ce --ldaps -d <domain> -u '<username>' -p '<password>' -i <dc-ip> -c LdapOnly -z
```

### NTDS dump

If selected and privileged validation succeeds, ad-kit runs the following in
an isolated temporary directory for each attempted DC:

```bash
secretsdump.py '<domain>/<admin-username>:<password>@<dc-ip>' -debug -user-status -just-dc-ntlm -outputfile <domain>
```

### Retrieval

If SCP retrieval is selected and this run produced eligible files, ad-kit
uses `ip -j address show` to list interface addresses. It then displays an
`scp` command for the user to run locally; ad-kit does not execute it.

!!! warning "Credentials in process arguments"
    The commands above pass passwords as process arguments. They may be visible
    to other local users or process-monitoring tools while the commands run.
    Avoid entering real passwords into shell history when reproducing them.

## Behaviour and failure handling

Enumeration returns a nonzero exit status if a requested validation, collection,
or NTDS dump fails. Where possible, completed results are preserved.

Before connecting, an advisory preflight checks for local executables needed by
the selected options. Missing tools are reported with installation guidance, but
do not prevent the workflow from continuing. The impact summary describes data
collection and asks for confirmation before an NTDS dump; declining cancels
enumeration.

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