# ad-kit

`ad-kit` is an automation toolkit designed to make Active Directory (AD) 
assessments more efficient.

It combines tool management, environment preparation, AD enumeration, domain 
data collection, NTDS extraction, and common security checks into a single 
command-line interface.

The toolkit is intended to provide a repeatable methodology for conducting 
AD security reviews and generating consistent assessment output.

## Features

- Tool installation and status verification
- Domain and Domain Controller enumeration 
- Assessment session tracking and engagement metadata
- [`netexec`](https://github.com/Pennyw0rth/NetExec) [audit mode](https://www.netexec.wiki/getting-started/audit-mode) configuration 
- Standard User and Domain Admin credential validation
- BloodHound data collection via [`rusthound-ce`](https://github.com/g0h4n/RustHound-CE) 
- NTDS extraction via Impacket [`secretsdump`](https://github.com/fortra/impacket/blob/master/examples/secretsdump.py) 
- SCP command generation for artefact retrieval
- Automated Active Directory security assessment checks
- Offline HTML and JSON findings reports with supporting evidence

## Installation

```bash
# Install UV
curl -LsSf https://astral.sh/uv/install.sh | sh

# Install ad-Kit
uv tool install git+https://github.com/CSpanias/ad-kit

# Verify installation
ad-kit -h
ad-kit --version

# Update
uv tool upgrade ad-kit
```

## Typical Workflow

A typical Active Directory assessment using `ad-kit` follows the workflow below:

```markdown
Install Required Tools (`tools`)
    |
    v
Enumerate Environment (`enum`)
    |
    +--> Session Metadata
    +--> Domain Users
    +--> Domain Controllers
    +--> Credential Validation
    +--> BloodHound Collection
    +--> NTDS Extraction
    |
    v
Security Assessment Checks (`check`)
    |
    +--> Findings
    +--> Evidence
    +--> HTML and JSON Reports
    |
    v
Continue Engagement
```

The generated artefacts can be consumed by other assessment tooling. For 
example, exported BloodHound collections (`.zip`) and NTDS dumps (`.ntds`) can 
be processed directly using [`password-audit`](https://github.com/CSpanias/password-audit).

## Commands

```bash
$ ad-kit -h

 Usage: ad-kit [OPTIONS] COMMAND [ARGS]...

 Active Directory Assessment Toolkit.

╭─Options──────────────────────────────────────────────────────────────────────╮
│ --help  -h      <bool>  Show this message and exit.                          │
╰──────────────────────────────────────────────────────────────────────────────╯
╭─Commands─────────────────────────────────────────────────────────────────────╮
│ enum   Perform basic domain enumeration:                                     │
│ tools  Manage assessment tools.                                              │
│ check  Execute assessment checks.                                            │
╰──────────────────────────────────────────────────────────────────────────────╯

 Examples:

     ad-kit tools install all
     ad-kit tools install certipy
     ad-kit tools status

     ad-kit enum

     ad-kit check all
     ad-kit check ldap
     ad-kit check run ldap pass-pol
```

`tools` displays all tools registered in AD-Kit and their installation source:

```bash
$ ad-kit tools -h

Usage: ad-kit tools [OPTIONS]

Display all tools registered in ad-kit and their installation source. 
```

`enum` bootstraps an AD assessment:

```bash
$ ad-kit enum -h
                                              
Usage: ad-kit enum [OPTIONS]

Perform basic domain enumeration:                                       

• Discover the target domain
• Enumerate domain controllers
• Configure NetExec\'s audit mode
• Validate a standard user account
• Validate a Domain Admin account
• Create user and machine account lists
• Collect BloodHound data using RustHound-CE
• Dump NTDS using secretsdump

╭─Options──────────────────────────────────────────────────────────────────────╮
│ --help  -h      <bool>  Show this message and exit.                          │
╰──────────────────────────────────────────────────────────────────────────────╯
```

`check` executes one or more AD assessment modules and generates a local HTML
findings report, a JSON integration export, and supporting evidence:

```bash
$ ad-kit check -h

 Usage: ad-kit check [OPTIONS] COMMAND [ARGS]...

 Execute assessment checks.

╭─Commands─────────────────────────────────────────────────────────────────────╮
│ all                    Execute all assessment checks.                        │
│ ldap                   Execute ldap assessment checks.                       │
│ tombstone              Execute tombstone assessment checks.                  │
│ smb                    Execute smb assessment checks.                        │
│ asreproast             Execute asreproast assessment checks.                 │
│ pass-pol               Execute pass-pol assessment checks.                   │
│ password-not-required  Execute password-not-required assessment checks.      │
│ password-never-expires Execute password-never-expires assessment checks.     │
│ maq                    Execute maq assessment checks.                        │
│ dns                    Execute dns assessment checks.                        │
│ pre2k                  Execute pre2k assessment checks.                      │
│ nopac                  Execute nopac assessment checks.                      │
│ scriptPath             Execute scriptPath assessment checks.                 │
│ privileged             Execute privileged assessment checks.                 │
│ delegation             Execute delegation assessment checks.                 │
│ kerberoast             Execute kerberoast assessment checks.                 │
│ adcs                   Execute adcs assessment checks.                       │
│ local-admin            Execute local-admin assessment checks.                │
│ ldap-info              Execute ldap-info assessment checks.                  │
│ coercion               Execute coercion assessment checks.                   │
│ run                    Execute selected assessment modules.                  │
╰─────────────────────────────────────────────────────────────────────────────╯
```