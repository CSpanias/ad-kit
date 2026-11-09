# ad-kit

`ad-kit` is an Active Directory assessment automation toolkit designed to 
streamline common internal penetration testing workflows.

It combines tool management, environment preparation, Active Directory (AD) 
enumeration, security assessment checks, BloodHound collection, and NTDS 
extraction into a single command-line interface.

The toolkit is intended to provide a repeatable methodology for conducting 
AD security reviews by combining data collection, assessment logic, evidence 
preservation, and report generation into a unified workflow.

## Features

- Tool installation and status verification
- Domain and Domain Controller enumeration 
- Assessment session tracking and engagement metadata
- [`netexec`](https://github.com/Pennyw0rth/NetExec) [audit mode](https://www.netexec.wiki/getting-started/audit-mode) configuration 
- Standard User and Domain Admin credential validation
- Automated Active Directory security assessment checks
- Markdown finding generation with supporting evidence
- BloodHound data collection via [`rusthound-ce`](https://github.com/g0h4n/RustHound-CE) 
- NTDS extraction via Impacket [`secretsdump`](https://github.com/fortra/impacket/blob/master/examples/secretsdump.py) 
- SCP command generation for artefact retrieval

Current assessment modules include:

1. LDAP signing and channel binding
2. SMB signing and SMBv1
3. Password policy review
4. Machine Account Quota (MAQ)
5. DNS record creation permissions
6. Pre-Windows 2000 computer accounts
7. Excessive privileged group membership
8. Kerberos delegation review
9. AS-REP roastable accounts
10. Kerberoastable accounts
11. Active Directory Certificate Services (AD CS) ESC review

## Installation

UV (Recommended)

```bash
# Install UV
curl -LsSf https://astral.sh/uv/install.sh | sh

# Install ad-Kit
uv tool install git+https://github.com/CSpanias/ad-kit

# Verify installation
ad-kit -h

# Update
uv tool upgrade ad-kit
```

## Typical Workflow

An Active Directory assessment generally follows the workflow below:

```text
Install Required Tools on JumpBox
    |
    v
Enumerate Environment
    |
    +--> Session Metadata
    +--> Domain Users
    +--> Domain Controllers
    |
    v
Validate Credentials
    |
    +--> Standard User
    +--> Domain Admin
    |
    v
Collect BloodHound Data & Dump NTDS
    |
    +--> *.zip
    +--> *.ntds
    |
    v
Security Assessment Checks
    |
    +--> Findings
    +--> Evidence
    +--> Markdown Reports
    |
    v
Continue Engagement
```

As an example, the transferred artefacts can be directly used by [`password-audit`](https://github.com/CSpanias/password-audit).

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
     ad-kit check ldap pass-pol
```

`tools` displays all tools registered in AD-Kit and their installation source:

```bash
$ ad-kit tools -h

Usage: ad-kit tools [OPTIONS]

Display all tools registered in AD-Kit and their installation source. 
```

`enum` bootstraps an assessment:

```bash
$ ad-kit enum -h
                                              
Usage: ad-kit enum [OPTIONS]

Perform basic domain enumeration:                                       

• Discover the target domain
• Enumerate domain controllers
• Configure NetExec's audit mode
• Validate a standard user account
• Validate a Domain Admin account
• Create user and machine account lists
• Collect BloodHound data using RustHound-CE
• Dump NTDS using secretsdump

╭─Options──────────────────────────────────────────────────────────────────────╮
│ --help  -h      <bool>  Show this message and exit.                          │
╰──────────────────────────────────────────────────────────────────────────────╯
```

`check` executes AD assessment modules and generates Markdown findings with 
supporting evidence:

```bash
$ ad-kit check -h

 Usage: ad-kit check [OPTIONS] COMMAND [ARGS]...

 Execute assessment checks.

╭─Options─────────────────────────────────────────────────────────────────────────────────────────────────────╮
│ --help  -h      <bool>  Show this message and exit.                                                         │
╰─────────────────────────────────────────────────────────────────────────────────────────────────────────────╯
╭─Commands────────────────────────────────────────────────────────────────────────────────────────────────────╮
│ all         Execute all assessment checks.                                                                  │
│ ldap        Execute LDAP security checks.                                                                   │
│ smb         Execute SMB security checks.                                                                    │
│ asreproast  Identify accounts susceptible to AS-REP roasting.                                               │
│ pass-pol    Execute password policy checks.                                                                 │
│ maq         Execute Machine Account Quota check.                                                            │
│ dns         Execute DNS permission check.                                                                   │
│ pre2k       Identify pre-created computer accounts susceptible to the pre-Windows 2000 password convention. │
│ privileged  Review privileged Active Directory group membership.                                            │
│ delegation  Review Active Directory delegation configuration.                                               │
│ kerberoast  Identify Kerberoastable accounts.                                                               │
│ adcs        Review Active Directory Certificate Services (AD CS) configuration.                             │
│ run         Execute selected assessment modules.                                                            │
╰─────────────────────────────────────────────────────────────────────────────────────────────────────────────╯
```