# ad-kit

`ad-kit` is an Active Directory assessment automation toolkit designed to streamline common internal penetration testing workflows.

It combines tool management, environment preparation, domain enumeration, BloodHound collection, and NTDS extraction into a single command-line interface.

## Features

- Tool installation and status verification
- Domain and Domain Controller enumeration 
- [`netexec`](https://github.com/Pennyw0rth/NetExec) [audit mode](https://www.netexec.wiki/getting-started/audit-mode) configuration 
- Standard User and Domain Admin credential validation 
- BloodHound data collection via [`rusthound-ce`](https://github.com/g0h4n/RustHound-CE) 
- NTDS extraction via Impacket [`secretsdump`](https://github.com/fortra/impacket/blob/master/examples/secretsdump.py) 
- Session tracking and engagement metadata 
- SCP command generation for artefact retrieval

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
Enumerate Domain and Domain Controllers
    |
    v
Validate Credentials
    |
    +--> Standard User
    |
    +--> Domain Admin
    |
    v
Collect BloodHound Data
    |
    +--> bloodhound/
    |
    v
Dump NTDS
    |
    +--> hashes/
    |
    v
Retrieve Assessment Artefacts
    |
    +--> bloodhound.zip
    +--> *.ntds
    |
    v
Continue Engagement
```

As an example, the transferred artefacts can be directly used by [`password-audit`](https://github.com/CSpanias/password-audit).

## Commands

`tools` displays all tools registered in AD-Kit and their installation source:

```bash
$ ad-kit tools -h

Usage: ad-kit tools [OPTIONS]

Display all tools registered in AD-Kit and their installation source. 
```

`status` checks which registered tools are currently installed:

```bash
ad-kit status -h

Usage: ad-kit status [OPTIONS]                                                           

Check which registered tools are currently installed.
```

`install` installs one or more tools from the AD-Kit registry:

```bash
$ ad-kit install -h                     

Usage: ad-kit install [OPTIONS] {tool}                                                           

Install one or more tools from the AD-Kit registry. Use 'all' to install every registered tool.

╭─Arguments──────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────╮
│ *    tool      <str>  Tool name or 'all'. [required]
╰────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────╯ 
```

`enum` bootstraps an assessment:


```bash
$ ad-kit enum -h
                                              
Usage: ad-kit enum [OPTIONS]

Perform basic domain enumeration:                                       

• Discover the target domain        
• Enumerate domain controllers       
• Validate a standard user account
• Validate a Domain Admin account
• Collect BloodHound data using RustHound-CE 
```

`dump` performs an NTDS extraction:

```bash
$ ad-kit dump -h

Usage: ad-kit dump [OPTIONS]

Perform an NTDS extraction using Impacket secretsdump.
```