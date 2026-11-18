# Typical Workflow

A typical Active Directory assessment using `ad-kit` follows the stages below.

## Stage 1: Install Required Tools

```bash
ad-kit tools install all
ad-kit tools status
```

## Stage 2: Enumerate Environment

```bash
ad-kit enum
```

This bootstraps the assessment by:

- Discovering the target domain
- Enumerating Domain Controllers
- Configuring NetExec's audit mode
- Validating a Standard User account
- Validating a Domain Admin account
- Creating user and machine account lists
- Collecting BloodHound data using RustHound-CE
- Dumping NTDS using secretsdump

Session metadata is saved to `ad-kit/session.json` for use by subsequent checks.

## Stage 3: Security Assessment Checks

Run all checks:

```bash
ad-kit check all
```

Or run specific checks:

```bash
ad-kit check ldap
ad-kit check run ldap pass-pol smb
```

Each assessment run generates:

- Console output (Rich tables)
- Offline HTML findings report (`ad-kit/ad-kit_findings.html`)
- JSON integration export (`ad-kit/ad-kit_findings.json`)
- Evidence files (`ad-kit/evidence/`)

## Stage 4: Retrieve Artefacts

`ad-kit enum` can generate an SCP command to pull artefacts from your jumpbox:

```bash
scp "user@host:/remote/dir/*.zip" "user@host:/remote/dir/*.ntds*" ./
```

The BloodHound `.zip` and NTDS `.ntds` files can be processed using [password-audit](https://github.com/CSpanias/password-audit).