# Findings Reference

Findings are generated during assessment checks and written to Markdown reports in the `ad-kit/` directory. Each finding has a unique ID, title, commentary, remediation guidance, and evidence.

## Finding Categories

| Category | Description |
|----------|-------------|
| LDAP | LDAP configuration issues (LDAP-001 to LDAP-003) |
| SMB | SMB configuration issues (SMB-001 to SMB-004) |
| ASREP | AS-REP roasting (ASREP-001 to ASREP-002) |
| KERB | Kerberoasting (KERB-001 to KERB-002) |
| ADCS | AD CS misconfigurations (ADCS-ESC1, ADCS-ESC8, ADCS-ESC15) |
| NOPAC | NoPAC vulnerability (NOPAC-001) |
| DNS | DNS record creation (DNS-001) |
| SCRIPT | Script path write access (SCRIPT-001) |
| PRIV | Privileged groups/accounts (PRIV-001 to PRIV-005) |
| DELEG | Delegation (DELEG-001 to DELEG-003) |
| PASS | Password policy (PASS-001 to PASS-003) |
| LDAPINFO | LDAP info exposure (LDAPINFO-001 to LDAPINFO-002) |
| COERCE | Authentication coercion (COERCE-001 to COERCE-002) |
| LA | Local administrator access (LA-001 to LA-002) |
| MAQ | Machine Account Quota (MAQ-001) |
| PRE2K | Pre-Windows 2000 computer accounts (PRE2K-001) |
| TOMB | Deleted AD object access (TOMB-001) |

## Finding Structure

Each finding definition is stored in YAML under `src/ad_kit/findings/<category>.yaml`:

```yaml
LDAP-001:
  id: LDAP-001
  title: LDAP Signing Not Enforced
  commentary: |
    LDAP signing is not required, allowing...
  remediation: |
    Enable LDAP signing...
  references:
    - https://example.com
```

## Report Output

Each check writes a Markdown findings report:

```
ad-kit/findings-ldap.md
ad-kit/findings-smb.md
ad-kit/findings-asreproast.md
...
```

Evidence is stored in `ad-kit/evidence/`.