# Findings Reference

Findings are generated during assessment checks and written to a self-contained HTML report in the `ad-kit/` directory. Each finding has a unique ID, title, commentary, remediation guidance, and evidence.

The HTML report groups related findings and provides separate copyable finding
and remediation introductions when a topic has more than one finding. The
finding introduction describes potential impacts rather than confirmed
exploitation; the remediation introduction summarises relevant actions.
Neither introduction is included in JSON or XML integration exports.

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
| LDAPINFO | LDAP info exposure (LDAPINFO-001) |
| COERCE | Authentication coercion (COERCE-001) |
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

Each run writes an HTML report, such as `ad-kit/ad-kit_findings_all.html` for a
full run or `ad-kit/ad-kit_findings_privileged.html` for one check. Each finding
or its individual commentary, evidence, and remediation sections can be copied
as Markdown. Affected assets and MAQ and DNS finding evidence are included in
commentary, and references in remediation. By default, it also writes a JSON
file with the same suffix for integration, containing the YAML ID and
commentary for every finding. With
`--csacyber`, SureFormat XML is written instead of JSON; it maps YAML IDs to
platform IDs and warns about findings without a mapping. The exports contain
findings from the current run only. Multiple selected checks use their names
in execution order as the suffix. A run replaces files with the same suffix
and format; older files in other formats are left untouched. The domain
hostname in the XML is lowercase. Host-specific findings use separate items;
hosts with missing or ambiguous IPs are exported by hostname with a warning.

Evidence is stored in `ad-kit/evidence/`.