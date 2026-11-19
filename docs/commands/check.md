# Check Commands

Execute assessment checks and generate HTML and JSON findings with supporting evidence.

## `ad-kit check`

Run all assessment checks in the established workflow order.

```bash
ad-kit check
ad-kit check all
```

## `ad-kit check run <modules>`

Execute one or more selected assessment modules.

```bash
# Run specific checks
ad-kit check run ldap smb pass-pol
```

Modules are executed in the order provided. Authentication is prompted once and reused across checks that require it.

The current run writes `ad-kit/ad-kit_findings.html` and
`ad-kit/ad-kit_findings.json`. The HTML report is self-contained and has
Copy Markdown buttons for each finding and for its individual commentary,
evidence, and remediation sections. Affected assets are included in commentary,
and references in remediation. Individual commentary and remediation copies
omit their section titles; the full finding copy includes them. Each run
replaces the HTML and JSON exports, including when running selected checks.
Previously generated Markdown files are not removed.

### SureFormat XML

Use `--csacyber` to write `ad-kit/ad-kit_findings.xml` instead of the generic
JSON export. The domain hostname comes from the session created by `ad-kit enum`;
the export fails before checks start if the domain is unavailable. The HTML
report is still written. Only findings supported by the integration mapping are
exported.

```bash
ad-kit check --csacyber
ad-kit check run ldap smb --csacyber --dc DC01.example.com
```

With `--dc`, LDAP signing, LDAP channel binding, LDAP null binds, DC coercion,
and NoPAC findings are written to `ad-kit/ad-kit_findings-dc.xml` for the
specified hostname. Other findings remain in the domain XML. Without `--dc`,
all mapped findings are written to the domain XML. Each run replaces its
selected outputs; files from earlier runs in other formats or without the
current DC split are not removed.

## Available Checks

| Check | Command | Description |
|-------|---------|-------------|
| LDAP | `ad-kit check ldap` | LDAP signing, channel binding, anonymous bind |
| SMB | `ad-kit check smb` | SMB signing, SMBv1, anonymous enumeration, writable shares |
| AS-REP Roasting | `ad-kit check asreproast` | AS-REP roastable accounts + privileged membership |
| Kerberoasting | `ad-kit check kerberoast` | Kerberoastable accounts + privileged membership |
| AD CS | `ad-kit check adcs` | Certificate template/CA misconfigurations (ESC) |
| NoPAC | `ad-kit check nopac` | NoPAC vulnerability on Domain Controllers |
| DNS | `ad-kit check dns` | ADIDNS record creation permissions |
| Pre-Windows 2000 | `ad-kit check pre2k` | Pre-2000 computer account passwords |
| Script Path | `ad-kit check scriptPath` | User logon script path write access |
| Privileged Groups | `ad-kit check privileged` | Privileged group membership + DCSync rights |
| Delegation | `ad-kit check delegation` | Unconstrained/constrained delegation |
| Password Policy | `ad-kit check pass-pol` | Domain password policy assessment |
| Password Not Required | `ad-kit check password-not-required` | PASSWD_NOTREQD accounts |
| Password Never Expires | `ad-kit check password-never-expires` | Non-expiring password accounts |
| Machine Account Quota | `ad-kit check maq` | Machine account creation quota |
| Tombstone | `ad-kit check tombstone` | Deleted AD object access |
| Local Administrator | `ad-kit check local-admin` | Local admin access on domain hosts |
| LDAP Info Exposure | `ad-kit check ldap-info` | Sensitive LDAP attribute exposure |
| Authentication Coercion | `ad-kit check coercion` | Coercion attack paths + Print Spooler |

## Authentication

Checks requiring a Standard User account will prompt for credentials once and reuse them across subsequent checks. Some checks (e.g., DNS cleanup) may prompt for Domain Administrator credentials.