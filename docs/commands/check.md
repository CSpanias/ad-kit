# Check Commands

Execute assessment checks and generate Markdown findings with supporting evidence.

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