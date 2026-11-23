# Check Commands

Execute assessment checks and generate HTML and JSON findings with supporting 
evidence.

```bash
# Run all assessment checks in the established workflow order
ad-kit check
ad-kit check all

# Execute one or more selected assessment modules
ad-kit check run ldap smb pass-pol

# Skip checks using a comma-separated list
ad-kit check all --exclude ldap,smb
ad-kit check --exclude ldap run ldap smb

# Limit concurrent target checks; 1 runs them sequentially
ad-kit check --workers 2 run ldap smb
ad-kit check smb --workers 8
```

Modules are executed in the order provided. Checks requiring a Standard User 
account will prompt for credentials once and reuse them across subsequent 
checks. Some checks (e.g., MAQ) may prompt for DA credentials.

`--exclude` accepts the exact check names listed below, separated by commas.
Specify it once and quote the list if it contains spaces.
It is available before or after `all`, `run`, and individual check commands.
Unknown names and excluding every selected check are errors.

Checks show progress through known targets, groups, script paths or queries where
available. Counts represent items processed, including incomplete checks.
External commands without measurable progress display an activity indicator
instead; they may continue running between progress updates.

LDAP configuration, SMB configuration, and SMB share access use up to four
workers by default. `--workers` accepts one through 16; select a lower value
for sensitive environments. Dependent operations on each target remain
ordered, and check modules themselves still run sequentially.

MAQ and DNS display current-run command evidence after their tables. LDAP and
SMB each display one anonymous enumeration sample with up to ten result rows;
the checks still cover every target. Known passwords are redacted; review
other potentially sensitive output before sharing screenshots.

Report filenames identify the checks in the current run:

- `ad-kit/ad-kit_findings_all.html` and `.json` for a full run, including
  runs with exclusions.
- `ad-kit/ad-kit_findings_privileged.html` and `.json` for a single check.
- `ad-kit/ad-kit_findings_ldap_smb.html` and `.json` for selected checks,
  using their names in execution order. Repeated names appear once in the
  filename.

With `--csacyber`, XML is written instead of JSON using the same suffix. With
`--dc`, the separate DC XML adds `-dc` before the extension. Each run replaces
only the matching HTML and selected export; an older export in the other format
is not removed.

When a command or host check cannot be completed, ad-kit preserves confirmed
findings and lists incomplete checks in the console and HTML report. The JSON
export contains findings only; consult the collapsed **Incomplete checks**
section at the end of the HTML report for coverage gaps.

The HTML report is self-contained and has **Copy Markdown** buttons for each 
finding and for its individual commentary, evidence, and remediation sections. 
Affected assets are included in commentary, and references in remediation. 

Individual section copies omit their section titles; the full finding copy
includes them.

## Available Checks

| Check | Command | Description |
|-------|---------|-------------|
| LDAP | `ad-kit check ldap` | LDAP signing, channel binding, anonymous bind |
| SMB | `ad-kit check smb` | SMB signing, SMBv1, anonymous shares, DC users, readable and writable shares |
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