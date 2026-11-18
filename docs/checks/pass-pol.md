# Password Policy Check

Retrieves the domain password and account-lockout policy and assesses each
setting against the ad-kit baseline.

```bash
ad-kit check pass-pol
```

!!! info "Prerequisite"
    Requires a valid Standard User account (authenticated).

## Commands run

ad-kit reads the effective domain policy with NetExec:

```bash
nxc ldap <dc_ip> -u <username> -p <password> --pass-pol
```

## What it checks

ad-kit reads the effective domain policy and compares each setting against the
baseline:

| Setting | Baseline |
|---------|----------|
| Minimum password length | at least 12 characters |
| Password history | at least 2 remembered passwords |
| Minimum password age | at least 1 day |
| Maximum password age | set (not never) |
| Password complexity | enabled |
| Lockout threshold | 1 to 10 attempts |
| Lockout duration | at least 30 minutes |
| Observation window | at least 15 minutes |

## How it works

The password and account-lockout policy controls how resistant the domain is to
password guessing:

- **Minimum length, history, and complexity** make passwords harder to guess
  and to recycle.
- **Maximum age** limits how long a password remains valid.
- **Minimum age** prevents a user cycling passwords immediately to defeat
  password history.
- **Lockout threshold** is the number of failed attempts that lock an account.
  A value of zero disables lockout entirely and permits unlimited guessing.
- **Lockout duration** is how long a locked account remains unavailable.
- **Observation window** is the period after which the failed-attempt count is
  reset.

These settings interact, so ad-kit assesses them together. For example, a very
high lockout threshold gives an attacker many attempts, and a short observation
window means those attempts are forgotten quickly.

Fine-Grained Password Policies (Password Settings Objects) can override the
default policy for specific users and groups, so the effective policy for an
individual account may differ from the default domain policy that this check
reads.

## Why it matters

Weak password and lockout settings make password spraying, brute force, and
credential stuffing practical, increasing the likelihood of account compromise.

## Findings

| Finding ID | Title |
|------------|-------|
| PASS-001 | Weak Password and Account Lockout Policy |

## Tooling

- [NetExec](https://github.com/Pennyw0rth/NetExec): used by this check
  (`--pass-pol`).

## References

- [mollysec: Password Spraying Explained](https://mollysec.com/posts/password-spray/)
- [hackndo: password spraying](https://en.hackndo.com/password-spraying/)
- [Microsoft: password policy](https://learn.microsoft.com/en-us/windows/security/threat-protection/security-policy-settings/password-policy)
- [Microsoft: account lockout policy](https://learn.microsoft.com/en-us/windows/security/threat-protection/security-policy-settings/account-lockout-policy)
- [NCSC: updating your password approach](https://www.ncsc.gov.uk/collection/passwords/updating-your-approach)