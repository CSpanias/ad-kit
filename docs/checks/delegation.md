# Delegation Check

Review Active Directory Kerberos delegation configuration.

```bash
ad-kit check delegation
```

## What it does

Identifies accounts configured for unconstrained delegation and constrained delegation with protocol transition.

## Findings

| Finding ID | Description |
|------------|-------------|
| DELEG-001 | Account with Unconstrained Delegation |
| DELEG-002 | Account with Constrained Delegation + Protocol Transition |
| DELEG-003 | Privileged account with any Kerberos delegation |