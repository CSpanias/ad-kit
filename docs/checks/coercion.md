# Authentication Coercion Check

Review hosts for authentication coercion attack paths and Domain Controllers with the Print Spooler service enabled.

```bash
ad-kit check coercion
```

## What it does

Identifies hosts exposing authentication coercion techniques (PrinterBug, PetitPotam, DFSCoerce, WebDAV) and Domain Controllers with Print Spooler enabled.

## Findings

| Finding ID | Description |
|------------|-------------|
| COERCE-001 | Domain Controller exposes coercion technique(s) |
| COERCE-002 | Domain Controller has Print Spooler service enabled |