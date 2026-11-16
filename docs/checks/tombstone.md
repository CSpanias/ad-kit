# Tombstone Check

Check whether the Standard User can query deleted AD objects.

```bash
ad-kit check tombstone
```

## What it does

Queries the deleted objects container on each Domain Controller using a read-only action. Never restores or deletes objects.

## Output

Per-DC table showing:
- Deleted objects count
- Status (Enumerated, Access denied, No deleted objects, Unknown, Container not found)

Requires a Standard User account from `ad-kit enum`.