# acs CLI — Agent Guidance

This file provides guidance for AI agents using the `acs` CLI to interact with Red Hat Advanced Cluster Security (StackRox).

## Quick Start

```bash
# Always check schema first
acs schema <service>.<method>

# Common operations
acs image scan --image <image>
acs policy list --output json
acs alert list --state ACTIVE
```

## Invariants

**Always follow these rules:**

1. **Use `--output json`** when you need to parse output programmatically
2. **Use `--dry-run`** before any mutation operation (create, update, delete)
3. **Use `--fields`** to limit response size and save context tokens
4. **Prefer workflow skills** (`acs +check-image`) over raw API calls for common tasks
5. **Check schema first** if unsure about parameters: `acs schema <service>.<method>`

## Output Formats

| Format | When to Use |
|--------|-------------|
| `json` | Parsing output, piping to other tools |
| `table` | Human review, debugging |
| `ndjson` | Streaming large result sets |

**Note:** When stdout is not a TTY (piped/scripted), JSON is the default.

## Authentication

Set credentials via environment variables:

```bash
export ROX_ENDPOINT=central.example.com:443
export ROX_API_TOKEN=<your-token>
# OR
export ROX_ADMIN_PASSWORD=<password>  # Uses admin user
```

Or via flags:

```bash
acs --endpoint central.example.com:443 --token <token> image list
```

## Error Handling

Exit codes indicate error type:

| Code | Meaning | Action |
|------|---------|--------|
| 0 | Success | Continue |
| 1 | API error | Check stderr for details |
| 2 | Input validation | Fix input and retry |
| 3 | Authentication | Check credentials |
| 4 | Not found | Verify resource exists |
| 5 | Permission denied | Check RBAC permissions |

Error responses are JSON on stderr:

```json
{"error": true, "status_code": 404, "message": "resource not found"}
```

## Common Workflows

### Image Security Check

```bash
# Quick check (workflow skill)
acs +check-image quay.io/myorg/app:latest

# Or step by step:
# 1. Scan image
acs image scan --image quay.io/myorg/app:latest --output json > scan.json

# 2. Check scan ID from response
SCAN_ID=$(jq -r '.id' scan.json)

# 3. Get vulnerabilities
acs image get --id $SCAN_ID --fields id,scan.vulnerabilities
```

### Policy Management

```bash
# List critical policies
acs policy list --query "Severity:CRITICAL" --fields id,name,severity

# Preview policy change
acs policy update --id <id> --json @policy.json --dry-run

# Apply if dry-run looks good
acs policy update --id <id> --json @policy.json
```

### Cluster Operations

```bash
# List clusters
acs cluster list --fields id,name,status

# Get sensor bundle
acs cluster getbundle --id <cluster-id> --output-dir ./bundle
```

## Field Filtering

Use `--fields` to reduce response size:

```bash
# Full response (~5000 tokens)
acs image get --id abc123

# Filtered (~200 tokens)
acs image get --id abc123 --fields id,name,scan.components[].name
```

Syntax:
- Comma-separated field names: `id,name,severity`
- Nested fields with dots: `scan.vulnerabilities`
- Array items: `components[].name`

## Schema Introspection

When unsure about an API:

```bash
# List all services
acs schema

# List methods in a service
acs schema image

# Get method details (parameters, request body, response)
acs schema image.scan
```

The schema response includes:
- HTTP method and path
- Required and optional parameters
- Request body structure
- Response structure

## Workflow Skills

These commands combine multiple API calls:

| Skill | Description |
|-------|-------------|
| `+check-image` | Scan image + check policies + summarize |
| `+deploy-sensor` | Generate bundle + deploy + wait |
| `+compliance-report` | Run checks + format report |
| `+policy-export` | Export policies as files |

Skills are prefixed with `+` to distinguish from raw API commands.

## Best Practices

1. **Start with schema** — Always `acs schema <method>` before first use
2. **Use dry-run** — Preview mutations before executing
3. **Filter fields** — Reduce token usage with `--fields`
4. **Parse JSON** — Use `jq` or language-native JSON parsing
5. **Check exit codes** — Script error handling based on exit codes
6. **Prefer skills** — Use `+` commands for common workflows

## Troubleshooting

### "Authentication failed"
- Check `ROX_API_TOKEN` or `ROX_ADMIN_PASSWORD` is set
- Verify token hasn't expired
- Try `acs central whoami` to test auth

### "Connection refused"
- Check `ROX_ENDPOINT` is correct
- Verify Central is running: `kubectl get pods -n stackrox`
- Try with `--insecure` if using self-signed certs

### "Resource not found"
- Verify resource ID with `acs <service> list`
- Check ID format (no URL encoding needed)

### "Permission denied"
- Check user/token has required RBAC role
- Try `acs central whoami` to see current permissions
