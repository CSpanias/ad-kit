# Tools Commands

Manage assessment tools registered in ad-kit.

## `ad-kit tools`

Display all tools registered in ad-kit and their installation source.

```bash
ad-kit tools
```

## `ad-kit tools status`

Check which registered tools are currently installed.

```bash
ad-kit tools status
```

A tool is considered installed if its executable can be found in the current `PATH`.

## `ad-kit tools install <tool>`

Install one or more tools from the ad-kit registry. Use `all` to install every registered tool.

```bash
# Install a specific tool
ad-kit tools install netexec

# Install all registered tools
ad-kit tools install all
```

The appropriate installer implementation is selected automatically based on the tool's configured installer type (uv or GitHub Release).