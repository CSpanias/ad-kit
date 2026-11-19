# Tools Commands

Manage assessment tools registered in ad-kit.

```bash
# Display all tools registered in ad-kit and their installation source
ad-kit tools

# Check which registered tools are currently installed
ad-kit tools status

# Install a specific tool
ad-kit tools install netexec

# Install all registered tools
ad-kit tools install all
```

A tool is considered installed if its executable can be found in the current 
`PATH`. The appropriate installer implementation is selected automatically 
based on the tool's configured installer type (`uv` or GitHub Release).