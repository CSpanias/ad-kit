# Tools Commands

Manage assessment tools registered in ad-kit.

```bash
# Display all tools registered in ad-kit and their installation source
ad-kit tools

# Check which registered tools are currently installed
ad-kit tools status

# Install a specific tool
ad-kit tools install netexec

# Reinstall a tool even if an executable is already on PATH
ad-kit tools install kerbrute --force

# Install all registered tools
ad-kit tools install all
```

A tool is considered installed if its executable can be found in the current 
`PATH`. The appropriate installer implementation is selected automatically 
based on the tool's configured installer type (`uv` or GitHub Release).
GitHub release binaries are installed to `~/.local/bin`; `--force` replaces
that destination but does not remove other installations. If another executable
takes precedence on `PATH`, ad-kit reports its location. `uv` tools are already
reinstalled by the normal install command; `--force` does not bypass conflicting
installations outside the uv directory.

If a shell still runs the old version after reinstalling, refresh its command
cache with `hash -r` in bash or `rehash` in zsh.