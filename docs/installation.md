# Installation

## Prerequisites

- Python 3.11+
- [UV](https://astral.sh/) (recommended package manager)
- A Kali Linux or similar assessment VM

## Install UV

```bash
curl -LsSf https://astral.sh/uv/install.sh | sh
```

## Install ad-kit

```bash
# Install ad-kit from GitHub
uv tool install git+https://github.com/CSpanias/ad-kit

# Verify installation
ad-kit -h

# Update to the latest version
uv tool upgrade ad-kit
```

## Development Installation

For contributing or modifying the source code:

```bash
git clone https://github.com/CSpanias/ad-kit /opt/ad-kit
cd /opt/ad-kit
uv venv
uv pip install -e .
ad-kit -h
```

## Required Tools

`ad-kit` relies on several external tools during enumeration and checks. Install them via:

```bash
ad-kit tools install all
```

Or install individual tools:

```bash
ad-kit tools install netexec
ad-kit tools install certipy
ad-kit tools install rusthound
```

Check installation status:

```bash
ad-kit tools status
```