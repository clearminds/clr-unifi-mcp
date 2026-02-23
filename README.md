# clr-unifi-mcp

Ubiquiti UniFi network controller

## Install

```bash
pip install clr-unifi-mcp
# or
uvx clr-unifi-mcp
```

## Configuration

**Preferred:** Configuration file at `~/.config/unifi/credentials.json` (chmod 600):

```json
{
  "url": "https://unifi.example.com:8443",
  "username": "admin",
  "password": "your-password",
  "site": "default"
}
```

**Alternative:** Environment variables are also supported:

| Variable | Description | Example |
|----------|-------------|---------|
| `UNIFI_URL` | UniFi Controller URL | `https://unifi.example.com:8443` |
| `UNIFI_USERNAME` | Username | `admin` |
| `UNIFI_PASSWORD` | Password | `your-password` |
| `UNIFI_SITE` | Site name | `default` |

Optional:

| Variable | Description | Default |
|----------|-------------|---------|
| `UNIFI_READ_ONLY` | Run in read-only mode | `false` |
| `TRANSPORT` | Transport protocol (`stdio` or `http`) | `stdio` |
| `LOG_LEVEL` | Log level | `INFO` |

See `--help` for additional options:

```bash
clr-unifi-mcp --help
```

## Development

```bash
git clone https://github.com/clearminds/clr-unifi-mcp.git
cd clr-unifi-mcp
uv sync
uv run clr-unifi-mcp
```

## License

MIT
