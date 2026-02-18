# unifi-mcp-server

Ubiquiti UniFi network controller

## Install

```bash
pip install unifi-mcp-server
# or
uvx unifi-mcp-server
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

See `--help` for additional options:

```bash
unifi-mcp-server --help
```

## Development

```bash
git clone https://github.com/clearminds/unifi-mcp-server.git
cd unifi-mcp-server
uv sync
uv run unifi-mcp-server
```

## License

MIT
