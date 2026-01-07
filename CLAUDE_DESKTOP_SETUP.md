# Claude Desktop Setup Guide

This guide will help you integrate the OpenCTI MCP Server with Claude Desktop.

## Prerequisites

- Claude Desktop app installed
- Python 3.8+ installed
- Access to an OpenCTI instance
- OpenCTI API token

## Step 1: Install Dependencies

First, ensure all dependencies are installed:

```bash
cd /Users/slacker/mcp/mcp-opencti

# Create virtual environment (if not already done)
python3 -m venv .venv
source .venv/bin/activate

# Install dependencies
pip install -r requirements.txt
```

## Step 2: Configure Environment Variables

Create a `.env` file in the project directory:

```bash
cp .env.example .env
```

Edit `.env` with your OpenCTI credentials:

```bash
OPENCTI_URL=http://localhost:8080
OPENCTI_TOKEN=your-actual-api-token-here
```

## Step 3: Configure Claude Desktop

### Locate Configuration File

The Claude Desktop configuration file is located at:

**macOS**: `~/Library/Application Support/Claude/claude_desktop_config.json`

**Windows**: `%APPDATA%\Claude\claude_desktop_config.json`

### Edit Configuration

Open the configuration file and add the OpenCTI MCP server:

```json
{
  "mcpServers": {
    "opencti": {
      "command": "python3",
      "args": [
        "/Users/slacker/mcp/mcp-opencti/opencti_mcp_server_v7.py"
      ],
      "env": {
        "OPENCTI_URL": "http://localhost:8080",
        "OPENCTI_TOKEN": "your-actual-api-token-here"
      }
    }
  }
}
```

**Important**: Replace the values with your actual OpenCTI URL and token.

### Alternative: Using uv (Recommended)

If you have `uv` installed:

```json
{
  "mcpServers": {
    "opencti": {
      "command": "uv",
      "args": [
        "run",
        "/Users/slacker/mcp/mcp-opencti/opencti_mcp_server_v7.py"
      ],
      "env": {
        "OPENCTI_URL": "http://localhost:8080",
        "OPENCTI_TOKEN": "your-actual-api-token-here"
      }
    }
  }
}
```

### Alternative: Using Virtual Environment

If you want to use your virtual environment:

```json
{
  "mcpServers": {
    "opencti": {
      "command": "/Users/slacker/mcp/mcp-opencti/.venv/bin/python",
      "args": [
        "/Users/slacker/mcp/mcp-opencti/opencti_mcp_server_v7.py"
      ],
      "env": {
        "OPENCTI_URL": "http://localhost:8080",
        "OPENCTI_TOKEN": "your-actual-api-token-here"
      }
    }
  }
}
```

## Step 4: Restart Claude Desktop

After editing the configuration:

1. **Quit Claude Desktop completely** (Cmd+Q on macOS)
2. **Restart Claude Desktop**
3. The MCP server should now be available

## Step 5: Verify Connection

In Claude Desktop, try asking:

```
"Search for threat actors related to APT28"
```

or

```
"What are the top 10 threat actors targeting the Financial Sector?"
```

Claude should now use the OpenCTI MCP tools to answer your questions.

## Troubleshooting

### Server Not Appearing

**Issue**: MCP server doesn't show up in Claude Desktop

**Solutions**:
1. Check the configuration file syntax (must be valid JSON)
2. Verify file paths are absolute, not relative
3. Restart Claude Desktop completely
4. Check Claude Desktop logs

### Connection Errors

**Issue**: "OPENCTI_TOKEN environment variable must be set"

**Solutions**:
1. Verify your token is correct in the config
2. Ensure no extra quotes or spaces
3. Check the token is active in OpenCTI

**Issue**: Connection timeout

**Solutions**:
1. Verify `OPENCTI_URL` is correct
2. Ensure OpenCTI is running and accessible
3. Check firewall/network settings

### Python Path Issues

**Issue**: "python3: command not found"

**Solutions**:
1. Use full path to Python: `/usr/local/bin/python3`
2. Or use virtual environment path: `/Users/slacker/mcp/mcp-opencti/.venv/bin/python`

### Import Errors

**Issue**: "ModuleNotFoundError: No module named 'mcp'"

**Solutions**:
1. Ensure dependencies are installed: `pip install -r requirements.txt`
2. Use the virtual environment Python path in the config
3. Verify the virtual environment is activated when installing

## Testing the Server Manually

Before configuring Claude Desktop, test the server works:

```bash
cd /Users/slacker/mcp/mcp-opencti
source .venv/bin/activate

export OPENCTI_URL="http://localhost:8080"
export OPENCTI_TOKEN="your-token-here"

python3 opencti_mcp_server_v7.py
```

The server should start without errors.

## Complete Configuration Example

Here's a complete `claude_desktop_config.json` example:

```json
{
  "mcpServers": {
    "opencti": {
      "command": "/Users/slacker/mcp/mcp-opencti/.venv/bin/python",
      "args": [
        "/Users/slacker/mcp/mcp-opencti/opencti_mcp_server_v7.py"
      ],
      "env": {
        "OPENCTI_URL": "http://localhost:8080",
        "OPENCTI_TOKEN": "xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx"
      }
    }
  }
}
```

## Usage Examples in Claude Desktop

Once configured, you can ask Claude:

### Sector Analysis
```
"What are the top 10 threat actors targeting Healthcare?"
"Show me the latest threat reports about the Financial sector"
```

### TTP Analysis
```
"What TTPs does APT28 use?"
"What attack patterns are associated with Lazarus Group?"
```

### Threat Actor Profiling
```
"Create a comprehensive profile of APT29"
"What malware does APT28 use?"
```

### Temporal Queries
```
"What are the most recent threat reports?"
"Show me the latest reports mentioning APT28"
```

### Search Operations
```
"Search for malware related to ransomware"
"Find vulnerabilities related to CVE-2024"
```

## Advanced Configuration

### Multiple OpenCTI Instances

You can configure multiple OpenCTI instances:

```json
{
  "mcpServers": {
    "opencti-prod": {
      "command": "/Users/slacker/mcp/mcp-opencti/.venv/bin/python",
      "args": [
        "/Users/slacker/mcp/mcp-opencti/opencti_mcp_server_v7.py"
      ],
      "env": {
        "OPENCTI_URL": "https://opencti.production.com",
        "OPENCTI_TOKEN": "prod-token"
      }
    },
    "opencti-dev": {
      "command": "/Users/slacker/mcp/mcp-opencti/.venv/bin/python",
      "args": [
        "/Users/slacker/mcp/mcp-opencti/opencti_mcp_server_v7.py"
      ],
      "env": {
        "OPENCTI_URL": "http://localhost:8080",
        "OPENCTI_TOKEN": "dev-token"
      }
    }
  }
}
```

### Adding Other MCP Servers

You can have multiple MCP servers:

```json
{
  "mcpServers": {
    "opencti": {
      "command": "/Users/slacker/mcp/mcp-opencti/.venv/bin/python",
      "args": [
        "/Users/slacker/mcp/mcp-opencti/opencti_mcp_server_v7.py"
      ],
      "env": {
        "OPENCTI_URL": "http://localhost:8080",
        "OPENCTI_TOKEN": "your-token"
      }
    },
    "filesystem": {
      "command": "npx",
      "args": [
        "-y",
        "@modelcontextprotocol/server-filesystem",
        "/Users/slacker/Documents"
      ]
    }
  }
}
```

## Viewing Logs

### Claude Desktop Logs

**macOS**: `~/Library/Logs/Claude/mcp*.log`

Check these logs if the server isn't working:

```bash
tail -f ~/Library/Logs/Claude/mcp*.log
```

### Server Logs

You can add logging to the server for debugging. The server outputs to stderr which Claude Desktop captures.

## Security Best Practices

1. **Never commit** `claude_desktop_config.json` with tokens
2. **Use environment variables** for sensitive data when possible
3. **Restrict API token permissions** in OpenCTI to read-only if possible
4. **Rotate tokens regularly**
5. **Use HTTPS** for production OpenCTI instances

## Getting Help

If you encounter issues:

1. Check the [TESTING.md](TESTING.md) guide
2. Review server logs
3. Test the server manually outside Claude Desktop
4. Open an issue on GitHub with:
   - Claude Desktop version
   - Python version
   - Error messages from logs
   - Your configuration (with tokens redacted)

## Quick Reference

### File Locations
- **Config**: `~/Library/Application Support/Claude/claude_desktop_config.json`
- **Logs**: `~/Library/Logs/Claude/mcp*.log`
- **Server**: `/Users/slacker/mcp/mcp-opencti/opencti_mcp_server_v7.py`

### Common Commands
```bash
# Install dependencies
cd /Users/slacker/mcp/mcp-opencti
pip install -r requirements.txt

# Test server
python3 opencti_mcp_server_v7.py

# View logs
tail -f ~/Library/Logs/Claude/mcp*.log
```

---

**Note**: After any configuration changes, always restart Claude Desktop completely for changes to take effect.
