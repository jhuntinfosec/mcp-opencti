# OpenCTI MCP Server

A comprehensive [Model Context Protocol (MCP)](https://modelcontextprotocol.io/) server for querying and exploring [OpenCTI](https://www.opencti.io/) threat intelligence platforms. This server exposes 26+ tools for advanced threat intelligence queries including sector analysis, TTP mapping, temporal queries, and relationship traversal.

[![Python 3.8+](https://img.shields.io/badge/python-3.8+-blue.svg)](https://www.python.org/downloads/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Code style: black](https://img.shields.io/badge/code%20style-black-000000.svg)](https://github.com/psf/black)

## Features

### 🔍 Entity Search
Search for STIX entities by name or keyword:
- Malware
- Intrusion Sets
- Attack Patterns (MITRE ATT&CK)
- Campaigns
- Vulnerabilities (CVEs)
- Threat Actors
- Tools
- Sectors
- Reports

### 🔗 Relationship Traversal
Navigate relationships between entities:
- Malware used by intrusion sets/threat actors
- Attack patterns (TTPs) used by threat actors
- Vulnerabilities exploited
- Tools employed
- Entities mentioned in reports

### 🏢 Sector-Based Analysis
Answer questions like:
- "What are the top 10 threat actors targeting the Financial Sector?"
- "Which intrusion sets target Healthcare?"

### 🎯 TTP Analysis
Retrieve Tactics, Techniques, and Procedures:
- TTPs used by threat actors
- TTPs used by intrusion sets
- Mapped to MITRE ATT&CK framework

### 📅 Temporal Queries
Get time-sorted intelligence:
- Latest threat reports
- Recent reports mentioning specific sectors
- Recent reports mentioning specific threat actors

### 🕵️ Threat Actor Deep-Dive
Comprehensive threat actor profiling:
- Malware used
- Campaigns attributed
- Vulnerabilities exploited
- TTPs employed
- Recent mentions in reports

## Installation

### Prerequisites

- Python 3.8 or higher
- Access to an OpenCTI instance
- OpenCTI API token

### Quick Start

1. **Clone the repository**:
   ```bash
   git clone https://github.com/yourusername/mcp-opencti.git
   cd mcp-opencti
   ```

2. **Create a virtual environment**:
   ```bash
   python3 -m venv .venv
   source .venv/bin/activate  # On Windows: .venv\Scripts\activate
   ```

3. **Install dependencies**:
   ```bash
   pip install -r requirements.txt
   ```

4. **Configure environment variables**:
   ```bash
   cp .env.example .env
   # Edit .env with your OpenCTI credentials
   ```

5. **Run the server**:
   ```bash
   uv run opencti_mcp_server_v7.py
   ```

## Configuration

### Environment Variables

Create a `.env` file in the project root:

```bash
OPENCTI_URL=http://localhost:8080
OPENCTI_TOKEN=your-api-token-here
```

- **OPENCTI_URL**: Base URL of your OpenCTI instance (default: `http://localhost:8080`)
- **OPENCTI_TOKEN**: Your OpenCTI API token (required)

### Obtaining an OpenCTI API Token

1. Log into your OpenCTI instance
2. Navigate to **Settings** → **Security** → **API Access**
3. Create a new API token with appropriate permissions
4. Copy the token to your `.env` file

## Usage

### Running the Server

#### Using uv (recommended)
```bash
uv run opencti_mcp_server_v7.py
```

#### Using Python directly
```bash
export OPENCTI_URL="http://localhost:8080"
export OPENCTI_TOKEN="your-api-token"
python opencti_mcp_server_v7.py
```

### Integration with MCP Clients

#### Claude Desktop

Add to your Claude Desktop configuration (`~/Library/Application Support/Claude/claude_desktop_config.json` on macOS):

```json
{
  "mcpServers": {
    "opencti": {
      "command": "uv",
      "args": ["run", "/path/to/opencti_mcp_server_v7.py"],
      "env": {
        "OPENCTI_URL": "http://localhost:8080",
        "OPENCTI_TOKEN": "your-api-token"
      }
    }
  }
}
```

#### Goose

```bash
goose mcp add opencti --command "uv run opencti_mcp_server_v7.py"
```

## Available Tools

### Search Tools
- `search_malware(search_term)` - Search for malware
- `search_intrusion_sets(search_term)` - Search for intrusion sets
- `search_attack_patterns(search_term)` - Search for attack patterns
- `search_campaigns(search_term)` - Search for campaigns
- `search_vulnerabilities(search_term)` - Search for CVEs
- `search_threat_actors(search_term)` - Search for threat actors
- `search_tools(search_term)` - Search for tools
- `search_sectors(search_term)` - Search for sectors
- `search_reports(search_term)` - Search for reports

### Relationship Tools
- `get_malwares_of_intrusion_set(name)` - Get malware used by intrusion set
- `get_attack_patterns_of_intrusion_set(name)` - Get attack patterns
- `get_vulnerabilities_of_malware(name)` - Get vulnerabilities exploited
- `get_tools_used_by_intrusion_set(name)` - Get tools used

### Sector Analysis Tools
- `get_threat_actors_targeting_sector(sector, limit)` - Get threat actors by sector
- `get_intrusion_sets_targeting_sector(sector, limit)` - Get intrusion sets by sector

### TTP Analysis Tools
- `get_ttps_of_threat_actor(name)` - Get TTPs used by threat actor
- `get_ttps_of_intrusion_set(name)` - Get TTPs used by intrusion set

### Temporal Query Tools
- `get_latest_reports(limit)` - Get most recent reports
- `get_latest_reports_by_sector(sector, limit)` - Get recent reports by sector
- `get_latest_reports_mentioning_threat_actor(name, limit)` - Get recent reports about threat actor

### Threat Actor Deep-Dive Tools
- `get_malwares_used_by_threat_actor(name)` - Get malware used
- `get_campaigns_by_threat_actor(name)` - Get campaigns attributed
- `get_vulnerabilities_exploited_by_threat_actor(name)` - Get vulnerabilities exploited

### Report Tools
- `get_report_details(title)` - Get detailed report information
- `get_malwares_of_report(title)` - Get malware mentioned in report
- `get_intrusion_sets_of_report(title)` - Get intrusion sets mentioned

## Example Queries

### Sector-Based Analysis
```
"What are the top 10 threat actors targeting the Financial Sector?"
→ Uses: get_threat_actors_targeting_sector("Financial Sector", limit=10)

"What are the latest threat reports about Healthcare?"
→ Uses: get_latest_reports_by_sector("Healthcare", limit=10)
```

### TTP Analysis
```
"What TTPs does APT28 use?"
→ Uses: get_ttps_of_threat_actor("APT28")

"What techniques does APT29 employ?"
→ Uses: get_ttps_of_intrusion_set("APT29")
```

### Threat Actor Profiling
```
"Create a profile of Lazarus Group"
→ Uses multiple tools:
  - get_malwares_used_by_threat_actor("Lazarus Group")
  - get_ttps_of_threat_actor("Lazarus Group")
  - get_campaigns_by_threat_actor("Lazarus Group")
  - get_vulnerabilities_exploited_by_threat_actor("Lazarus Group")
```

### Temporal Queries
```
"What are the most recent threat reports mentioning APT28?"
→ Uses: get_latest_reports_mentioning_threat_actor("APT28", limit=10)
```

## Development

### Running Tests

```bash
# Install test dependencies
pip install -r requirements-test.txt

# Run all tests
pytest test_opencti_mcp_server_v7.py -v

# Run with coverage
pytest test_opencti_mcp_server_v7.py --cov=opencti_mcp_server_v7 --cov-report=html
```

See [TESTING.md](TESTING.md) for detailed testing documentation.

### Code Quality

```bash
# Format code
black opencti_mcp_server_v7.py

# Lint
flake8 opencti_mcp_server_v7.py --max-line-length=120

# Type check
mypy opencti_mcp_server_v7.py --ignore-missing-imports
```

## Architecture

### Data Model

The server leverages OpenCTI's STIX 2.1 data model:

- **Entities**: Malware, Threat Actors, Intrusion Sets, Attack Patterns, etc.
- **Relationships**: `uses`, `targets`, `attributed-to`, etc.
- **Sectors**: Modeled as Identity entities with `identity_class` of "sector"
- **TTPs**: Represented as Attack-Pattern entities (MITRE ATT&CK)

### Design Patterns

1. **Single Client Instance**: Reuses one OpenCTI client for all requests
2. **Lazy Initialization**: Client created on module load
3. **Graceful Degradation**: Returns empty results instead of errors
4. **Flexible Matching**: Exact name matching with fallback to fuzzy search
5. **Consistent Return Types**: All tools return lists of dictionaries

## Troubleshooting

### Connection Issues

**Error**: `OPENCTI_TOKEN environment variable must be set`
- **Solution**: Ensure your `.env` file exists and contains the token

**Error**: Connection timeout
- **Solution**: Check that your `OPENCTI_URL` is correct and OpenCTI is running

### Empty Results

**Issue**: Tools return empty lists
- **Possible causes**:
  - Entity doesn't exist in your OpenCTI instance
  - Exact name mismatch (try using search tools first)
  - No relationships exist between entities

**Solution**: Use search tools to find exact entity names:
```python
search_threat_actors("APT")  # Find all APT groups
```

### Performance

**Issue**: Slow queries
- **Solution**: Reduce the `limit` parameter for large result sets
- **Tip**: Latest reports queries can be slow with high limits

## Contributing

Contributions are welcome! Please:

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/amazing-feature`)
3. Write tests for new functionality
4. Ensure all tests pass (`pytest`)
5. Format code with Black (`black .`)
6. Commit your changes (`git commit -m 'Add amazing feature'`)
7. Push to the branch (`git push origin feature/amazing-feature`)
8. Open a Pull Request

## Documentation

- [NEW_FEATURES.md](NEW_FEATURES.md) - Detailed feature documentation
- [TESTING.md](TESTING.md) - Testing guide
- [TEST_SUMMARY.md](TEST_SUMMARY.md) - Test coverage summary
- [CHANGELOG.md](CHANGELOG.md) - Version history

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## Acknowledgments

- [OpenCTI](https://www.opencti.io/) - Open Cyber Threat Intelligence Platform
- [Model Context Protocol](https://modelcontextprotocol.io/) - MCP specification
- [pycti](https://github.com/OpenCTI-Platform/client-python) - OpenCTI Python client

## Support

- **Issues**: [GitHub Issues](https://github.com/yourusername/mcp-opencti/issues)
- **OpenCTI Documentation**: https://docs.opencti.io/
- **MCP Documentation**: https://modelcontextprotocol.io/

## Roadmap

- [ ] Geographic filtering (threat actors by origin country)
- [ ] Confidence scoring filters
- [ ] Date range filtering for reports
- [ ] Aggregate statistics and counting
- [ ] Graph visualization export
- [ ] Bulk query operations
- [ ] Custom field selection
- [ ] Pagination support for large result sets

## Authors

- https://www.jhuntinfosec.com

## Version

Current version: 1.0.0

See [CHANGELOG.md](CHANGELOG.md) for version history.
