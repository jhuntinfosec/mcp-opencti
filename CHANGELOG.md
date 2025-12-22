# Changelog

All notable changes to the OpenCTI MCP Server project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [1.0.0] - 2025-12-22

### Added
- Initial release of OpenCTI MCP Server
- **26+ MCP tools** for comprehensive threat intelligence querying
- **Entity Search Tools**:
  - `search_malware()` - Search for malware by keyword
  - `search_intrusion_sets()` - Search for intrusion sets
  - `search_attack_patterns()` - Search for MITRE ATT&CK techniques
  - `search_campaigns()` - Search for campaigns
  - `search_vulnerabilities()` - Search for CVEs
  - `search_threat_actors()` - Search for threat actors
  - `search_tools()` - Search for tools
  - `search_sectors()` - Search for sectors/industries
  - `search_reports()` - Search for threat reports

- **Relationship Traversal Tools**:
  - `get_malwares_of_intrusion_set()` - Get malware used by intrusion sets
  - `get_attack_patterns_of_intrusion_set()` - Get attack patterns of intrusion sets
  - `get_vulnerabilities_of_malware()` - Get vulnerabilities exploited by malware
  - `get_tools_used_by_intrusion_set()` - Get tools used by intrusion sets

- **Sector Analysis Tools**:
  - `get_threat_actors_targeting_sector()` - Find threat actors by targeted sector
  - `get_intrusion_sets_targeting_sector()` - Find intrusion sets by targeted sector

- **TTP Analysis Tools**:
  - `get_ttps_of_threat_actor()` - Get TTPs used by threat actors
  - `get_ttps_of_intrusion_set()` - Get TTPs used by intrusion sets

- **Temporal Query Tools**:
  - `get_latest_reports()` - Get most recent threat reports
  - `get_latest_reports_by_sector()` - Get recent reports mentioning sectors
  - `get_latest_reports_mentioning_threat_actor()` - Get recent reports about threat actors

- **Threat Actor Deep-Dive Tools**:
  - `get_malwares_used_by_threat_actor()` - Get malware used by threat actors
  - `get_campaigns_by_threat_actor()` - Get campaigns attributed to threat actors
  - `get_vulnerabilities_exploited_by_threat_actor()` - Get vulnerabilities exploited

- **Report Tools**:
  - `get_report_details()` - Get detailed information about a report
  - `get_malwares_of_report()` - Get malware mentioned in a report
  - `get_intrusion_sets_of_report()` - Get intrusion sets mentioned in a report

- **Helper Functions**:
  - `_format_aliases()` - Format alias lists
  - `_format_entity_with_aliases()` - Format entity data
  - `_format_relationship_target()` - Extract relationship targets
  - `_find_entity_by_name()` - Find entities by exact name
  - `_get_related_entities()` - Forward relationship traversal
  - `_get_reverse_related_entities()` - Reverse relationship traversal
  - `_find_entity_by_filter()` - Complex filtering with sorting

- **Features**:
  - Environment variable configuration (OPENCTI_URL, OPENCTI_TOKEN)
  - Single OpenCTI client instance for connection reuse
  - Graceful error handling with empty result returns
  - Flexible name matching with fuzzy search fallback
  - Sorting support for temporal queries (orderBy, orderMode)
  - Configurable result limits

- **Testing**:
  - Comprehensive test suite with 85+ test cases
  - 12 test classes covering all functionality
  - Full mocking - no live OpenCTI instance required
  - Coverage reporting with pytest-cov
  - Edge case and error path testing

- **Documentation**:
  - Comprehensive README.md with examples
  - NEW_FEATURES.md with detailed feature descriptions
  - TESTING.md with testing guide
  - TEST_SUMMARY.md with test coverage overview
  - Complete docstrings for all functions and tools

- **Development Tools**:
  - requirements.txt for production dependencies
  - requirements-test.txt for testing dependencies
  - .gitignore for Python projects
  - .env.example for environment variables
  - pytest.ini for test configuration
  - GitHub Actions workflow for CI/CD

### Security
- API token authentication required
- Environment variable protection for credentials
- No automatic entity creation to preserve database integrity

### Performance
- Connection pooling via single client instance
- Efficient relationship queries
- Configurable result limits to prevent large data transfers

## [Unreleased]

### Planned Features
- Geographic filtering (threat actors by origin country)
- Confidence scoring filters for relationships
- Date range filtering for reports
- Aggregate statistics and counting operations
- Graph visualization export
- Bulk query operations
- Custom field selection in results
- Pagination support for large result sets
- Caching layer for frequently accessed data
- Rate limiting and request throttling

---

## Release Notes

### Version 1.0.0 Highlights

This initial release provides a production-ready MCP server for OpenCTI with comprehensive threat intelligence querying capabilities. The server supports:

- **Use Cases**:
  - Sector-focused threat intelligence gathering
  - Threat actor profiling and analysis
  - TTP (Tactics, Techniques, Procedures) mapping
  - Vulnerability intelligence
  - Temporal threat tracking

- **Integration**:
  - Compatible with Claude Desktop
  - Compatible with Goose
  - Compatible with any MCP-compliant client

- **Quality**:
  - 100% test coverage for critical paths
  - Type hints throughout
  - Comprehensive error handling
  - Production-ready code quality

### Migration Guide

This is the initial release, so no migration is required.

### Breaking Changes

None - initial release.

### Deprecations

None - initial release.

---

[1.0.0]: https://github.com/yourusername/mcp-opencti/releases/tag/v1.0.0
[Unreleased]: https://github.com/yourusername/mcp-opencti/compare/v1.0.0...HEAD
