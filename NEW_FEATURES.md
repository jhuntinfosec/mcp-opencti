# OpenCTI MCP Server - New Features

This document describes the new comprehensive functionality added to the OpenCTI MCP server.

## Summary of New Tools

The server now includes **13 new tools** that enable advanced threat intelligence queries:

### 1. Sector-Based Analysis

#### `get_threat_actors_targeting_sector(sector_name, limit=10)`
Find threat actors that target a specific sector.

**Example Query:** "What are the top 10 threat actors that target the Financial Sector?"
```python
get_threat_actors_targeting_sector("Financial Sector", limit=10)
```

#### `get_intrusion_sets_targeting_sector(sector_name, limit=10)`
Find intrusion sets that target a specific sector.

**Example Query:** "Which intrusion sets target the Healthcare sector?"
```python
get_intrusion_sets_targeting_sector("Healthcare", limit=10)
```

#### `search_sectors(search_term)`
Search for sectors/industries in OpenCTI.

**Example Query:** "What sectors are available in the database?"
```python
search_sectors("sector")
```

---

### 2. TTP/Technique Analysis

#### `get_ttps_of_threat_actor(threat_actor_name)`
Get TTPs (attack patterns) used by a threat actor.

**Example Query:** "What TTPs does the threat actor APT28 use?"
```python
get_ttps_of_threat_actor("APT28")
```

#### `get_ttps_of_intrusion_set(intrusion_set_name)`
Get TTPs used by an intrusion set (alias for `get_attack_patterns_of_intrusion_set`).

**Example Query:** "What techniques does APT29 use?"
```python
get_ttps_of_intrusion_set("APT29")
```

---

### 3. Time-Based Report Queries

#### `get_latest_reports(limit=10)`
Get the most recent threat reports.

**Example Query:** "What are the latest threat reports?"
```python
get_latest_reports(limit=10)
```

#### `get_latest_reports_by_sector(sector_name, limit=10)`
Get recent reports mentioning a specific sector.

**Example Query:** "What are the latest threat reports that mention the Energy sector?"
```python
get_latest_reports_by_sector("Energy", limit=10)
```

#### `get_latest_reports_mentioning_threat_actor(threat_actor_name, limit=10)`
Get recent reports mentioning a specific threat actor.

**Example Query:** "What are the most recent threat reports that mention APT28?"
```python
get_latest_reports_mentioning_threat_actor("APT28", limit=10)
```

---

### 4. Threat Actor Deep-Dive Tools

#### `get_malwares_used_by_threat_actor(threat_actor_name)`
Get malware used by a threat actor.

**Example Query:** "What malware does Lazarus Group use?"
```python
get_malwares_used_by_threat_actor("Lazarus Group")
```

#### `get_campaigns_by_threat_actor(threat_actor_name)`
Get campaigns attributed to a threat actor.

**Example Query:** "What campaigns are attributed to APT28?"
```python
get_campaigns_by_threat_actor("APT28")
```

#### `get_vulnerabilities_exploited_by_threat_actor(threat_actor_name)`
Get vulnerabilities exploited by a threat actor.

**Example Query:** "What vulnerabilities does APT29 exploit?"
```python
get_vulnerabilities_exploited_by_threat_actor("APT29")
```

---

## Implementation Details

### New Helper Functions

1. **`_get_reverse_related_entities(to_entity_id, from_types)`**
   - Fetches entities that point TO a target entity (reverse relationships)
   - Used for finding threat actors/intrusion sets that target sectors

2. **`_find_entity_by_filter(entity_type, filters, order_by, order_mode, limit)`**
   - Generic function for filtering and sorting entities
   - Supports complex OpenCTI filter structures
   - Enables ordering by fields like `published`, `created`, etc.

### Key Features

- **Sorting Support**: Reports can be sorted by publication date (most recent first)
- **Relationship Traversal**: Both forward and reverse STIX relationships
- **Flexible Matching**: Exact name matching with fallback to fuzzy search
- **Configurable Limits**: Control the number of results returned (default: 10)

---

## Example Use Cases

### Use Case 1: Sector-Focused Threat Intelligence
"I need to brief executives on threats to our Financial sector operations."

```python
# 1. Find threat actors targeting the sector
threat_actors = get_threat_actors_targeting_sector("Financial Sector", limit=10)

# 2. For each threat actor, get their TTPs
for actor in threat_actors:
    ttps = get_ttps_of_threat_actor(actor["name"])
    malware = get_malwares_used_by_threat_actor(actor["name"])

# 3. Get recent reports about the sector
reports = get_latest_reports_by_sector("Financial", limit=5)
```

### Use Case 2: Threat Actor Profile
"Create a comprehensive profile of APT28."

```python
# Get all information about APT28
ttps = get_ttps_of_threat_actor("APT28")
malware = get_malwares_used_by_threat_actor("APT28")
campaigns = get_campaigns_by_threat_actor("APT28")
vulnerabilities = get_vulnerabilities_exploited_by_threat_actor("APT28")
recent_reports = get_latest_reports_mentioning_threat_actor("APT28", limit=10)
```

### Use Case 3: Sector Threat Landscape
"What's the current threat landscape for Healthcare?"

```python
# 1. Get threat actors
threat_actors = get_threat_actors_targeting_sector("Healthcare", limit=10)

# 2. Get intrusion sets
intrusion_sets = get_intrusion_sets_targeting_sector("Healthcare", limit=10)

# 3. Get recent reports
reports = get_latest_reports_by_sector("Healthcare", limit=10)
```

---

## API Design Patterns

All new tools follow consistent patterns:

1. **Naming Convention**: `get_<what>_<relationship>_<entity>` or `search_<entity>`
2. **Parameters**: Entity names as strings, optional `limit` parameter
3. **Return Type**: List of dictionaries with `stix_id` and `name` fields
4. **Error Handling**: Returns empty list `[]` if entity not found
5. **Documentation**: Complete docstrings with parameters and examples

---

## Testing Recommendations

To test the new functionality:

1. **Start the server**:
   ```bash
   export OPENCTI_URL="http://localhost:8080"
   export OPENCTI_TOKEN="your-token-here"
   uv run opencti_mcp_server_v7.py
   ```

2. **Test sector queries**:
   - Verify sectors exist in your OpenCTI instance
   - Test with common sectors: "Financial Sector", "Healthcare", "Energy", "Government"

3. **Test TTP queries**:
   - Use known threat actors from your instance
   - Verify attack patterns are linked

4. **Test temporal queries**:
   - Check that reports have `published` dates
   - Verify sorting is correct (most recent first)

---

## Notes on OpenCTI Data Model

- **Sectors** are modeled as `Identity` entities with `identity_class` of "sector" or "class"
- **TTPs** are represented as `Attack-Pattern` entities (typically MITRE ATT&CK techniques)
- **Relationships** use STIX Core Relationship types (`targets`, `uses`, etc.)
- **Published dates** on reports enable temporal sorting

---

## Future Enhancements

Potential additions for future versions:

1. **Geographic filtering**: Find threat actors by origin country
2. **Confidence scoring**: Filter relationships by confidence level
3. **Date range filtering**: Get reports within specific time periods
4. **Aggregate statistics**: Count relationships, group by type
5. **Graph visualization**: Export relationship graphs
6. **Bulk queries**: Query multiple entities at once
