"""
OpenCTI MCP Server
===================

This script implements a Model Context Protocol (MCP) server that
exposes multiple tools for working with the OpenCTI platform.  The tools
implemented here mirrors the behaviour of the Python example
`get_malwares_of_intrusion_set.py` from the `OpenCTI-Platform/client-python`
repository.  Given the name of an intrusion set, the tool ensures the
intrusion set exists (creating it if necessary) and then returns the
malware objects linked to it through STIX relationships.

To run the server you need to provide two environment variables:

* ``OPENCTI_URL`` – Base URL of your OpenCTI instance (defaults to
  ``http://localhost:8080`` when unset).
* ``OPENCTI_TOKEN`` – API token for authenticating with your OpenCTI instance.

For local testing you can run the server via ``uv`` (the recommended
process manager used by the MCP Python SDK):

.. code-block:: shell

    # create a virtual environment and install dependencies first
    python3 -m venv .venv
    source .venv/bin/activate
    pip install mcp[fastmcp] pycti

    # set the required environment variables
    export OPENCTI_URL="http://localhost:8080"
    export OPENCTI_TOKEN="<your-opencti-api-token>"

    # start the MCP server using the stdio transport
    uv run opencti_mcp_server.py

When adding this server to Goose as a command‑line extension, use
``uv run opencti_mcp_server.py`` as the command.  See the accompanying
documentation for full setup instructions.
"""

from __future__ import annotations

import os
from typing import Any, Dict, List, Optional

from mcp.server.fastmcp import FastMCP
from pycti import OpenCTIApiClient


def _create_opencti_client() -> OpenCTIApiClient:
    """Initialise an OpenCTI API client using environment variables.

    Returns
    -------
    pycti.OpenCTIApiClient
        An authenticated client configured with ``OPENCTI_URL`` and
        ``OPENCTI_TOKEN``.

    Raises
    ------
    RuntimeError
        If the ``OPENCTI_TOKEN`` variable is not set.
    """
    api_url = os.environ.get("OPENCTI_URL", "http://localhost:8080")
    api_token = os.environ.get("OPENCTI_TOKEN")
    if not api_token:
        raise RuntimeError(
            "OPENCTI_TOKEN environment variable must be set to authenticate with OpenCTI"
        )
    return OpenCTIApiClient(api_url, api_token)


# Instantiate the MCP server.  The name and instructions will be exposed to
# clients (e.g. Goose) to help them understand what capabilities are
# available.
mcp = FastMCP(
    name="OpenCTI MCP Server",
    instructions=(
        "This server exposes a comprehensive suite of tools for querying and exploring an "
        "OpenCTI instance via the Python client. It supports:\n\n"
        "1. Entity Search: Search for STIX entities (malware, intrusion sets, attack patterns, "
        "campaigns, vulnerabilities, threat actors, tools, sectors, and reports) by name or keyword.\n\n"
        "2. Relationship Traversal: Navigate relationships between entities (e.g., malwares used by "
        "intrusion sets, attack patterns/TTPs used by threat actors, vulnerabilities exploited, "
        "tools employed, and entities mentioned in reports).\n\n"
        "3. Sector-Based Analysis: Query threat actors and intrusion sets targeting specific sectors "
        "(e.g., 'What are the top 10 threat actors targeting the Financial Sector?').\n\n"
        "4. TTP Analysis: Retrieve TTPs (Tactics, Techniques, Procedures) used by threat actors "
        "and intrusion sets, mapped to MITRE ATT&CK framework.\n\n"
        "5. Temporal Queries: Get the most recent threat reports, optionally filtered by sector, "
        "threat actor, or other criteria, sorted by publication date.\n\n"
        "The server does not create new entities automatically; if an entity is not found, "
        "an empty result is returned. Set the OPENCTI_URL and OPENCTI_TOKEN environment "
        "variables before starting the server to authenticate to your OpenCTI instance."
    ),
)


# Initialize the OpenCTI client once when the module is loaded.  Reusing the
# same client instance avoids reconnecting on every tool call.  If the
# environment variables are missing, initialisation will fail with a
# descriptive error.
_cti_client = _create_opencti_client()


def _format_aliases(alias_list: Optional[List[str]]) -> str:
    """Convert a list of aliases to a comma-separated string.
    
    Parameters
    ----------
    alias_list : list of str or None
        List of alias strings, or None if no aliases exist.
    
    Returns
    -------
    str
        Comma-separated string of aliases, or empty string if None or empty list.
    """
    if not alias_list:
        return ""
    if isinstance(alias_list, list):
        return ", ".join(alias_list)
    return str(alias_list)


def _format_entity_with_aliases(entity: Dict[str, Any]) -> Dict[str, str]:
    """Extract and format common entity fields including aliases.
    
    Parameters
    ----------
    entity : dict
        Raw entity dictionary from OpenCTI API.
    
    Returns
    -------
    dict
        Formatted dictionary with stix_id, name, aliases, and description fields.
    """
    return {
        "stix_id": entity.get("stix_id", ""),
        "name": entity.get("name", ""),
        "aliases": _format_aliases(entity.get("aliases")),
        "description": entity.get("description") or "",
    }


def _format_relationship_target(relationship: Dict[str, Any]) -> Dict[str, str]:
    """Extract target object details from a STIX relationship.
    
    Parameters
    ----------
    relationship : dict
        A STIX core relationship dictionary containing a 'to' field.
    
    Returns
    -------
    dict
        Dictionary with stix_id and name of the target object.
    """
    to_obj = relationship.get("to", {})
    return {
        "stix_id": to_obj.get("stix_id", ""),
        "name": to_obj.get("name", ""),
    }


def _find_entity_by_name(
    entity_type: str,
    entity_name: str,
) -> Optional[Dict[str, Any]]:
    """Find an entity by name using OpenCTI filters.
    
    Parameters
    ----------
    entity_type : str
        The entity type (e.g., 'intrusion_set', 'malware', 'report').
    entity_name : str
        The name to search for.
    
    Returns
    -------
    dict or None
        The entity dictionary if found, None otherwise.
    """
    entity_client = getattr(_cti_client, entity_type)
    return entity_client.read(
        filters={
            "mode": "and",
            "filters": [{"key": "name", "values": [entity_name]}],
            "filterGroups": [],
        }
    )


def _get_related_entities(
    from_entity_id: str,
    to_types: List[str],
) -> List[Dict[str, str]]:
    """Fetch entities related to a source entity via STIX relationships.

    Parameters
    ----------
    from_entity_id : str
        Internal OpenCTI ID of the source entity.
    to_types : list of str
        List of target entity types to filter (e.g., ['Malware', 'Tool']).

    Returns
    -------
    list of dict
        List of related entities with stix_id and name fields.
    """
    relations = _cti_client.stix_core_relationship.list(
        fromId=from_entity_id,
        toTypes=to_types,
    )
    return [_format_relationship_target(rel) for rel in relations]


def _get_reverse_related_entities(
    to_entity_id: str,
    from_types: List[str],
) -> List[Dict[str, str]]:
    """Fetch entities related to a target entity via reverse STIX relationships.

    This function finds entities that point TO the specified entity, rather than
    entities that the specified entity points to.

    Parameters
    ----------
    to_entity_id : str
        Internal OpenCTI ID of the target entity.
    from_types : list of str
        List of source entity types to filter (e.g., ['Threat-Actor', 'Intrusion-Set']).

    Returns
    -------
    list of dict
        List of related entities with stix_id and name fields.
    """
    relations = _cti_client.stix_core_relationship.list(
        toId=to_entity_id,
        fromTypes=from_types,
    )
    # For reverse relationships, we want the 'from' object
    results = []
    for rel in relations:
        from_obj = rel.get("from", {})
        results.append({
            "stix_id": from_obj.get("stix_id", ""),
            "name": from_obj.get("name", ""),
        })
    return results


def _find_entity_by_filter(
    entity_type: str,
    filters: Dict[str, Any],
    order_by: Optional[str] = None,
    order_mode: str = "desc",
    limit: int = 10,
) -> List[Dict[str, Any]]:
    """Find entities using OpenCTI filters with sorting and limiting.

    Parameters
    ----------
    entity_type : str
        The entity type (e.g., 'threat_actor', 'report').
    filters : dict
        OpenCTI filter structure with mode, filters, and filterGroups.
    order_by : str, optional
        Field name to sort by (e.g., 'created', 'published').
    order_mode : str
        Sort direction: 'asc' or 'desc' (default: 'desc').
    limit : int
        Maximum number of results to return (default: 10).

    Returns
    -------
    list of dict
        List of matching entities.
    """
    entity_client = getattr(_cti_client, entity_type)
    kwargs = {
        "filters": filters,
        "first": limit,
    }
    if order_by:
        kwargs["orderBy"] = order_by
        kwargs["orderMode"] = order_mode

    return entity_client.list(**kwargs)


@mcp.tool()
def get_malwares_of_intrusion_set(intrusion_set_name: str) -> List[Dict[str, str]]:
    """Return malwares linked to a given intrusion set, creating the set if needed.

    This tool replicates the behaviour of the
    ``examples/get_malwares_of_intrusion_set.py`` example from the
    `OpenCTI-Platform/client-python` repository.  Given the name of an
    intrusion set it will:

    1. Check whether an intrusion set with the given name already exists.
    2. If none exists, create a new intrusion set with the current timestamp
       as both the ``first_seen`` and ``last_seen`` fields and a basic
       description.  The ``update=True`` flag means the call is idempotent
       when the intrusion set already exists.
    3. Query all STIX core relationships from the intrusion set to objects of
       type ``Malware``.
    4. Return a list of dictionaries, each containing the ``stix_id`` and
       ``name`` of the linked malware.

    Parameters
    ----------
    intrusion_set_name: str
        The human‑readable name of the intrusion set to look up or create
        (for example ``"APT28"``).

    Returns
    -------
    list of dict
        A list where each element has two keys: ``stix_id`` and ``name``.  If
        the intrusion set has no linked malware, the list will be empty.

    Raises
    ------
    RuntimeError
        If the OpenCTI client could not be initialised due to missing
        environment variables.
    """
    # Ensure we have a valid API client.  This will raise if the token is
    # missing, so that users get a clear error rather than a cryptic failure
    # downstream.
    cti = _cti_client

    # Look up the intrusion set by name.  The OpenCTI API supports complex
    # filter structures; see the OpenCTI documentation for details.  Here we
    # search by the ``name`` attribute.  If there is no match the client
    # returns ``None``.
    intrusion_set = _find_entity_by_name("intrusion_set", intrusion_set_name)

    # If the intrusion set doesn't exist, return an empty list rather than
    # creating a new one.  The original example created intrusion sets on
    # demand, but this server now avoids automatic creation to preserve
    # database integrity.
    if intrusion_set is None:
        return []

    # Fetch all STIX core relationships from this intrusion set to Malware objects
    return _get_related_entities(intrusion_set["id"], ["Malware"])


@mcp.tool()
def search_malware(search_term: str) -> List[Dict[str, str]]:
    """Search for malware in OpenCTI and return details.

    This tool allows a user to search for malware objects in OpenCTI by
    specifying a search term.  It uses the `malware.list` endpoint of
    the `pycti` client to perform a fuzzy search.  For each matching
    malware the tool returns key details such as the STIX identifier,
    name, aliases and description.

    Parameters
    ----------
    search_term: str
        A string to match against malware names, aliases and
        descriptions (e.g. "windows", "credential", "APT28").

    Returns
    -------
    list of dict
        A list of dictionaries where each entry contains information
        about a malware object: ``stix_id`` (the primary STIX
        identifier), ``name`` (primary name), ``aliases`` (list of
        alternative names) and ``description``.
    """
    cti = _cti_client
    # Perform the search.  ``malware.list`` accepts a ``search`` parameter
    # which performs a full‑text search across malware objects.  It
    # returns a list of malware dictionaries.
    malwares = cti.malware.list(search=search_term)
    return [_format_entity_with_aliases(malware) for malware in malwares]


# ---------------------------------------------------------------------------
# Entity search tools
# These tools perform full‑text searches on various OpenCTI entity types.  They
# return lists of simplified objects containing a few key fields.  Each tool
# follows the same pattern: call the appropriate ``list`` method with a
# ``search`` parameter, then collapse alias lists into comma‑separated
# strings and extract the description.


@mcp.tool()
def search_intrusion_sets(search_term: str) -> List[Dict[str, str]]:
    """Search for intrusion sets by a free‑text term.

    Parameters
    ----------
    search_term: str
        Text to match against intrusion set names, aliases and descriptions.

    Returns
    -------
    list of dict
        Each entry contains ``stix_id``, ``name``, ``aliases`` and
        ``description`` for a matching intrusion set.
    """
    cti = _cti_client
    intrusion_sets = cti.intrusion_set.list(search=search_term)
    return [_format_entity_with_aliases(iset) for iset in intrusion_sets]


@mcp.tool()
def search_attack_patterns(search_term: str) -> List[Dict[str, str]]:
    """Search for attack patterns (MITRE techniques) by text.

    Parameters
    ----------
    search_term: str
        Text to search within attack pattern names and descriptions.

    Returns
    -------
    list of dict
        A list of attack patterns with their STIX ID, name and description.
    """
    cti = _cti_client
    patterns = cti.attack_pattern.list(search=search_term)
    return [_format_entity_with_aliases(pattern) for pattern in patterns]


@mcp.tool()
def search_campaigns(search_term: str) -> List[Dict[str, str]]:
    """Search for campaigns in OpenCTI.

    Parameters
    ----------
    search_term: str
        Text to search for within campaign names and descriptions.

    Returns
    -------
    list of dict
        Each entry contains the campaign's STIX ID, name and description.
    """
    cti = _cti_client
    campaigns = cti.campaign.list(search=search_term)
    return [_format_entity_with_aliases(camp) for camp in campaigns]


@mcp.tool()
def search_vulnerabilities(search_term: str) -> List[Dict[str, str]]:
    """Search for vulnerabilities (e.g. CVEs) by text.

    Parameters
    ----------
    search_term: str
        Text to search within vulnerability names (e.g. CVE IDs) and
        descriptions.

    Returns
    -------
    list of dict
        List of vulnerabilities with STIX ID, name and description.
    """
    cti = _cti_client
    vulnerabilities = cti.vulnerability.list(search=search_term)
    return [_format_entity_with_aliases(vuln) for vuln in vulnerabilities]


@mcp.tool()
def search_threat_actors(search_term: str) -> List[Dict[str, str]]:
    """Search for threat actors by name or description.

    Parameters
    ----------
    search_term: str
        Text to search within threat actor names, aliases and descriptions.

    Returns
    -------
    list of dict
        List of threat actors with STIX ID, name and description.
    """
    cti = _cti_client
    actors = cti.threat_actor.list(search=search_term)
    return [_format_entity_with_aliases(actor) for actor in actors]


@mcp.tool()
def search_tools(search_term: str) -> List[Dict[str, str]]:
    """Search for tools (legitimate utilities or hacker tools) in OpenCTI.

    Parameters
    ----------
    search_term: str
        Text to search within tool names and descriptions.

    Returns
    -------
    list of dict
        A list of tools with STIX ID, name and description.
    """
    cti = _cti_client
    tools = cti.tool.list(search=search_term)
    return [_format_entity_with_aliases(tool_obj) for tool_obj in tools]


# ---------------------------------------------------------------------------
# Relationship‑based tools
# These tools traverse STIX relationships to fetch objects related to a given
# entity.  They use ``stix_core_relationship.list`` with the source object's
# internal OpenCTI ID and the desired target type.  If the source object
# cannot be found the tools return an empty list.


@mcp.tool()
def get_attack_patterns_of_intrusion_set(intrusion_set_name: str) -> List[Dict[str, str]]:
    """Return attack patterns linked to an intrusion set.

    Parameters
    ----------
    intrusion_set_name: str
        The name of the intrusion set for which to list associated attack patterns.

    Returns
    -------
    list of dict
        A list of attack patterns (MITRE techniques) with their STIX ID and name.
    """
    intrusion_set = _find_entity_by_name("intrusion_set", intrusion_set_name)
    if intrusion_set is None:
        return []
    return _get_related_entities(intrusion_set["id"], ["Attack-Pattern"])


@mcp.tool()
def get_vulnerabilities_of_malware(malware_name: str) -> List[Dict[str, str]]:
    """Return vulnerabilities linked to a given malware.

    Parameters
    ----------
    malware_name: str
        The name of the malware to look up.

    Returns
    -------
    list of dict
        List of vulnerabilities with STIX ID and name.
    """
    malware = _find_entity_by_name("malware", malware_name)
    if malware is None:
        return []
    return _get_related_entities(malware["id"], ["Vulnerability"])


@mcp.tool()
def get_tools_used_by_intrusion_set(intrusion_set_name: str) -> List[Dict[str, str]]:
    """Return tools associated with an intrusion set.

    Parameters
    ----------
    intrusion_set_name: str
        Name of the intrusion set whose tools you want to list.

    Returns
    -------
    list of dict
        List of tools with STIX ID and name.
    """
    intrusion_set = _find_entity_by_name("intrusion_set", intrusion_set_name)
    if intrusion_set is None:
        return []
    return _get_related_entities(intrusion_set["id"], ["Tool"])


# ---------------------------------------------------------------------------
# Report tools
# Tools for searching, retrieving and traversing objects related to reports.


@mcp.tool()
def search_reports(search_term: str) -> List[Dict[str, str]]:
    """Search for reports by a free‑text term.

    Parameters
    ----------
    search_term: str
        Text to match against report titles, abstracts and descriptions.

    Returns
    -------
    list of dict
        List of reports with their STIX ID, name (title), published date and description.
    """
    cti = _cti_client
    reports = cti.report.list(search=search_term)
    results: List[Dict[str, str]] = []
    for report in reports:
        # Extract a published date if present; convert None to empty string
        published = report.get("published") or ""
        # Convert list of labels into comma‑separated string, if needed
        labels = report.get("objectMarking", [])  # not sure; the API may use `report.get("labels")`
        # Use generic field `labels` if available; fallback to empty list
        labels = report.get("labels") or []
        labels_str = ", ".join(labels) if isinstance(labels, list) else str(labels)
        results.append(
            {
                "stix_id": report.get("stix_id", ""),
                "name": report.get("name", ""),
                "published": published,
                "labels": labels_str,
                "description": report.get("description") or "",
            }
        )
    return results


@mcp.tool()
def get_report_details(report_title: str) -> Dict[str, str]:
    """Return detailed information about a single report.

    Parameters
    ----------
    report_title: str
        The exact title (name) of the report to retrieve.

    Returns
    -------
    dict
        A dictionary containing the report's STIX ID, name, published date,
        labels and description.  If no report matches the name, all fields
        are empty strings.
    """
    report = _find_entity_by_name("report", report_title)
    if report is None:
        return {"stix_id": "", "name": "", "published": "", "labels": "", "description": ""}
    # Extract labels; in report objects, `labels` may be a list of strings
    labels = report.get("labels") or []
    labels_str = ", ".join(labels) if isinstance(labels, list) else str(labels)
    return {
        "stix_id": report.get("stix_id", ""),
        "name": report.get("name", ""),
        "published": report.get("published", ""),
        "labels": labels_str,
        "description": report.get("description") or "",
    }


@mcp.tool()
def get_malwares_of_report(report_title: str) -> List[Dict[str, str]]:
    """Return malware objects referenced in a report.

    Parameters
    ----------
    report_title: str
        The title of the report whose malware you want to list.

    Returns
    -------
    list of dict
        A list of malware with STIX ID and name.  Returns an empty list
        if the report is not found.
    """
    report = _find_entity_by_name("report", report_title)
    if report is None:
        return []
    return _get_related_entities(report["id"], ["Malware"])


@mcp.tool()
def get_intrusion_sets_of_report(report_title: str) -> List[Dict[str, str]]:
    """Return intrusion sets referenced in a report.

    Parameters
    ----------
    report_title: str
        Title of the report whose intrusion sets you want to list.

    Returns
    -------
    list of dict
        List of intrusion sets with STIX ID and name.  Returns an empty list
        if the report cannot be found.
    """
    report = _find_entity_by_name("report", report_title)
    if report is None:
        return []
    return _get_related_entities(report["id"], ["Intrusion-Set"])


# ---------------------------------------------------------------------------
# Advanced query tools
# These tools support more sophisticated queries including sector-based
# filtering, TTP analysis, and time-based report searches.


@mcp.tool()
def get_threat_actors_targeting_sector(sector_name: str, limit: int = 10) -> List[Dict[str, str]]:
    """Return threat actors that target a specific sector.

    This tool finds threat actors that have relationships to a given sector
    (e.g., "Financial", "Healthcare", "Government"). In OpenCTI, sectors are
    modeled as Identity entities, and threat actors have "targets" relationships
    to them.

    Parameters
    ----------
    sector_name: str
        The name of the sector to search for (e.g., "Financial Sector",
        "Healthcare", "Energy").
    limit: int
        Maximum number of threat actors to return (default: 10).

    Returns
    -------
    list of dict
        List of threat actors with STIX ID and name. Returns an empty list
        if the sector is not found or has no targeting threat actors.
    """
    # First, find the sector (Identity entity with sector class)
    sector = _cti_client.identity.read(
        filters={
            "mode": "and",
            "filters": [{"key": "name", "values": [sector_name]}],
            "filterGroups": [],
        }
    )

    if sector is None:
        # Try a broader search if exact name doesn't match
        sectors = _cti_client.identity.list(search=sector_name, first=1)
        if not sectors:
            return []
        sector = sectors[0]

    # Find threat actors that target this sector
    return _get_reverse_related_entities(sector["id"], ["Threat-Actor"])[:limit]


@mcp.tool()
def get_intrusion_sets_targeting_sector(sector_name: str, limit: int = 10) -> List[Dict[str, str]]:
    """Return intrusion sets that target a specific sector.

    Parameters
    ----------
    sector_name: str
        The name of the sector to search for (e.g., "Financial Sector",
        "Healthcare", "Government").
    limit: int
        Maximum number of intrusion sets to return (default: 10).

    Returns
    -------
    list of dict
        List of intrusion sets with STIX ID and name.
    """
    # First, find the sector (Identity entity)
    sector = _cti_client.identity.read(
        filters={
            "mode": "and",
            "filters": [{"key": "name", "values": [sector_name]}],
            "filterGroups": [],
        }
    )

    if sector is None:
        # Try a broader search if exact name doesn't match
        sectors = _cti_client.identity.list(search=sector_name, first=1)
        if not sectors:
            return []
        sector = sectors[0]

    # Find intrusion sets that target this sector
    return _get_reverse_related_entities(sector["id"], ["Intrusion-Set"])[:limit]


@mcp.tool()
def get_ttps_of_threat_actor(threat_actor_name: str) -> List[Dict[str, str]]:
    """Return TTPs (attack patterns) used by a specific threat actor.

    TTPs (Tactics, Techniques, and Procedures) are represented in OpenCTI
    as attack patterns, typically mapped to the MITRE ATT&CK framework.

    Parameters
    ----------
    threat_actor_name: str
        The name of the threat actor to query.

    Returns
    -------
    list of dict
        List of attack patterns (TTPs) with STIX ID and name.
    """
    threat_actor = _find_entity_by_name("threat_actor", threat_actor_name)
    if threat_actor is None:
        return []
    return _get_related_entities(threat_actor["id"], ["Attack-Pattern"])


@mcp.tool()
def get_ttps_of_intrusion_set(intrusion_set_name: str) -> List[Dict[str, str]]:
    """Return TTPs (attack patterns) used by a specific intrusion set.

    This is an alias for get_attack_patterns_of_intrusion_set with clearer
    naming for TTP-focused queries.

    Parameters
    ----------
    intrusion_set_name: str
        The name of the intrusion set to query.

    Returns
    -------
    list of dict
        List of attack patterns (TTPs) with STIX ID and name.
    """
    return get_attack_patterns_of_intrusion_set(intrusion_set_name)


@mcp.tool()
def get_latest_reports_by_sector(sector_name: str, limit: int = 10) -> List[Dict[str, str]]:
    """Return the most recent threat reports that mention a specific sector.

    Parameters
    ----------
    sector_name: str
        The name or keyword for the sector (e.g., "financial", "healthcare").
    limit: int
        Maximum number of reports to return (default: 10).

    Returns
    -------
    list of dict
        List of reports sorted by published date (most recent first), with
        STIX ID, name, published date, labels, and description.
    """
    # Search for reports mentioning the sector and sort by published date
    reports = _cti_client.report.list(
        search=sector_name,
        orderBy="published",
        orderMode="desc",
        first=limit
    )

    results: List[Dict[str, str]] = []
    for report in reports:
        published = report.get("published") or ""
        labels = report.get("labels") or []
        labels_str = ", ".join(labels) if isinstance(labels, list) else str(labels)
        results.append({
            "stix_id": report.get("stix_id", ""),
            "name": report.get("name", ""),
            "published": published,
            "labels": labels_str,
            "description": report.get("description") or "",
        })
    return results


@mcp.tool()
def get_latest_reports_mentioning_threat_actor(threat_actor_name: str, limit: int = 10) -> List[Dict[str, str]]:
    """Return the most recent reports that mention a specific threat actor.

    Parameters
    ----------
    threat_actor_name: str
        The name of the threat actor.
    limit: int
        Maximum number of reports to return (default: 10).

    Returns
    -------
    list of dict
        List of reports sorted by published date (most recent first).
    """
    # First find the threat actor
    threat_actor = _find_entity_by_name("threat_actor", threat_actor_name)
    if threat_actor is None:
        # Fallback to text search if exact name doesn't match
        reports = _cti_client.report.list(
            search=threat_actor_name,
            orderBy="published",
            orderMode="desc",
            first=limit
        )
    else:
        # Get reports that reference this threat actor via relationships
        relations = _cti_client.stix_core_relationship.list(
            fromId=threat_actor["id"],
            toTypes=["Report"],
        )
        # Also check reverse relationships (reports referencing the actor)
        reverse_relations = _cti_client.stix_core_relationship.list(
            toId=threat_actor["id"],
            fromTypes=["Report"],
        )

        # Collect all report IDs
        report_ids = []
        for rel in relations:
            to_obj = rel.get("to", {})
            if to_obj.get("id"):
                report_ids.append(to_obj["id"])
        for rel in reverse_relations:
            from_obj = rel.get("from", {})
            if from_obj.get("id"):
                report_ids.append(from_obj["id"])

        # Fetch the actual reports and sort by published date
        reports = []
        for report_id in set(report_ids):  # deduplicate
            report = _cti_client.report.read(id=report_id)
            if report:
                reports.append(report)

        # Sort by published date (most recent first)
        reports.sort(key=lambda r: r.get("published") or "", reverse=True)
        reports = reports[:limit]

    results: List[Dict[str, str]] = []
    for report in reports:
        published = report.get("published") or ""
        labels = report.get("labels") or []
        labels_str = ", ".join(labels) if isinstance(labels, list) else str(labels)
        results.append({
            "stix_id": report.get("stix_id", ""),
            "name": report.get("name", ""),
            "published": published,
            "labels": labels_str,
            "description": report.get("description") or "",
        })
    return results


@mcp.tool()
def get_latest_reports(limit: int = 10) -> List[Dict[str, str]]:
    """Return the most recent threat reports from OpenCTI.

    Parameters
    ----------
    limit: int
        Maximum number of reports to return (default: 10).

    Returns
    -------
    list of dict
        List of reports sorted by published date (most recent first).
    """
    reports = _cti_client.report.list(
        orderBy="published",
        orderMode="desc",
        first=limit
    )

    results: List[Dict[str, str]] = []
    for report in reports:
        published = report.get("published") or ""
        labels = report.get("labels") or []
        labels_str = ", ".join(labels) if isinstance(labels, list) else str(labels)
        results.append({
            "stix_id": report.get("stix_id", ""),
            "name": report.get("name", ""),
            "published": published,
            "labels": labels_str,
            "description": report.get("description") or "",
        })
    return results


@mcp.tool()
def get_malwares_used_by_threat_actor(threat_actor_name: str) -> List[Dict[str, str]]:
    """Return malware used by a specific threat actor.

    Parameters
    ----------
    threat_actor_name: str
        The name of the threat actor.

    Returns
    -------
    list of dict
        List of malware with STIX ID and name.
    """
    threat_actor = _find_entity_by_name("threat_actor", threat_actor_name)
    if threat_actor is None:
        return []
    return _get_related_entities(threat_actor["id"], ["Malware"])


@mcp.tool()
def get_campaigns_by_threat_actor(threat_actor_name: str) -> List[Dict[str, str]]:
    """Return campaigns attributed to a specific threat actor.

    Parameters
    ----------
    threat_actor_name: str
        The name of the threat actor.

    Returns
    -------
    list of dict
        List of campaigns with STIX ID and name.
    """
    threat_actor = _find_entity_by_name("threat_actor", threat_actor_name)
    if threat_actor is None:
        return []
    return _get_related_entities(threat_actor["id"], ["Campaign"])


@mcp.tool()
def get_vulnerabilities_exploited_by_threat_actor(threat_actor_name: str) -> List[Dict[str, str]]:
    """Return vulnerabilities exploited by a specific threat actor.

    Parameters
    ----------
    threat_actor_name: str
        The name of the threat actor.

    Returns
    -------
    list of dict
        List of vulnerabilities with STIX ID and name.
    """
    threat_actor = _find_entity_by_name("threat_actor", threat_actor_name)
    if threat_actor is None:
        return []
    return _get_related_entities(threat_actor["id"], ["Vulnerability"])


@mcp.tool()
def search_sectors(search_term: str) -> List[Dict[str, str]]:
    """Search for sectors (industries/verticals) in OpenCTI.

    Sectors are typically modeled as Identity entities with an identity_class
    of "class" or "sector".

    Parameters
    ----------
    search_term: str
        Text to search for within sector names.

    Returns
    -------
    list of dict
        List of sectors with STIX ID, name, and description.
    """
    identities = _cti_client.identity.list(search=search_term)
    results: List[Dict[str, str]] = []
    for identity in identities:
        # Filter to only include sectors (you may need to adjust this based on your OpenCTI setup)
        identity_class = identity.get("identity_class", "")
        if "sector" in identity_class.lower() or "class" in identity_class.lower() or not identity_class:
            results.append({
                "stix_id": identity.get("stix_id", ""),
                "name": identity.get("name", ""),
                "description": identity.get("description") or "",
            })
    return results


if __name__ == "__main__":  # pragma: no cover - only runs when executed directly
    # When executing this file directly (e.g. ``python opencti_mcp_server.py``)
    # start the server using the default stdio transport.  In production you
    # typically launch the server via ``uv run opencti_mcp_server.py`` which
    # enables proper asyncio event loop management and concurrency.
    mcp.run()
