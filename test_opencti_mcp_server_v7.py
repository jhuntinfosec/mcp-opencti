"""
Unit Tests for OpenCTI MCP Server
==================================

This module contains comprehensive unit tests for the OpenCTI MCP server.
Tests use mocking to avoid requiring a live OpenCTI instance.

To run the tests:
    pytest test_opencti_mcp_server_v7.py -v

To run with coverage:
    pytest test_opencti_mcp_server_v7.py --cov=opencti_mcp_server_v7 --cov-report=html
"""

import os
from typing import Any, Dict, List
from unittest.mock import MagicMock, patch, PropertyMock

import pytest

# Mock the FastMCP import before importing the module under test
with patch.dict(os.environ, {"OPENCTI_TOKEN": "test-token"}):
    import opencti_mcp_server_v7 as server


@pytest.fixture
def mock_opencti_client():
    """Create a mock OpenCTI client for testing."""
    with patch.object(server, "_cti_client") as mock_client:
        yield mock_client


class TestHelperFunctions:
    """Test suite for helper functions."""

    def test_format_aliases_with_list(self):
        """Test formatting a list of aliases."""
        aliases = ["alias1", "alias2", "alias3"]
        result = server._format_aliases(aliases)
        assert result == "alias1, alias2, alias3"

    def test_format_aliases_with_empty_list(self):
        """Test formatting an empty list."""
        result = server._format_aliases([])
        assert result == ""

    def test_format_aliases_with_none(self):
        """Test formatting None."""
        result = server._format_aliases(None)
        assert result == ""

    def test_format_aliases_with_non_list(self):
        """Test formatting a non-list value."""
        result = server._format_aliases("single_alias")
        assert result == "single_alias"

    def test_format_entity_with_aliases(self):
        """Test formatting an entity with all fields present."""
        entity = {
            "stix_id": "malware--12345",
            "name": "TestMalware",
            "aliases": ["BadMalware", "EvilSoftware"],
            "description": "A test malware",
        }
        result = server._format_entity_with_aliases(entity)
        assert result["stix_id"] == "malware--12345"
        assert result["name"] == "TestMalware"
        assert result["aliases"] == "BadMalware, EvilSoftware"
        assert result["description"] == "A test malware"

    def test_format_entity_with_missing_fields(self):
        """Test formatting an entity with missing fields."""
        entity = {"name": "TestEntity"}
        result = server._format_entity_with_aliases(entity)
        assert result["stix_id"] == ""
        assert result["name"] == "TestEntity"
        assert result["aliases"] == ""
        assert result["description"] == ""

    def test_format_relationship_target(self):
        """Test extracting target from a relationship."""
        relationship = {
            "to": {
                "stix_id": "malware--67890",
                "name": "TargetMalware",
            }
        }
        result = server._format_relationship_target(relationship)
        assert result["stix_id"] == "malware--67890"
        assert result["name"] == "TargetMalware"

    def test_format_relationship_target_missing_to(self):
        """Test extracting target when 'to' field is missing."""
        relationship = {}
        result = server._format_relationship_target(relationship)
        assert result["stix_id"] == ""
        assert result["name"] == ""


class TestEntityLookup:
    """Test suite for entity lookup functions."""

    def test_find_entity_by_name_success(self, mock_opencti_client):
        """Test finding an entity that exists."""
        mock_entity = {"id": "123", "name": "APT28", "stix_id": "intrusion-set--123"}
        mock_opencti_client.intrusion_set.read.return_value = mock_entity

        result = server._find_entity_by_name("intrusion_set", "APT28")

        assert result == mock_entity
        mock_opencti_client.intrusion_set.read.assert_called_once()

    def test_find_entity_by_name_not_found(self, mock_opencti_client):
        """Test finding an entity that doesn't exist."""
        mock_opencti_client.malware.read.return_value = None

        result = server._find_entity_by_name("malware", "NonexistentMalware")

        assert result is None

    def test_get_related_entities(self, mock_opencti_client):
        """Test fetching related entities via relationships."""
        mock_relationships = [
            {"to": {"stix_id": "malware--111", "name": "Malware1"}},
            {"to": {"stix_id": "malware--222", "name": "Malware2"}},
        ]
        mock_opencti_client.stix_core_relationship.list.return_value = mock_relationships

        result = server._get_related_entities("intrusion-set--999", ["Malware"])

        assert len(result) == 2
        assert result[0]["stix_id"] == "malware--111"
        assert result[1]["name"] == "Malware2"

    def test_get_reverse_related_entities(self, mock_opencti_client):
        """Test fetching reverse related entities."""
        mock_relationships = [
            {"from": {"stix_id": "threat-actor--111", "name": "Actor1"}},
            {"from": {"stix_id": "threat-actor--222", "name": "Actor2"}},
        ]
        mock_opencti_client.stix_core_relationship.list.return_value = mock_relationships

        result = server._get_reverse_related_entities("identity--999", ["Threat-Actor"])

        assert len(result) == 2
        assert result[0]["stix_id"] == "threat-actor--111"
        assert result[1]["name"] == "Actor2"

    def test_find_entity_by_filter(self, mock_opencti_client):
        """Test finding entities with filters and sorting."""
        mock_entities = [
            {"stix_id": "report--111", "name": "Report1"},
            {"stix_id": "report--222", "name": "Report2"},
        ]
        mock_opencti_client.report.list.return_value = mock_entities

        filters = {
            "mode": "and",
            "filters": [{"key": "name", "values": ["test"]}],
            "filterGroups": [],
        }
        result = server._find_entity_by_filter(
            "report", filters, order_by="published", order_mode="desc", limit=10
        )

        assert result == mock_entities
        mock_opencti_client.report.list.assert_called_once_with(
            filters=filters,
            first=10,
            orderBy="published",
            orderMode="desc",
        )


class TestMalwareTools:
    """Test suite for malware-related tools."""

    def test_get_malwares_of_intrusion_set_success(self, mock_opencti_client):
        """Test getting malwares of an existing intrusion set."""
        mock_intrusion_set = {"id": "123", "name": "APT28"}
        mock_malwares = [
            {"to": {"stix_id": "malware--111", "name": "X-Agent"}},
            {"to": {"stix_id": "malware--222", "name": "Sofacy"}},
        ]
        mock_opencti_client.intrusion_set.read.return_value = mock_intrusion_set
        mock_opencti_client.stix_core_relationship.list.return_value = mock_malwares

        result = server.get_malwares_of_intrusion_set("APT28")

        assert len(result) == 2
        assert result[0]["name"] == "X-Agent"
        assert result[1]["stix_id"] == "malware--222"

    def test_get_malwares_of_intrusion_set_not_found(self, mock_opencti_client):
        """Test getting malwares when intrusion set doesn't exist."""
        mock_opencti_client.intrusion_set.read.return_value = None

        result = server.get_malwares_of_intrusion_set("NonexistentAPT")

        assert result == []

    def test_search_malware(self, mock_opencti_client):
        """Test searching for malware."""
        mock_malwares = [
            {
                "stix_id": "malware--111",
                "name": "Ransomware1",
                "aliases": ["Ransom", "CryptoLocker"],
                "description": "A ransomware",
            },
            {
                "stix_id": "malware--222",
                "name": "Trojan1",
                "aliases": None,
                "description": "A trojan",
            },
        ]
        mock_opencti_client.malware.list.return_value = mock_malwares

        result = server.search_malware("ransom")

        assert len(result) == 2
        assert result[0]["aliases"] == "Ransom, CryptoLocker"
        assert result[1]["aliases"] == ""

    def test_get_vulnerabilities_of_malware(self, mock_opencti_client):
        """Test getting vulnerabilities exploited by malware."""
        mock_malware = {"id": "123", "name": "TestMalware"}
        mock_vulns = [
            {"to": {"stix_id": "vulnerability--111", "name": "CVE-2024-0001"}},
        ]
        mock_opencti_client.malware.read.return_value = mock_malware
        mock_opencti_client.stix_core_relationship.list.return_value = mock_vulns

        result = server.get_vulnerabilities_of_malware("TestMalware")

        assert len(result) == 1
        assert result[0]["name"] == "CVE-2024-0001"


class TestSearchTools:
    """Test suite for entity search tools."""

    def test_search_intrusion_sets(self, mock_opencti_client):
        """Test searching for intrusion sets."""
        mock_sets = [
            {"stix_id": "intrusion-set--111", "name": "APT28", "aliases": [], "description": "Russian APT"},
        ]
        mock_opencti_client.intrusion_set.list.return_value = mock_sets

        result = server.search_intrusion_sets("APT28")

        assert len(result) == 1
        assert result[0]["name"] == "APT28"

    def test_search_attack_patterns(self, mock_opencti_client):
        """Test searching for attack patterns."""
        mock_patterns = [
            {"stix_id": "attack-pattern--111", "name": "T1059", "aliases": [], "description": "Command execution"},
        ]
        mock_opencti_client.attack_pattern.list.return_value = mock_patterns

        result = server.search_attack_patterns("command")

        assert len(result) == 1
        assert result[0]["name"] == "T1059"

    def test_search_campaigns(self, mock_opencti_client):
        """Test searching for campaigns."""
        mock_campaigns = [
            {"stix_id": "campaign--111", "name": "Operation X", "aliases": [], "description": "A campaign"},
        ]
        mock_opencti_client.campaign.list.return_value = mock_campaigns

        result = server.search_campaigns("Operation")

        assert len(result) == 1

    def test_search_vulnerabilities(self, mock_opencti_client):
        """Test searching for vulnerabilities."""
        mock_vulns = [
            {"stix_id": "vulnerability--111", "name": "CVE-2024-0001", "aliases": [], "description": "A CVE"},
        ]
        mock_opencti_client.vulnerability.list.return_value = mock_vulns

        result = server.search_vulnerabilities("CVE-2024")

        assert len(result) == 1

    def test_search_threat_actors(self, mock_opencti_client):
        """Test searching for threat actors."""
        mock_actors = [
            {"stix_id": "threat-actor--111", "name": "Lazarus", "aliases": ["Hidden Cobra"], "description": "NK APT"},
        ]
        mock_opencti_client.threat_actor.list.return_value = mock_actors

        result = server.search_threat_actors("Lazarus")

        assert len(result) == 1
        assert result[0]["aliases"] == "Hidden Cobra"

    def test_search_tools(self, mock_opencti_client):
        """Test searching for tools."""
        mock_tools = [
            {"stix_id": "tool--111", "name": "Mimikatz", "aliases": [], "description": "Credential dumper"},
        ]
        mock_opencti_client.tool.list.return_value = mock_tools

        result = server.search_tools("Mimikatz")

        assert len(result) == 1


class TestReportTools:
    """Test suite for report-related tools."""

    def test_search_reports(self, mock_opencti_client):
        """Test searching for reports."""
        mock_reports = [
            {
                "stix_id": "report--111",
                "name": "APT Report 2024",
                "published": "2024-01-01",
                "labels": ["apt", "malware"],
                "description": "Annual report",
            },
        ]
        mock_opencti_client.report.list.return_value = mock_reports

        result = server.search_reports("APT")

        assert len(result) == 1
        assert result[0]["labels"] == "apt, malware"

    def test_get_report_details_success(self, mock_opencti_client):
        """Test getting report details for an existing report."""
        mock_report = {
            "stix_id": "report--111",
            "name": "Test Report",
            "published": "2024-01-01",
            "labels": ["label1", "label2"],
            "description": "A test report",
        }
        mock_opencti_client.report.read.return_value = mock_report

        result = server.get_report_details("Test Report")

        assert result["name"] == "Test Report"
        assert result["labels"] == "label1, label2"

    def test_get_report_details_not_found(self, mock_opencti_client):
        """Test getting report details when report doesn't exist."""
        mock_opencti_client.report.read.return_value = None

        result = server.get_report_details("Nonexistent Report")

        assert result["stix_id"] == ""
        assert result["name"] == ""

    def test_get_malwares_of_report(self, mock_opencti_client):
        """Test getting malwares mentioned in a report."""
        mock_report = {"id": "123", "name": "Test Report"}
        mock_malwares = [
            {"to": {"stix_id": "malware--111", "name": "TestMalware"}},
        ]
        mock_opencti_client.report.read.return_value = mock_report
        mock_opencti_client.stix_core_relationship.list.return_value = mock_malwares

        result = server.get_malwares_of_report("Test Report")

        assert len(result) == 1
        assert result[0]["name"] == "TestMalware"

    def test_get_intrusion_sets_of_report(self, mock_opencti_client):
        """Test getting intrusion sets mentioned in a report."""
        mock_report = {"id": "123", "name": "Test Report"}
        mock_sets = [
            {"to": {"stix_id": "intrusion-set--111", "name": "APT28"}},
        ]
        mock_opencti_client.report.read.return_value = mock_report
        mock_opencti_client.stix_core_relationship.list.return_value = mock_sets

        result = server.get_intrusion_sets_of_report("Test Report")

        assert len(result) == 1


class TestRelationshipTools:
    """Test suite for relationship traversal tools."""

    def test_get_attack_patterns_of_intrusion_set(self, mock_opencti_client):
        """Test getting attack patterns of an intrusion set."""
        mock_set = {"id": "123", "name": "APT28"}
        mock_patterns = [
            {"to": {"stix_id": "attack-pattern--111", "name": "T1059"}},
        ]
        mock_opencti_client.intrusion_set.read.return_value = mock_set
        mock_opencti_client.stix_core_relationship.list.return_value = mock_patterns

        result = server.get_attack_patterns_of_intrusion_set("APT28")

        assert len(result) == 1
        assert result[0]["name"] == "T1059"

    def test_get_tools_used_by_intrusion_set(self, mock_opencti_client):
        """Test getting tools used by an intrusion set."""
        mock_set = {"id": "123", "name": "APT28"}
        mock_tools = [
            {"to": {"stix_id": "tool--111", "name": "Mimikatz"}},
        ]
        mock_opencti_client.intrusion_set.read.return_value = mock_set
        mock_opencti_client.stix_core_relationship.list.return_value = mock_tools

        result = server.get_tools_used_by_intrusion_set("APT28")

        assert len(result) == 1


class TestSectorAnalysisTools:
    """Test suite for sector-based analysis tools."""

    def test_get_threat_actors_targeting_sector_success(self, mock_opencti_client):
        """Test getting threat actors targeting a specific sector."""
        mock_sector = {"id": "123", "name": "Financial Sector"}
        mock_actors = [
            {"from": {"stix_id": "threat-actor--111", "name": "APT28"}},
            {"from": {"stix_id": "threat-actor--222", "name": "Lazarus"}},
        ]
        mock_opencti_client.identity.read.return_value = mock_sector
        mock_opencti_client.stix_core_relationship.list.return_value = mock_actors

        result = server.get_threat_actors_targeting_sector("Financial Sector", limit=10)

        assert len(result) == 2
        assert result[0]["name"] == "APT28"

    def test_get_threat_actors_targeting_sector_fallback_search(self, mock_opencti_client):
        """Test fallback to search when exact name doesn't match."""
        mock_sector = {"id": "123", "name": "Financial"}
        mock_actors = [
            {"from": {"stix_id": "threat-actor--111", "name": "APT28"}},
        ]
        mock_opencti_client.identity.read.return_value = None
        mock_opencti_client.identity.list.return_value = [mock_sector]
        mock_opencti_client.stix_core_relationship.list.return_value = mock_actors

        result = server.get_threat_actors_targeting_sector("finance", limit=10)

        assert len(result) == 1

    def test_get_threat_actors_targeting_sector_not_found(self, mock_opencti_client):
        """Test when sector is not found."""
        mock_opencti_client.identity.read.return_value = None
        mock_opencti_client.identity.list.return_value = []

        result = server.get_threat_actors_targeting_sector("Nonexistent Sector")

        assert result == []

    def test_get_intrusion_sets_targeting_sector(self, mock_opencti_client):
        """Test getting intrusion sets targeting a sector."""
        mock_sector = {"id": "123", "name": "Healthcare"}
        mock_sets = [
            {"from": {"stix_id": "intrusion-set--111", "name": "APT29"}},
        ]
        mock_opencti_client.identity.read.return_value = mock_sector
        mock_opencti_client.stix_core_relationship.list.return_value = mock_sets

        result = server.get_intrusion_sets_targeting_sector("Healthcare", limit=10)

        assert len(result) == 1

    def test_search_sectors(self, mock_opencti_client):
        """Test searching for sectors."""
        mock_identities = [
            {"stix_id": "identity--111", "name": "Financial Sector", "identity_class": "sector", "description": "Finance"},
            {"stix_id": "identity--222", "name": "Healthcare Sector", "identity_class": "sector", "description": "Health"},
            {"stix_id": "identity--333", "name": "John Doe", "identity_class": "individual", "description": "Person"},
        ]
        mock_opencti_client.identity.list.return_value = mock_identities

        result = server.search_sectors("sector")

        # Should only return sector identities, not individuals
        assert len(result) == 2
        assert result[0]["name"] == "Financial Sector"


class TestTTPAnalysisTools:
    """Test suite for TTP analysis tools."""

    def test_get_ttps_of_threat_actor(self, mock_opencti_client):
        """Test getting TTPs of a threat actor."""
        mock_actor = {"id": "123", "name": "APT28"}
        mock_ttps = [
            {"to": {"stix_id": "attack-pattern--111", "name": "T1059"}},
            {"to": {"stix_id": "attack-pattern--222", "name": "T1105"}},
        ]
        mock_opencti_client.threat_actor.read.return_value = mock_actor
        mock_opencti_client.stix_core_relationship.list.return_value = mock_ttps

        result = server.get_ttps_of_threat_actor("APT28")

        assert len(result) == 2

    def test_get_ttps_of_threat_actor_not_found(self, mock_opencti_client):
        """Test getting TTPs when threat actor doesn't exist."""
        mock_opencti_client.threat_actor.read.return_value = None

        result = server.get_ttps_of_threat_actor("NonexistentActor")

        assert result == []

    def test_get_ttps_of_intrusion_set(self, mock_opencti_client):
        """Test getting TTPs of an intrusion set."""
        mock_set = {"id": "123", "name": "APT29"}
        mock_ttps = [
            {"to": {"stix_id": "attack-pattern--111", "name": "T1566"}},
        ]
        mock_opencti_client.intrusion_set.read.return_value = mock_set
        mock_opencti_client.stix_core_relationship.list.return_value = mock_ttps

        result = server.get_ttps_of_intrusion_set("APT29")

        assert len(result) == 1


class TestTemporalQueryTools:
    """Test suite for time-based report queries."""

    def test_get_latest_reports(self, mock_opencti_client):
        """Test getting latest reports."""
        mock_reports = [
            {
                "stix_id": "report--111",
                "name": "Report 1",
                "published": "2024-12-01",
                "labels": ["apt"],
                "description": "Latest report",
            },
            {
                "stix_id": "report--222",
                "name": "Report 2",
                "published": "2024-11-01",
                "labels": [],
                "description": "Older report",
            },
        ]
        mock_opencti_client.report.list.return_value = mock_reports

        result = server.get_latest_reports(limit=10)

        assert len(result) == 2
        mock_opencti_client.report.list.assert_called_once_with(
            orderBy="published",
            orderMode="desc",
            first=10,
        )

    def test_get_latest_reports_by_sector(self, mock_opencti_client):
        """Test getting latest reports mentioning a sector."""
        mock_reports = [
            {
                "stix_id": "report--111",
                "name": "Financial Threat Report",
                "published": "2024-12-01",
                "labels": ["financial"],
                "description": "Finance threats",
            },
        ]
        mock_opencti_client.report.list.return_value = mock_reports

        result = server.get_latest_reports_by_sector("financial", limit=10)

        assert len(result) == 1
        assert result[0]["name"] == "Financial Threat Report"

    def test_get_latest_reports_mentioning_threat_actor_with_relationships(self, mock_opencti_client):
        """Test getting reports mentioning a threat actor via relationships."""
        mock_actor = {"id": "123", "name": "APT28"}
        mock_report = {
            "stix_id": "report--111",
            "name": "APT28 Analysis",
            "published": "2024-12-01",
            "labels": ["apt"],
            "description": "APT28 report",
        }
        mock_relations = [
            {"to": {"id": "report-id-111"}},
        ]
        mock_opencti_client.threat_actor.read.return_value = mock_actor
        mock_opencti_client.stix_core_relationship.list.side_effect = [
            mock_relations,  # forward relations
            [],  # reverse relations
        ]
        mock_opencti_client.report.read.return_value = mock_report

        result = server.get_latest_reports_mentioning_threat_actor("APT28", limit=10)

        assert len(result) == 1
        assert result[0]["name"] == "APT28 Analysis"

    def test_get_latest_reports_mentioning_threat_actor_fallback_search(self, mock_opencti_client):
        """Test fallback to text search when threat actor not found."""
        mock_reports = [
            {
                "stix_id": "report--111",
                "name": "Unknown Actor Report",
                "published": "2024-12-01",
                "labels": [],
                "description": "Report",
            },
        ]
        mock_opencti_client.threat_actor.read.return_value = None
        mock_opencti_client.report.list.return_value = mock_reports

        result = server.get_latest_reports_mentioning_threat_actor("UnknownActor", limit=10)

        assert len(result) == 1


class TestThreatActorDeepDiveTools:
    """Test suite for threat actor deep-dive tools."""

    def test_get_malwares_used_by_threat_actor(self, mock_opencti_client):
        """Test getting malware used by a threat actor."""
        mock_actor = {"id": "123", "name": "Lazarus"}
        mock_malwares = [
            {"to": {"stix_id": "malware--111", "name": "WannaCry"}},
        ]
        mock_opencti_client.threat_actor.read.return_value = mock_actor
        mock_opencti_client.stix_core_relationship.list.return_value = mock_malwares

        result = server.get_malwares_used_by_threat_actor("Lazarus")

        assert len(result) == 1
        assert result[0]["name"] == "WannaCry"

    def test_get_campaigns_by_threat_actor(self, mock_opencti_client):
        """Test getting campaigns attributed to a threat actor."""
        mock_actor = {"id": "123", "name": "APT28"}
        mock_campaigns = [
            {"to": {"stix_id": "campaign--111", "name": "Operation X"}},
        ]
        mock_opencti_client.threat_actor.read.return_value = mock_actor
        mock_opencti_client.stix_core_relationship.list.return_value = mock_campaigns

        result = server.get_campaigns_by_threat_actor("APT28")

        assert len(result) == 1

    def test_get_vulnerabilities_exploited_by_threat_actor(self, mock_opencti_client):
        """Test getting vulnerabilities exploited by a threat actor."""
        mock_actor = {"id": "123", "name": "APT29"}
        mock_vulns = [
            {"to": {"stix_id": "vulnerability--111", "name": "CVE-2024-0001"}},
        ]
        mock_opencti_client.threat_actor.read.return_value = mock_actor
        mock_opencti_client.stix_core_relationship.list.return_value = mock_vulns

        result = server.get_vulnerabilities_exploited_by_threat_actor("APT29")

        assert len(result) == 1
        assert result[0]["name"] == "CVE-2024-0001"


class TestClientInitialization:
    """Test suite for OpenCTI client initialization."""

    def test_create_opencti_client_success(self):
        """Test successful client initialization."""
        with patch.dict(os.environ, {"OPENCTI_TOKEN": "test-token", "OPENCTI_URL": "http://test:8080"}):
            with patch("opencti_mcp_server_v7.OpenCTIApiClient") as mock_client_class:
                client = server._create_opencti_client()
                mock_client_class.assert_called_once_with("http://test:8080", "test-token")

    def test_create_opencti_client_missing_token(self):
        """Test client initialization fails without token."""
        with patch.dict(os.environ, {}, clear=True):
            with pytest.raises(RuntimeError, match="OPENCTI_TOKEN environment variable must be set"):
                server._create_opencti_client()

    def test_create_opencti_client_default_url(self):
        """Test client uses default URL when not specified."""
        with patch.dict(os.environ, {"OPENCTI_TOKEN": "test-token"}, clear=True):
            with patch("opencti_mcp_server_v7.OpenCTIApiClient") as mock_client_class:
                client = server._create_opencti_client()
                mock_client_class.assert_called_once_with("http://localhost:8080", "test-token")


class TestEdgeCases:
    """Test suite for edge cases and error handling."""

    def test_empty_relationship_list(self, mock_opencti_client):
        """Test handling empty relationship lists."""
        mock_opencti_client.stix_core_relationship.list.return_value = []

        result = server._get_related_entities("some-id", ["Malware"])

        assert result == []

    def test_relationship_with_missing_fields(self, mock_opencti_client):
        """Test handling relationships with missing 'to' fields."""
        mock_relationships = [
            {"to": {}},  # Missing stix_id and name
            {"to": {"stix_id": "malware--111"}},  # Missing name
        ]
        mock_opencti_client.stix_core_relationship.list.return_value = mock_relationships

        result = server._get_related_entities("some-id", ["Malware"])

        assert len(result) == 2
        assert result[0]["stix_id"] == ""
        assert result[0]["name"] == ""
        assert result[1]["name"] == ""

    def test_report_with_none_published_date(self, mock_opencti_client):
        """Test handling reports with None published dates."""
        mock_reports = [
            {
                "stix_id": "report--111",
                "name": "Report",
                "published": None,
                "labels": None,
                "description": None,
            },
        ]
        mock_opencti_client.report.list.return_value = mock_reports

        result = server.get_latest_reports(limit=1)

        assert result[0]["published"] == ""
        assert result[0]["labels"] == ""
        assert result[0]["description"] == ""

    def test_limit_applied_to_reverse_relationships(self, mock_opencti_client):
        """Test that limit is correctly applied to reverse relationship results."""
        mock_sector = {"id": "123", "name": "Financial"}
        # Create 15 mock threat actors
        mock_actors = [
            {"from": {"stix_id": f"threat-actor--{i}", "name": f"Actor{i}"}}
            for i in range(15)
        ]
        mock_opencti_client.identity.read.return_value = mock_sector
        mock_opencti_client.stix_core_relationship.list.return_value = mock_actors

        result = server.get_threat_actors_targeting_sector("Financial", limit=10)

        # Should only return 10 results due to limit
        assert len(result) == 10
