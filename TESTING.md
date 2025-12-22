# Testing Guide for OpenCTI MCP Server

This guide explains how to run the comprehensive unit test suite for the OpenCTI MCP Server.

## Prerequisites

Ensure you have Python 3.8+ installed and have set up your virtual environment:

```bash
python3 -m venv .venv
source .venv/bin/activate  # On Windows: .venv\Scripts\activate
```

## Installation

Install the testing dependencies:

```bash
pip install -r requirements-test.txt
```

This will install:
- `pytest` - Testing framework
- `pytest-cov` - Coverage reporting
- `pytest-mock` - Mocking utilities
- `black` - Code formatter
- `flake8` - Linter
- `mypy` - Type checker

## Running Tests

### Run All Tests

```bash
pytest test_opencti_mcp_server_v7.py -v
```

The `-v` flag provides verbose output showing each test case.

### Run Tests with Coverage

Generate a coverage report to see which parts of your code are tested:

```bash
pytest test_opencti_mcp_server_v7.py --cov=opencti_mcp_server_v7 --cov-report=html
```

This creates an `htmlcov/` directory with a detailed HTML coverage report. Open `htmlcov/index.html` in your browser to view it.

### Run Tests with Coverage (Terminal Output)

For a quick coverage summary in the terminal:

```bash
pytest test_opencti_mcp_server_v7.py --cov=opencti_mcp_server_v7 --cov-report=term-missing
```

### Run Specific Test Classes

To run only tests for a specific feature:

```bash
# Test only helper functions
pytest test_opencti_mcp_server_v7.py::TestHelperFunctions -v

# Test only sector analysis tools
pytest test_opencti_mcp_server_v7.py::TestSectorAnalysisTools -v

# Test only TTP analysis tools
pytest test_opencti_mcp_server_v7.py::TestTTPAnalysisTools -v
```

### Run Specific Test Cases

To run a single test:

```bash
pytest test_opencti_mcp_server_v7.py::TestHelperFunctions::test_format_aliases_with_list -v
```

### Run Tests Matching a Pattern

```bash
pytest test_opencti_mcp_server_v7.py -k "threat_actor" -v
```

This runs all tests with "threat_actor" in the name.

## Code Quality Checks

### Format Code with Black

```bash
black opencti_mcp_server_v7.py test_opencti_mcp_server_v7.py
```

### Lint with Flake8

```bash
flake8 opencti_mcp_server_v7.py test_opencti_mcp_server_v7.py --max-line-length=120
```

### Type Check with MyPy

```bash
mypy opencti_mcp_server_v7.py --ignore-missing-imports
```

## Test Structure

The test suite is organized into the following test classes:

### 1. `TestHelperFunctions`
Tests for utility functions:
- `_format_aliases()` - Alias formatting
- `_format_entity_with_aliases()` - Entity formatting
- `_format_relationship_target()` - Relationship extraction

### 2. `TestEntityLookup`
Tests for entity lookup functions:
- `_find_entity_by_name()` - Finding entities by name
- `_get_related_entities()` - Forward relationships
- `_get_reverse_related_entities()` - Reverse relationships
- `_find_entity_by_filter()` - Complex filtering

### 3. `TestMalwareTools`
Tests for malware-related MCP tools:
- `get_malwares_of_intrusion_set()`
- `search_malware()`
- `get_vulnerabilities_of_malware()`

### 4. `TestSearchTools`
Tests for entity search tools:
- `search_intrusion_sets()`
- `search_attack_patterns()`
- `search_campaigns()`
- `search_vulnerabilities()`
- `search_threat_actors()`
- `search_tools()`

### 5. `TestReportTools`
Tests for report-related tools:
- `search_reports()`
- `get_report_details()`
- `get_malwares_of_report()`
- `get_intrusion_sets_of_report()`

### 6. `TestRelationshipTools`
Tests for relationship traversal:
- `get_attack_patterns_of_intrusion_set()`
- `get_tools_used_by_intrusion_set()`

### 7. `TestSectorAnalysisTools`
Tests for sector-based analysis:
- `get_threat_actors_targeting_sector()`
- `get_intrusion_sets_targeting_sector()`
- `search_sectors()`

### 8. `TestTTPAnalysisTools`
Tests for TTP analysis:
- `get_ttps_of_threat_actor()`
- `get_ttps_of_intrusion_set()`

### 9. `TestTemporalQueryTools`
Tests for time-based queries:
- `get_latest_reports()`
- `get_latest_reports_by_sector()`
- `get_latest_reports_mentioning_threat_actor()`

### 10. `TestThreatActorDeepDiveTools`
Tests for threat actor deep-dive:
- `get_malwares_used_by_threat_actor()`
- `get_campaigns_by_threat_actor()`
- `get_vulnerabilities_exploited_by_threat_actor()`

### 11. `TestClientInitialization`
Tests for OpenCTI client setup:
- Client initialization
- Environment variable handling
- Error conditions

### 12. `TestEdgeCases`
Tests for edge cases and error handling:
- Empty results
- Missing fields
- None values
- Limit enforcement

## Understanding Test Output

### Successful Test Run

```
test_opencti_mcp_server_v7.py::TestHelperFunctions::test_format_aliases_with_list PASSED [ 1%]
test_opencti_mcp_server_v7.py::TestHelperFunctions::test_format_aliases_with_empty_list PASSED [ 2%]
...
========================= 85 passed in 2.34s =========================
```

### Failed Test

If a test fails, pytest shows detailed information:

```
FAILED test_opencti_mcp_server_v7.py::TestHelperFunctions::test_format_aliases_with_list
AssertionError: assert 'alias1,alias2' == 'alias1, alias2'
  - alias1, alias2
  ?       -
  + alias1,alias2
```

### Coverage Report

```
Name                          Stmts   Miss  Cover   Missing
-----------------------------------------------------------
opencti_mcp_server_v7.py        312      8    97%   45-52, 201
-----------------------------------------------------------
TOTAL                           312      8    97%
```

## Continuous Integration

You can integrate these tests into your CI/CD pipeline:

### GitHub Actions Example

Create `.github/workflows/test.yml`:

```yaml
name: Tests

on: [push, pull_request]

jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v3
      - name: Set up Python
        uses: actions/setup-python@v4
        with:
          python-version: '3.11'
      - name: Install dependencies
        run: |
          pip install -r requirements-test.txt
      - name: Run tests with coverage
        run: |
          pytest test_opencti_mcp_server_v7.py --cov=opencti_mcp_server_v7 --cov-report=xml
      - name: Upload coverage to Codecov
        uses: codecov/codecov-action@v3
```

## Troubleshooting

### Import Errors

If you see import errors:
```
ModuleNotFoundError: No module named 'mcp'
```

Make sure you've installed the dependencies:
```bash
pip install -r requirements-test.txt
```

### Environment Variable Errors

The tests mock environment variables, so you don't need to set `OPENCTI_TOKEN` or `OPENCTI_URL` when running tests.

### Pytest Not Found

If `pytest` command is not found:
```bash
python -m pytest test_opencti_mcp_server_v7.py -v
```

## Writing New Tests

When adding new functionality to the MCP server, follow these guidelines:

1. **Create a test for each new MCP tool**:
   ```python
   def test_new_tool_name(self, mock_opencti_client):
       """Test description."""
       # Arrange
       mock_opencti_client.entity.method.return_value = mock_data

       # Act
       result = server.new_tool_name(params)

       # Assert
       assert len(result) == expected_count
   ```

2. **Test success and failure paths**:
   - Test with valid data
   - Test with entity not found
   - Test with empty results
   - Test with missing fields

3. **Use descriptive test names**:
   - `test_<function_name>_<scenario>`
   - Example: `test_get_malwares_of_intrusion_set_not_found`

4. **Add docstrings to tests**:
   ```python
   def test_example(self):
       """Test that example function handles edge case X correctly."""
   ```

## Best Practices

1. **Run tests before committing**: Always run the full test suite before pushing code
2. **Maintain high coverage**: Aim for >90% code coverage
3. **Test edge cases**: Don't just test the happy path
4. **Keep tests isolated**: Each test should be independent
5. **Use meaningful assertions**: Make it clear what you're testing
6. **Mock external dependencies**: Never call the real OpenCTI API in tests

## Additional Resources

- [pytest documentation](https://docs.pytest.org/)
- [pytest-cov documentation](https://pytest-cov.readthedocs.io/)
- [unittest.mock documentation](https://docs.python.org/3/library/unittest.mock.html)
