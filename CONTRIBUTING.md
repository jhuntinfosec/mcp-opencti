# Contributing to OpenCTI MCP Server

Thank you for your interest in contributing! This document provides guidelines for contributing to the project.

## Code of Conduct

This project adheres to a code of conduct that all contributors are expected to follow. Please be respectful and professional in all interactions.

## How to Contribute

### Reporting Bugs

Before creating bug reports, please check existing issues to avoid duplicates. When creating a bug report, include:

- **Clear title and description**
- **Steps to reproduce** the issue
- **Expected behavior** vs actual behavior
- **Environment details** (OS, Python version, OpenCTI version)
- **Error messages or logs** if applicable

### Suggesting Enhancements

Enhancement suggestions are tracked as GitHub issues. When creating an enhancement suggestion, include:

- **Clear title and description**
- **Use case** for the enhancement
- **Expected behavior** of the new feature
- **Alternative solutions** you've considered

### Pull Requests

1. **Fork the repository** and create your branch from `main`
2. **Make your changes** following the coding standards
3. **Add tests** for any new functionality
4. **Update documentation** (README, docstrings, etc.)
5. **Ensure tests pass** locally
6. **Submit the pull request**

## Development Setup

### Prerequisites

- Python 3.8+
- Git
- Access to an OpenCTI instance (for integration testing)

### Setting Up Your Environment

```bash
# Clone your fork
git clone https://github.com/yourusername/mcp-opencti.git
cd mcp-opencti

# Create virtual environment
python3 -m venv .venv
source .venv/bin/activate  # On Windows: .venv\Scripts\activate

# Install dependencies
pip install -r requirements.txt
pip install -r requirements-test.txt

# Copy environment template
cp .env.example .env
# Edit .env with your OpenCTI credentials
```

## Coding Standards

### Python Style

- Follow **PEP 8** style guidelines
- Use **Black** for code formatting (line length: 120)
- Use **flake8** for linting
- Use **mypy** for type checking

### Code Quality Checks

```bash
# Format code
black opencti_mcp_server_v7.py test_opencti_mcp_server_v7.py

# Lint
flake8 opencti_mcp_server_v7.py --max-line-length=120

# Type check
mypy opencti_mcp_server_v7.py --ignore-missing-imports
```

### Documentation

- **Docstrings**: All functions must have docstrings in NumPy format
- **Type hints**: Use type hints for all function parameters and returns
- **Comments**: Add comments for complex logic
- **README updates**: Update README.md for new features

### Example Docstring

```python
def example_function(param1: str, param2: int) -> List[Dict[str, str]]:
    """Brief description of what this function does.

    Longer description if needed, explaining the purpose,
    behavior, and any important details.

    Parameters
    ----------
    param1 : str
        Description of param1.
    param2 : int
        Description of param2.

    Returns
    -------
    list of dict
        Description of what is returned.

    Raises
    ------
    ValueError
        When and why this error is raised.
    """
    pass
```

## Testing

### Writing Tests

- **Test coverage**: Aim for >90% code coverage
- **Test organization**: Group related tests in test classes
- **Test naming**: Use descriptive names: `test_<function>_<scenario>`
- **Mocking**: Mock external dependencies (OpenCTI API calls)

### Running Tests

```bash
# Run all tests
pytest test_opencti_mcp_server_v7.py -v

# Run specific test class
pytest test_opencti_mcp_server_v7.py::TestSectorAnalysisTools -v

# Run with coverage
pytest test_opencti_mcp_server_v7.py --cov=opencti_mcp_server_v7 --cov-report=html

# View coverage report
open htmlcov/index.html  # macOS
# or
start htmlcov/index.html  # Windows
```

### Test Example

```python
def test_new_feature(self, mock_opencti_client):
    """Test that new feature works correctly."""
    # Arrange
    mock_data = {"id": "123", "name": "Test"}
    mock_opencti_client.entity.method.return_value = mock_data

    # Act
    result = server.new_function("input")

    # Assert
    assert len(result) == 1
    assert result[0]["name"] == "Test"
```

## Commit Guidelines

### Commit Message Format

```
<type>(<scope>): <subject>

<body>

<footer>
```

### Types

- **feat**: New feature
- **fix**: Bug fix
- **docs**: Documentation changes
- **style**: Code style changes (formatting, etc.)
- **refactor**: Code refactoring
- **test**: Adding or updating tests
- **chore**: Maintenance tasks

### Examples

```
feat(sector): add support for geographic filtering

Add new tool get_threat_actors_by_country() that filters
threat actors by their country of origin.

Closes #123
```

```
fix(reports): handle None values in published dates

Reports without published dates were causing errors.
Now defaults to empty string.

Fixes #456
```

## Branching Strategy

- **main**: Production-ready code
- **develop**: Integration branch for features
- **feature/***: New features
- **fix/***: Bug fixes
- **docs/***: Documentation updates

### Creating a Feature Branch

```bash
git checkout -b feature/your-feature-name
# Make changes
git add .
git commit -m "feat(scope): description"
git push origin feature/your-feature-name
```

## Pull Request Process

1. **Update documentation** for any changed functionality
2. **Add tests** that cover your changes
3. **Ensure all tests pass** locally
4. **Update CHANGELOG.md** with your changes
5. **Create pull request** with clear description
6. **Address review comments** promptly
7. **Squash commits** if requested

### Pull Request Template

```markdown
## Description
Brief description of the changes

## Type of Change
- [ ] Bug fix
- [ ] New feature
- [ ] Breaking change
- [ ] Documentation update

## Testing
- [ ] Tests pass locally
- [ ] Added new tests
- [ ] Coverage maintained/improved

## Checklist
- [ ] Code follows style guidelines
- [ ] Documentation updated
- [ ] CHANGELOG.md updated
- [ ] No breaking changes (or documented)
```

## Adding New MCP Tools

When adding a new MCP tool:

1. **Add the function** to `opencti_mcp_server_v7.py`
2. **Decorate with** `@mcp.tool()`
3. **Add comprehensive docstring** in NumPy format
4. **Add type hints** for parameters and return
5. **Write tests** in `test_opencti_mcp_server_v7.py`
6. **Update README.md** with the new tool
7. **Update CHANGELOG.md** with the addition
8. **Add usage examples** to documentation

### Example New Tool

```python
@mcp.tool()
def get_new_feature(entity_name: str, limit: int = 10) -> List[Dict[str, str]]:
    """Brief description of what this tool does.

    Parameters
    ----------
    entity_name: str
        Description of the parameter.
    limit: int
        Maximum number of results (default: 10).

    Returns
    -------
    list of dict
        Description of what is returned.
    """
    entity = _find_entity_by_name("entity_type", entity_name)
    if entity is None:
        return []
    return _get_related_entities(entity["id"], ["Target-Type"])[:limit]
```

## Release Process

Releases are managed by project maintainers:

1. Update version in relevant files
2. Update CHANGELOG.md
3. Create release branch
4. Run full test suite
5. Create GitHub release
6. Tag with version number

## Questions?

If you have questions about contributing:

- Open an issue for discussion
- Check existing documentation
- Reach out to maintainers

## License

By contributing, you agree that your contributions will be licensed under the MIT License.

---

Thank you for contributing to OpenCTI MCP Server! 🎉
