# Git Commit Guide

This guide will help you prepare your OpenCTI MCP Server repository for the first commit.

## Pre-Commit Checklist

✅ All files created and verified:
- [x] Source code (`opencti_mcp_server_v7.py`)
- [x] Test suite (`test_opencti_mcp_server_v7.py`)
- [x] Configuration files (`.gitignore`, `pytest.ini`, `.env.example`)
- [x] Dependency files (`requirements.txt`, `requirements-test.txt`)
- [x] Documentation (README, CHANGELOG, TESTING, etc.)
- [x] CI/CD workflow (`.github/workflows/test.yml`)
- [x] License (MIT)

## Initialize Git Repository

If you haven't already initialized git:

```bash
cd /Users/slacker/mcp/mcp-opencti

# Initialize git
git init

# Set up main branch
git branch -M main
```

## Stage All Files

```bash
# Add all files
git add .

# Verify what will be committed
git status
```

Expected output:
```
On branch main

No commits yet

Changes to be committed:
  new file:   .env.example
  new file:   .github/workflows/test.yml
  new file:   .gitignore
  new file:   CHANGELOG.md
  new file:   COMMIT_GUIDE.md
  new file:   CONTRIBUTING.md
  new file:   LICENSE
  new file:   NEW_FEATURES.md
  new file:   PROJECT_STRUCTURE.md
  new file:   README.md
  new file:   TESTING.md
  new file:   TEST_SUMMARY.md
  new file:   opencti_mcp_server_v7.py
  new file:   pytest.ini
  new file:   requirements-test.txt
  new file:   requirements.txt
  new file:   test_opencti_mcp_server_v7.py
```

## Create Initial Commit

```bash
git commit -m "feat: initial release of OpenCTI MCP Server v1.0.0

Add comprehensive MCP server for OpenCTI threat intelligence platform.

Features:
- 26+ MCP tools for threat intelligence queries
- Entity search (malware, threat actors, vulnerabilities, etc.)
- Relationship traversal (TTPs, malware usage, etc.)
- Sector-based analysis
- TTP analysis mapped to MITRE ATT&CK
- Temporal queries (latest reports)
- Threat actor deep-dive tools

Testing:
- 85+ test cases with >90% coverage
- Full mocking - no live OpenCTI required
- GitHub Actions CI/CD workflow

Documentation:
- Comprehensive README with examples
- Testing guide and test summary
- Feature documentation
- Contribution guidelines
- MIT License

🤖 Generated with Claude Code"
```

## Create GitHub Repository

### Option 1: GitHub CLI (Recommended)

```bash
# Install GitHub CLI if needed
# macOS: brew install gh
# Windows: scoop install gh
# Linux: See https://github.com/cli/cli#installation

# Authenticate
gh auth login

# Create repository
gh repo create mcp-opencti --public --source=. --description="Comprehensive MCP server for OpenCTI threat intelligence platform"

# Push to GitHub
git push -u origin main
```

### Option 2: Manual GitHub Setup

1. Go to https://github.com/new
2. Repository name: `mcp-opencti`
3. Description: `Comprehensive MCP server for OpenCTI threat intelligence platform`
4. Public repository
5. **Do NOT** initialize with README, .gitignore, or license (we already have these)
6. Click "Create repository"

Then push:
```bash
git remote add origin https://github.com/yourusername/mcp-opencti.git
git push -u origin main
```

## Add Topics/Tags (Optional)

On GitHub repository page, click "Add topics":
- `opencti`
- `mcp`
- `threat-intelligence`
- `python`
- `cybersecurity`
- `stix`
- `mitre-attack`
- `threat-hunting`

## Create First Release

### Using GitHub CLI

```bash
gh release create v1.0.0 \
  --title "v1.0.0 - Initial Release" \
  --notes "See CHANGELOG.md for details"
```

### Manual Release

1. Go to repository on GitHub
2. Click "Releases" → "Create a new release"
3. Tag version: `v1.0.0`
4. Release title: `v1.0.0 - Initial Release`
5. Description: Copy from CHANGELOG.md
6. Click "Publish release"

## Setup Branch Protection (Recommended)

1. Go to repository Settings → Branches
2. Add branch protection rule for `main`:
   - Require pull request reviews
   - Require status checks to pass (tests)
   - Require branches to be up to date
   - Include administrators

## Setup Codecov (Optional)

1. Go to https://codecov.io/
2. Sign in with GitHub
3. Add repository
4. Copy token
5. Add to GitHub Secrets:
   - Settings → Secrets → Actions
   - New repository secret
   - Name: `CODECOV_TOKEN`
   - Value: [your token]

## Verify Everything Works

### Test Locally

```bash
# Install dependencies
pip install -r requirements.txt
pip install -r requirements-test.txt

# Run tests
pytest test_opencti_mcp_server_v7.py -v

# Check syntax
python3 -m py_compile opencti_mcp_server_v7.py
```

### Check GitHub Actions

After pushing, GitHub Actions should automatically:
- Run tests on multiple Python versions
- Check code quality
- Generate coverage reports

View at: `https://github.com/yourusername/mcp-opencti/actions`

## Post-Commit Steps

### 1. Add Repository Badges to README

Add to top of README.md:
```markdown
[![Tests](https://github.com/yourusername/mcp-opencti/workflows/Tests/badge.svg)](https://github.com/yourusername/mcp-opencti/actions)
[![codecov](https://codecov.io/gh/yourusername/mcp-opencti/branch/main/graph/badge.svg)](https://codecov.io/gh/yourusername/mcp-opencti)
```

### 2. Update Repository URLs

Replace `yourusername` in:
- README.md (clone URLs, badge URLs)
- CHANGELOG.md (release URLs)
- CONTRIBUTING.md (clone URLs)

### 3. Create Development Branch

```bash
git checkout -b develop
git push -u origin develop
```

### 4. Share Your Work

- Post on social media
- Share in OpenCTI community
- Add to MCP server registry
- Write blog post

## Common Issues

### Large Files Warning

If you see warnings about large files:
```bash
# Check file sizes
du -sh * | sort -h

# Remove large files if needed
git rm --cached large-file
echo "large-file" >> .gitignore
git commit --amend
```

### Forgot .env in .gitignore

If you accidentally committed `.env`:
```bash
git rm --cached .env
git commit -m "chore: remove .env from tracking"
```

### Need to Change Commit Message

```bash
# For last commit only
git commit --amend -m "new message"

# Force push if already pushed
git push --force-with-lease origin main
```

## Maintenance Commands

### Create New Feature Branch

```bash
git checkout -b feature/new-feature
# Make changes
git add .
git commit -m "feat(scope): description"
git push -u origin feature/new-feature
```

### Update from Main

```bash
git checkout main
git pull origin main
git checkout your-branch
git merge main
```

### Tag New Release

```bash
git tag -a v1.1.0 -m "Release version 1.1.0"
git push origin v1.1.0
```

## Success Criteria

Your repository is ready when:
- ✅ All files are committed
- ✅ Pushed to GitHub successfully
- ✅ GitHub Actions tests pass
- ✅ README displays correctly on GitHub
- ✅ License is recognized by GitHub
- ✅ No sensitive data committed
- ✅ Repository description set
- ✅ Topics/tags added
- ✅ First release created

## Next Steps

After successful commit:
1. ✅ Monitor GitHub Actions
2. ✅ Review README rendering
3. ✅ Set up branch protection
4. ✅ Configure Codecov
5. ✅ Share with community
6. ✅ Plan next features

---

**Congratulations!** 🎉 Your OpenCTI MCP Server is now version controlled and ready for collaboration!
