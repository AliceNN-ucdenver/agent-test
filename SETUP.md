# Setup Guide: CodeQL + Alice AI Remediation

Complete setup instructions for deploying this CodeQL + Claude AI automated remediation system to your repository.

## 📋 Overview

This repository template provides:
- **Vulnerable TypeScript application** with 10+ OWASP vulnerabilities
- **CodeQL security scanning** workflow
- **Automated issue creation** with embedded security prompts
- **Alice AI remediation** via `@alice` mentions in issues

## 🚀 Quick Start (5 Minutes)

### Option 1: Copy to New Repository

```bash
# 1. Create a new repository on GitHub (web UI or CLI)
gh repo create my-security-demo --public --clone

# 2. Copy all files from this examples/agents folder
cd my-security-demo
cp -r /path/to/maintainabilityai/examples/agents/* .
cp -r /path/to/maintainabilityai/examples/agents/.github .

# 3. Commit and push
git add .
git commit -m "Initial commit: CodeQL + Alice AI remediation system"
git push origin main
```

### Option 2: Use as GitHub Template

1. Click "Use this template" on GitHub
2. Name your new repository
3. Clone and proceed to configuration

---

## 🔐 Required Secrets

You need to configure **one secret** in your repository:

### 1. ANTHROPIC_API_KEY (Required for Claude AI)

**Get your API key**: https://console.anthropic.com/settings/keys

**Add to repository**:
```bash
# Via GitHub CLI
gh secret set ANTHROPIC_API_KEY --body "sk-ant-api03-..."

# Or via GitHub Web UI:
# Settings → Secrets and variables → Actions → New repository secret
```

**Permissions**: The secret needs access to:
- Claude API (provided by Anthropic)
- No special permissions required

### 2. GITHUB_TOKEN (Automatic)

The `GITHUB_TOKEN` is automatically provided by GitHub Actions. No manual setup needed!

**Permissions granted** (automatically):
- `contents: read` - Read repository code
- `issues: write` - Create and update issues
- `security-events: read` - Access CodeQL results
- `pull-requests: write` - Create PRs for fixes

---

## ⚙️ Repository Configuration

### Enable GitHub Actions

1. Go to **Settings → Actions → General**
2. Under "Actions permissions", select:
   - ✅ Allow all actions and reusable workflows
3. Under "Workflow permissions", select:
   - ✅ Read and write permissions
   - ✅ Allow GitHub Actions to create and approve pull requests

### Enable CodeQL Security Scanning

CodeQL is automatically enabled by the workflow, but you can also:

1. Go to **Security → Code scanning → Set up code scanning**
2. Choose "Advanced" setup
3. Use the provided `.github/workflows/codeql.yml` workflow

### Enable Issue Creation

No additional setup needed! Issues will be created automatically by the `codeql-to-issues.yml` workflow.

---

## 📦 Repository Structure

After copying, your repository will have:

```
.
├── .github/
│   └── workflows/
│       ├── codeql.yml                  # Step 1: Run CodeQL security scan
│       ├── codeql-to-issues.yml        # Step 2: Create issues from findings
│       └── alice-remediation.yml      # Step 3: AI-assisted remediation
├── src/
│   ├── app.ts                          # Vulnerable Express API (10+ issues)
│   ├── auth.ts                         # Authentication vulnerabilities
│   ├── admin.ts                        # Access control vulnerabilities
│   ├── package.json                    # Dependencies
│   └── tsconfig.json                   # TypeScript config
├── automation/
│   ├── process-codeql-results.js       # Issue creation script
│   └── prompt-mappings.json            # CodeQL → OWASP mappings
├── SETUP.md                            # This file
├── README.md                           # Main documentation
└── .gitignore                          # Ignore logs, node_modules
```

---

## 🔄 Workflow Sequence

### 1. CodeQL Scan (Automatic)

**Trigger**: Push to main, PR, or weekly schedule

```yaml
# .github/workflows/codeql.yml
on:
  push:
    branches: [ "main" ]
  pull_request:
    branches: [ "main" ]
  schedule:
    - cron: '0 0 * * 1'  # Weekly
```

**What it does**:
- Analyzes TypeScript/JavaScript code
- Detects security vulnerabilities (OWASP Top 10)
- Uploads SARIF results to GitHub Security tab
- Saves SARIF as artifact for next workflow

### 2. Issue Creation (Automatic)

**Trigger**: After CodeQL scan completes successfully

```yaml
# .github/workflows/codeql-to-issues.yml
on:
  workflow_run:
    workflows: ["CodeQL Security Analysis"]
    types: [completed]
```

**What it does**:
- Downloads CodeQL SARIF results
- Maps findings to OWASP categories (29 rules configured)
- Fetches security prompts from MaintainabilityAI repository
- Creates GitHub issues with:
  - Vulnerability details and code snippet
  - Embedded OWASP security prompt (full context)
  - Maintainability considerations (optional)
  - Threat model analysis (optional)
  - Human review checklist
- Applies labels: `codeql-finding`, `security/high`, `owasp/a03-injection`, etc.
- Deduplicates (won't create duplicates for same finding)

### 3. Alice AI Remediation (On Demand)

**Trigger**: Comment `@alice` on any issue with `codeql-finding` label

```yaml
# .github/workflows/alice-remediation.yml
on:
  issue_comment:
    types: [created]
```

**What it does**:
- Reads the issue body (includes vulnerability details + prompts)
- Uses `anthropics/claude-code-action@v1` to analyze
- Alice posts a **remediation plan** with:
  - Root cause analysis
  - Proposed solution with code examples
  - Security controls checklist
  - Maintainability considerations
  - Testing strategy
- **Waits for human approval** before implementing
- After approval (`@alice approved - implement this fix`):
  - Creates branch: `fix/issue-{N}-security`
  - Implements the approved fix
  - Adds/updates tests
  - Creates PR with link back to issue

---

## 🧪 Testing the Setup

### Step 1: Trigger CodeQL Scan

```bash
# Push a commit to trigger CodeQL
git commit --allow-empty -m "Trigger CodeQL scan"
git push origin main

# Or manually trigger
gh workflow run "CodeQL Security Analysis"
```

**Expected**:
- Workflow runs for ~5 minutes
- See results in **Security → Code scanning alerts**

### Step 2: Verify Issue Creation

Wait for CodeQL to complete, then:

```bash
# Check for workflow run
gh run list --workflow="CodeQL to Security Issues"

# View logs
gh run view <run-id> --log
```

**Expected**:
- New issues created in **Issues** tab
- Labels: `codeql-finding`, `security/critical`, `owasp/a03-injection`
- Issues contain embedded OWASP prompts

Example issues you should see:
- `[Security] SQL injection in src/app.ts:25`
- `[Security] Weak cryptography in src/app.ts:78`
- `[Security] Broken access control in src/admin.ts:15`
- `[Security] Path traversal in src/admin.ts:50`

### Step 3: Test Alice AI Remediation

```bash
# Pick any issue with codeql-finding label
# Post a comment:
@alice Please provide a remediation plan for this vulnerability following the security and maintainability guidelines above.
```

**Expected**:
- Alice AI workflow triggers (~2 minutes)
- Alice posts detailed remediation plan
- Issue gets label: `remediation-in-progress`
- Label `awaiting-remediation-plan` removed

### Step 4: Approve and Implement

After reviewing Alice's plan, comment:
```
@alice approved - implement this fix
```

**Expected**:
- New branch created: `fix/issue-{N}-security`
- Code changes committed
- New PR created
- PR linked back to original issue

---

## 🎛️ Configuration Options

### Adjust Severity Threshold

Edit `.github/workflows/codeql-to-issues.yml`:

```yaml
env:
  SEVERITY_THRESHOLD: 'medium'  # Options: critical, high, medium, low
```

**Default**: `high` (only critical + high severity issues)

### Limit Issues Per Run

```yaml
env:
  MAX_ISSUES_PER_RUN: '5'  # Limit to prevent spam
```

**Default**: `10`

### Enable Additional Prompts

```yaml
env:
  ENABLE_MAINTAINABILITY: 'true'  # Include complexity, DRY, SRP prompts
  ENABLE_THREAT_MODEL: 'true'     # Include STRIDE threat modeling
```

**Default**: Both `true`

### Auto-Assign to Team

```yaml
env:
  AUTO_ASSIGN: 'security-team,alice,bob'  # Comma-separated GitHub usernames
```

**Default**: None (no auto-assignment)

### Exclude Paths

```yaml
env:
  EXCLUDED_PATHS: 'test/,__tests__/,*.test.ts,node_modules/'
```

**Default**: Empty (process all files)

### Custom Prompt Repository

```yaml
env:
  PROMPT_REPO: 'your-org/your-prompts-repo'
  PROMPT_BRANCH: 'main'
```

**Default**: `AliceNN-ucdenver/MaintainabilityAI` (uses upstream prompts)

---

## 🛠️ Customization

### Add More CodeQL Rules

Edit `automation/prompt-mappings.json`:

```json
{
  "codeql_to_owasp": {
    "js/your-custom-rule": "A03_injection"
  }
}
```

### Customize Issue Template

Edit `automation/process-codeql-results.js`, function `createIssueBody()`:

```javascript
function createIssueBody(vulnerability, prompts) {
  // Customize the issue format here
  return `...`;
}
```

### Modify Alice Prompt

Edit `.github/workflows/alice-remediation.yml`, the `prompt:` section:

```yaml
prompt: |
  # Add your custom instructions here
  ...
```

---

## 🐛 Troubleshooting

### CodeQL scan runs but no issues created

**Possible causes**:
1. No vulnerabilities detected → Check vulnerable code still exists
2. Severity below threshold → Lower `SEVERITY_THRESHOLD` to `low`
3. Workflow failed → Check logs: `gh run view --workflow="CodeQL to Security Issues"`

**Solution**:
```bash
# Check SARIF results
gh run download <run-id> -n codeql-sarif
cat results.sarif | jq '.runs[0].results | length'
```

### Alice workflow not triggering

**Possible causes**:
1. Missing `ANTHROPIC_API_KEY` secret
2. Issue doesn't have `codeql-finding` label
3. Comment doesn't contain `@alice`

**Solution**:
```bash
# Verify secret exists
gh secret list | grep ANTHROPIC

# Check workflow runs
gh run list --workflow="Alice AI Remediation"
```

### "Error: Resource not accessible by integration"

**Cause**: Insufficient GitHub Actions permissions

**Solution**:
1. Go to **Settings → Actions → General**
2. Under "Workflow permissions":
   - ✅ Read and write permissions
   - ✅ Allow GitHub Actions to create and approve pull requests

### Issues created but prompts missing

**Cause**: Unable to fetch from MaintainabilityAI repository

**Solution**:
1. Check network connectivity to GitHub
2. Verify `PROMPT_REPO` setting is correct
3. Check processing logs: `gh run download <run-id> -n codeql-processing-logs`

### Rate limit errors

**Cause**: Creating too many issues too quickly

**Solution**:
```yaml
# Reduce batch size
env:
  MAX_ISSUES_PER_RUN: '3'
```

---

## 📊 Monitoring

### View Processing Statistics

After each run:

```bash
# Download logs
gh run download <run-id> -n codeql-processing-logs

# View summary
cat summary.json | jq
```

Example output:
```json
{
  "timestamp": "2025-10-13T14:30:00Z",
  "total": 15,
  "created": 8,
  "updated": 3,
  "skipped": 4,
  "by_severity": {
    "critical": 2,
    "high": 6,
    "medium": 5,
    "low": 2
  },
  "by_owasp": {
    "A03_injection": 4,
    "A01_broken_access_control": 3,
    "A02_crypto_failures": 1
  }
}
```

### View Workflow Status

```bash
# List recent runs
gh run list

# Watch in real-time
gh run watch
```

---

## 🎓 Learning Resources

### OWASP Top 10 (2021)
- Full documentation: https://owasp.org/Top10/
- MaintainabilityAI prompts: https://maintainability.ai/docs/prompts/owasp/

### CodeQL Documentation
- Writing queries: https://codeql.github.com/docs/writing-codeql-queries/
- JavaScript queries: https://codeql.github.com/codeql-query-help/javascript/

### Claude Code Action
- Documentation: https://github.com/anthropics/claude-code-action
- Solutions guide: https://github.com/anthropics/claude-code-action/blob/main/docs/solutions.md

---

## 🎯 Next Steps

After setup:

1. **Explore the vulnerabilities**: Review `src/app.ts`, `src/auth.ts`, `src/admin.ts`
2. **Run CodeQL scan**: Push a commit and watch the workflow
3. **Review created issues**: Check the Issues tab for security findings
4. **Test Alice remediation**: Pick an issue and comment `@alice`
5. **Review and approve**: Examine Alice's plan and approve implementation
6. **Merge the fix**: Review the PR and merge when ready

---

## 📝 License

This template is part of the MaintainabilityAI project (MIT License).

The vulnerable code is for **educational purposes only** - DO NOT use in production!

---

## 🤝 Support

Issues or questions?
- Check [GitHub Issues](https://github.com/AliceNN-ucdenver/MaintainabilityAI/issues)
- Review processing logs: `automation/logs/processing.log`
- Consult MaintainabilityAI docs: https://maintainability.ai/docs
