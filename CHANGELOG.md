# Changelog

## 2025-10-13 - Production Ready Release (v1.4)

### Improved

#### 8. Enhanced Deployment Script ✨
**Enhancement**: Improved `deploy-test.sh` with automatic template cloning and better defaults

**Changes**:
- Clones latest template from GitHub (no local path dependencies)
- Sensible defaults for all prompts (just press Enter!)
- Automatic cleanup of temporary clone directory
- More user-friendly prompts with `[default]` syntax

**Defaults**:
- Target directory: `~/agent-test`
- Repository name: `agent-test`
- Visibility: `public`
- Create repo: `yes` (Y/n)

**Benefits**:
- ✅ No need to have the repo cloned locally
- ✅ Always uses latest template version from GitHub
- ✅ Faster setup (fewer prompts to answer)
- ✅ Automatic cleanup (no leftover temp files)

**File**: `deploy-test.sh`

**Example usage**:
```bash
# Run from anywhere - just hit Enter for all defaults!
curl -sSL https://raw.githubusercontent.com/AliceNN-ucdenver/MaintainabilityAI/main/examples/agents/deploy-test.sh | bash

# Or locally:
./deploy-test.sh
# Press Enter 4 times + enter API key = done!
```

---

## 2025-10-13 - Production Ready Release (v1.3)

### Added

#### 7. Code Snippet Extraction from Source Files ✨
**Feature**: Display vulnerable code in GitHub issues even when SARIF lacks snippets

**Problem**: CodeQL SARIF files often don't include the `region.snippet.text` field, so issues showed "(No code snippet available)"

**Solution**:
- Implemented `extractCodeSnippet()` function to read source files directly
- Falls back to file extraction when SARIF lacks snippets
- Includes 2 lines of context before/after vulnerable code
- Adds line numbers for easy navigation
- Marks vulnerable lines with `→` prefix

**Benefits**:
- ✅ Always shows code context in issues
- ✅ Helps developers understand vulnerabilities faster
- ✅ Line numbers match CodeQL's analysis
- ✅ Graceful fallback if file not found

**File**: `automation/process-codeql-results.js`

**Example output**:
```
  71: app.post('/api/login', async (req, res) => {
  72:   const { username, password } = req.body;
→  73:   const query = `SELECT * FROM users WHERE username = '${username}'`;
→  74:   const result = await pool.query(query);
  75:   if (result.rows.length > 0) {
```

---

## 2025-10-13 - Production Ready Release (v1.2)

### Added

#### 6. Auto-Close Resolved Vulnerabilities ✨
**Feature**: Automatically close issues when vulnerabilities are fixed and no longer appear in CodeQL scans

**How it works**:
- After processing new findings, checks all open `codeql-finding` issues
- Compares against current SARIF results
- If vulnerability no longer exists → auto-closes the issue
- Adds closing comment with scan details
- Applies `resolved` label for tracking

**Protections**:
- ✅ Skips issues labeled `false-positive` (manual override)
- ✅ Adds detailed closing comment with scan info
- ✅ Includes commit SHA and branch for audit trail
- ✅ Can be reopened if closed incorrectly

**Benefits**:
- ✅ Reduces manual issue triage
- ✅ Keeps issue tracker clean
- ✅ Provides immediate feedback on fixes
- ✅ Tracks resolution in issue history

**File**: `automation/process-codeql-results.js`

**Example closing comment**:
```markdown
## ✅ Vulnerability Resolved

This issue is being automatically closed because the vulnerability 
is no longer detected in the latest CodeQL scan.

**Details:**
- **Rule**: `js/sql-injection`
- **File**: `src/app.ts`
- **Line**: 73
- **Scan Date**: 2025-10-13T16:30:00.000Z
- **Branch**: main
- **Commit**: abc123

If this was closed in error, please reopen and add the 
`false-positive` label to prevent auto-closing in the future.

🤖 Auto-closed by CodeQL to Issues automation
```

---

## 2025-10-13 - Production Ready Release (v1.1)

### Improved

#### 5. Alice Workflow Optimization ✨
**Enhancement**: Better handling of approval workflow to avoid redundant plan regeneration

**Changes**:
- Added `track_progress: true` to enable progress tracking comments
- Updated prompt with explicit approval detection logic
- Alice now checks for previous remediation plan before re-analyzing
- If approval found, skips directly to implementation (no plan repost)

**Benefits**:
- ✅ Faster approval-to-implementation workflow
- ✅ No duplicate remediation plans
- ✅ Clearer intent in workflow runs
- ✅ Better use of API credits

**File**: `.github/workflows/alice-remediation.yml`

---

## 2025-10-13 - Production Ready Release (v1.0)

All critical issues identified during testing have been resolved. System is production-ready.

### Fixed Issues

#### 1. GitHub Issue Body Size Limit ✅
**Problem**: Issues failing with "body is too long (maximum is 65536 characters)"

**Solution**:
- Wrapped all prompts in collapsible `<details>` tags
- Intelligent truncation: OWASP (40KB), Maintainability (10KB), Threat Model (10KB)
- Final safety check at 65,000 characters
- Shows prompt sizes for transparency

**File**: `automation/process-codeql-results.js`

---

#### 2. SARIF File Extraction ✅
**Problem**: Workflow failing because CodeQL creates `javascript.sarif` (language-specific)

**Solution**:
- Automatically finds and renames any `*.sarif` file to `codeql-results.sarif`
- Works with all languages (JavaScript, TypeScript, Python, Go, etc.)

**File**: `.github/workflows/codeql-to-issues.yml`

---

#### 3. Missing CodeQL Rule Mappings ✅
**Problem**: 3 rules skipped with "no OWASP mapping" warning

**Solution**: Added mappings for:
- `js/request-forgery` → A01 Broken Access Control
- `js/http-to-file-access` → A01 Broken Access Control
- `js/file-access-to-http` → A05 Security Misconfiguration

**Total rules mapped**: 32 (was 29)

**File**: `automation/prompt-mappings.json`

---

#### 4. Claude Code Action Authentication ✅
**Problem**: Action failing with "Claude Code is not installed on this repository"

**Solution**: Added `github_token: ${{ secrets.GITHUB_TOKEN }}` parameter

**File**: `.github/workflows/alice-remediation.yml`

---

## Testing Status

✅ **Issue Creation**: Tested with 12 findings, all processed successfully
✅ **SARIF Extraction**: Works with `javascript.sarif`
✅ **Prompt Embedding**: All prompts collapsible, no size errors
✅ **Rule Coverage**: All detected vulnerabilities mapped
✅ **Alice AI**: Authentication working, approval workflow optimized
✅ **Auto-Close**: Resolves issues when vulnerabilities are fixed
✅ **Code Snippets**: File extraction works when SARIF lacks snippets

---

## Deployment

Use `deploy-test.sh` for fresh deployment. All fixes included automatically.

```bash
./deploy-test.sh
```

---

## Credits

**Built with**:
- [CodeQL](https://codeql.github.com) - Semantic code analysis
- [Alice AI](https://anthropic.com/claude) - AI-assisted remediation
- [MaintainabilityAI](https://maintainability.ai) - OWASP security prompts
- [claude-code-action](https://github.com/anthropics/claude-code-action) - GitHub integration

🤖 **AI-assisted development** using Claude Code following MaintainabilityAI's "Golden Rules of Vibe Coding"
