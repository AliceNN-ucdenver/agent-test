# 🚀 Deploy to New Repository

**Copy this folder to a new repository and start using CodeQL + Alice AI in 5 minutes.**

## Option 1: Quick Deploy Script

```bash
#!/bin/bash
# deploy.sh - Copy this template to a new repository

# Configuration
NEW_REPO_NAME="my-security-demo"
NEW_REPO_ORG="your-github-username"  # or organization
ANTHROPIC_API_KEY="sk-ant-api03-..."  # Get from https://console.anthropic.com/settings/keys

echo "🚀 Deploying CodeQL + Alice AI template to ${NEW_REPO_ORG}/${NEW_REPO_NAME}"

# Create new repository
echo "📦 Creating new GitHub repository..."
gh repo create "${NEW_REPO_ORG}/${NEW_REPO_NAME}" \
  --public \
  --description "CodeQL + Alice AI security automation" \
  --clone

cd "${NEW_REPO_NAME}"

# Copy all files from this template
echo "📋 Copying template files..."
cp -r /path/to/maintainabilityai/examples/agents/* .
cp -r /path/to/maintainabilityai/examples/agents/.github .
cp /path/to/maintainabilityai/examples/agents/.gitignore .

# Initialize git and push
echo "📤 Pushing to GitHub..."
git add .
git commit -m "Initial commit: CodeQL + Alice AI automation

🤖 AI-assisted repository setup using MaintainabilityAI template
"
git push origin main

# Add Anthropic API key secret
echo "🔐 Adding ANTHROPIC_API_KEY secret..."
gh secret set ANTHROPIC_API_KEY --body "${ANTHROPIC_API_KEY}"

# Enable GitHub Actions permissions
echo "⚙️  Configuring GitHub Actions permissions..."
echo "⚠️  Manual step required:"
echo "    Go to: https://github.com/${NEW_REPO_ORG}/${NEW_REPO_NAME}/settings/actions"
echo "    Enable: Read and write permissions"
echo "    Enable: Allow GitHub Actions to create and approve pull requests"
echo ""

# Trigger first CodeQL scan
echo "🔍 Triggering initial CodeQL scan..."
git commit --allow-empty -m "Trigger initial CodeQL security scan"
git push origin main

echo "✅ Deployment complete!"
echo ""
echo "📋 Next steps:"
echo "  1. Enable GitHub Actions permissions (see manual step above)"
echo "  2. Wait ~5 minutes for CodeQL scan to complete"
echo "  3. Check Issues tab for security findings"
echo "  4. Comment '@alice' on any issue to start remediation"
echo ""
echo "📚 Documentation:"
echo "  - README.md - Overview and quick start"
echo "  - SETUP.md - Complete configuration guide"
echo "  - EXAMPLE_ISSUE.md - See what issues look like"
echo ""
echo "🔗 Repository: https://github.com/${NEW_REPO_ORG}/${NEW_REPO_NAME}"
```

**Save as `deploy.sh`, edit configuration at top, then run:**
```bash
chmod +x deploy.sh
./deploy.sh
```

---

## Option 2: Manual Copy (Step-by-Step)

### 1. Create New Repository

```bash
# Via GitHub CLI
gh repo create my-security-demo --public --clone
cd my-security-demo

# Or via web: https://github.com/new
```

### 2. Copy Template Files

```bash
# From the maintainabilityai repo
cd my-security-demo
cp -r /path/to/maintainabilityai/examples/agents/* .
cp -r /path/to/maintainabilityai/examples/agents/.github .
cp /path/to/maintainabilityai/examples/agents/.gitignore .
```

**Files copied:**
- `.github/workflows/` - 3 GitHub Actions workflows
- `src/` - Vulnerable TypeScript demo app
- `automation/` - Issue creation scripts
- `README.md`, `SETUP.md`, `EXAMPLE_ISSUE.md` - Documentation
- `package.json`, `.gitignore`

### 3. Commit and Push

```bash
git add .
git commit -m "Initial commit: CodeQL + Alice AI automation"
git push origin main
```

### 4. Add Required Secret

```bash
# Get your key from: https://console.anthropic.com/settings/keys
gh secret set ANTHROPIC_API_KEY --body "sk-ant-api03-..."
```

### 5. Enable GitHub Actions Permissions

Go to: **https://github.com/YOUR-ORG/YOUR-REPO/settings/actions**

Under "Workflow permissions":
- ✅ Read and write permissions
- ✅ Allow GitHub Actions to create and approve pull requests

Click "Save"

### 6. Trigger Initial Scan

```bash
git commit --allow-empty -m "Trigger initial CodeQL scan"
git push origin main
```

### 7. Monitor Progress

```bash
# Watch workflow runs
gh run watch

# Or check on web
# https://github.com/YOUR-ORG/YOUR-REPO/actions
```

**Expected timeline:**
- 0-5 min: CodeQL scan runs
- 5-7 min: Issues created automatically
- Check **Issues** tab for security findings

### 8. Test Alice AI

On any issue with `codeql-finding` label:
```
@alice Please provide a remediation plan for this vulnerability
```

Wait ~2 minutes for Alice to respond with detailed plan.

---

## Option 3: Use as Template Repository (Future)

After uploading to GitHub, you can make it a template:

1. Go to **Settings → General**
2. Check ✅ "Template repository"
3. Now others can click "Use this template"

---

## 🎯 What You'll Get

After deployment, your repository will have:

### ✅ Vulnerable Demo App
- `src/app.ts` - Express API with 10+ OWASP vulnerabilities
- `src/auth.ts` - Authentication failures
- `src/admin.ts` - Access control issues

### ✅ Automated Workflows
- CodeQL security scanning (weekly + on push/PR)
- Automatic issue creation with embedded prompts
- Alice AI remediation on `@alice` mentions

### ✅ Comprehensive Documentation
- README.md - Overview and quick start
- SETUP.md - Detailed configuration guide
- EXAMPLE_ISSUE.md - Example issue format

### ✅ Ready to Run
- No additional configuration needed (except secret + permissions)
- Works out of the box
- Fully customizable

---

## 🔧 Post-Deployment Customization

### Replace Demo App with Your Code

1. Delete `src/` folder
2. Add your TypeScript/JavaScript code
3. Update `package.json` if needed
4. Push changes
5. CodeQL will scan your actual code

### Adjust Severity Threshold

Edit `.github/workflows/codeql-to-issues.yml`:
```yaml
env:
  SEVERITY_THRESHOLD: 'medium'  # Show more issues
```

### Add Team Auto-Assignment

```yaml
env:
  AUTO_ASSIGN: 'security-team,alice,bob'
```

### Exclude Paths

```yaml
env:
  EXCLUDED_PATHS: 'test/,docs/,*.test.ts'
```

### Use Custom Prompts

Fork MaintainabilityAI, modify prompts, then:
```yaml
env:
  PROMPT_REPO: 'your-org/your-fork'
  PROMPT_BRANCH: 'custom-prompts'
```

---

## 🐛 Troubleshooting

### "Permission denied" during workflow run

**Fix**: Enable workflow permissions (see Step 5 above)

### No issues created after scan

**Check**:
```bash
# Download SARIF to see if vulnerabilities were detected
gh run list --workflow="CodeQL Security Analysis"
gh run download <run-id> -n codeql-sarif
cat results.sarif | jq '.runs[0].results | length'
```

**If 0 results**: Demo code may have been modified. Restore `src/` folder.

### Claude workflow not triggering

**Check**:
1. Secret exists: `gh secret list | grep ANTHROPIC`
2. Issue has label: `codeql-finding`
3. Comment contains: `@alice`

### Rate limit errors

**Fix**: Reduce batch size in `.github/workflows/codeql-to-issues.yml`:
```yaml
env:
  MAX_ISSUES_PER_RUN: '3'
```

---

## 📊 Verify Deployment

After 10 minutes, verify:

✅ **CodeQL scan completed**
```bash
gh run list --workflow="CodeQL Security Analysis"
# Should show "completed" status
```

✅ **Issues created**
```bash
gh issue list --label codeql-finding
# Should show 5-15 security issues
```

✅ **Labels applied**
```bash
gh label list | grep -E "security/|owasp/|codeql-finding"
# Should show security labels
```

✅ **Workflows enabled**
```bash
gh workflow list
# Should show:
# - CodeQL Security Analysis
# - CodeQL to Security Issues
# - Alice AI Remediation
```

---

## 📚 Learn More

- **[README.md](README.md)** - Overview and features
- **[SETUP.md](SETUP.md)** - Complete configuration guide
- **[EXAMPLE_ISSUE.md](EXAMPLE_ISSUE.md)** - See issue format
- **MaintainabilityAI**: https://maintainability.ai

---

## 🎓 Example Repositories

See these repos using this template:
- Coming soon after initial deployment!

---

**Questions?** Open an issue or check the [SETUP.md](SETUP.md) guide.

**🤖 Built with Alice AI** using the MaintainabilityAI framework.
