#!/bin/bash
set -e  # Exit on error

# Colors for output
GREEN='\033[0;32m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
BOLD='\033[1m'
NC='\033[0m' # No Color

clear
echo ""
echo -e "${CYAN}${BOLD}"
cat << 'EOF'
╔══════════════════════════════════════════════════════════════════════╗
║                                                                      ║
║                   MAINTAINABILITY AI CLAUDE AGENT                    ║
║                                                                      ║
║                        Deployment Demo Script                        ║
║                                                                      ║
╚══════════════════════════════════════════════════════════════════════╝
EOF
echo -e "${NC}"
echo ""
echo -e "${BLUE}${BOLD}        🤖 AI-Assisted Security Remediation Deployment 🔒${NC}"
echo ""
echo -e "${CYAN}        CodeQL Scanner + Claude AI + GitHub Actions${NC}"
echo -e "${CYAN}        Automated OWASP vulnerability detection & fixing${NC}"
echo ""
echo -e "${GREEN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
echo ""

# Configuration
TEMPLATE_REPO="https://github.com/AliceNN-ucdenver/MaintainabilityAI.git"
DEFAULT_TARGET_DIR="$HOME/agent-test"
DEFAULT_REPO_NAME="agent-test"
TEMP_DIR=$(mktemp -d)

# Cleanup function
cleanup() {
    if [ -d "$TEMP_DIR" ]; then
        echo -e "${BLUE}🧹 Cleaning up temporary directory...${NC}"
        rm -rf "$TEMP_DIR"
    fi
}

# Register cleanup on exit
trap cleanup EXIT

# Prompt for target directory with default
echo -e "${YELLOW}📋 Configuration:${NC}"
echo ""
read -p "Target directory [${DEFAULT_TARGET_DIR}]: " TARGET_DIR
TARGET_DIR="${TARGET_DIR:-$DEFAULT_TARGET_DIR}"

read -p "GitHub repository name [${DEFAULT_REPO_NAME}]: " REPO_NAME
REPO_NAME="${REPO_NAME:-$DEFAULT_REPO_NAME}"
echo ""

# Clone the template repository
echo -e "${BLUE}📦 Cloning MaintainabilityAI template...${NC}"
git clone --depth 1 "$TEMPLATE_REPO" "$TEMP_DIR" >/dev/null 2>&1

if [ ! -d "$TEMP_DIR/examples/agents" ]; then
    echo -e "${RED}❌ Error: Could not find examples/agents in cloned repository${NC}"
    exit 1
fi

SOURCE_DIR="$TEMP_DIR/examples/agents"
echo -e "${GREEN}✅ Template cloned successfully${NC}"
echo ""

# Prompt for Anthropic API key
echo -e "${YELLOW}📋 Setup Information:${NC}"
echo ""
echo "You'll need an Anthropic API key to use Claude AI remediation."
echo "Get your key from: https://console.anthropic.com/settings/keys"
echo ""
read -s -p "Enter your Anthropic API key (sk-ant-api03-...): " ANTHROPIC_API_KEY
echo ""
echo -e "${GREEN}✓ API key captured${NC}"
echo ""

if [ -z "$ANTHROPIC_API_KEY" ]; then
    echo -e "${RED}❌ Error: API key is required${NC}"
    exit 1
fi

# Validate API key format
if [[ ! "$ANTHROPIC_API_KEY" =~ ^sk-ant- ]]; then
    echo -e "${YELLOW}⚠️  Warning: API key doesn't start with 'sk-ant-'. Is this correct?${NC}"
    read -p "Continue anyway? (y/n): " CONTINUE
    if [[ ! "$CONTINUE" =~ ^[Yy]$ ]]; then
        echo "Aborted."
        exit 1
    fi
fi

# Check if target directory already exists
if [ -d "$TARGET_DIR" ]; then
    echo -e "${YELLOW}⚠️  Target directory already exists: $TARGET_DIR${NC}"
    read -p "Delete and recreate? (y/n): " RECREATE
    if [[ "$RECREATE" =~ ^[Yy]$ ]]; then
        echo -e "${BLUE}🗑️  Removing existing directory...${NC}"
        rm -rf "$TARGET_DIR"
    else
        echo "Aborted."
        exit 1
    fi
fi

# Create target directory
echo -e "${BLUE}📁 Creating directory: $TARGET_DIR${NC}"
mkdir -p "$TARGET_DIR"

# Copy all files including dotfiles
echo -e "${BLUE}📋 Copying all files (including hidden files)...${NC}"
cp -r "$SOURCE_DIR"/* "$TARGET_DIR/" 2>/dev/null || true
cp -r "$SOURCE_DIR"/.github "$TARGET_DIR/" 2>/dev/null || true
cp "$SOURCE_DIR"/.gitignore "$TARGET_DIR/" 2>/dev/null || true

echo -e "${GREEN}✅ Files copied successfully${NC}"
echo ""

# Change to target directory
cd "$TARGET_DIR"

# Initialize git repository
echo -e "${BLUE}🔧 Initializing Git repository...${NC}"
git init -b main

# Configure git (use existing config or defaults)
if ! git config user.name > /dev/null 2>&1; then
    echo -e "${YELLOW}⚠️  Git user.name not configured${NC}"
    read -p "Enter your name for git commits: " GIT_NAME
    git config user.name "$GIT_NAME"
fi

if ! git config user.email > /dev/null 2>&1; then
    echo -e "${YELLOW}⚠️  Git user.email not configured${NC}"
    read -p "Enter your email for git commits: " GIT_EMAIL
    git config user.email "$GIT_EMAIL"
fi

# Create initial commit
echo -e "${BLUE}📝 Creating initial commit...${NC}"
git add .
git commit -m "Initial commit: CodeQL + Claude AI automation

🤖 AI-assisted repository setup using MaintainabilityAI template

This repository includes:
- Vulnerable TypeScript demo app (educational)
- CodeQL security scanning workflow
- Automated issue creation with OWASP prompts
- Claude AI remediation via @claude mentions

Template from: https://maintainability.ai
"

echo -e "${GREEN}✅ Git repository initialized${NC}"
echo ""

# Create GitHub repository
echo -e "${BLUE}🚀 Creating GitHub repository...${NC}"
echo ""
read -p "Create GitHub repository now? [Y/n]: " CREATE_REPO
CREATE_REPO="${CREATE_REPO:-y}"

if [[ "$CREATE_REPO" =~ ^[Yy]$ ]]; then
    # Check if gh CLI is installed
    if ! command -v gh &> /dev/null; then
        echo -e "${RED}❌ Error: GitHub CLI (gh) is not installed${NC}"
        echo "Install from: https://cli.github.com/"
        echo ""
        echo "You can manually create the repository and add the remote later."
        CREATE_REPO="n"
    else
        # Check if gh is authenticated
        if ! gh auth status &> /dev/null; then
            echo -e "${YELLOW}⚠️  GitHub CLI not authenticated${NC}"
            echo "Authenticating with GitHub..."
            gh auth login
        fi

        # Prompt for repository visibility with default
        read -p "Make repository public or private? [public]: " VISIBILITY
        VISIBILITY=$(echo "${VISIBILITY:-public}" | tr '[:upper:]' '[:lower:]')

        if [[ ! "$VISIBILITY" =~ ^(public|private)$ ]]; then
            VISIBILITY="public"
            echo -e "${YELLOW}⚠️  Invalid choice. Defaulting to public.${NC}"
        fi

        # Create repository
        echo -e "${BLUE}📦 Creating $VISIBILITY repository: $REPO_NAME${NC}"
        gh repo create "$REPO_NAME" \
            --"$VISIBILITY" \
            --source=. \
            --description="CodeQL + Claude AI security automation (Test deployment)" \
            --push

        if [ $? -eq 0 ]; then
            echo -e "${GREEN}✅ Repository created and pushed successfully${NC}"
            REPO_CREATED=true

            # Get repository URL
            REPO_URL=$(gh repo view --json url -q .url)
            echo ""
            echo -e "${GREEN}🔗 Repository URL: $REPO_URL${NC}"
        else
            echo -e "${RED}❌ Failed to create repository${NC}"
            REPO_CREATED=false
        fi
    fi
else
    echo -e "${YELLOW}⚠️  Skipping GitHub repository creation${NC}"
    echo "You can create it manually later with:"
    echo "  gh repo create $REPO_NAME --public --source=. --push"
    REPO_CREATED=false
fi

echo ""

# Add Anthropic API key secret
if [ "$REPO_CREATED" = true ]; then
    echo -e "${BLUE}🔐 Adding ANTHROPIC_API_KEY secret...${NC}"
    echo "$ANTHROPIC_API_KEY" | gh secret set ANTHROPIC_API_KEY

    if [ $? -eq 0 ]; then
        echo -e "${GREEN}✅ Secret added successfully${NC}"
    else
        echo -e "${RED}❌ Failed to add secret${NC}"
        echo "You can add it manually in GitHub Settings → Secrets"
    fi
    echo ""
fi

# Summary
echo ""
echo -e "${GREEN}╔════════════════════════════════════════════════════════════════╗${NC}"
echo -e "${GREEN}║  ✅ Deployment Complete!                                       ║${NC}"
echo -e "${GREEN}╔════════════════════════════════════════════════════════════════╗${NC}"
echo ""
echo -e "${BLUE}📁 Local repository:${NC} $TARGET_DIR"

if [ "$REPO_CREATED" = true ]; then
    echo -e "${BLUE}🔗 GitHub repository:${NC} $REPO_URL"
    echo -e "${BLUE}🔐 Secret configured:${NC} ANTHROPIC_API_KEY ✅"
fi

echo ""
echo -e "${YELLOW}📋 Next Steps:${NC}"
echo ""

if [ "$REPO_CREATED" = true ]; then
    echo "1. Enable GitHub Actions permissions:"
    echo "   ${REPO_URL}/settings/actions"
    echo "   ✅ Read and write permissions"
    echo "   ✅ Allow GitHub Actions to create and approve pull requests"
    echo ""
    echo "2. Trigger CodeQL scan:"
    echo "   cd $TARGET_DIR"
    echo "   git commit --allow-empty -m 'Trigger CodeQL scan'"
    echo "   git push"
    echo ""
    echo "3. Wait ~5 minutes, then check Issues tab:"
    echo "   ${REPO_URL}/issues"
    echo ""
    echo "4. Test Claude AI on any issue with 'codeql-finding' label:"
    echo "   Comment: @claude Please provide a remediation plan"
    echo ""
    echo "5. After reviewing plan, approve:"
    echo "   Comment: @claude approved - implement this fix"
else
    echo "1. Create GitHub repository:"
    echo "   cd $TARGET_DIR"
    echo "   gh repo create $REPO_NAME --public --source=. --push"
    echo ""
    echo "2. Add Anthropic API key secret:"
    echo "   gh secret set ANTHROPIC_API_KEY"
    echo ""
    echo "3. Follow steps above to enable permissions and trigger scan"
fi

echo ""
echo -e "${BLUE}📚 Documentation:${NC}"
echo "   README.md  - Overview and quick start"
echo "   SETUP.md   - Complete configuration guide"
echo "   DEPLOY.md  - Deployment instructions"
echo ""
echo -e "${GREEN}🎉 Happy testing!${NC}"
echo ""
