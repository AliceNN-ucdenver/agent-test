#!/usr/bin/env node

/**
 * CodeQL SARIF Results Processor
 *
 * This script processes CodeQL SARIF results and creates GitHub issues with
 * embedded MaintainabilityAI prompts for security vulnerabilities.
 *
 * @module process-codeql-results
 * @requires @octokit/rest
 * @requires axios
 */

const { Octokit } = require('@octokit/rest');
const axios = require('axios');
const fs = require('fs');
const path = require('path');

// ============================================================================
// CONFIGURATION
// ============================================================================

const config = {
  githubToken: process.env.GITHUB_TOKEN,
  promptRepo: process.env.PROMPT_REPO || 'AliceNN-ucdenver/MaintainabilityAI',
  promptBranch: process.env.PROMPT_BRANCH || 'main',
  severityThreshold: process.env.SEVERITY_THRESHOLD || 'high',
  maxIssuesPerRun: parseInt(process.env.MAX_ISSUES_PER_RUN || '10', 10),
  enableMaintainability: process.env.ENABLE_MAINTAINABILITY === 'true',
  enableThreatModel: process.env.ENABLE_THREAT_MODEL === 'true',
  autoAssign: (process.env.AUTO_ASSIGN || '').split(',').filter(Boolean),
  excludedPaths: (process.env.EXCLUDED_PATHS || '').split(',').filter(Boolean),
  owner: process.env.GITHUB_REPOSITORY_OWNER || (process.env.GITHUB_REPOSITORY || '/').split('/')[0],
  repo: (process.env.GITHUB_REPOSITORY || '/').split('/')[1],
  sarifPath: process.env.SARIF_PATH || 'results.sarif',
  branch: process.env.GITHUB_REF_NAME || 'main',
  sha: process.env.GITHUB_SHA || 'unknown'
};

// Validate required configuration
if (!config.githubToken) {
  console.error('❌ ERROR: GITHUB_TOKEN environment variable is required');
  process.exit(1);
}

if (!config.owner || !config.repo) {
  console.error('❌ ERROR: Could not determine repository owner/name from GITHUB_REPOSITORY');
  process.exit(1);
}

console.log('🔧 Configuration:');
console.log(`   Repository: ${config.owner}/${config.repo}`);
console.log(`   SARIF Path: ${config.sarifPath}`);
console.log(`   Severity Threshold: ${config.severityThreshold}`);
console.log(`   Max Issues Per Run: ${config.maxIssuesPerRun}`);
console.log(`   Maintainability Prompts: ${config.enableMaintainability ? '✅' : '❌'}`);
console.log(`   Threat Model Prompts: ${config.enableThreatModel ? '✅' : '❌'}`);
console.log(`   Prompt Source: ${config.promptRepo}@${config.promptBranch}`);

// ============================================================================
// INITIALIZE SERVICES
// ============================================================================

const octokit = new Octokit({ auth: config.githubToken });

// Load prompt mappings
const mappingsPath = path.join(__dirname, 'prompt-mappings.json');
let mappings;

try {
  mappings = JSON.parse(fs.readFileSync(mappingsPath, 'utf8'));
  console.log(`✅ Loaded prompt mappings from ${mappingsPath}`);
} catch (error) {
  console.error(`❌ ERROR: Could not load prompt mappings from ${mappingsPath}:`, error.message);
  process.exit(1);
}

// ============================================================================
// LOGGING SETUP
// ============================================================================

const logsDir = path.join(__dirname, 'logs');
const logFile = path.join(logsDir, 'processing.log');
const summaryFile = path.join(logsDir, 'summary.json');

// Create logs directory if it doesn't exist
if (!fs.existsSync(logsDir)) {
  fs.mkdirSync(logsDir, { recursive: true });
  console.log(`✅ Created logs directory: ${logsDir}`);
}

/**
 * Sanitize log messages to prevent injection and information leakage
 * @param {string} message - Raw log message
 * @returns {string} Sanitized message
 */
function sanitizeLogMessage(message) {
  if (typeof message !== 'string') {
    return String(message);
  }

  return message
    // Remove control characters (newlines, tabs, ANSI codes, etc.)
    .replace(/[\x00-\x1F\x7F-\x9F]/g, '')
    // Truncate very long messages (prevent log file bloat)
    .substring(0, 500)
    // Replace multiple spaces with single space
    .replace(/\s+/g, ' ')
    .trim();
}

/**
 * Sanitize file paths to prevent information leakage
 * @param {string} filePath - File path
 * @returns {string} Sanitized path (relative, not absolute)
 */
function sanitizeFilePath(filePath) {
  if (typeof filePath !== 'string') {
    return String(filePath);
  }
  // Remove absolute paths, keep relative
  return filePath.replace(process.cwd(), '.');
}

/**
 * Append a structured log message to the log file (JSON format)
 * @param {string} level - Log level (INFO, WARN, ERROR, SUCCESS)
 * @param {string} message - Log message
 * @param {Object} metadata - Additional metadata (optional)
 */
function log(level, message, metadata = {}) {
  const timestamp = new Date().toISOString();
  const sanitized = sanitizeLogMessage(message);

  // Structured JSON log entry
  const logEntry = {
    timestamp,
    level,
    message: sanitized,
    ...Object.keys(metadata).reduce((acc, key) => {
      acc[key] = sanitizeLogMessage(String(metadata[key]));
      return acc;
    }, {})
  };

  // Write JSON log
  fs.appendFileSync(logFile, JSON.stringify(logEntry) + '\n');

  // Console output with emojis
  const prefix = {
    INFO: 'ℹ️',
    WARN: '⚠️',
    ERROR: '❌',
    SUCCESS: '✅'
  }[level] || '📝';

  console.log(`${prefix} ${sanitized}`);
}

// ============================================================================
// PROMPT CACHE & INTEGRITY
// ============================================================================

const promptCache = new Map();
const crypto = require('crypto');

// Load prompt hashes for integrity verification
const promptHashesPath = path.join(__dirname, 'prompt-hashes.json');
let promptHashes = {};

try {
  promptHashes = JSON.parse(fs.readFileSync(promptHashesPath, 'utf8'));
  log('SUCCESS', 'Loaded prompt hash manifest', {
    files: Object.keys(promptHashes.owasp || {}).length +
           Object.keys(promptHashes.maintainability || {}).length +
           Object.keys(promptHashes['threat-modeling'] || {}).length
  });
} catch (error) {
  log('ERROR', 'Failed to load prompt-hashes.json', { error: error.message });
  console.error('❌ CRITICAL: Cannot verify prompt integrity without hash manifest');
  process.exit(1);
}

// Allowlist of trusted domains for fetching prompts
const ALLOWED_DOMAINS = [
  'raw.githubusercontent.com'
];

/**
 * Verify domain and protocol for prompt URLs
 * @param {string} urlString - URL to verify
 * @returns {boolean} True if allowed
 */
function verifyPromptUrl(urlString) {
  try {
    const url = new URL(urlString);

    // Verify HTTPS
    if (url.protocol !== 'https:') {
      log('ERROR', 'Blocked non-HTTPS prompt URL', { protocol: url.protocol });
      return false;
    }

    // Verify domain allowlist
    if (!ALLOWED_DOMAINS.includes(url.hostname)) {
      log('ERROR', 'Blocked prompt fetch from untrusted domain', { domain: url.hostname });
      return false;
    }

    return true;
  } catch (error) {
    log('ERROR', 'Invalid prompt URL', { error: error.message });
    return false;
  }
}

/**
 * Verify SHA-256 hash of fetched content
 * @param {string} content - Content to verify
 * @param {string} expectedHash - Expected hash in format "sha256:abc123..."
 * @returns {boolean} True if hash matches
 */
function verifyPromptIntegrity(content, expectedHash) {
  const actualHash = `sha256:${crypto.createHash('sha256').update(content).digest('hex')}`;
  return actualHash === expectedHash;
}

/**
 * Fetch a prompt from the MaintainabilityAI repository with integrity verification
 * @param {string} category - Category (owasp, maintainability, threat-modeling)
 * @param {string} file - Prompt filename
 * @returns {Promise<string|null>} Prompt content or null if not found/verification failed
 */
async function fetchPrompt(category, file) {
  const cacheKey = `${category}/${file}`;

  // Check cache first
  if (promptCache.has(cacheKey)) {
    log('INFO', `Using cached prompt: ${cacheKey}`);
    return promptCache.get(cacheKey);
  }

  // Verify file is in allowlist (has expected hash)
  const expectedHash = promptHashes[category]?.[file];
  if (!expectedHash) {
    log('ERROR', `Prompt not in hash manifest: ${cacheKey}`);
    return null;
  }

  const url = `https://raw.githubusercontent.com/${config.promptRepo}/${config.promptBranch}/examples/promptpack/${category}/${file}`;

  // Verify URL domain and protocol
  if (!verifyPromptUrl(url)) {
    return null;
  }

  try {
    log('INFO', `Fetching prompt: ${cacheKey}`);
    // Note: automation/ directory excluded from CodeQL scanning (see .github/codeql/codeql-config.yml)
    // This code fetches security prompts FROM trusted remote with domain allowlist + HTTPS + SHA-256 verification
    const response = await axios.get(url, {
      timeout: 10000,
      validateStatus: (status) => status === 200
    });

    const content = response.data;

    // Verify integrity with SHA-256 hash
    if (!verifyPromptIntegrity(content, expectedHash)) {
      log('ERROR', `Prompt integrity verification FAILED: ${cacheKey}`, {
        expected: expectedHash.substring(0, 20) + '...',
        actual: `sha256:${crypto.createHash('sha256').update(content).digest('hex').substring(0, 15)}...`
      });
      return null;
    }

    promptCache.set(cacheKey, content);
    log('SUCCESS', `Prompt verified and cached: ${cacheKey}`, {
      size: content.length,
      hash: expectedHash.substring(0, 20) + '...'
    });

    return content;
  } catch (error) {
    if (error.response?.status === 404) {
      log('WARN', `Prompt not found: ${cacheKey}`);
    } else {
      log('ERROR', `Failed to fetch prompt: ${cacheKey}`, { error: error.message });
    }

    promptCache.set(cacheKey, null);
    return null;
  }
}

// ============================================================================
// TITLE EXTRACTION UTILITIES
// ============================================================================

/**
 * Extract OWASP number and title from filename or content
 * @param {string} filename - Filename (e.g., "A01_broken_access_control.md")
 * @param {string} content - Markdown content
 * @returns {Object} Object with num and title properties
 */
function extractOwaspInfo(filename, content) {
  // Extract number: "A01_broken_access_control.md" → "A01"
  const numMatch = filename.match(/A(\d{2})/);
  const num = numMatch ? `A${numMatch[1]}` : '';

  // Extract title from first heading: "# Broken Access Control (OWASP A01) — Compact..."
  const titleMatch = content.match(/^#\s+([^(—\n]+)/m);
  const title = titleMatch ? titleMatch[1].trim() : '';

  return { num, title };
}

/**
 * Extract maintainability title from filename
 * @param {string} filename - Filename (e.g., "complexity-reduction.md")
 * @returns {string} Formatted title (e.g., "Complexity Reduction")
 */
function extractMaintainabilityTitle(filename) {
  // "complexity-reduction.md" → "Complexity Reduction"
  return filename
    .replace('.md', '')
    .split('-')
    .map(word => word.charAt(0).toUpperCase() + word.slice(1))
    .join(' ');
}

/**
 * Extract STRIDE threat name from filename
 * @param {string} filename - Filename (e.g., "spoofing.md")
 * @returns {string} Formatted title (e.g., "Spoofing")
 */
function extractStrideTitle(filename) {
  // "spoofing.md" → "Spoofing"
  return filename
    .replace('.md', '')
    .split('-')
    .map(word => word.charAt(0).toUpperCase() + word.slice(1))
    .join(' ');
}

// ============================================================================
// CODE SNIPPET EXTRACTION
// ============================================================================

/**
 * Extract code snippet from a file
 * @param {string} filePath - Path to the file
 * @param {number} startLine - Start line number (1-indexed)
 * @param {number} endLine - End line number (1-indexed)
 * @param {number} contextLines - Number of context lines before/after
 * @returns {string} Code snippet
 */
function extractCodeSnippet(filePath, startLine, endLine, contextLines = 2) {
  try {
    // Check if file exists
    if (!fs.existsSync(filePath)) {
      log('WARN', `File not found for snippet extraction: ${filePath}`);
      return '(File not found)';
    }

    // Read the file
    const fileContent = fs.readFileSync(filePath, 'utf8');
    const lines = fileContent.split('\n');

    // Calculate snippet range with context
    const snippetStart = Math.max(0, startLine - contextLines - 1);
    const snippetEnd = Math.min(lines.length, endLine + contextLines);

    // Extract lines
    const snippetLines = lines.slice(snippetStart, snippetEnd);

    // Add line numbers for context
    const numberedLines = snippetLines.map((line, index) => {
      const lineNum = snippetStart + index + 1;
      const isVulnerable = lineNum >= startLine && lineNum <= endLine;
      const prefix = isVulnerable ? '→ ' : '  ';
      return `${prefix}${String(lineNum).padStart(4)}: ${line}`;
    });

    return numberedLines.join('\n');
  } catch (error) {
    log('WARN', `Failed to extract code snippet from ${filePath}: ${error.message}`);
    return '(Unable to extract code snippet)';
  }
}

// ============================================================================
// SARIF PARSING
// ============================================================================

/**
 * Parse SARIF results file and extract vulnerabilities
 * @param {string} sarifPath - Path to SARIF file
 * @returns {Array<Object>} Array of vulnerability objects
 */
function parseSARIFResults(sarifPath) {
  log('INFO', `Parsing SARIF file: ${sarifPath}`);

  if (!fs.existsSync(sarifPath)) {
    log('ERROR', `SARIF file not found: ${sarifPath}`);
    return [];
  }

  let sarif;
  try {
    const content = fs.readFileSync(sarifPath, 'utf8');
    sarif = JSON.parse(content);
  } catch (error) {
    log('ERROR', `Failed to parse SARIF file: ${error.message}`);
    return [];
  }

  const vulnerabilities = [];

  // SARIF structure: runs[0].results[]
  for (const run of sarif.runs || []) {
    const tool = run.tool?.driver?.name || 'CodeQL';
    const toolVersion = run.tool?.driver?.semanticVersion || run.tool?.driver?.version || 'unknown';

    for (const result of run.results || []) {
      try {
        const ruleId = result.ruleId;
        const message = result.message?.text || 'No description provided';
        const level = result.level || 'warning';

        // Get primary location
        const location = result.locations?.[0]?.physicalLocation;
        if (!location) {
          log('WARN', `Skipping result without location: ${ruleId}`);
          continue;
        }

        const filePath = location.artifactLocation?.uri || 'unknown';
        const region = location.region || {};
        const startLine = region.startLine || 1;
        const endLine = region.endLine || startLine;
        const startColumn = region.startColumn || 1;
        const endColumn = region.endColumn || startColumn;

        // Extract code snippet
        let codeSnippet = region.snippet?.text || '';

        // If SARIF doesn't include snippet, extract from file
        if (!codeSnippet || codeSnippet.trim() === '') {
          codeSnippet = extractCodeSnippet(filePath, startLine, endLine, 2);
        }

        // Get rule details
        const rule = run.tool?.driver?.rules?.find(r => r.id === ruleId);
        const ruleName = rule?.shortDescription?.text || rule?.name || ruleId;
        const ruleHelp = rule?.help?.text || rule?.fullDescription?.text || '';

        vulnerabilities.push({
          ruleId,
          ruleName,
          ruleHelp,
          message,
          level,
          severity: mappings.severity_mapping[level] || 'medium',
          filePath,
          startLine,
          endLine,
          startColumn,
          endColumn,
          codeSnippet: codeSnippet.trim(),
          tool,
          toolVersion
        });
      } catch (error) {
        log('ERROR', `Failed to parse result: ${error.message}`);
      }
    }
  }

  log('SUCCESS', `Parsed ${vulnerabilities.length} vulnerabilities from SARIF`);
  return vulnerabilities;
}

// ============================================================================
// OWASP MAPPING
// ============================================================================

/**
 * Map CodeQL rule to OWASP category
 * @param {string} ruleId - CodeQL rule ID
 * @returns {Object|null} OWASP category info or null
 */
function mapToOWASP(ruleId) {
  const owaspKey = mappings.codeql_to_owasp[ruleId];

  if (!owaspKey) {
    log('WARN', `No OWASP mapping found for rule: ${ruleId}`);
    return null;
  }

  const category = mappings.owasp_categories[owaspKey];

  if (!category) {
    log('ERROR', `OWASP category not found: ${owaspKey}`);
    return null;
  }

  return {
    key: owaspKey,
    ...category
  };
}

// ============================================================================
// MAINTAINABILITY DETECTION
// ============================================================================

/**
 * Detect maintainability concerns based on message/rule content
 * @param {Object} groupedFinding - Grouped vulnerability object
 * @returns {Array<string>} Array of maintainability prompt files
 */
function detectMaintainabilityConcerns(groupedFinding) {
  if (!config.enableMaintainability) {
    return [];
  }

  const concerns = new Set();
  const searchText = `${groupedFinding.message} ${groupedFinding.ruleHelp} ${groupedFinding.ruleId}`.toLowerCase();

  // Check maintainability triggers from mappings
  for (const [key, trigger] of Object.entries(mappings.maintainability_triggers)) {
    for (const keyword of trigger.keywords) {
      if (searchText.includes(keyword.toLowerCase())) {
        concerns.add(trigger.prompt_file);
        log('INFO', `Detected maintainability concern: ${key} for ${groupedFinding.ruleId}`);
        break;
      }
    }
  }

  return Array.from(concerns);
}

// ============================================================================
// ISSUE BODY GENERATION
// ============================================================================

/**
 * Create formatted GitHub issue body with embedded prompts for grouped findings
 * @param {Object} groupedFinding - Grouped vulnerability object with occurrences array
 * @param {Object} prompts - Object containing fetched prompts
 * @returns {string} Formatted issue body in Markdown
 */
function createIssueBody(groupedFinding, prompts) {
  const timestamp = new Date().toISOString();
  const owaspCategory = prompts.owaspCategory || 'Unknown';
  const owaspKey = prompts.owaspKey || '';
  const count = groupedFinding.occurrences.length;

  // Determine language from file extension
  const ext = path.extname(groupedFinding.filePath).toLowerCase();
  const languageMap = {
    '.js': 'javascript',
    '.ts': 'typescript',
    '.jsx': 'javascript',
    '.tsx': 'typescript',
    '.py': 'python',
    '.java': 'java',
    '.go': 'go',
    '.cs': 'csharp',
    '.rb': 'ruby',
    '.php': 'php'
  };
  const language = languageMap[ext] || 'text';

  // Build issue body header
  let body = `## 🔴 Security Vulnerability: ${groupedFinding.ruleName}

**Detected by**: ${groupedFinding.tool} v${groupedFinding.toolVersion}
**Created**: ${timestamp}
**Occurrences**: ${count} location${count > 1 ? 's' : ''} in this file

---

### 📋 Vulnerability Details

| Property | Value |
|----------|-------|
| **Severity** | ${groupedFinding.severity.toUpperCase()} |
| **CodeQL Rule** | \`${groupedFinding.ruleId}\` |
| **OWASP Category** | [${owaspCategory}](https://maintainability.ai/docs/prompts/owasp/${prompts.owaspFile || ''}) |
| **File** | \`${groupedFinding.filePath}\` |
| **Total Occurrences** | ${count} |

### 💻 Vulnerable Code Locations

`;

  // Add each occurrence
  groupedFinding.occurrences.forEach((occurrence, index) => {
    const locationLabel = count > 1 ? `#### Location ${index + 1}: Lines ${occurrence.startLine}${occurrence.endLine !== occurrence.startLine ? `-${occurrence.endLine}` : ''}` : `#### Lines ${occurrence.startLine}${occurrence.endLine !== occurrence.startLine ? `-${occurrence.endLine}` : ''}`;

    body += `
${locationLabel}

\`\`\`${language}
${occurrence.codeSnippet || '(No code snippet available)'}
\`\`\`

**Issue**: ${occurrence.message}

`;
  });

  // Add rule help if available
  if (groupedFinding.ruleHelp) {
    body += `
**Additional Context**: ${groupedFinding.ruleHelp}
`;
  }

  // Add OWASP prompts with nested collapsible sections
  if (prompts.owaspPrompts && prompts.owaspPrompts.length > 0) {
    body += `
<details>
<summary>📘 <strong>OWASP Security Guidance</strong> (${prompts.owaspPrompts.length} ${prompts.owaspPrompts.length === 1 ? 'guide' : 'guides'})</summary>

`;

    prompts.owaspPrompts.forEach(prompt => {
      const { num, title } = extractOwaspInfo(prompt.filename, prompt.content);

      body += `
<details>
<summary>🔒 <strong>${num} - ${title}</strong></summary>

${prompt.content}

</details>

`;
    });

    body += `
</details>

`;
  }

  // Add maintainability prompts with nested collapsible sections
  if (prompts.maintainabilityPrompts && prompts.maintainabilityPrompts.length > 0) {
    body += `
<details>
<summary>🏗️ <strong>Maintainability Guidance</strong> (${prompts.maintainabilityPrompts.length} ${prompts.maintainabilityPrompts.length === 1 ? 'guide' : 'guides'})</summary>

`;

    prompts.maintainabilityPrompts.forEach(prompt => {
      const title = extractMaintainabilityTitle(prompt.filename);

      body += `
<details>
<summary>📐 <strong>${title}</strong></summary>

${prompt.content}

</details>

`;
    });

    body += `
</details>

`;
  }

  // Add threat model prompts with nested collapsible sections
  if (prompts.threatModelPrompts && prompts.threatModelPrompts.length > 0) {
    body += `
<details>
<summary>🎯 <strong>Threat Model Analysis (STRIDE)</strong> (${prompts.threatModelPrompts.length} ${prompts.threatModelPrompts.length === 1 ? 'threat' : 'threats'})</summary>

`;

    prompts.threatModelPrompts.forEach(prompt => {
      const title = extractStrideTitle(prompt.filename);

      body += `
<details>
<summary>🎭 <strong>${title}</strong></summary>

${prompt.content}

</details>

`;
    });

    body += `
</details>

`;
  }

  // Add Claude Remediation Zone at the bottom
  body += `

---

## 🤖 Claude Remediation Zone

To request a remediation plan for **all ${count} occurrence${count > 1 ? 's' : ''}**, **copy and paste this comment**:

\`\`\`
@claude Please provide a remediation plan for all ${count} occurrence${count > 1 ? 's' : ''} of this vulnerability in ${groupedFinding.filePath} following the security and maintainability guidelines provided.
\`\`\`

---

`;

  // Add additional metadata (collapsed)
  body += `
<details>
<summary>📊 Additional Metadata</summary>

- **Detection Time**: ${timestamp}
- **Language**: ${language.charAt(0).toUpperCase() + language.slice(1)}
- **Tool**: ${groupedFinding.tool} v${groupedFinding.toolVersion}
- **Repository**: ${config.owner}/${config.repo}
- **Branch**: ${config.branch}
- **Commit**: ${config.sha}
- **Rule ID**: ${groupedFinding.ruleId}
- **OWASP Category**: ${owaspKey}
- **Severity**: ${groupedFinding.severity} (CodeQL level: ${groupedFinding.level})
- **Prompt Source**: ${config.promptRepo}@${config.promptBranch}

</details>
`;

  // Final safety check: GitHub has a 65536 character limit for issue bodies
  const MAX_BODY_LENGTH = 65000; // Leave buffer for safety
  if (body.length > MAX_BODY_LENGTH) {
    log('WARN', `Issue body too long (${body.length} chars), truncating to ${MAX_BODY_LENGTH}`);
    body = body.substring(0, MAX_BODY_LENGTH) + '\n\n---\n\n**⚠️ Note**: This issue was truncated due to size limits. See the OWASP category link above for complete security guidance.';
  }

  return body;
}

// ============================================================================
// ISSUE TITLE GENERATION
// ============================================================================

/**
 * Generate a concise issue title for grouped findings
 * @param {Object} groupedFinding - Grouped vulnerability object with occurrences array
 * @returns {string} Issue title
 */
function createIssueTitle(groupedFinding) {
  const fileName = path.basename(groupedFinding.filePath);
  const count = groupedFinding.occurrences.length;

  // Always use "(X occurrence/occurrences)" format for consistency
  return `[Security] ${groupedFinding.ruleName} in ${fileName} (${count} occurrence${count > 1 ? 's' : ''})`;
}

// ============================================================================
// ISSUE DEDUPLICATION
// ============================================================================

/**
 * Find existing issue for a grouped finding
 * @param {Object} groupedFinding - Grouped vulnerability object
 * @returns {Promise<Object|null>} Existing issue or null
 */
async function findExistingIssue(groupedFinding) {
  try {
    log('INFO', `Searching for existing issue: ${groupedFinding.ruleId} in ${groupedFinding.filePath}`);

    // Search for issues with codeql-finding label
    const { data: issues } = await octokit.rest.issues.listForRepo({
      owner: config.owner,
      repo: config.repo,
      labels: 'codeql-finding',
      state: 'open',
      per_page: 100
    });

    // Look for matching issue by ruleId + filePath only (ignore line numbers)
    for (const issue of issues) {
      const body = issue.body || '';

      // Check if rule ID and file path match
      const hasRuleId = body.includes(`\`${groupedFinding.ruleId}\``);
      const hasFilePath = body.includes(`\`${groupedFinding.filePath}\``);

      if (hasRuleId && hasFilePath) {
        log('INFO', `Found existing issue #${issue.number}`);
        return issue;
      }
    }

    log('INFO', 'No existing issue found');
    return null;
  } catch (error) {
    log('ERROR', `Failed to search for existing issue: ${error.message}`);
    return null;
  }
}

// ============================================================================
// ISSUE LABELS
// ============================================================================

/**
 * Generate labels for an issue
 * @param {Object} groupedFinding - Grouped vulnerability object
 * @param {Object} owaspInfo - OWASP category info
 * @param {Array<string>} maintainabilityFiles - Maintainability prompt files
 * @returns {Array<string>} Array of label names
 */
function generateLabels(groupedFinding, owaspInfo, maintainabilityFiles) {
  const labels = ['codeql-finding'];

  // Severity label
  const severityLabel = mappings.label_mapping[groupedFinding.severity];
  if (severityLabel) {
    labels.push(severityLabel);
  }

  // OWASP label
  if (owaspInfo?.key) {
    labels.push(`owasp/${owaspInfo.key.toLowerCase()}`);
  }

  // Maintainability labels
  for (const file of maintainabilityFiles) {
    const aspect = file.replace('.md', '');
    labels.push(`maintainability/${aspect}`);
  }

  // Remediation status label
  labels.push('awaiting-remediation-plan');

  return labels;
}

// ============================================================================
// ISSUE CREATION/UPDATE
// ============================================================================

/**
 * Create or update a GitHub issue
 * @param {Object} groupedFinding - Grouped vulnerability object with occurrences array
 * @param {string} issueBody - Formatted issue body
 * @param {Array<string>} labels - Issue labels
 * @returns {Promise<Object>} Created/updated issue
 */
async function createOrUpdateIssue(groupedFinding, issueBody, labels) {
  const title = createIssueTitle(groupedFinding);

  // Check for existing issue
  const existingIssue = await findExistingIssue(groupedFinding);

  if (existingIssue) {
    // Update existing issue
    try {
      log('INFO', `Updating existing issue #${existingIssue.number}`);

      const { data: issue } = await octokit.rest.issues.update({
        owner: config.owner,
        repo: config.repo,
        issue_number: existingIssue.number,
        body: issueBody,
        labels: labels
      });

      // Add comment to indicate update
      await octokit.rest.issues.createComment({
        owner: config.owner,
        repo: config.repo,
        issue_number: existingIssue.number,
        body: `🔄 **Issue Updated**\n\nThis vulnerability was re-detected in the latest CodeQL scan.\n\n**Commit**: ${config.sha}\n**Branch**: ${config.branch}\n**Timestamp**: ${new Date().toISOString()}`
      });

      log('SUCCESS', `Updated issue #${issue.number}: ${title}`);
      return { issue, action: 'updated' };
    } catch (error) {
      log('ERROR', `Failed to update issue #${existingIssue.number}: ${error.message}`);
      throw error;
    }
  } else {
    // Create new issue
    try {
      log('INFO', `Creating new issue: ${title}`);

      const issueData = {
        owner: config.owner,
        repo: config.repo,
        title: title,
        body: issueBody,
        labels: labels
      };

      // Add assignees if configured
      if (config.autoAssign.length > 0) {
        issueData.assignees = config.autoAssign;
      }

      const { data: issue } = await octokit.rest.issues.create(issueData);

      log('SUCCESS', `Created issue #${issue.number}: ${title}`);
      return { issue, action: 'created' };
    } catch (error) {
      log('ERROR', `Failed to create issue: ${error.message}`);
      throw error;
    }
  }
}

// ============================================================================
// PATH FILTERING
// ============================================================================

/**
 * Check if a file path should be excluded
 * @param {string} filePath - File path to check
 * @returns {boolean} True if path should be excluded
 */
function shouldExcludePath(filePath) {
  for (const excludedPath of config.excludedPaths) {
    if (filePath.includes(excludedPath)) {
      return true;
    }
  }
  return false;
}

// ============================================================================
// SEVERITY FILTERING
// ============================================================================

/**
 * Check if vulnerability meets severity threshold
 * @param {string} severity - Vulnerability severity
 * @returns {boolean} True if severity meets threshold
 */
function meetsSeverityThreshold(severity) {
  const severityLevels = ['low', 'medium', 'high', 'critical'];
  const thresholdIndex = severityLevels.indexOf(config.severityThreshold);
  const severityIndex = severityLevels.indexOf(severity);

  return severityIndex >= thresholdIndex;
}

// ============================================================================
// AUTO-CLOSE RESOLVED ISSUES
// ============================================================================

/**
 * Auto-close issues for vulnerabilities that are no longer in the SARIF results
 * For grouped issues, closes only if ALL occurrences are resolved
 * @param {Set<string>} currentVulnerabilities - Set of current vulnerability keys (ruleId:filePath:line)
 * @returns {Promise<number>} Number of issues closed
 */
async function autoCloseResolvedIssues(currentVulnerabilities) {
  let closedCount = 0;

  try {
    // Get all open issues with codeql-finding label
    const { data: openIssues } = await octokit.rest.issues.listForRepo({
      owner: config.owner,
      repo: config.repo,
      labels: 'codeql-finding',
      state: 'open',
      per_page: 100
    });

    log('INFO', `Found ${openIssues.length} open CodeQL issue(s) to check`);

    for (const issue of openIssues) {
      // Skip issues marked as false-positive
      const labels = issue.labels.map(l => typeof l === 'string' ? l : l.name);
      if (labels.includes('false-positive')) {
        log('INFO', `Skipping issue #${issue.number} (marked as false-positive)`);
        continue;
      }

      const body = issue.body || '';

      // Extract rule and file from issue body
      const ruleMatch = body.match(/\*\*CodeQL Rule\*\* \| `([^`]+)`/);
      const fileMatch = body.match(/\*\*File\*\* \| `([^`]+)`/);

      if (!ruleMatch || !fileMatch) {
        log('WARN', `Could not parse issue #${issue.number}, skipping auto-close check`);
        continue;
      }

      const ruleId = ruleMatch[1];
      const filePath = fileMatch[1];

      // Extract all line numbers from the issue body for grouped findings
      // Matches "Location X: Lines Y" or "Lines Y" or "#### Location 1: Lines 45-47"
      const lineMatches = body.matchAll(/Lines?\s+(\d+)(?:-\d+)?/gi);
      const issueLines = new Set();

      for (const match of lineMatches) {
        issueLines.add(match[1]);
      }

      // If no lines found, try the old format (single line in table)
      if (issueLines.size === 0) {
        const oldFormatLine = body.match(/\*\*Lines\*\* \| (\d+)/);
        if (oldFormatLine) {
          issueLines.add(oldFormatLine[1]);
        }
      }

      if (issueLines.size === 0) {
        log('WARN', `Could not extract line numbers from issue #${issue.number}, skipping auto-close check`);
        continue;
      }

      // Check if ANY of the issue's occurrences still exist in current scan
      let hasAnyOccurrence = false;
      for (const line of issueLines) {
        const vulnKey = `${ruleId}:${filePath}:${line}`;
        if (currentVulnerabilities.has(vulnKey)) {
          hasAnyOccurrence = true;
          break;
        }
      }

      // Only close if ALL occurrences are resolved (none exist in current scan)
      if (!hasAnyOccurrence) {
        log('INFO', `All occurrences resolved for ${ruleId} in ${filePath}, closing issue #${issue.number}`);

        // Close the issue
        await octokit.rest.issues.update({
          owner: config.owner,
          repo: config.repo,
          issue_number: issue.number,
          state: 'closed'
        });

        // Add closing comment
        const occurrenceCount = issueLines.size;
        await octokit.rest.issues.createComment({
          owner: config.owner,
          repo: config.repo,
          issue_number: issue.number,
          body: `## ✅ All Vulnerabilities Resolved

This issue is being automatically closed because **all ${occurrenceCount} occurrence${occurrenceCount > 1 ? 's' : ''}** of this vulnerability ${occurrenceCount > 1 ? 'are' : 'is'} no longer detected in the latest CodeQL scan.

**Details:**
- **Rule**: \`${ruleId}\`
- **File**: \`${filePath}\`
- **Occurrences Resolved**: ${occurrenceCount}
- **Scan Date**: ${new Date().toISOString()}
- **Branch**: ${config.branch}
- **Commit**: ${config.sha}

If this was closed in error, please reopen and add the \`false-positive\` label to prevent auto-closing in the future.

---

🤖 Auto-closed by CodeQL to Issues automation`
        });

        // Add resolved label
        await octokit.rest.issues.addLabels({
          owner: config.owner,
          repo: config.repo,
          issue_number: issue.number,
          labels: ['resolved']
        });

        closedCount++;

        // Rate limiting protection
        await new Promise(resolve => setTimeout(resolve, 1000));
      } else {
        log('INFO', `Issue #${issue.number} still has active occurrences, keeping open`);
      }
    }
  } catch (error) {
    log('ERROR', `Error in auto-close: ${error.message}`);
    throw error;
  }

  return closedCount;
}

// ============================================================================
// FINDING GROUPING
// ============================================================================

/**
 * Group findings by ruleId and filePath to create one issue per rule per file
 * @param {Array<Object>} findings - Array of vulnerabilities
 * @returns {Array<Object>} Array of grouped findings
 */
function groupFindingsByRuleAndFile(findings) {
  const groups = new Map();

  for (const finding of findings) {
    const key = `${finding.ruleId}:${finding.filePath}`;

    if (!groups.has(key)) {
      groups.set(key, {
        ruleId: finding.ruleId,
        ruleName: finding.ruleName,
        ruleHelp: finding.ruleHelp,
        filePath: finding.filePath,
        level: finding.level,
        severity: finding.severity,
        tool: finding.tool,
        toolVersion: finding.toolVersion,
        message: finding.message,
        occurrences: []
      });
    }

    groups.get(key).occurrences.push({
      startLine: finding.startLine,
      endLine: finding.endLine,
      startColumn: finding.startColumn,
      endColumn: finding.endColumn,
      codeSnippet: finding.codeSnippet,
      message: finding.message
    });
  }

  return Array.from(groups.values());
}

// ============================================================================
// MAIN PROCESSING
// ============================================================================

/**
 * Process findings and create/update issues
 * @param {Array<Object>} findings - Array of vulnerabilities
 * @returns {Promise<Object>} Processing results
 */
async function processFindings(findings) {
  const results = {
    total: findings.length,
    created: 0,
    updated: 0,
    skipped: 0,
    closed: 0,
    errors: [],
    by_severity: { critical: 0, high: 0, medium: 0, low: 0 },
    by_owasp: {}
  };

  // GROUP FINDINGS FIRST by ruleId + filePath
  log('INFO', 'Grouping findings by rule and file...');
  const groupedFindings = groupFindingsByRuleAndFile(findings);
  log('SUCCESS', `Grouped ${findings.length} finding(s) into ${groupedFindings.length} issue(s)`);

  let processedCount = 0;

  // Track current vulnerabilities for auto-close feature (track all individual occurrences)
  const currentVulnerabilities = new Set();

  for (const groupedFinding of groupedFindings) {
    try {
      // Check if we've reached the limit
      if (processedCount >= config.maxIssuesPerRun) {
        log('WARN', `Reached max issues per run (${config.maxIssuesPerRun}), stopping`);
        results.skipped += groupedFindings.length - processedCount;
        break;
      }

      // Count by severity
      results.by_severity[groupedFinding.severity] = (results.by_severity[groupedFinding.severity] || 0) + 1;

      // Filter by severity threshold
      if (!meetsSeverityThreshold(groupedFinding.severity)) {
        log('INFO', `Skipping ${groupedFinding.ruleId} (severity ${groupedFinding.severity} below threshold ${config.severityThreshold})`);
        results.skipped++;
        continue;
      }

      // Filter by excluded paths
      if (shouldExcludePath(groupedFinding.filePath)) {
        log('INFO', `Skipping ${groupedFinding.ruleId} (path ${groupedFinding.filePath} is excluded)`);
        results.skipped++;
        continue;
      }

      // Map to OWASP
      const owaspInfo = mapToOWASP(groupedFinding.ruleId);
      if (!owaspInfo) {
        log('WARN', `Skipping ${groupedFinding.ruleId} (no OWASP mapping)`);
        results.skipped++;
        continue;
      }

      // Count by OWASP
      results.by_owasp[owaspInfo.key] = (results.by_owasp[owaspInfo.key] || 0) + 1;

      log('INFO', `Processing grouped finding: ${groupedFinding.ruleId} (${owaspInfo.key}) - ${groupedFinding.occurrences.length} occurrence(s)`);

      // Fetch prompts
      const prompts = {
        owaspKey: owaspInfo.key,
        owaspCategory: owaspInfo.name,
        owaspFile: owaspInfo.prompt_file,
        owaspPrompts: [],
        maintainabilityPrompts: [],
        threatModelPrompts: []
      };

      // Fetch OWASP prompt (now as array for nested collapsible structure)
      const owaspContent = await fetchPrompt('owasp', owaspInfo.prompt_file);
      if (owaspContent) {
        prompts.owaspPrompts.push({
          filename: owaspInfo.prompt_file,
          content: owaspContent
        });
      }

      // Detect and fetch maintainability prompts (use first occurrence as representative)
      const maintainabilityFiles = detectMaintainabilityConcerns(groupedFinding);

      // Add mapped maintainability prompts from OWASP category
      if (owaspInfo.maintainability) {
        for (const aspect of owaspInfo.maintainability) {
          const file = `${aspect}.md`;
          if (!maintainabilityFiles.includes(file)) {
            maintainabilityFiles.push(file);
          }
        }
      }

      for (const file of maintainabilityFiles) {
        const content = await fetchPrompt('maintainability', file);
        if (content) {
          prompts.maintainabilityPrompts.push({
            filename: file,
            content
          });
        }
      }

      // Fetch threat model prompts if enabled
      if (config.enableThreatModel && owaspInfo.threat_model) {
        for (const threat of owaspInfo.threat_model) {
          const file = `${threat}.md`;
          const content = await fetchPrompt('threat-modeling', file);
          if (content) {
            prompts.threatModelPrompts.push({
              filename: file,
              content
            });
          }
        }
      }

      // Create issue body
      const issueBody = createIssueBody(groupedFinding, prompts);

      // Generate labels
      const labels = generateLabels(groupedFinding, owaspInfo, maintainabilityFiles);

      // Create or update issue
      const { issue, action } = await createOrUpdateIssue(groupedFinding, issueBody, labels);

      if (action === 'created') {
        results.created++;
      } else if (action === 'updated') {
        results.updated++;
      }

      // Track ALL occurrences of this vulnerability as currently existing
      for (const occurrence of groupedFinding.occurrences) {
        const vulnKey = `${groupedFinding.ruleId}:${groupedFinding.filePath}:${occurrence.startLine}`;
        currentVulnerabilities.add(vulnKey);
      }

      processedCount++;

      // Rate limiting protection
      await new Promise(resolve => setTimeout(resolve, 1000));

    } catch (error) {
      log('ERROR', `Failed to process grouped finding ${groupedFinding.ruleId}: ${error.message}`);
      results.errors.push({
        ruleId: groupedFinding.ruleId,
        filePath: groupedFinding.filePath,
        error: error.message
      });
      results.skipped++;
    }
  }

  // Auto-close resolved vulnerabilities
  log('INFO', 'Checking for resolved vulnerabilities to auto-close...');
  try {
    const closedCount = await autoCloseResolvedIssues(currentVulnerabilities);
    results.closed = closedCount;
    log('INFO', `Auto-closed ${closedCount} resolved issue(s)`);
  } catch (error) {
    log('ERROR', `Failed to auto-close resolved issues: ${error.message}`);
  }

  return results;
}

// ============================================================================
// SUMMARY GENERATION
// ============================================================================

/**
 * Generate and save summary statistics
 * @param {Object} results - Processing results
 */
function generateSummary(results) {
  const summary = {
    timestamp: new Date().toISOString(),
    repository: `${config.owner}/${config.repo}`,
    branch: config.branch,
    commit: config.sha,
    configuration: {
      severity_threshold: config.severityThreshold,
      max_issues_per_run: config.maxIssuesPerRun,
      maintainability_enabled: config.enableMaintainability,
      threat_model_enabled: config.enableThreatModel
    },
    ...results
  };

  fs.writeFileSync(summaryFile, JSON.stringify(summary, null, 2));
  log('SUCCESS', `Saved summary to ${summaryFile}`);

  // Output summary to console
  console.log('\n' + '='.repeat(80));
  console.log('📊 PROCESSING SUMMARY');
  console.log('='.repeat(80));
  console.log(`Total Findings:     ${results.total}`);
  console.log(`Issues Created:     ${results.created}`);
  console.log(`Issues Updated:     ${results.updated}`);
  console.log(`Issues Closed:      ${results.closed || 0} (auto-closed resolved vulnerabilities)`);
  console.log(`Issues Skipped:     ${results.skipped}`);
  console.log(`Errors:             ${results.errors.length}`);
  console.log('\nBy Severity:');
  console.log(`  Critical:         ${results.by_severity.critical || 0}`);
  console.log(`  High:             ${results.by_severity.high || 0}`);
  console.log(`  Medium:           ${results.by_severity.medium || 0}`);
  console.log(`  Low:              ${results.by_severity.low || 0}`);
  console.log('\nBy OWASP Category:');
  for (const [category, count] of Object.entries(results.by_owasp)) {
    const categoryName = mappings.owasp_categories[category]?.name || category;
    console.log(`  ${categoryName}: ${count}`);
  }

  if (results.errors.length > 0) {
    console.log('\n⚠️  Errors:');
    for (const error of results.errors) {
      console.log(`  - ${error.ruleId} in ${error.filePath}: ${error.error}`);
    }
  }

  console.log('='.repeat(80) + '\n');
}

// ============================================================================
// MAIN EXECUTION
// ============================================================================

async function main() {
  const startTime = Date.now();

  log('INFO', 'Starting CodeQL SARIF processing');
  log('INFO', `Repository: ${config.owner}/${config.repo}`);
  log('INFO', `SARIF file: ${config.sarifPath}`);

  try {
    // Parse SARIF results
    const findings = parseSARIFResults(config.sarifPath);

    if (findings.length === 0) {
      log('INFO', 'No vulnerabilities found in SARIF results');
      generateSummary({
        total: 0,
        created: 0,
        updated: 0,
        skipped: 0,
        errors: [],
        by_severity: { critical: 0, high: 0, medium: 0, low: 0 },
        by_owasp: {}
      });
      return;
    }

    // Process findings
    const results = await processFindings(findings);

    // Generate summary
    generateSummary(results);

    const duration = ((Date.now() - startTime) / 1000).toFixed(2);
    log('SUCCESS', `Processing complete in ${duration}s`);

    // Exit with error if there were processing errors
    if (results.errors.length > 0) {
      log('WARN', `Completed with ${results.errors.length} error(s)`);
      process.exit(1);
    }

  } catch (error) {
    log('ERROR', `Fatal error: ${error.message}`);
    console.error(error);
    process.exit(1);
  }
}

// Run main function
if (require.main === module) {
  main().catch(error => {
    console.error('❌ Unhandled error:', error);
    process.exit(1);
  });
}

module.exports = {
  parseSARIFResults,
  mapToOWASP,
  fetchPrompt,
  createIssueBody,
  findExistingIssue,
  generateLabels,
  shouldExcludePath,
  meetsSeverityThreshold
};
