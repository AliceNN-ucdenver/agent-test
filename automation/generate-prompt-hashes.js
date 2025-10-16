#!/usr/bin/env node

/**
 * Generate SHA-256 Hashes for Prompt Pack Files
 *
 * This script generates a hash manifest for all prompt pack files to ensure
 * integrity when fetching from remote sources.
 *
 * Usage:
 *   node generate-prompt-hashes.js
 *
 * Output:
 *   prompt-hashes.json
 */

const fs = require('fs');
const crypto = require('crypto');
const path = require('path');

// Path to prompt pack directory (relative to this script)
const PROMPTPACK_DIR = path.join(__dirname, '../../../examples/promptpack');
const OUTPUT_FILE = path.join(__dirname, 'prompt-hashes.json');

const CATEGORIES = ['owasp', 'maintainability', 'threat-modeling'];

/**
 * Generate SHA-256 hash for a file
 * @param {string} filePath - Path to file
 * @returns {string} SHA-256 hash in format "sha256:abc123..."
 */
function generateHash(filePath) {
  const content = fs.readFileSync(filePath, 'utf8');
  const hash = crypto.createHash('sha256').update(content).digest('hex');
  return `sha256:${hash}`;
}

/**
 * Generate hashes for all prompt pack files
 * @returns {Object} Hash manifest
 */
function generateHashManifest() {
  const manifest = {
    _metadata: {
      generated: new Date().toISOString(),
      generator: 'generate-prompt-hashes.js',
      algorithm: 'SHA-256'
    }
  };

  let totalFiles = 0;
  let totalSize = 0;

  console.log('🔐 Generating Prompt Pack Hash Manifest\n');

  for (const category of CATEGORIES) {
    const categoryDir = path.join(PROMPTPACK_DIR, category);

    if (!fs.existsSync(categoryDir)) {
      console.error(`❌ ERROR: Category directory not found: ${categoryDir}`);
      process.exit(1);
    }

    manifest[category] = {};

    const files = fs.readdirSync(categoryDir)
      .filter(f => f.endsWith('.md') && f !== 'index.md')
      .sort();

    console.log(`📁 ${category}/`);

    for (const file of files) {
      const filePath = path.join(categoryDir, file);
      const stats = fs.statSync(filePath);
      const hash = generateHash(filePath);

      manifest[category][file] = hash;
      totalFiles++;
      totalSize += stats.size;

      console.log(`   ✅ ${file.padEnd(40)} ${hash.substring(0, 20)}...`);
    }

    console.log('');
  }

  return { manifest, totalFiles, totalSize };
}

/**
 * Main execution
 */
function main() {
  try {
    // Generate hashes
    const { manifest, totalFiles, totalSize } = generateHashManifest();

    // Write to file
    fs.writeFileSync(
      OUTPUT_FILE,
      JSON.stringify(manifest, null, 2) + '\n'
    );

    // Summary
    console.log('═'.repeat(70));
    console.log('📊 Summary:');
    console.log(`   Total files: ${totalFiles}`);
    console.log(`   Total size:  ${(totalSize / 1024).toFixed(2)} KB`);
    console.log(`   Output:      ${path.relative(process.cwd(), OUTPUT_FILE)}`);
    console.log('═'.repeat(70));
    console.log('✅ Hash manifest generated successfully!\n');

    // Validation tip
    console.log('💡 Tips:');
    console.log('   - Commit prompt-hashes.json to version control');
    console.log('   - Re-run this script after updating any prompt files');
    console.log('   - CI will validate hashes match on every push/PR\n');

  } catch (error) {
    console.error('❌ ERROR:', error.message);
    process.exit(1);
  }
}

// Run if called directly
if (require.main === module) {
  main();
}

module.exports = { generateHash, generateHashManifest };
