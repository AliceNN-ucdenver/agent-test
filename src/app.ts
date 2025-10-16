/**
 * Vulnerable Express API - Educational Example
 *
 * This application intentionally contains security vulnerabilities
 * for demonstration purposes with CodeQL + Claude AI remediation.
 *
 * DO NOT use this code in production!
 */

import express from 'express';
import { Pool } from 'pg';
import crypto from 'crypto';

const app = express();
app.use(express.json());

// A01 - Broken Access Control: Hardcoded connection string
const pool = new Pool({
  connectionString: 'postgresql://admin:password123@localhost:5432/mydb'
});

// A03 - Injection: Vulnerable login endpoint
app.post('/api/login', async (req, res) => {
  const { username, password } = req.body;

  // SQL Injection vulnerability - string concatenation
  const query = `SELECT * FROM users WHERE username = '${username}' AND password = '${password}'`;

  try {
    const result = await pool.query(query);

    if (result.rows.length > 0) {
      // A07 - Authentication Failure: No password hashing
      res.json({
        success: true,
        user: result.rows[0]  // A01: Exposing full user record
      });
    } else {
      res.status(401).json({ success: false, message: 'Invalid credentials' });
    }
  } catch (error) {
    // A09 - Logging Failure: Exposing sensitive error details
    res.status(500).json({
      error: error.message,
      query: query  // Exposing query structure
    });
  }
});

// A03 - Injection: Vulnerable search endpoint
app.get('/api/users/search', async (req, res) => {
  const searchTerm = req.query.q;

  // NoSQL-style injection if using JSON queries
  const query = `SELECT * FROM users WHERE name LIKE '%${searchTerm}%'`;

  try {
    const result = await pool.query(query);
    res.json(result.rows);
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// A01 - Broken Access Control: No authorization check
app.get('/api/admin/users/:id', async (req, res) => {
  const userId = req.params.id;

  // Direct object reference without ownership check
  const query = `SELECT * FROM users WHERE id = ${userId}`;

  try {
    const result = await pool.query(query);
    if (result.rows.length > 0) {
      res.json(result.rows[0]);
    } else {
      res.status(404).json({ error: 'User not found' });
    }
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// A02 - Cryptographic Failures: Weak encryption
app.post('/api/encrypt', (req, res) => {
  const { data } = req.body;

  // Using deprecated and insecure MD5
  const hash = crypto.createHash('md5').update(data).digest('hex');

  // Using weak DES encryption
  const cipher = crypto.createCipher('des', 'hardcoded-secret-key');
  let encrypted = cipher.update(data, 'utf8', 'hex');
  encrypted += cipher.final('hex');

  res.json({ hash, encrypted });
});

// A04 - Insecure Design: Predictable password reset tokens
app.post('/api/password-reset', async (req, res) => {
  const { email } = req.body;

  // Predictable token based on timestamp
  const resetToken = Math.floor(Date.now() / 1000).toString();

  // Store in database without expiration
  await pool.query(
    `UPDATE users SET reset_token = '${resetToken}' WHERE email = '${email}'`
  );

  res.json({
    message: 'Reset token sent',
    token: resetToken  // Exposing token in response
  });
});

// A05 - Security Misconfiguration: Overly permissive CORS
app.use((req, res, next) => {
  res.header('Access-Control-Allow-Origin', '*');
  res.header('Access-Control-Allow-Methods', '*');
  res.header('Access-Control-Allow-Headers', '*');
  next();
});

// A08 - Integrity Failures: No signature verification
app.post('/api/upload', (req, res) => {
  const { fileData, fileName } = req.body;

  // No integrity check on uploaded data
  // No file type validation
  // No size limits

  res.json({ message: 'File uploaded', fileName });
});

// A10 - SSRF: Unvalidated URL fetching
app.post('/api/fetch-url', async (req, res) => {
  const { url } = req.body;

  // No URL validation - allows internal network access
  const response = await fetch(url);
  const data = await response.text();

  res.json({ content: data });
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log(`Vulnerable API running on port ${PORT}`);
  console.log('⚠️  WARNING: This application contains intentional vulnerabilities!');
});

export default app;
