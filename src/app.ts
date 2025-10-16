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
import { z } from 'zod';
import { loginSchema, searchSchema, userIdSchema, emailSchema } from './validation';
import {
  globalLimiter,
  loginLimiter,
  loginSlowDown,
  passwordResetLimiter,
  searchLimiter,
  adminLimiter
} from './rate-limiter';

const app = express();
app.use(express.json());
app.use(globalLimiter); // ✅ Global rate limit: 100 requests per 15 min

// A01 - Broken Access Control: Hardcoded connection string
const pool = new Pool({
  connectionString: 'postgresql://admin:password123@localhost:5432/mydb'
});

// A03 - Injection: FIXED - Parameterized queries with input validation
// A04 - Insecure Design: FIXED - Multi-layer rate limiting added
app.post('/api/login',
  loginLimiter,      // Layer 1: Max 5 attempts per 15 min per IP
  loginSlowDown,     // Layer 2: Progressive delay after 3rd attempt
  async (req, res) => {
    try {
      // Validate input with Zod schema (allowlist regex)
      const { username, password } = loginSchema.parse(req.body);

      // Layer 3: Account-based lockout (future enhancement with Redis)
      // Check if account locked: await redis.get(`lockout:${username}`)

      // Parameterized query - SQL structure separate from data
      const query = 'SELECT id, username, email, role FROM users WHERE username = $1 AND password = $2';
      const result = await pool.query(query, [username, password]);

      if (result.rows.length > 0) {
        // A07 - Authentication Failure: No password hashing (separate issue)
        res.json({
          success: true,
          user: result.rows[0]
        });
      } else {
        res.status(401).json({ success: false, message: 'Invalid credentials' });
      }
    } catch (error) {
      // Generic error message - don't expose SQL details
      if (error instanceof z.ZodError) {
        res.status(400).json({ success: false, message: 'Invalid input' });
      } else {
        console.error('Login error:', error); // Log server-side only
        res.status(500).json({ success: false, message: 'Operation failed' });
      }
    }
  }
);

// A03 - Injection: FIXED - Parameterized queries with input validation
// A04 - Insecure Design: FIXED - Rate limiting added
app.get('/api/users/search',
  searchLimiter, // Max 30 requests/min per IP
  async (req, res) => {
    try {
      // Validate input with Zod schema (allowlist regex)
      const { q: searchTerm } = searchSchema.parse(req.query);

      // ✅ Key Pattern 3: Resource limits already present (Zod validation)
      // Parameterized query with LIKE pattern
      const query = 'SELECT id, username, email FROM users WHERE name ILIKE $1';
      const result = await pool.query(query, [`%${searchTerm}%`]);

      res.json(result.rows);
    } catch (error) {
      // Generic error message - don't expose SQL details
      if (error instanceof z.ZodError) {
        res.status(400).json({ error: 'Invalid search term' });
      } else {
        console.error('Search error:', error); // Log server-side only
        res.status(500).json({ error: 'Search failed' });
      }
    }
  }
);

// A01 - Broken Access Control: No authorization check (separate issue)
// A03 - Injection: FIXED - Parameterized queries with input validation
// A04 - Insecure Design: FIXED - Rate limiting added
app.get('/api/admin/users/:id',
  adminLimiter, // Max 20 requests/min per IP
  async (req, res) => {
    try {
      // Validate input with Zod schema
      const userId = userIdSchema.parse(req.params.id);

      // Parameterized query - SQL structure separate from data
      const query = 'SELECT id, username, email, role FROM users WHERE id = $1';
      const result = await pool.query(query, [userId]);

      if (result.rows.length > 0) {
        res.json(result.rows[0]);
      } else {
        res.status(404).json({ error: 'User not found' });
      }
    } catch (error) {
      // Generic error message - don't expose SQL details
      if (error instanceof z.ZodError) {
        res.status(400).json({ error: 'Invalid user ID' });
      } else {
        console.error('User fetch error:', error); // Log server-side only
        res.status(500).json({ error: 'Operation failed' });
      }
    }
  }
);

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

// A04 - Insecure Design: Predictable password reset tokens (partially fixed)
// A03 - Injection: FIXED - Parameterized queries with input validation
// A04 - Insecure Design: FIXED - Rate limiting added
app.post('/api/password-reset',
  passwordResetLimiter, // Max 3 requests/hour per IP
  async (req, res) => {
    try {
      // Validate input with Zod schema
      const email = emailSchema.parse(req.body.email);

      // Generate secure reset token (improved from timestamp)
      const resetToken = crypto.randomBytes(32).toString('hex');

      // Parameterized query - SQL structure separate from data
      const query = 'UPDATE users SET reset_token = $1, reset_token_expiry = NOW() + INTERVAL \'1 hour\' WHERE email = $2';
      await pool.query(query, [resetToken, email]);

      // Generic response (prevents email enumeration)
      res.json({
        message: 'If the email exists, a reset link has been sent'
      });
    } catch (error) {
      // Generic error message - don't expose SQL details
      if (error instanceof z.ZodError) {
        res.status(400).json({ error: 'Invalid email' });
      } else {
        console.error('Password reset error:', error); // Log server-side only
        res.status(500).json({ error: 'Operation failed' });
      }
    }
  }
);

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
