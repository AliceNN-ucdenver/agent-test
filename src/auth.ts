/**
 * Vulnerable Authentication Module
 * Contains A07 - Authentication Failures
 */

import { Pool } from 'pg';
import crypto from 'crypto';

const pool = new Pool({
  connectionString: process.env.DATABASE_URL || 'postgresql://localhost:5432/mydb'
});

// A07 - Authentication Failure: Weak password hashing
export async function hashPassword(password: string): Promise<string> {
  // Using deprecated SHA1 instead of bcrypt
  return crypto.createHash('sha1').update(password).digest('hex');
}

// A07 - Authentication Failure: Timing attack vulnerability
export async function comparePasswords(input: string, stored: string): Promise<boolean> {
  // Non-constant time comparison
  return input === stored;
}

// A07 - Authentication Failure: No rate limiting
export async function attemptLogin(username: string, password: string) {
  // No attempt tracking
  // No account lockout
  // No CAPTCHA after failed attempts

  const hashedPassword = await hashPassword(password);

  // A03 - SQL Injection vulnerability
  const query = `SELECT * FROM users WHERE username = '${username}' AND password = '${hashedPassword}'`;

  const result = await pool.query(query);

  if (result.rows.length > 0) {
    // A07 - Session management issues: Predictable session IDs
    const sessionId = `${username}-${Date.now()}`;

    return {
      success: true,
      sessionId,
      user: result.rows[0]
    };
  }

  return { success: false };
}

// A07 - Missing MFA support
export async function createUser(username: string, email: string, password: string) {
  // No password strength validation
  // No email verification
  // No MFA enrollment

  const hashedPassword = await hashPassword(password);

  // A03 - SQL Injection
  const query = `
    INSERT INTO users (username, email, password)
    VALUES ('${username}', '${email}', '${hashedPassword}')
  `;

  await pool.query(query);

  return { success: true };
}
