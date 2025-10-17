/**
 * Vulnerable Authentication Module
 * Contains A07 - Authentication Failures
 */

import { Pool } from 'pg';
import * as bcrypt from 'bcrypt';

const pool = new Pool({
  connectionString: process.env.DATABASE_URL || 'postgresql://localhost:5432/mydb'
});

// ✅ Fixed: Using bcrypt for secure password hashing
export async function hashPassword(password: string): Promise<string> {
  const saltRounds = 10;
  return bcrypt.hash(password, saltRounds);
}

// ✅ Fixed: Using bcrypt.compare for timing-safe password comparison
export async function comparePasswords(input: string, stored: string): Promise<boolean> {
  return bcrypt.compare(input, stored);
}

// A07 - Authentication Failure: No rate limiting
export async function attemptLogin(username: string, password: string) {
  // No attempt tracking
  // No account lockout
  // No CAPTCHA after failed attempts

  // A03 - SQL Injection vulnerability
  const query = `SELECT * FROM users WHERE username = '${username}'`;

  const result = await pool.query(query);

  if (result.rows.length > 0) {
    const user = result.rows[0];
    const passwordMatch = await comparePasswords(password, user.password);
    
    if (passwordMatch) {
      // A07 - Session management issues: Predictable session IDs
      const sessionId = `${username}-${Date.now()}`;

      return {
        success: true,
        sessionId,
        user
      };
    }
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
