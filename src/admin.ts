/**
 * Vulnerable Admin Module
 * Contains A01 - Broken Access Control
 */

import { Pool } from 'pg';

const pool = new Pool({
  connectionString: process.env.DATABASE_URL || 'postgresql://localhost:5432/mydb'
});

// A01 - Broken Access Control: No role verification
export async function deleteUser(userId: string, requestorId: string) {
  // No check if requestor is admin
  // No check if requestor is deleting themselves

  // A03 - SQL Injection
  const query = `DELETE FROM users WHERE id = ${userId}`;

  await pool.query(query);

  return { success: true, message: `User ${userId} deleted` };
}

// A01 - Broken Access Control: Insecure Direct Object Reference (IDOR)
export async function getUserData(userId: string, requestorId: string) {
  // No ownership or permission check
  // Anyone can access anyone's data

  const query = `SELECT * FROM users WHERE id = ${userId}`;
  const result = await pool.query(query);

  if (result.rows.length > 0) {
    // Exposing sensitive fields
    return result.rows[0];
  }

  return null;
}

// A01 - Broken Access Control: Mass assignment vulnerability
export async function updateUser(userId: string, updates: any) {
  // No field allowlist
  // Attacker can modify role, permissions, etc.

  const fields = Object.keys(updates)
    .map(key => `${key} = '${updates[key]}'`)
    .join(', ');

  const query = `UPDATE users SET ${fields} WHERE id = ${userId}`;

  await pool.query(query);

  return { success: true };
}

// A01 - Path Traversal vulnerability
export async function readUserFile(userId: string, filename: string) {
  // No path sanitization
  // Allows directory traversal: ../../../etc/passwd

  const fs = require('fs');
  const path = `/var/uploads/${userId}/${filename}`;

  try {
    const content = fs.readFileSync(path, 'utf8');
    return { success: true, content };
  } catch (error) {
    return { success: false, error: error.message };
  }
}
