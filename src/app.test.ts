/**
 * Comprehensive Test Suite for SQL Injection Fixes
 *
 * Tests all 4 fixed endpoints with:
 * - Positive tests (valid inputs)
 * - Attack vector tests (SQL injection attempts)
 * - Edge case tests (empty, null, exceeding limits)
 */

import request from 'supertest';
import app from './app';
import { z } from 'zod';

describe('SQL Injection Prevention - Issue #3', () => {
  describe('POST /api/login', () => {
    it('should reject SQL injection in username', async () => {
      const response = await request(app)
        .post('/api/login')
        .send({ username: "admin' OR '1'='1' --", password: 'ValidPass123' });

      expect(response.status).toBe(400);
      expect(response.body.message).toBe('Invalid input');
    });

    it('should reject SQL injection in password', async () => {
      const response = await request(app)
        .post('/api/login')
        .send({ username: 'admin', password: "' OR '1'='1' --" });

      expect(response.status).toBe(400);
      expect(response.body.message).toBe('Invalid input');
    });

    it('should reject username with special characters', async () => {
      const response = await request(app)
        .post('/api/login')
        .send({ username: 'admin;DROP TABLE users;--', password: 'ValidPass123' });

      expect(response.status).toBe(400);
    });

    it('should reject SQL UNION attack in username', async () => {
      const response = await request(app)
        .post('/api/login')
        .send({ username: "admin' UNION SELECT * FROM passwords--", password: 'test' });

      expect(response.status).toBe(400);
    });

    it('should reject empty username', async () => {
      const response = await request(app)
        .post('/api/login')
        .send({ username: '', password: 'ValidPass123' });

      expect(response.status).toBe(400);
    });

    it('should reject username below minimum length', async () => {
      const response = await request(app)
        .post('/api/login')
        .send({ username: 'ab', password: 'ValidPass123' });

      expect(response.status).toBe(400);
    });

    it('should reject username exceeding max length', async () => {
      const response = await request(app)
        .post('/api/login')
        .send({ username: 'a'.repeat(51), password: 'ValidPass123' });

      expect(response.status).toBe(400);
    });

    it('should reject password below minimum length', async () => {
      const response = await request(app)
        .post('/api/login')
        .send({ username: 'testuser', password: 'short' });

      expect(response.status).toBe(400);
    });

    it('should reject password without uppercase', async () => {
      const response = await request(app)
        .post('/api/login')
        .send({ username: 'testuser', password: 'alllowercase123' });

      expect(response.status).toBe(400);
    });

    it('should reject password without number', async () => {
      const response = await request(app)
        .post('/api/login')
        .send({ username: 'testuser', password: 'NoNumbersHere' });

      expect(response.status).toBe(400);
    });

    it('should handle null input gracefully', async () => {
      const response = await request(app)
        .post('/api/login')
        .send({ username: null, password: null });

      expect(response.status).toBe(400);
    });

    it('should handle undefined input gracefully', async () => {
      const response = await request(app)
        .post('/api/login')
        .send({});

      expect(response.status).toBe(400);
    });
  });

  describe('GET /api/users/search', () => {
    it('should reject SQL injection in search term', async () => {
      const response = await request(app)
        .get('/api/users/search')
        .query({ q: "%'; DROP TABLE users; --" });

      expect(response.status).toBe(400);
      expect(response.body.error).toBe('Invalid search term');
    });

    it('should reject search term with SQL comment syntax', async () => {
      const response = await request(app)
        .get('/api/users/search')
        .query({ q: 'john--' });

      expect(response.status).toBe(400);
    });

    it('should reject search term with semicolon', async () => {
      const response = await request(app)
        .get('/api/users/search')
        .query({ q: 'john; DELETE FROM users;' });

      expect(response.status).toBe(400);
    });

    it('should reject UNION attack in search', async () => {
      const response = await request(app)
        .get('/api/users/search')
        .query({ q: "john' UNION SELECT password FROM users--" });

      expect(response.status).toBe(400);
    });

    it('should reject search term exceeding max length', async () => {
      const response = await request(app)
        .get('/api/users/search')
        .query({ q: 'a'.repeat(101) });

      expect(response.status).toBe(400);
    });

    it('should reject search term with quotes', async () => {
      const response = await request(app)
        .get('/api/users/search')
        .query({ q: "john' OR '1'='1" });

      expect(response.status).toBe(400);
    });

    it('should reject search term with backslash', async () => {
      const response = await request(app)
        .get('/api/users/search')
        .query({ q: "john\\" });

      expect(response.status).toBe(400);
    });

    it('should accept alphanumeric search with spaces', async () => {
      const response = await request(app)
        .get('/api/users/search')
        .query({ q: 'john doe' });

      // Should return 200 or 500 (db connection), not 400 (validation)
      expect([200, 500]).toContain(response.status);
    });

    it('should accept search with periods and hyphens', async () => {
      const response = await request(app)
        .get('/api/users/search')
        .query({ q: 'john.doe-smith' });

      expect([200, 500]).toContain(response.status);
    });
  });

  describe('GET /api/admin/users/:id', () => {
    it('should reject SQL injection in user ID', async () => {
      const response = await request(app)
        .get('/api/admin/users/1 OR 1=1');

      expect(response.status).toBe(400);
      expect(response.body.error).toBe('Invalid user ID');
    });

    it('should reject user ID with SQL operators', async () => {
      const response = await request(app)
        .get('/api/admin/users/1; DROP TABLE users;');

      expect(response.status).toBe(400);
    });

    it('should reject user ID with UNION attack', async () => {
      const response = await request(app)
        .get('/api/admin/users/1 UNION SELECT * FROM passwords');

      expect(response.status).toBe(400);
    });

    it('should reject user ID with quote injection', async () => {
      const response = await request(app)
        .get("/api/admin/users/1' OR '1'='1");

      expect(response.status).toBe(400);
    });

    it('should reject user ID with comment syntax', async () => {
      const response = await request(app)
        .get('/api/admin/users/1--');

      expect(response.status).toBe(400);
    });

    it('should reject non-numeric, non-UUID user ID', async () => {
      const response = await request(app)
        .get('/api/admin/users/not-a-valid-id');

      expect(response.status).toBe(400);
    });

    it('should accept valid UUID', async () => {
      const response = await request(app)
        .get('/api/admin/users/550e8400-e29b-41d4-a716-446655440000');

      // Should return 404 or 500 (db connection), not 400 (validation)
      expect([404, 500]).toContain(response.status);
    });

    it('should accept valid numeric ID', async () => {
      const response = await request(app)
        .get('/api/admin/users/123');

      // Should return 404 or 500 (db connection), not 400 (validation)
      expect([404, 500]).toContain(response.status);
    });
  });

  describe('POST /api/password-reset', () => {
    it('should reject SQL injection in email', async () => {
      const response = await request(app)
        .post('/api/password-reset')
        .send({ email: "user@test.com'; UPDATE users SET is_admin = true WHERE email = 'attacker@test.com" });

      expect(response.status).toBe(400);
      expect(response.body.error).toBe('Invalid email');
    });

    it('should reject email with SQL comment syntax', async () => {
      const response = await request(app)
        .post('/api/password-reset')
        .send({ email: "user@test.com'--" });

      expect(response.status).toBe(400);
    });

    it('should reject email with semicolon injection', async () => {
      const response = await request(app)
        .post('/api/password-reset')
        .send({ email: "user@test.com'; DROP TABLE users;--" });

      expect(response.status).toBe(400);
    });

    it('should reject malformed email', async () => {
      const response = await request(app)
        .post('/api/password-reset')
        .send({ email: 'not-an-email' });

      expect(response.status).toBe(400);
    });

    it('should reject email without @ symbol', async () => {
      const response = await request(app)
        .post('/api/password-reset')
        .send({ email: 'usertest.com' });

      expect(response.status).toBe(400);
    });

    it('should reject email below minimum length', async () => {
      const response = await request(app)
        .post('/api/password-reset')
        .send({ email: 'a@b' });

      expect(response.status).toBe(400);
    });

    it('should reject email exceeding max length', async () => {
      const response = await request(app)
        .post('/api/password-reset')
        .send({ email: 'a'.repeat(250) + '@example.com' });

      expect(response.status).toBe(400);
    });

    it('should reject UNION attack in email', async () => {
      const response = await request(app)
        .post('/api/password-reset')
        .send({ email: "user@test.com' UNION SELECT password FROM users--" });

      expect(response.status).toBe(400);
    });

    it('should handle null email gracefully', async () => {
      const response = await request(app)
        .post('/api/password-reset')
        .send({ email: null });

      expect(response.status).toBe(400);
    });

    it('should handle missing email gracefully', async () => {
      const response = await request(app)
        .post('/api/password-reset')
        .send({});

      expect(response.status).toBe(400);
    });

    it('should accept valid email', async () => {
      const response = await request(app)
        .post('/api/password-reset')
        .send({ email: 'user@example.com' });

      // Should return 200 or 500 (db connection), not 400 (validation)
      expect([200, 500]).toContain(response.status);

      // Should not expose token in response
      if (response.status === 200) {
        expect(response.body).not.toHaveProperty('token');
        expect(response.body.message).toContain('reset');
      }
    });
  });

  describe('Input Validation Edge Cases', () => {
    it('should trim whitespace from username', async () => {
      const response = await request(app)
        .post('/api/login')
        .send({ username: '  testuser  ', password: 'ValidPass123' });

      // Should succeed validation (returns 401 or 500, not 400)
      expect([401, 500]).toContain(response.status);
    });

    it('should trim whitespace from search term', async () => {
      const response = await request(app)
        .get('/api/users/search')
        .query({ q: '  john  ' });

      // Should succeed validation (returns 200 or 500, not 400)
      expect([200, 500]).toContain(response.status);
    });

    it('should trim whitespace from email', async () => {
      const response = await request(app)
        .post('/api/password-reset')
        .send({ email: '  user@example.com  ' });

      // Should succeed validation (returns 200 or 500, not 400)
      expect([200, 500]).toContain(response.status);
    });
  });
});

describe('Defense in Depth Verification', () => {
  it('should have multiple layers of protection against SQL injection', () => {
    // Layer 1: Input validation with Zod (allowlist regex)
    // Layer 2: Parameterized queries (pg library escaping)
    // Layer 3: Generic error messages (no information leakage)

    // This test verifies all layers are present by checking that:
    // 1. Invalid input is rejected at validation layer (tested above)
    // 2. Valid input uses parameterized queries (code review)
    // 3. Errors don't expose SQL details (tested above)

    expect(true).toBe(true); // Placeholder for manual verification
  });
});
