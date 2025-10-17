/**
 * Test Suite for Authentication Security Fixes
 * 
 * Tests for Issue: [Security] js/insufficient-password-hash in auth.ts
 * Validates that bcrypt is used instead of SHA1 for password hashing
 */

import { hashPassword, comparePasswords } from './auth';

describe('Password Hashing Security - Issue: js/insufficient-password-hash', () => {
  describe('hashPassword', () => {
    it('should hash password using bcrypt', async () => {
      const password = 'TestPassword123';
      const hash = await hashPassword(password);

      // Bcrypt hashes start with $2a$, $2b$, or $2y$
      expect(hash).toMatch(/^\$2[aby]\$/);
    });

    it('should generate different hashes for the same password', async () => {
      const password = 'TestPassword123';
      const hash1 = await hashPassword(password);
      const hash2 = await hashPassword(password);

      // Bcrypt uses random salts, so hashes should be different
      expect(hash1).not.toBe(hash2);
    });

    it('should generate hash of appropriate length', async () => {
      const password = 'TestPassword123';
      const hash = await hashPassword(password);

      // Bcrypt hashes are 60 characters long
      expect(hash.length).toBe(60);
    });

    it('should handle empty password', async () => {
      const password = '';
      const hash = await hashPassword(password);

      expect(hash).toMatch(/^\$2[aby]\$/);
      expect(hash.length).toBe(60);
    });

    it('should handle long password', async () => {
      const password = 'a'.repeat(100);
      const hash = await hashPassword(password);

      expect(hash).toMatch(/^\$2[aby]\$/);
      expect(hash.length).toBe(60);
    });

    it('should handle special characters in password', async () => {
      const password = 'Test!@#$%^&*()_+-=[]{}|;:,.<>?';
      const hash = await hashPassword(password);

      expect(hash).toMatch(/^\$2[aby]\$/);
      expect(hash.length).toBe(60);
    });
  });

  describe('comparePasswords', () => {
    it('should return true for matching password and hash', async () => {
      const password = 'TestPassword123';
      const hash = await hashPassword(password);
      const result = await comparePasswords(password, hash);

      expect(result).toBe(true);
    });

    it('should return false for non-matching password', async () => {
      const password = 'TestPassword123';
      const wrongPassword = 'WrongPassword456';
      const hash = await hashPassword(password);
      const result = await comparePasswords(wrongPassword, hash);

      expect(result).toBe(false);
    });

    it('should be case-sensitive', async () => {
      const password = 'TestPassword123';
      const hash = await hashPassword(password);
      const result = await comparePasswords('testpassword123', hash);

      expect(result).toBe(false);
    });

    it('should handle empty password comparison', async () => {
      const password = '';
      const hash = await hashPassword(password);
      const result = await comparePasswords(password, hash);

      expect(result).toBe(true);
    });

    it('should return false for empty password against non-empty hash', async () => {
      const password = 'TestPassword123';
      const hash = await hashPassword(password);
      const result = await comparePasswords('', hash);

      expect(result).toBe(false);
    });

    it('should handle special characters correctly', async () => {
      const password = 'Test!@#$%^&*()_+-=[]{}|;:,.<>?';
      const hash = await hashPassword(password);
      const result = await comparePasswords(password, hash);

      expect(result).toBe(true);
    });
  });

  describe('Security Properties', () => {
    it('should not use SHA1 hashing (no 40-character hex strings)', async () => {
      const password = 'TestPassword123';
      const hash = await hashPassword(password);

      // SHA1 produces 40 character hex strings
      expect(hash.length).not.toBe(40);
      expect(hash).not.toMatch(/^[a-f0-9]{40}$/);
    });

    it('should use salted hashing (different hashes for same input)', async () => {
      const password = 'TestPassword123';
      const hash1 = await hashPassword(password);
      const hash2 = await hashPassword(password);

      // With proper salting, hashes should be different
      expect(hash1).not.toBe(hash2);
    });

    it('should be timing-safe (use bcrypt.compare instead of string comparison)', async () => {
      // This test verifies that we're using bcrypt.compare which is timing-safe
      // We can't directly test timing resistance, but we can verify the function works
      const password = 'TestPassword123';
      const hash = await hashPassword(password);
      
      const correctResult = await comparePasswords(password, hash);
      const incorrectResult = await comparePasswords('WrongPassword', hash);
      
      expect(correctResult).toBe(true);
      expect(incorrectResult).toBe(false);
    });
  });
});
