/**
 * Centralized Input Validation Schemas
 *
 * Following OWASP A03 Injection guidance:
 * - Allowlist regex patterns for all inputs
 * - Strict length limits
 * - Type validation with Zod
 */

import { z } from 'zod';

// Validation constants - single source of truth
export const VALIDATION_CONSTANTS = {
  USERNAME_MIN_LENGTH: 3,
  USERNAME_MAX_LENGTH: 50,
  PASSWORD_MIN_LENGTH: 12,
  PASSWORD_MAX_LENGTH: 128,
  SEARCH_MAX_LENGTH: 100,
  EMAIL_MIN_LENGTH: 5,
  EMAIL_MAX_LENGTH: 255
} as const;

// Username validation: alphanumeric + underscore only
export const usernameSchema = z.string()
  .trim()
  .min(VALIDATION_CONSTANTS.USERNAME_MIN_LENGTH, 'Username must be at least 3 characters')
  .max(VALIDATION_CONSTANTS.USERNAME_MAX_LENGTH, 'Username must be at most 50 characters')
  .regex(/^[a-zA-Z0-9_]+$/, 'Username can only contain letters, numbers, and underscores');

// Password validation: minimum complexity requirements
export const passwordSchema = z.string()
  .min(VALIDATION_CONSTANTS.PASSWORD_MIN_LENGTH, 'Password must be at least 12 characters')
  .max(VALIDATION_CONSTANTS.PASSWORD_MAX_LENGTH, 'Password must be at most 128 characters')
  .regex(/^(?=.*[A-Z])(?=.*[0-9])/, 'Password must contain at least one uppercase letter and one number');

// Login endpoint validation
export const loginSchema = z.object({
  username: usernameSchema,
  password: passwordSchema
});

// Search term validation: alphanumeric + spaces, periods, hyphens
export const searchSchema = z.object({
  q: z.string()
    .trim()
    .max(VALIDATION_CONSTANTS.SEARCH_MAX_LENGTH, 'Search term must be at most 100 characters')
    .regex(/^[a-zA-Z0-9 .\-]*$/, 'Search term contains invalid characters')
});

// User ID validation: UUID or positive integer
export const userIdSchema = z.string()
  .uuid('Invalid user ID format')
  .or(z.string().regex(/^\d+$/, 'User ID must be a valid UUID or number').transform(Number));

// Email validation: RFC-compliant
export const emailSchema = z.string()
  .trim()
  .min(VALIDATION_CONSTANTS.EMAIL_MIN_LENGTH, 'Email must be at least 5 characters')
  .max(VALIDATION_CONSTANTS.EMAIL_MAX_LENGTH, 'Email must be at most 255 characters')
  .email('Invalid email format');
