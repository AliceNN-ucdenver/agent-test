/**
 * Rate Limiting Configuration
 *
 * Following OWASP A04 Insecure Design + DoS Prevention guidance:
 * - Multi-layer rate limiting (defense in depth)
 * - Stricter limits for critical endpoints (login, password reset)
 * - Standard headers for client transparency
 */

import rateLimit from 'express-rate-limit';
import slowDown from 'express-slow-down';

// ✅ Key Pattern 1: Global rate limiter (broad protection)
export const globalLimiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 100, // 100 requests per window per IP
  message: 'Too many requests from this IP, please try again later.',
  standardHeaders: true, // Return rate limit info in headers
  legacyHeaders: false, // Disable X-RateLimit-* headers
});

// ✅ Key Pattern 1: Strict login rate limiter
export const loginLimiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 5, // 5 login attempts per window
  message: 'Too many login attempts. Please try again in 15 minutes.',
  standardHeaders: true,
  skipSuccessfulRequests: false, // Count all attempts
});

// ✅ Key Pattern 1 + 2: Slow down after 3rd login attempt
export const loginSlowDown = slowDown({
  windowMs: 15 * 60 * 1000, // 15 minutes
  delayAfter: 3, // Start slowing down after 3rd request
  delayMs: 1000, // Add 1 second delay per request after delayAfter
});

// ✅ Key Pattern 1: Password reset rate limiter (stricter)
export const passwordResetLimiter = rateLimit({
  windowMs: 60 * 60 * 1000, // 1 hour
  max: 3, // 3 attempts per hour per IP
  message: 'Too many password reset attempts. Please try again later.',
  standardHeaders: true,
});

// ✅ Key Pattern 1: Search rate limiter (moderate)
export const searchLimiter = rateLimit({
  windowMs: 60 * 1000, // 1 minute
  max: 30, // 30 searches per minute
  message: 'Too many search requests. Please slow down.',
  standardHeaders: true,
});

// ✅ Key Pattern 1: Admin endpoint rate limiter
export const adminLimiter = rateLimit({
  windowMs: 60 * 1000, // 1 minute
  max: 20, // 20 requests per minute
  message: 'Too many admin requests. Please slow down.',
  standardHeaders: true,
});
