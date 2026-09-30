/**
 * Security Hardening Guide: Defending Against Online Password Guessing (Hydra / Brute-Force)
 *
 * This document describes the defensive controls implemented in SecureLens
 * based on the Hydra testing practical guide.
 */

// 1. RATE LIMITING (Implemented in /src/lib/security/rate-limiter.ts)
// Limits repetitive requests per IP and per account identifier.
// Prevents high-velocity dictionary and credential spraying attacks.

// 2. ACCOUNT LOCKOUT & PROGRESSIVE DELAYS
// After 5 consecutive failed login attempts on a specific account:
// - Lock the account for 15 minutes or trigger an email unlock code.
// - Introduce artificial delay (exponential backoff) on failed attempts.

// 3. SECURE PASSWORD HASHING
// Passwords must never be stored in plain text or legacy hashes (MD5, SHA-1).
// Recommended algorithm: Argon2id or Bcrypt (cost factor >= 12).

// 4. MULTI-FACTOR AUTHENTICATION (MFA)
// Enforce TOTP (Time-based One-Time Passwords) or FIDO2/WebAuthn hardware keys.
// Even if an attacker guesses the primary password, access is denied without the second factor.

// 5. BOT & HEADLESS DETECTION
// Monitor for user-agents lacking standard browser headers, high request concurrency,
// or non-standard TCP/TLS fingerprints.

// 6. GENERIC ERROR RESPONSES
// Always return uniform responses on authentication failure:
// "Invalid email or password" (never indicate whether the user exists or not).
