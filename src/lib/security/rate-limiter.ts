// Framework-agnostic Sliding Window Rate Limiter
// Compatible with Next.js API Routes, Node.js HTTP, Express, and Edge runtimes

export interface RateLimitRecord {
  count: number;
  resetTime: number;
}

export interface RateLimitOptions {
  windowMs: number;
  maxAttempts: number;
  message?: string;
}

export interface RateLimitResult {
  allowed: boolean;
  remaining: number;
  resetTime: number;
  retryAfterSeconds: number;
  message?: string;
}

const memoryStore = new Map<string, RateLimitRecord>();

/**
 * Checks whether an incoming identifier (e.g. client IP or account ID) exceeds the rate limit.
 * Blocks high-frequency password guessing and THC Hydra attacks.
 */
export function checkRateLimit(
  identifier: string,
  options: RateLimitOptions = {
    windowMs: 15 * 60 * 1000, // 15-minute sliding window
    maxAttempts: 5,           // Maximum 5 failed attempts
    message: 'Too many authentication attempts. Please try again in 15 minutes.'
  }
): RateLimitResult {
  const now = Date.now();
  const record = memoryStore.get(identifier);

  if (!record || now > record.resetTime) {
    memoryStore.set(identifier, {
      count: 1,
      resetTime: now + options.windowMs,
    });
    return {
      allowed: true,
      remaining: options.maxAttempts - 1,
      resetTime: now + options.windowMs,
      retryAfterSeconds: 0,
    };
  }

  if (record.count >= options.maxAttempts) {
    const retryAfter = Math.ceil((record.resetTime - now) / 1000);
    return {
      allowed: false,
      remaining: 0,
      resetTime: record.resetTime,
      retryAfterSeconds: retryAfter,
      message: options.message,
    };
  }

  record.count++;
  return {
    allowed: true,
    remaining: options.maxAttempts - record.count,
    resetTime: record.resetTime,
    retryAfterSeconds: 0,
  };
}

/**
 * Reset rate limit counter upon successful authenticated login
 */
export function resetRateLimit(identifier: string): void {
  memoryStore.delete(identifier);
}
