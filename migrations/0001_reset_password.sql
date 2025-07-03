-- Migration number: 0001 	 2025-07-03T19:22:45.713Z

-- add a hashed reset token and its expiry (unix seconds)
ALTER TABLE users ADD COLUMN reset_token_hash TEXT;
ALTER TABLE users ADD COLUMN reset_expires INTEGER;

-- (Optionally) index for faster lookup by token
CREATE INDEX IF NOT EXISTS idx_users_reset_token_hash
  ON users(reset_token_hash);
