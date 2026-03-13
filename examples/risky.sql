-- examples/risky.sql
-- These operations will generate HIGH risk alerts and fix suggestions.
-- Run: schema-risk analyze examples/risky.sql

-- R01: CREATE INDEX without CONCURRENTLY — holds SHARE lock
-- schema-risk fix will rewrite this to use CONCURRENTLY
CREATE INDEX idx_orders_status ON orders(status);

-- R02: ADD COLUMN NOT NULL without DEFAULT — fails on non-empty tables
ALTER TABLE users ADD COLUMN verified BOOLEAN NOT NULL;

-- R07: ALTER COLUMN TYPE — rewrites entire table under ACCESS EXCLUSIVE lock
ALTER TABLE orders ALTER COLUMN total TYPE NUMERIC(20, 4);
