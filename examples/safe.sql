-- examples/safe.sql
-- These operations are safe and should not trigger any guard or high-risk alerts.

CREATE TABLE notifications (
    id          BIGSERIAL PRIMARY KEY,
    user_id     BIGINT NOT NULL,
    message     TEXT NOT NULL,
    read_at     TIMESTAMPTZ,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX CONCURRENTLY idx_notifications_user_id
    ON notifications(user_id);

CREATE INDEX CONCURRENTLY idx_notifications_created_at
    ON notifications(created_at);
