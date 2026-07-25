BEGIN;

CREATE TABLE IF NOT EXISTS ironvault.app_settings (
    setting_key TEXT PRIMARY KEY,
    setting_value TEXT NOT NULL,
    updated_by TEXT,
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

INSERT INTO ironvault.app_settings (setting_key, setting_value, updated_by)
VALUES ('idle_timeout_minutes', '10', 'system')
ON CONFLICT (setting_key) DO NOTHING;

COMMIT;