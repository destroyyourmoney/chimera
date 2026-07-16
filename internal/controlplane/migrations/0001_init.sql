-- Schema is intentionally minimal per ROADMAP2 §0: only *access state*
-- (hash/status/expiry/limits), never activity logs (no IPs, no
-- connect/disconnect timestamps, no per-device last-seen). Plain SQL, no
-- SQLite-specific types, so a later Postgres move (ROADMAP2 §1) is a
-- driver swap, not a schema rewrite.

CREATE TABLE accounts (
    id          INTEGER PRIMARY KEY,
    number_hash TEXT NOT NULL UNIQUE, -- sha256(account number), hex
    status      TEXT NOT NULL,        -- 'active' | 'revoked'
    expires_at  INTEGER NOT NULL,     -- unix seconds
    device_limit INTEGER NOT NULL DEFAULT 5,
    created_at  INTEGER NOT NULL
);

CREATE TABLE devices (
    id          INTEGER PRIMARY KEY,
    account_id  INTEGER NOT NULL REFERENCES accounts(id) ON DELETE CASCADE,
    device_pub_key TEXT NOT NULL, -- base64
    short_id_hex   TEXT NOT NULL UNIQUE,
    created_at     INTEGER NOT NULL
    -- deliberately no `label`/`last_seen_at` -- see ROADMAP2 §0.
);
CREATE INDEX idx_devices_account ON devices(account_id);

CREATE TABLE servers (
    id         INTEGER PRIMARY KEY,
    host       TEXT NOT NULL,
    port       INTEGER NOT NULL,
    pubkey     TEXT NOT NULL, -- base64url X25519 static pub
    sni        TEXT NOT NULL,
    fingerprint TEXT NOT NULL DEFAULT '',
    country    TEXT NOT NULL,
    city       TEXT NOT NULL,
    load_pct   INTEGER NOT NULL DEFAULT 0,
    healthy    INTEGER NOT NULL DEFAULT 1, -- 0/1
    created_at INTEGER NOT NULL
);

CREATE TABLE revocations (
    id            INTEGER PRIMARY KEY,
    short_id_hex  TEXT NOT NULL UNIQUE,
    revoked_at    INTEGER NOT NULL
);
CREATE INDEX idx_revocations_revoked_at ON revocations(revoked_at);
