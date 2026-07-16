-- Multiple transport listeners per catalog server (ROADMAP2 §3/§4): a
-- physical box can run several `chimera server -transport X` processes side
-- by side (Reality/TCP, QUIC/H3, Shadowsocks-AEAD, DNS-over-TCP), each on
-- its own port but sharing the same server identity (host/pubkey/sni/city/
-- country/etc. stay on `servers`). Previously `servers.port` was the only
-- place a port lived, implicitly meaning "the one Reality/TCP listener" --
-- every row here is one of those listeners, `servers.port` is kept as the
-- default/primary (Reality) one for any client too old to read `listeners`.
CREATE TABLE listeners (
    id         INTEGER PRIMARY KEY,
    server_id  INTEGER NOT NULL REFERENCES servers(id) ON DELETE CASCADE,
    transport  TEXT NOT NULL, -- 'reality' | 'quic' | 'ss' | 'dot'
    port       INTEGER NOT NULL,
    created_at INTEGER NOT NULL,
    UNIQUE (server_id, transport)
);
CREATE INDEX idx_listeners_server ON listeners(server_id);

-- Backfill: every server row that predates this migration gets its existing
-- `port` recorded as a 'reality' listener, so `CatalogStore.List` (which now
-- always nests `listeners`) never returns a server with an empty list.
INSERT INTO listeners (server_id, transport, port, created_at)
SELECT id, 'reality', port, unixepoch() FROM servers;
