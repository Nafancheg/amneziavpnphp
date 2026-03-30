# Strict Data Contracts — VPN Client & Container Management

## Contract 1: Handshake / Traffic Source of Truth

**RULE**: `last_handshake`, `bytes_sent`, `bytes_received` MUST ONLY be written by:
- `VpnClient::syncAllStatsForServer()` — batch sync
- `VpnClient::syncStats()` — single client sync

**FORBIDDEN**: `attach_existing_server.php` and any import script MUST NOT write
handshake or traffic data for EXISTING clients. For NEW clients (INSERT),
handshake and traffic values from the WG dump are accepted (initial snapshot).

**FORMAT**: `last_handshake` stored as UTC datetime string via `gmdate('Y-m-d H:i:s', $epoch)`.
Epoch=0 → NULL. Display converts UTC → APP_TIMEZONE.

## Contract 2: Container ↔ Client Ownership

**RULE**: Each client belongs to exactly ONE container via `peer_protocol` column.
- `peer_protocol` stores the Docker container name (e.g. `amnezia-awg`, `amnezia-awg2`)
- Clients are displayed ONLY for the currently active container (`server.container_name`)
- `VpnClient::listByServer()` MUST filter by active `container_name`
- Switching containers = switching which clients are visible

**RULE**: Container switch is instant (cached config), no confirmation dialog needed.

## Contract 3: Sync Isolation

**RULE**: `syncAllStatsForServer()` syncs ALL containers (not just active).
Each client's stats come from their own `peer_protocol` container.
Clients with unknown `peer_protocol` fall back to all WG containers.

## Contract 4: Attach = Discovery Only

**RULE**: `attach_existing_server.php` discovers containers and peers. It:
- Creates/updates client records (name, public_key, client_ip, peer_protocol)
- Does NOT overwrite `last_handshake`, `bytes_sent`, `bytes_received` for existing clients
- For new clients: writes initial handshake/traffic snapshot from WG dump
- After attach completes, a sync should be triggered to populate fresh stats

## Contract 5: peer_protocol Format

**RULE**: `peer_protocol` MUST always store the full Docker container name
(e.g. `amnezia-awg`, `amnezia-awg2`, `amnezia-xray`), NOT short protocol codes
(e.g. `awg`, `awg2`, `xray`).

**WHY**: `syncAllStatsForServer()` uses `peer_protocol` as the Docker container
name for `docker exec` SSH commands. Short codes would cause runtime errors.

**APPLIES TO**: `VpnClient::create()`, `attach_existing_server.php`, `restore()`.

## Contract 6: Xray Client Management

**RULE**: Xray (VLESS+Reality) clients use UUID as client identifier (stored in `client_ip` column).
- `public_key`, `private_key`, `preshared_key` are empty for xray clients
- `config` stores a VLESS URI (not WG INI format)
- `client_ip` = UUID (e.g. `501acc62-e453-4a7e-a16f-d7a6541b0ed0`)

**OPERATIONS**:
- Create: generate UUID, add to `server.json` clients + `clientsTable`, restart xray
- Revoke: remove UUID from `server.json` clients, restart xray
- Restore: re-add UUID to `server.json` clients, restart xray
- Sync: xray has no `wg show` equivalent — skip in `syncAllStatsForServer()`

**KEYS**: Xray server keys (`xray_public_key`, `xray_short_id`, `xray_sni`) are cached in
`awg_params.containers.amnezia-xray` during attach for use in VLESS URI generation.
