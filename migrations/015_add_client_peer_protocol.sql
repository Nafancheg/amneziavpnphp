-- Add per-client VPN protocol code (awg, awg2, xray, wg, openvpn, ikev2, ...)
SET @has_col := (
  SELECT COUNT(*)
  FROM information_schema.COLUMNS
  WHERE TABLE_SCHEMA = DATABASE()
    AND TABLE_NAME = 'vpn_clients'
    AND COLUMN_NAME = 'peer_protocol'
);

SET @ddl := IF(
  @has_col = 0,
  'ALTER TABLE vpn_clients ADD COLUMN peer_protocol VARCHAR(32) NULL AFTER description',
  'SELECT 1'
);

PREPARE stmt FROM @ddl;
EXECUTE stmt;
DEALLOCATE PREPARE stmt;

-- Optional index for filtering by protocol in future
SET @has_idx := (
  SELECT COUNT(*)
  FROM information_schema.STATISTICS
  WHERE TABLE_SCHEMA = DATABASE()
    AND TABLE_NAME = 'vpn_clients'
    AND INDEX_NAME = 'idx_peer_protocol'
);

SET @idx_ddl := IF(
  @has_idx = 0,
  'ALTER TABLE vpn_clients ADD INDEX idx_peer_protocol (peer_protocol)',
  'SELECT 1'
);

PREPARE idx_stmt FROM @idx_ddl;
EXECUTE idx_stmt;
DEALLOCATE PREPARE idx_stmt;
