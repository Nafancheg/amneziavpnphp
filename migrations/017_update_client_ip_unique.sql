-- Update unique constraint to include peer_protocol (each container has its own IP space)
-- Idempotent: checks if old index exists before dropping, and if new one already exists

SET @has_old_idx := (
  SELECT COUNT(*)
  FROM information_schema.STATISTICS
  WHERE TABLE_SCHEMA = DATABASE()
    AND TABLE_NAME = 'vpn_clients'
    AND INDEX_NAME = 'unique_server_client_ip'
    AND COLUMN_NAME = 'client_ip'
    AND NOT EXISTS (
      SELECT 1 FROM information_schema.STATISTICS s2
      WHERE s2.TABLE_SCHEMA = DATABASE()
        AND s2.TABLE_NAME = 'vpn_clients'
        AND s2.INDEX_NAME = 'unique_server_client_ip'
        AND s2.COLUMN_NAME = 'peer_protocol'
    )
);

SET @drop_ddl := IF(
  @has_old_idx > 0,
  'ALTER TABLE vpn_clients DROP INDEX unique_server_client_ip, ADD UNIQUE KEY unique_server_client_ip (server_id, client_ip, peer_protocol)',
  'SELECT 1'
);

PREPARE stmt FROM @drop_ddl;
EXECUTE stmt;
DEALLOCATE PREPARE stmt;
