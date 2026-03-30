-- Add local description field for clients (panel-only metadata)
SET @has_col := (
  SELECT COUNT(*)
  FROM information_schema.COLUMNS
  WHERE TABLE_SCHEMA = DATABASE()
    AND TABLE_NAME = 'vpn_clients'
    AND COLUMN_NAME = 'description'
);

SET @ddl := IF(
  @has_col = 0,
  'ALTER TABLE vpn_clients ADD COLUMN description TEXT NULL AFTER name',
  'SELECT 1'
);

PREPARE stmt FROM @ddl;
EXECUTE stmt;
DEALLOCATE PREPARE stmt;
