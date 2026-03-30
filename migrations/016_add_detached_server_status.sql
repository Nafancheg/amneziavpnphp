-- Add 'detached' status for vpn_servers to support non-destructive panel detach.

SET @status_col_type := (
  SELECT COLUMN_TYPE
  FROM information_schema.COLUMNS
  WHERE TABLE_SCHEMA = DATABASE()
    AND TABLE_NAME = 'vpn_servers'
    AND COLUMN_NAME = 'status'
  LIMIT 1
);

SET @needs_alter := IF(
  @status_col_type IS NULL,
  0,
  IF(LOCATE("'detached'", @status_col_type) > 0, 0, 1)
);

SET @ddl := IF(
  @needs_alter = 1,
  "ALTER TABLE vpn_servers MODIFY COLUMN status ENUM('deploying','active','stopped','error','detached') NOT NULL DEFAULT 'deploying'",
  'SELECT 1'
);

PREPARE stmt FROM @ddl;
EXECUTE stmt;
DEALLOCATE PREPARE stmt;

-- Normalize legacy detached records.
UPDATE vpn_servers
SET status = 'detached'
WHERE (status = 'stopped' OR status = '')
  AND error_message = 'Detached from panel';
