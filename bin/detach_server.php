<?php

require_once __DIR__ . '/../inc/Config.php';
require_once __DIR__ . '/../inc/DB.php';

Config::load(__DIR__ . '/../.env');

$serverId = isset($argv[1]) ? (int)$argv[1] : 0;
$deleteClients = in_array('--delete-clients', $argv, true);

if ($serverId <= 0) {
    fwrite(STDERR, "Usage: php bin/detach_server.php <server_id> [--delete-clients]\n");
    exit(1);
}

$pdo = DB::conn();

$stmt = $pdo->prepare('SELECT id, name, status FROM vpn_servers WHERE id = ? LIMIT 1');
$stmt->execute([$serverId]);
$server = $stmt->fetch();

if (!$server) {
    fwrite(STDERR, "Server not found: {$serverId}\n");
    exit(2);
}

try {
    $pdo->beginTransaction();

    if ($deleteClients) {
        $del = $pdo->prepare('DELETE FROM vpn_clients WHERE server_id = ?');
        $del->execute([$serverId]);
        $deleted = (int)$del->rowCount();
    } else {
        $disabled = $pdo->prepare('UPDATE vpn_clients SET status = ?, updated_at = NOW() WHERE server_id = ?');
        $disabled->execute(['disabled', $serverId]);
        $deleted = 0;
    }

    $upd = $pdo->prepare('UPDATE vpn_servers SET status = ?, error_message = ?, updated_at = NOW() WHERE id = ?');
    $upd->execute(['detached', 'Detached from panel', $serverId]);

    $pdo->commit();

    echo "DETACH_OK\n";
    echo "server_id={$serverId}\n";
    echo "server_name={$server['name']}\n";
    echo "delete_clients=" . ($deleteClients ? 'yes' : 'no') . "\n";
    echo "deleted_clients={$deleted}\n";
} catch (Throwable $e) {
    if ($pdo->inTransaction()) {
        $pdo->rollBack();
    }
    fwrite(STDERR, "DETACH_ERROR: " . $e->getMessage() . "\n");
    exit(3);
}
