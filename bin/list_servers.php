<?php
require_once __DIR__ . '/../inc/Config.php';
require_once __DIR__ . '/../inc/DB.php';
Config::load(__DIR__ . '/../.env');
$pdo = DB::conn();
$rows = $pdo->query('SELECT id, name, host, status, container_name, vpn_port, awg_params FROM vpn_servers')->fetchAll(PDO::FETCH_ASSOC);
foreach ($rows as $r) {
    echo "ID={$r['id']} name={$r['name']} host={$r['host']} status={$r['status']} container={$r['container_name']} port={$r['vpn_port']}\n";
    if ($r['awg_params']) {
        $p = json_decode($r['awg_params'], true);
        echo "  awg_params keys: " . implode(', ', array_keys($p ?? [])) . "\n";
    }
}
