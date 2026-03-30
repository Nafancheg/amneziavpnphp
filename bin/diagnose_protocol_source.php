<?php

require_once __DIR__ . '/../inc/Config.php';
require_once __DIR__ . '/../inc/DB.php';

Config::load(__DIR__ . '/../.env');

$serverId = isset($argv[1]) ? (int)$argv[1] : 0;
if ($serverId <= 0) {
    fwrite(STDERR, "Usage: php bin/diagnose_protocol_source.php <server_id>\n");
    exit(1);
}

$pdo = DB::conn();
$stmt = $pdo->prepare('SELECT host, port, username, password, container_name FROM vpn_servers WHERE id = ? LIMIT 1');
$stmt->execute([$serverId]);
$server = $stmt->fetch(PDO::FETCH_ASSOC);

if (!$server) {
    fwrite(STDERR, "Server not found\n");
    exit(2);
}

$container = (string)($server['container_name'] ?: 'amnezia-awg');
$remoteCmd = "docker exec -i " . escapeshellarg($container) . " sh -lc " . escapeshellarg('cat /opt/amnezia/awg/clientsTable 2>/dev/null');

if (strtolower((string)$server['username']) !== 'root') {
    $remoteCmd = "printf %s\\n " . escapeshellarg((string)$server['password']) . " | sudo -S -p '' " . $remoteCmd;
}

$sshCommand = sprintf(
    'sshpass -p %s ssh -p %d -q -o LogLevel=ERROR -o StrictHostKeyChecking=accept-new -o UserKnownHostsFile=%s -o PreferredAuthentications=password -o PubkeyAuthentication=no %s %s 2>&1',
    escapeshellarg((string)$server['password']),
    (int)$server['port'],
    escapeshellarg(__DIR__ . '/../storage/ssh_known_hosts'),
    escapeshellarg((string)$server['username'] . '@' . (string)$server['host']),
    escapeshellarg($remoteCmd)
);

$raw = trim((string)shell_exec($sshCommand));
if ($raw === '') {
    echo "EMPTY_CLIENTSTABLE\n";
    exit(0);
}

$data = json_decode($raw, true);
if (!is_array($data)) {
    echo "NOT_JSON\n";
    echo substr($raw, 0, 800) . "\n";
    exit(0);
}

$explicitKeys = [
    'protocol',
    'proto',
    'vpnProto',
    'protocolVersion',
    'protocol_version',
    'profileType',
    'clientType',
    'tunnelType',
    'connectionType',
    'transport',
    'mode',
];

$explicitRows = 0;
$containerTopRows = 0;
$containerUserDataRows = 0;

foreach ($data as $row) {
    if (!is_array($row)) {
        continue;
    }

    $hasExplicit = false;
    foreach ($explicitKeys as $key) {
        if (isset($row[$key]) && is_string($row[$key]) && trim($row[$key]) !== '') {
            $hasExplicit = true;
            break;
        }
        if (
            isset($row['userData'])
            && is_array($row['userData'])
            && isset($row['userData'][$key])
            && is_string($row['userData'][$key])
            && trim($row['userData'][$key]) !== ''
        ) {
            $hasExplicit = true;
            break;
        }
    }

    if ($hasExplicit) {
        $explicitRows++;
    }

    if (isset($row['container']) && is_string($row['container']) && trim($row['container']) !== '') {
        $containerTopRows++;
    }

    if (
        isset($row['userData'])
        && is_array($row['userData'])
        && isset($row['userData']['container'])
        && is_string($row['userData']['container'])
        && trim($row['userData']['container']) !== ''
    ) {
        $containerUserDataRows++;
    }
}

echo 'TOTAL=' . count($data) . "\n";
echo 'EXPLICIT_PROTOCOL_ROWS=' . $explicitRows . "\n";
echo 'CONTAINER_TOP_ROWS=' . $containerTopRows . "\n";
echo 'CONTAINER_USERDATA_ROWS=' . $containerUserDataRows . "\n";

$limit = min(5, count($data));
for ($i = 0; $i < $limit; $i++) {
    if (!is_array($data[$i])) {
        continue;
    }
    echo 'ROW_KEYS_' . $i . '=' . implode(',', array_keys($data[$i])) . "\n";
    if (isset($data[$i]['userData']) && is_array($data[$i]['userData'])) {
        echo 'ROW_USERDATA_KEYS_' . $i . '=' . implode(',', array_keys($data[$i]['userData'])) . "\n";
    }
}
