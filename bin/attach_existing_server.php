<?php

require_once __DIR__ . '/../inc/Config.php';
require_once __DIR__ . '/../inc/DB.php';

Config::load(__DIR__ . '/../.env');

$serverId = isset($argv[1]) ? (int)$argv[1] : 0;
if ($serverId <= 0) {
    fwrite(STDERR, "Usage: php bin/attach_existing_server.php <server_id>\n");
    exit(1);
}

$pdo = DB::conn();
$stmt = $pdo->prepare('SELECT * FROM vpn_servers WHERE id = ? LIMIT 1');
$stmt->execute([$serverId]);
$server = $stmt->fetch();

if (!$server) {
    fwrite(STDERR, "Server not found: {$serverId}\n");
    exit(1);
}

function shell_arg(string $value): string
{
    return escapeshellarg($value);
}

function require_valid_connection_params(array $server): void
{
    $host = trim((string)($server['host'] ?? ''));
    $username = trim((string)($server['username'] ?? ''));
    $password = (string)($server['password'] ?? '');
    $port = (int)($server['port'] ?? 0);

    if ($host === '' || !preg_match('/^[a-z0-9._:-]+$/i', $host)) {
        throw new RuntimeException('Invalid server host format');
    }

    if ($username === '' || !preg_match('/^[a-z_][a-z0-9_-]*$/i', $username)) {
        throw new RuntimeException('Invalid SSH username format');
    }

    if ($password === '') {
        throw new RuntimeException('Empty SSH password');
    }

    if ($port < 1 || $port > 65535) {
        throw new RuntimeException('Invalid SSH port');
    }
}

function get_known_hosts_path(): string
{
    $storageDir = __DIR__ . '/../storage';
    if (!is_dir($storageDir) && !mkdir($storageDir, 0700, true) && !is_dir($storageDir)) {
        throw new RuntimeException('Failed to create storage directory for SSH known hosts');
    }

    $knownHosts = $storageDir . '/ssh_known_hosts';
    if (!file_exists($knownHosts) && file_put_contents($knownHosts, '') === false) {
        throw new RuntimeException('Failed to initialize SSH known hosts file');
    }

    return $knownHosts;
}

function ssh_exec(array $server, string $command, bool $sudo = false): string
{
    require_valid_connection_params($server);

    $host = trim((string)$server['host']);
    $username = trim((string)$server['username']);
    $password = (string)$server['password'];
    $port = (int)$server['port'];
    $knownHosts = get_known_hosts_path();

    if ($sudo && strtolower($username) !== 'root') {
        $command = "printf '%s\\n' " . shell_arg($password) . " | sudo -S -p '' " . $command;
    }

    $sshParts = [
        'sshpass',
        '-p',
        $password,
        'ssh',
        '-p',
        (string)$port,
        '-q',
        '-o',
        'LogLevel=ERROR',
        '-o',
        'StrictHostKeyChecking=accept-new',
        '-o',
        'UserKnownHostsFile=' . $knownHosts,
        '-o',
        'PreferredAuthentications=password',
        '-o',
        'PubkeyAuthentication=no',
        $username . '@' . $host,
        $command,
    ];

    $ssh = implode(' ', array_map(static fn(string $part): string => shell_arg($part), $sshParts)) . ' 2>&1';

    return trim((string)shell_exec($ssh));
}

function normalize_protocol_code(?string $raw, string $fallback = 'awg'): string
{
    $value = strtolower(trim((string)$raw));
    if ($value === '') {
        return $fallback;
    }
    if (str_contains($value, 'awg2')) {
        return 'awg2';
    }
    if (str_contains($value, 'amneziawg') || preg_match('/\bawg\b/', $value)) {
        return 'awg';
    }
    if (str_contains($value, 'wireguard') || preg_match('/\bwg\b/', $value)) {
        return 'wg';
    }
    if (
        str_contains($value, 'xray')
        || in_array($value, ['vless', 'vmess', 'trojan', 'shadowsocks', 'reality'], true)
    ) {
        return 'xray';
    }
    if (str_contains($value, 'openvpn') || $value === 'ovpn') {
        return 'openvpn';
    }
    if (str_contains($value, 'ikev2') || str_contains($value, 'ipsec')) {
        return 'ikev2';
    }

    return $fallback;
}

function detect_protocol_from_container_name(string $containerName): ?string
{
    $value = strtolower(trim($containerName));
    if ($value === '') {
        return null;
    }

    if (str_contains($value, 'awg2')) {
        return 'awg2';
    }
    if (str_contains($value, 'amnezia-awg') || preg_match('/(^|[-_])awg($|[-_])/', $value)) {
        return 'awg';
    }
    if (str_contains($value, 'wireguard') || preg_match('/(^|[-_])wg($|[-_])/', $value)) {
        return 'wg';
    }
    if (str_contains($value, 'xray')) {
        return 'xray';
    }
    if (str_contains($value, 'openvpn') || str_contains($value, 'ovpn')) {
        return 'openvpn';
    }
    if (str_contains($value, 'ikev2') || str_contains($value, 'ipsec')) {
        return 'ikev2';
    }

    return null;
}

function detect_protocol_from_container_files(array $server, string $containerName): ?string
{
    if (!preg_match('/^[a-zA-Z0-9][a-zA-Z0-9_.-]*$/', $containerName)) {
        return null;
    }

    $containerArg = shell_arg($containerName);
    $probe = "docker exec -i {$containerArg} sh -lc '"
        . "if [ -f /opt/amnezia/awg/awg0.conf ] || [ -f /opt/amnezia/awg/wg0.conf ]; then echo awg; "
        . "elif [ -f /opt/amnezia/wireguard/wg0.conf ]; then echo wg; "
        . "elif [ -f /opt/amnezia/xray/server.json ]; then echo xray; "
        . "elif [ -f /opt/amnezia/openvpn/server.conf ]; then echo openvpn; "
        . "elif [ -d /opt/amnezia/ikev2 ] || [ -f /etc/ipsec.conf ]; then echo ikev2; "
        . "else echo unknown; fi' 2>/dev/null || true";

    $detected = strtolower(trim(ssh_exec($server, $probe, true)));
    if ($detected === '' || $detected === 'unknown') {
        return null;
    }

    return normalize_protocol_code($detected, 'unknown');
}

// Non-protocol service containers — not VPN tunnels, excluded from protocol list
const NON_PROTOCOL_CONTAINERS = ['amnezia-dns', 'amnezia-dns-local'];

function is_protocol_container(string $containerName): bool
{
    return !in_array(strtolower(trim($containerName)), NON_PROTOCOL_CONTAINERS, true);
}

function discover_installed_containers(array $server): array
{
    // Use Names+Ports like amnezia-client: extract external port and transport protocol
    $dockerList = ssh_exec($server, "docker ps --format '{{.Names}} {{.Ports}}' 2>/dev/null || true", true);
    $rows = preg_split('/\r?\n/', trim($dockerList));
    if (!is_array($rows)) {
        return [];
    }

    $result = [];
    foreach ($rows as $row) {
        $line = trim((string)$row);
        if ($line === '') {
            continue;
        }

        // amnezia-client regex: (amnezia[-a-z0-9]*).*?:(\d+)->(\d+)/(udp|tcp)
        $name = '';
        $externalPort = null;
        $transportProto = null;

        if (preg_match('/^([a-zA-Z0-9][a-zA-Z0-9_.-]*)/', $line, $nm)) {
            $name = $nm[1];
        }
        if ($name === '') {
            continue;
        }
        if (!preg_match('/^[a-zA-Z0-9][a-zA-Z0-9_.-]*$/', $name)) {
            continue;
        }

        // Skip non-protocol service containers (amnezia-dns etc.)
        if (!is_protocol_container($name)) {
            continue;
        }

        // Extract port mapping: 0.0.0.0:51820->51820/udp
        if (preg_match('/:(\d+)->(\d+)\/(udp|tcp)/', $line, $pm)) {
            $externalPort = (int)$pm[1];
            $transportProto = strtolower($pm[3]);
        }

        $protocol = detect_protocol_from_container_name($name);

        $result[] = [
            'name' => $name,
            'protocol' => $protocol,
            'external_port' => $externalPort,
            'transport_proto' => $transportProto,
        ];
    }

    return $result;
}

function choose_attach_container(string $requestedContainer, array $installedContainers): ?array
{
    foreach ($installedContainers as $row) {
        if (($row['name'] ?? '') === $requestedContainer) {
            return $row;
        }
    }

    // If user explicitly set non-default container and it is missing, fail fast.
    if ($requestedContainer !== '' && $requestedContainer !== 'amnezia-awg') {
        return null;
    }

    if (empty($installedContainers)) {
        return null;
    }

    $priority = [
        'awg2' => 10,
        'awg' => 20,
        'wg' => 30,
        'xray' => 40,
        'openvpn' => 50,
        'ikev2' => 60,
    ];

    usort($installedContainers, static function (array $a, array $b) use ($priority): int {
        $pa = $priority[$a['protocol'] ?? ''] ?? 100;
        $pb = $priority[$b['protocol'] ?? ''] ?? 100;
        if ($pa === $pb) {
            return strcmp((string)($a['name'] ?? ''), (string)($b['name'] ?? ''));
        }
        return $pa <=> $pb;
    });

    return $installedContainers[0] ?? null;
}

function extract_protocol_candidate(array $row): ?string
{
    $keys = ['protocol', 'proto', 'vpnProto', 'protocolVersion', 'protocol_version', 'profileType', 'clientType', 'tunnelType', 'connectionType', 'transport', 'mode'];
    foreach ($keys as $k) {
        if (isset($row[$k]) && is_string($row[$k]) && trim($row[$k]) !== '') {
            return $row[$k];
        }
    }

    $nestedKeys = ['userData', 'config', 'profile', 'connection', 'settings'];
    foreach ($nestedKeys as $parent) {
        if (!isset($row[$parent]) || !is_array($row[$parent])) {
            continue;
        }
        foreach ($keys as $k) {
            if (isset($row[$parent][$k]) && is_string($row[$parent][$k]) && trim($row[$parent][$k]) !== '') {
                return $row[$parent][$k];
            }
        }
    }

    if (isset($row['container']) && is_string($row['container']) && trim($row['container']) !== '') {
        return $row['container'];
    }
    if (isset($row['userData']) && is_array($row['userData']) && isset($row['userData']['container']) && is_string($row['userData']['container']) && trim($row['userData']['container']) !== '') {
        return $row['userData']['container'];
    }

    return null;
}

// --- Read config of a single WireGuard-family container ---
function read_wg_container_config(array $server, string $cName, string $protocol, ?int $extPort, ?string $transportProto): ?array
{
    if (!preg_match('/^[a-zA-Z0-9][a-zA-Z0-9_.-]*$/', $cName)) {
        return null;
    }
    $cArg = shell_arg($cName);

    // Ensure container is running
    $running = ssh_exec($server, "docker inspect -f '{{.State.Running}}' {$cArg} 2>/dev/null || echo false", true);
    if ($running !== 'true') {
        ssh_exec($server, "docker start {$cArg}", true);
        usleep(500000);
        $running = ssh_exec($server, "docker inspect -f '{{.State.Running}}' {$cArg} 2>/dev/null || echo false", true);
        if ($running !== 'true') {
            return null;
        }
    }

    $baseDir = $protocol === 'wg' ? '/opt/amnezia/wireguard' : '/opt/amnezia/awg';

    // Batch all reads into a single SSH call to avoid connection issues
    $batchCmd = "docker exec {$cArg} sh -c '"
        . "echo __PUBKEY_START__;"
        . "cat {$baseDir}/wireguard_server_public_key.key 2>/dev/null || cat {$baseDir}/server_public.key 2>/dev/null || true;"
        . "echo __PUBKEY_END__;"
        . "echo __PSK_START__;"
        . "cat {$baseDir}/wireguard_psk.key 2>/dev/null || cat {$baseDir}/preshared.key 2>/dev/null || true;"
        . "echo __PSK_END__;"
        . "echo __CONF_START__;"
        . "cat {$baseDir}/awg0.conf 2>/dev/null || cat {$baseDir}/wg0.conf 2>/dev/null || true;"
        . "echo __CONF_END__;"
        . "'";
    $batchOutput = ssh_exec($server, $batchCmd, true);

    $pubKey = '';
    if (preg_match('/__PUBKEY_START__\s*(.*?)\s*__PUBKEY_END__/s', $batchOutput, $m)) {
        $pubKey = trim($m[1]);
    }
    $psk = '';
    if (preg_match('/__PSK_START__\s*(.*?)\s*__PSK_END__/s', $batchOutput, $m)) {
        $psk = trim($m[1]);
    }
    $wgConf = '';
    if (preg_match('/__CONF_START__\s*(.*?)\s*__CONF_END__/s', $batchOutput, $m)) {
        $wgConf = trim($m[1]);
    }

    if ($wgConf === '') {
        return null;
    }

    $cfg = ['protocol' => $protocol];
    if ($pubKey !== '') {
        $cfg['server_public_key'] = $pubKey;
    }
    if ($psk !== '') {
        $cfg['preshared_key'] = $psk;
    }

    if (preg_match('/^ListenPort\s*=\s*(\d+)/mi', $wgConf, $m)) {
        $cfg['listen_port'] = (int)$m[1];
    }
    if (preg_match('/^Address\s*=\s*([^\s]+)/mi', $wgConf, $m)) {
        $cfg['vpn_subnet'] = trim($m[1]);
    }

    // AWG params
    foreach (['Jc', 'Jmin', 'Jmax', 'S1', 'S2', 'H1', 'H2', 'H3', 'H4'] as $k) {
        if (preg_match('/^' . preg_quote($k, '/') . '\\s*=\\s*([0-9]+)/mi', $wgConf, $m)) {
            $cfg[$k] = (int)$m[1];
        }
    }

    // AWG2-specific
    foreach (['cookieReplyPacketJunkSize', 'transportPacketJunkSize'] as $k) {
        if (preg_match('/^' . preg_quote($k, '/') . '\\s*=\\s*([0-9]+)/mi', $wgConf, $m)) {
            $cfg[$k] = (int)$m[1];
        }
    }
    if (preg_match('/^protocolVersion\s*=\s*(\S+)/mi', $wgConf, $m)) {
        $cfg['protocolVersion'] = $m[1];
    }

    // Special junk i1-i5
    for ($iIdx = 1; $iIdx <= 5; $iIdx++) {
        if (preg_match('/^#\s*i' . $iIdx . '\s*=\s*([0-9]+)/mi', $wgConf, $m)) {
            $cfg['i' . $iIdx] = (int)$m[1];
        }
    }

    // Port: prefer docker external, fallback to ListenPort
    if ($extPort !== null && $extPort > 0) {
        $cfg['vpn_port'] = $extPort;
    } elseif (isset($cfg['listen_port'])) {
        $cfg['vpn_port'] = $cfg['listen_port'];
    }

    if ($transportProto !== null && $transportProto !== '') {
        $cfg['transport_proto'] = $transportProto;
    }

    if (!isset($cfg['vpn_subnet'])) {
        $cfg['vpn_subnet'] = '10.8.1.0/24';
    }

    return $cfg;
}

// ============================================================
// MAIN FLOW: Discover all containers, read all configs
// ============================================================

$ping = ssh_exec($server, 'echo ok');
if ($ping !== 'ok') {
    fwrite(STDERR, "SSH connection failed\n");
    exit(2);
}

$installedContainers = discover_installed_containers($server);

// Also detect protocol from files for containers with unknown protocol
foreach ($installedContainers as &$ic) {
    if (($ic['protocol'] ?? null) === null) {
        $detected = detect_protocol_from_container_files($server, $ic['name']);
        if ($detected !== null) {
            $ic['protocol'] = $detected;
        }
    }
}
unset($ic);

$installedProtocols = [];
foreach ($installedContainers as $installed) {
    $code = (string)($installed['protocol'] ?? '');
    if ($code !== '' && !in_array($code, $installedProtocols, true)) {
        $installedProtocols[] = $code;
    }
}

if (empty($installedContainers)) {
    fwrite(STDERR, "No protocol containers found on server\n");
    exit(6);
}

// Read config of EACH container and store in allConfigs
$allConfigs = [];
foreach ($installedContainers as $ic) {
    $cName = (string)$ic['name'];
    $cProto = (string)($ic['protocol'] ?? '');
    $cExtPort = $ic['external_port'] ?? null;
    $cTransport = $ic['transport_proto'] ?? null;
    if (!in_array($cProto, ['awg', 'awg2', 'wg'], true)) {
        if ($cProto === 'xray') {
            // Read xray config: server.json + clientsTable + keys in one SSH call
            $xrayBatchCmd = "docker exec " . shell_arg($cName) . " sh -c '"
                . "echo __XSERVER_START__;"
                . "cat /opt/amnezia/xray/server.json 2>/dev/null || true;"
                . "echo __XSERVER_END__;"
                . "echo __XCLIENTS_START__;"
                . "cat /opt/amnezia/xray/clientsTable 2>/dev/null || true;"
                . "echo __XCLIENTS_END__;"
                . "echo __XPUBKEY_START__;"
                . "cat /opt/amnezia/xray/xray_public.key 2>/dev/null || true;"
                . "echo __XPUBKEY_END__;"
                . "echo __XSHORTID_START__;"
                . "cat /opt/amnezia/xray/xray_short_id.key 2>/dev/null || true;"
                . "echo __XSHORTID_END__;"
                . "'";
            $xrayBatchOut = ssh_exec($server, $xrayBatchCmd, true);

            $xrayServerJson = null;
            if (preg_match('/__XSERVER_START__\s*(.*?)\s*__XSERVER_END__/s', $xrayBatchOut, $m)) {
                $xrayServerJson = json_decode(trim($m[1]), true);
            }
            $xrayClientsTable = null;
            if (preg_match('/__XCLIENTS_START__\s*(.*?)\s*__XCLIENTS_END__/s', $xrayBatchOut, $m)) {
                $xrayClientsTable = json_decode(trim($m[1]), true);
            }
            $xrayPubKey = '';
            if (preg_match('/__XPUBKEY_START__\s*(.*?)\s*__XPUBKEY_END__/s', $xrayBatchOut, $m)) {
                $xrayPubKey = trim($m[1]);
            }
            $xrayShortId = '';
            if (preg_match('/__XSHORTID_START__\s*(.*?)\s*__XSHORTID_END__/s', $xrayBatchOut, $m)) {
                $xrayShortId = trim($m[1]);
            }

            // Extract SNI from server.json
            $xraySni = '';
            if (is_array($xrayServerJson)) {
                $inbound = $xrayServerJson['inbounds'][0] ?? [];
                $realitySettings = $inbound['streamSettings']['realitySettings'] ?? [];
                $xraySni = $realitySettings['serverNames'][0] ?? $realitySettings['dest'] ?? '';
                $xraySni = preg_replace('/:\d+$/', '', $xraySni); // remove port from dest
            }

            $allConfigs[$cName] = [
                'protocol' => $cProto,
                'vpn_port' => $cExtPort,
                'transport_proto' => $cTransport,
                'xray_server_json' => $xrayServerJson,
                'xray_clients_table' => $xrayClientsTable,
                'xray_public_key' => $xrayPubKey,
                'xray_short_id' => $xrayShortId,
                'xray_sni' => $xraySni,
            ];
        } else {
            // Other non-WG protocols: store basic info only
            $allConfigs[$cName] = [
                'protocol' => $cProto,
                'vpn_port' => $cExtPort,
                'transport_proto' => $cTransport,
            ];
        }
        continue;
    }

    $cfg = read_wg_container_config($server, $cName, $cProto, $cExtPort, $cTransport);
    if ($cfg !== null) {
        $allConfigs[$cName] = $cfg;
    }
}

// Choose active container
$requestedContainerName = trim((string)($server['container_name'] ?? ''));
if ($requestedContainerName === '') {
    $requestedContainerName = 'amnezia-awg';
}

$selectedContainer = choose_attach_container($requestedContainerName, $installedContainers);
if ($selectedContainer === null) {
    $protocolList = empty($installedProtocols) ? '<none>' : implode(',', $installedProtocols);
    fwrite(STDERR, "Container not found for attach: {$requestedContainerName}; installed_protocols={$protocolList}\n");
    exit(6);
}

$containerName = (string)$selectedContainer['name'];
$defaultPeerProtocol = (string)($selectedContainer['protocol'] ?? '');

// If active container is non-WG (e.g. xray), find the first WG container for VPN params
$wgContainerForParams = null;
if (in_array($defaultPeerProtocol, ['awg', 'awg2', 'wg'], true)) {
    $wgContainerForParams = $containerName;
} else {
    foreach ($installedContainers as $icCandidate) {
        $cp = (string)($icCandidate['protocol'] ?? '');
        if (in_array($cp, ['awg', 'awg2', 'wg'], true) && isset($allConfigs[(string)$icCandidate['name']])) {
            $wgContainerForParams = (string)$icCandidate['name'];
            break;
        }
    }
}

$activeConfig = $allConfigs[$wgContainerForParams ?? $containerName] ?? $allConfigs[$containerName] ?? null;
if ($activeConfig === null) {
    fwrite(STDERR, "Failed to read config from container '{$containerName}'\n");
    exit(4);
}

$vpnPort = $activeConfig['vpn_port'] ?? null;
$vpnSubnet = $activeConfig['vpn_subnet'] ?? '10.8.1.0/24';
$publicKey = $activeConfig['server_public_key'] ?? '';
$presharedKey = $activeConfig['preshared_key'] ?? '';
$dockerTransportProto = $activeConfig['transport_proto'] ?? null;
$dockerExternalPort = $activeConfig['vpn_port'] ?? null;

// vpnPort may be null for non-WG containers — use port from any WG container or fallback
if ($vpnPort === null && $wgContainerForParams !== null) {
    $vpnPort = $allConfigs[$wgContainerForParams]['vpn_port'] ?? null;
}
if ($vpnPort === null) {
    // Try any WG container's port
    foreach ($allConfigs as $cfgName => $cfg) {
        if (isset($cfg['vpn_port'])) {
            $vpnPort = $cfg['vpn_port'];
            break;
        }
    }
}
if ($vpnPort === null) {
    $vpnPort = 0; // no WG containers have a port, but we can still attach
}

if (!preg_match('/^[a-zA-Z0-9][a-zA-Z0-9_.-]*$/', $containerName)) {
    fwrite(STDERR, "Invalid container name format\n");
    exit(9);
}
$containerArg = shell_arg($containerName);

// ============================================================
// IMPORT PEERS FROM ALL WG CONTAINERS (each has its own users)
// ============================================================

$hasPeerProtocolColumn = (bool)$pdo->query("SELECT COUNT(*) FROM information_schema.COLUMNS WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME = 'vpn_clients' AND COLUMN_NAME = 'peer_protocol'")->fetchColumn();

$importedClients = 0;
$totalPeersFound = 0;

foreach ($installedContainers as $ic) {
    $icName = (string)$ic['name'];
    $icProto = (string)($ic['protocol'] ?? '');

    if (!in_array($icProto, ['awg', 'awg2', 'wg'], true)) {
        // Handle xray container import
        if ($icProto === 'xray') {
            $xrayCfg = $allConfigs[$icName] ?? null;
            if (!$xrayCfg || !is_array($xrayCfg['xray_clients_table'] ?? null)) {
                echo "container={$icName}: skipped (no clientsTable)\n";
                continue;
            }

            // Build set of active UUIDs from server.json
            $activeXrayUuids = [];
            if (is_array($xrayCfg['xray_server_json'] ?? null)) {
                foreach ($xrayCfg['xray_server_json']['inbounds'][0]['settings']['clients'] ?? [] as $xc) {
                    $activeXrayUuids[] = (string)$xc['id'];
                }
            }

            $icPeerCount = 0;
            foreach ($xrayCfg['xray_clients_table'] as $xrayClient) {
                if (!is_array($xrayClient)) continue;
                $clientUuid = (string)($xrayClient['clientId'] ?? '');
                $clientName = (string)($xrayClient['userData']['clientName'] ?? 'Unknown');
                if ($clientUuid === '') continue;

                $isActive = in_array($clientUuid, $activeXrayUuids, true);
                $peerProtocol = $icName; // 'amnezia-xray'

                // Use UUID as client_ip for xray (no IP allocation in xray)
                $clientIp = $clientUuid;

                if ($hasPeerProtocolColumn) {
                    $sel = $pdo->prepare('SELECT id FROM vpn_clients WHERE server_id = ? AND client_ip = ? AND peer_protocol = ? LIMIT 1');
                    $sel->execute([$serverId, $clientIp, $peerProtocol]);
                } else {
                    $sel = $pdo->prepare('SELECT id FROM vpn_clients WHERE server_id = ? AND client_ip = ? LIMIT 1');
                    $sel->execute([$serverId, $clientIp]);
                }
                $existingId = (int)($sel->fetchColumn() ?: 0);

                if ($existingId) {
                    // CONTRACT-4: discovery only, no stats overwrite
                    $updClient = $pdo->prepare('UPDATE vpn_clients SET name = ?, status = ?, updated_at = NOW() WHERE id = ?');
                    $updClient->execute([$clientName, $isActive ? 'active' : 'disabled', $existingId]);
                } else {
                    $insClient = $pdo->prepare('INSERT INTO vpn_clients (server_id, user_id, name, client_ip, public_key, private_key, preshared_key, config, qr_code, status, bytes_received, bytes_sent, last_handshake, peer_protocol) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 0, 0, NULL, ?)');
                    $insClient->execute([
                        $serverId, (int)$server['user_id'], $clientName, $clientIp,
                        '', '', '', null, null,
                        $isActive ? 'active' : 'disabled',
                        $peerProtocol,
                    ]);
                    $importedClients++;
                }
                $icPeerCount++;
            }
            $totalPeersFound += $icPeerCount;
            echo "container={$icName}: {$icPeerCount} xray clients imported/updated\n";
        }
        continue;
    }
    if (!preg_match('/^[a-zA-Z0-9][a-zA-Z0-9_.-]*$/', $icName)) {
        continue;
    }

    $icArg = shell_arg($icName);
    $icBaseDir = $icProto === 'wg' ? '/opt/amnezia/wireguard' : '/opt/amnezia/awg';

    // Read peers dump + clientsTable in a single SSH call
    $icDumpCmd = "wg show wg0 dump";
    if ($icProto === 'awg2') {
        $icDumpCmd = "awg show awg0 dump || awg show wg0 dump || wg show awg0 dump || wg show wg0 dump";
    } elseif ($icProto === 'awg') {
        $icDumpCmd = "wg show wg0 dump || wg show awg0 dump";
    }

    $batchImportCmd = "docker exec {$icArg} sh -c '"
        . "echo __DUMP_START__;"
        . "{$icDumpCmd} 2>/dev/null || true;"
        . "echo __DUMP_END__;"
        . "echo __CLIENTS_START__;"
        . "cat {$icBaseDir}/clientsTable 2>/dev/null || true;"
        . "echo __CLIENTS_END__;"
        . "'";
    $batchImportOutput = ssh_exec($server, $batchImportCmd, true);

    $icDump = '';
    if (preg_match('/__DUMP_START__\s*(.*?)\s*__DUMP_END__/s', $batchImportOutput, $m)) {
        $icDump = trim($m[1]);
    }

    if ($icDump === '') {
        continue;
    }

    $icClientsJson = '';
    if (preg_match('/__CLIENTS_START__\s*(.*?)\s*__CLIENTS_END__/s', $batchImportOutput, $m)) {
        $icClientsJson = trim($m[1]);
    }

    // Read clientsTable for name mapping
    $icNameMap = [];
    if ($icClientsJson !== '') {
        $icClientsTable = json_decode($icClientsJson, true);
        if (is_array($icClientsTable)) {
            foreach ($icClientsTable as $row) {
                if (!is_array($row)) continue;
                $clientKey = (string)($row['clientId'] ?? $row['publicKey'] ?? $row['clientPublicKey'] ?? '');
                $mappedName = $row['userData']['clientName'] ?? $row['clientName'] ?? null;
                if ($clientKey !== '' && is_string($mappedName) && $mappedName !== '') {
                    $icNameMap[$clientKey] = $mappedName;
                }
            }
        }
    }

    // Parse peers
    $icLines = preg_split('/\r?\n/', trim($icDump));
    $icPeerCount = 0;

    for ($i = 1; $i < count($icLines); $i++) {
        $line = trim((string)$icLines[$i]);
        if ($line === '') continue;

        $parts = preg_split('/\s+/', $line);
        if (!is_array($parts) || count($parts) < 8) continue;

        $peerPublicKey = (string)$parts[0];
        $peerPsk = (string)$parts[1];
        $allowedIpsRaw = (string)$parts[3];
        $latestHandshakeEpoch = (int)$parts[4];
        $bytesRx = (int)$parts[5];
        $bytesTx = (int)$parts[6];

        if ($peerPublicKey === '') continue;

        $firstAllowed = trim(explode(',', $allowedIpsRaw)[0] ?? '');
        $clientIp = trim(explode('/', $firstAllowed)[0] ?? '');
        if ($clientIp === '') continue;

        $clientName = $icNameMap[$peerPublicKey] ?? ('imported_' . substr($peerPublicKey, 0, 8));
        $lastHandshake = $latestHandshakeEpoch > 0 ? gmdate('Y-m-d H:i:s', $latestHandshakeEpoch) : null;
        $peerPskNormalized = ($peerPsk === '(none)' || $peerPsk === '') ? null : $peerPsk;
        $icPeerCount++;

        // peer_protocol stores the container name for precise sync/display
        $peerProtocol = $icName;

        if ($hasPeerProtocolColumn) {
            $sel = $pdo->prepare('SELECT id, name FROM vpn_clients WHERE server_id = ? AND public_key = ? LIMIT 1');
            $sel->execute([$serverId, $peerPublicKey]);
        } else {
            $sel = $pdo->prepare('SELECT id, name FROM vpn_clients WHERE server_id = ? AND (public_key = ? OR client_ip = ?) LIMIT 1');
            $sel->execute([$serverId, $peerPublicKey, $clientIp]);
        }
        $existingClient = $sel->fetch(PDO::FETCH_ASSOC) ?: null;
        $existingId = (int)($existingClient['id'] ?? 0);

        if ($existingId) {
            // CONTRACT-4: Attach = discovery only. Never overwrite handshake/traffic for existing clients.
            // Stats are managed exclusively by syncStats/syncAllStatsForServer.
            if ($hasPeerProtocolColumn) {
                $updClient = $pdo->prepare('UPDATE vpn_clients SET name = ?, public_key = ?, preshared_key = ?, client_ip = ?, status = ?, peer_protocol = ?, updated_at = NOW() WHERE id = ?');
                $updClient->execute([
                    $clientName, $peerPublicKey, $peerPskNormalized, $clientIp,
                    'active', $peerProtocol,
                    (int)$existingId,
                ]);
            } else {
                $updClient = $pdo->prepare('UPDATE vpn_clients SET name = ?, public_key = ?, preshared_key = ?, client_ip = ?, status = ?, updated_at = NOW() WHERE id = ?');
                $updClient->execute([
                    $clientName, $peerPublicKey, $peerPskNormalized, $clientIp,
                    'active',
                    (int)$existingId,
                ]);
            }
        } else {
            if ($hasPeerProtocolColumn) {
                $insClient = $pdo->prepare('INSERT INTO vpn_clients (server_id, user_id, name, client_ip, public_key, private_key, preshared_key, config, qr_code, status, bytes_received, bytes_sent, last_handshake, peer_protocol) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)');
                $insClient->execute([
                    $serverId, (int)$server['user_id'], $clientName, $clientIp,
                    $peerPublicKey, '', $peerPskNormalized, null, null,
                    'active', $bytesRx, $bytesTx, $lastHandshake, $peerProtocol,
                ]);
            } else {
                $insClient = $pdo->prepare('INSERT INTO vpn_clients (server_id, user_id, name, client_ip, public_key, private_key, preshared_key, config, qr_code, status, bytes_received, bytes_sent, last_handshake) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)');
                $insClient->execute([
                    $serverId, (int)$server['user_id'], $clientName, $clientIp,
                    $peerPublicKey, '', $peerPskNormalized, null, null,
                    'active', $bytesRx, $bytesTx, $lastHandshake,
                ]);
            }
            $importedClients++;
        }
    }

    $totalPeersFound += $icPeerCount;
    echo "container={$icName}: {$icPeerCount} peers imported/updated\n";
}

// Build awg_params with per-container configs
$awg = [];

// Active container's params at top level (backward compat)
$activeParams = $allConfigs[$containerName] ?? [];
foreach ($activeParams as $k => $v) {
    if (!in_array($k, ['server_public_key', 'preshared_key', 'listen_port'], true) && !is_array($v)) {
        $awg[$k] = $v;
    }
}

// All container configs cached for instant switching
$awg['containers'] = $allConfigs;

if (!empty($installedProtocols)) {
    $awg['installed_protocols'] = $installedProtocols;
}
$containersInfo = [];
foreach ($installedContainers as $ic) {
    $info = ['name' => $ic['name'], 'protocol' => $ic['protocol'] ?? null];
    if (isset($ic['external_port'])) $info['port'] = $ic['external_port'];
    if (isset($ic['transport_proto'])) $info['transport'] = $ic['transport_proto'];
    $containersInfo[] = $info;
}
if (!empty($containersInfo)) {
    $awg['installed_containers'] = $containersInfo;
}

$upd = $pdo->prepare(
    'UPDATE vpn_servers SET status = ?, container_name = ?, vpn_port = ?, vpn_subnet = ?, server_public_key = ?, preshared_key = ?, awg_params = ?, deployed_at = COALESCE(deployed_at, NOW()), error_message = NULL WHERE id = ?'
);
$upd->execute([
    'active',
    $containerName,
    $vpnPort,
    $vpnSubnet,
    $publicKey ?: null,
    $presharedKey ?: null,
    !empty($awg) ? json_encode($awg, JSON_UNESCAPED_UNICODE) : null,
    $serverId,
]);

echo "ATTACH_OK\n";
echo "server_id={$serverId}\n";
echo "container={$containerName}\n";
echo "vpn_port={$vpnPort}\n";
echo "vpn_subnet={$vpnSubnet}\n";
echo "public_key=" . ($publicKey !== '' ? 'yes' : 'no') . "\n";
echo "preshared_key=" . ($presharedKey !== '' ? 'yes' : 'no') . "\n";
echo "containers_read=" . count($allConfigs) . "\n";
echo "awg_params_keys=" . (!empty($awg) ? implode(',', array_keys($awg)) : '<none>') . "\n";
echo "protocol_version=" . ($activeParams['protocolVersion'] ?? '-') . "\n";
echo "transport_proto=" . ($dockerTransportProto ?? '-') . "\n";
echo "docker_external_port=" . ($dockerExternalPort ?? '-') . "\n";
echo "imported_clients={$importedClients}\n";
echo "total_peers_found={$totalPeersFound}\n";
echo "default_peer_protocol={$defaultPeerProtocol}\n";
echo "installed_protocols=" . (empty($installedProtocols) ? '<none>' : implode(',', $installedProtocols)) . "\n";
