<?php
/**
 * VPN Client Management Class
 * Handles creation and management of VPN client configurations
 * Based on amnezia_client_config_v2.php
 */
class VpnClient {
    private $clientId;
    private $data;
    private static ?bool $hasPeerProtocolColumnCache = null;
    
    public function __construct(?int $clientId = null) {
        $this->clientId = $clientId;
        if ($clientId) {
            $this->load();
        }
    }
    
    /**
     * Load client data from database
     */
    private function load(): void {
        $pdo = DB::conn();
        $stmt = $pdo->prepare('SELECT * FROM vpn_clients WHERE id = ?');
        $stmt->execute([$this->clientId]);
        $this->data = $stmt->fetch();
        if (!$this->data) {
            throw new Exception('Client not found');
        }
    }
    
    /**
     * Create new VPN client
     * 
     * @param int $serverId Server ID
     * @param int $userId User ID
     * @param string $name Client name
     * @param int|null $expiresInDays Days until expiration (null = never expires)
     * @return int Client ID
     */
    public static function create(int $serverId, int $userId, string $name, ?int $expiresInDays = null): int {
        $pdo = DB::conn();
        
        // Sanitize client name (replace only spaces with underscores, allow any other characters including Cyrillic)
        $name = trim($name);
        $name = str_replace(' ', '_', $name);
        
        // Get server data
        $server = new VpnServer($serverId);
        $serverData = $server->getData();
        
        if (!$serverData || $serverData['status'] !== 'active') {
            throw new Exception('Server is not active');
        }

        // CONTRACT-2: peer_protocol must store the full container name (e.g. "amnezia-awg")
        // because syncAllStatsForServer uses it as docker container name for SSH commands.
        $clientProtocol = $serverData['container_name'] ?? self::detectServerProtocolCode($serverData);
        
        $containerName = $serverData['container_name'];
        $isXray = str_contains(strtolower($containerName), 'xray');
        
        // Get AWG parameters from server
        $awgParams = json_decode($serverData['awg_params'], true) ?: [];

        if ($isXray) {
            return self::createXrayClient($serverId, $userId, $name, $serverData, $awgParams, $clientProtocol, $expiresInDays);
        }
        
        // Generate client keys
        $keys = self::generateClientKeys($serverData, $name);
        
        // Get next available IP
        $clientIP = self::getNextClientIP($serverData);
        
        // Build client configuration
        $config = self::buildClientConfig(
            $keys['private'],
            $clientIP,
            $serverData['server_public_key'],
            $serverData['preshared_key'],
            $serverData['host'],
            $serverData['vpn_port'],
            $awgParams
        );
        
        // Add client to server
        self::addClientToServer($serverData, $keys['public'], $clientIP, $name, $clientProtocol);
        
        // Generate QR code
        $qrCode = self::generateQRCode($config);
        
        // Calculate expiration date
        $expiresAt = $expiresInDays ? date('Y-m-d H:i:s', strtotime("+{$expiresInDays} days")) : null;
        
        // Insert into database
        if (self::hasPeerProtocolColumn()) {
            $stmt = $pdo->prepare('
                INSERT INTO vpn_clients 
                (server_id, user_id, name, client_ip, public_key, private_key, preshared_key, config, qr_code, status, expires_at, peer_protocol) 
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            ');

            $stmt->execute([
                $serverId,
                $userId,
                $name,
                $clientIP,
                $keys['public'],
                $keys['private'],
                $serverData['preshared_key'],
                $config,
                $qrCode,
                'active',
                $expiresAt,
                $clientProtocol,
            ]);
        } else {
            $stmt = $pdo->prepare('
                INSERT INTO vpn_clients 
                (server_id, user_id, name, client_ip, public_key, private_key, preshared_key, config, qr_code, status, expires_at) 
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            ');

            $stmt->execute([
                $serverId,
                $userId,
                $name,
                $clientIP,
                $keys['public'],
                $keys['private'],
                $serverData['preshared_key'],
                $config,
                $qrCode,
                'active',
                $expiresAt
            ]);
        }
        
        return (int)$pdo->lastInsertId();
    }

    /**
     * Create Xray (VLESS+Reality) client
     */
    private static function createXrayClient(
        int $serverId, int $userId, string $name,
        array $serverData, array $awgParams,
        string $clientProtocol, ?int $expiresInDays
    ): int {
        $pdo = DB::conn();
        $containerName = $serverData['container_name'];

        if (!self::hasPeerProtocolColumn()) {
            throw new Exception('Xray support requires migration 015 (peer_protocol column)');
        }

        // Generate UUID for the new client
        $uuid = self::generateUuid4();

        // Read xray keys from awg_params cache (populated by attach)
        $xrayCfg = $awgParams['containers'][$containerName] ?? [];
        $xrayPubKey = (string)($xrayCfg['xray_public_key'] ?? '');
        $xrayShortId = (string)($xrayCfg['xray_short_id'] ?? '');
        $xraySni = (string)($xrayCfg['xray_sni'] ?? '');
        $vpnPort = (int)($serverData['vpn_port'] ?: ($xrayCfg['vpn_port'] ?? 443));

        // If keys not cached, read from server
        if ($xrayPubKey === '' || $xrayShortId === '') {
            $readCmd = sprintf(
                "docker exec -i %s sh -c 'cat /opt/amnezia/xray/xray_public.key; echo __SEP__; cat /opt/amnezia/xray/xray_short_id.key'",
                escapeshellarg($containerName)
            );
            $out = self::executeServerCommand($serverData, $readCmd, true);
            $parts = explode('__SEP__', $out);
            if (count($parts) >= 2) {
                $xrayPubKey = trim($parts[0]);
                $xrayShortId = trim($parts[1]);
            }
        }

        if ($xraySni === '') {
            // Read SNI from server.json
            $readCmd = sprintf(
                "docker exec -i %s cat /opt/amnezia/xray/server.json",
                escapeshellarg($containerName)
            );
            $sjson = self::executeServerCommand($serverData, $readCmd, true);
            $serverJsonData = json_decode(trim($sjson), true);
            if (is_array($serverJsonData)) {
                $rs = $serverJsonData['inbounds'][0]['streamSettings']['realitySettings'] ?? [];
                $xraySni = $rs['serverNames'][0] ?? preg_replace('/:\d+$/', '', $rs['dest'] ?? '');
            }
        }

        // Add UUID to server.json inbounds[0].settings.clients
        self::addXrayClientToServer($serverData, $uuid, $name);

        // Build VLESS connection URI
        $config = self::buildXrayVlessUri(
            $uuid, $serverData['host'], $vpnPort, $xrayPubKey, $xrayShortId, $xraySni, $name
        );

        // Generate QR code
        $qrCode = self::generateQRCode($config);

        // Calculate expiration date
        $expiresAt = $expiresInDays ? date('Y-m-d H:i:s', strtotime("+{$expiresInDays} days")) : null;

        // Insert into database — client_ip = uuid for xray
        $stmt = $pdo->prepare('
            INSERT INTO vpn_clients
            (server_id, user_id, name, client_ip, public_key, private_key, preshared_key, config, qr_code, status, expires_at, peer_protocol)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        ');
        $stmt->execute([
            $serverId, $userId, $name,
            $uuid, // client_ip = UUID for xray
            '', '', '', // no WG keys
            $config, $qrCode, 'active', $expiresAt, $clientProtocol,
        ]);

        return (int)$pdo->lastInsertId();
    }

    /**
     * Generate RFC4122 v4 UUID
     */
    private static function generateUuid4(): string {
        $data = random_bytes(16);
        $data[6] = chr(ord($data[6]) & 0x0f | 0x40); // version 4
        $data[8] = chr(ord($data[8]) & 0x3f | 0x80); // variant RFC4122
        return vsprintf('%s%s-%s-%s-%s-%s%s%s', str_split(bin2hex($data), 4));
    }

    /**
     * Build VLESS connection URI for Xray client
     */
    private static function buildXrayVlessUri(
        string $uuid, string $host, int $port,
        string $publicKey, string $shortId, string $sni, string $name
    ): string {
        $params = http_build_query([
            'encryption' => 'none',
            'flow' => 'xtls-rprx-vision',
            'type' => 'tcp',
            'security' => 'reality',
            'sni' => $sni,
            'fp' => 'chrome',
            'pbk' => $publicKey,
            'sid' => $shortId,
        ]);
        return "vless://{$uuid}@{$host}:{$port}?{$params}#" . rawurlencode($name);
    }

    /**
     * Add a new xray client UUID to server.json and clientsTable on the remote server
     */
    private static function addXrayClientToServer(array $serverData, string $uuid, string $name): void {
        $containerName = $serverData['container_name'];
        $containerArg = escapeshellarg($containerName);

        // Read current server.json
        $cmd = sprintf("docker exec -i %s cat /opt/amnezia/xray/server.json", $containerArg);
        $sjson = self::executeServerCommand($serverData, $cmd, true);
        $config = json_decode(trim($sjson), true);
        if (!is_array($config)) {
            throw new Exception('Failed to read xray server.json');
        }

        // Add new client
        $config['inbounds'][0]['settings']['clients'][] = [
            'id' => $uuid,
            'flow' => 'xtls-rprx-vision',
        ];

        // Write back server.json
        $newJson = json_encode($config, JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES);
        $tmpFile = '/tmp/xray_cfg_' . bin2hex(random_bytes(4)) . '.json';
        $writeCmd = sprintf(
            "docker exec -i %s sh -c 'cat > %s' <<'XRAYEOF'\n%s\nXRAYEOF",
            $containerArg, $tmpFile, $newJson
        );
        self::executeServerCommand($serverData, $writeCmd, true);

        $mvCmd = sprintf("docker exec -i %s sh -c 'mv %s /opt/amnezia/xray/server.json'", $containerArg, $tmpFile);
        self::executeServerCommand($serverData, $mvCmd, true);

        // Update clientsTable
        $cmd2 = sprintf("docker exec -i %s cat /opt/amnezia/xray/clientsTable 2>/dev/null", $containerArg);
        $tableJson = self::executeServerCommand($serverData, $cmd2, true);
        $table = json_decode(trim($tableJson), true);
        if (!is_array($table)) {
            $table = [];
        }

        $table[] = [
            'clientId' => $uuid,
            'userData' => [
                'clientName' => $name,
                'creationDate' => date('D M j H:i:s Y'),
            ],
        ];

        $newTableJson = json_encode($table, JSON_PRETTY_PRINT | JSON_UNESCAPED_UNICODE);
        $tmpFile2 = '/tmp/xray_ct_' . bin2hex(random_bytes(4)) . '.json';
        $writeCmd2 = sprintf(
            "docker exec -i %s sh -c 'cat > %s' <<'XRAYEOF'\n%s\nXRAYEOF",
            $containerArg, $tmpFile2, $newTableJson
        );
        self::executeServerCommand($serverData, $writeCmd2, true);

        $mvCmd2 = sprintf("docker exec -i %s sh -c 'mv %s /opt/amnezia/xray/clientsTable'", $containerArg, $tmpFile2);
        self::executeServerCommand($serverData, $mvCmd2, true);

        // Restart xray to apply config
        $restartCmd = sprintf("docker restart %s", $containerArg);
        self::executeServerCommand($serverData, $restartCmd, true);
    }
    
    /**
     * Generate client keys on remote server
     */
    private static function generateClientKeys(array $serverData, string $clientName): array {
        $containerName = $serverData['container_name'];
        
        // Sanitize clientName for use in shell — allow only safe chars for tmp filenames
        $safeClientName = preg_replace('/[^a-zA-Z0-9_-]/', '_', $clientName);
        if ($safeClientName === '') {
            $safeClientName = 'client';
        }
        
        // AWG2 containers have 'awg' tool, legacy/wg have 'wg'
        $cn = strtolower($containerName);
        $isAwg2 = str_contains($cn, 'awg2');
        if (!$isAwg2) {
            $awgParams = is_string($serverData['awg_params'] ?? null)
                ? json_decode($serverData['awg_params'], true)
                : ($serverData['awg_params'] ?? []);
            $isAwg2 = (strtolower(trim((string)($awgParams['protocolVersion'] ?? ''))) === '2');
        }
        $tool = $isAwg2 ? 'awg' : 'wg';
        
        $cmd = sprintf(
            "docker exec -i %s sh -c \"umask 077; %s genkey | tee /tmp/%s_priv.key | %s pubkey > /tmp/%s_pub.key; cat /tmp/%s_priv.key; echo '---'; cat /tmp/%s_pub.key; rm -f /tmp/%s_priv.key /tmp/%s_pub.key\"",
            escapeshellarg($containerName),
            $tool, $safeClientName, $tool, $safeClientName, $safeClientName, $safeClientName, $safeClientName, $safeClientName
        );
        
        $escaped = escapeshellarg($cmd);
        $sshCmd = sprintf(
            "sshpass -p %s ssh -p %d -q -o LogLevel=ERROR -o StrictHostKeyChecking=accept-new -o PreferredAuthentications=password -o PubkeyAuthentication=no %s@%s %s 2>&1",
            escapeshellarg($serverData['password']),
            (int)$serverData['port'],
            escapeshellarg($serverData['username']),
            escapeshellarg($serverData['host']),
            $escaped
        );
        
        $out = shell_exec($sshCmd);
        $parts = explode("---", trim($out));
        
        if (count($parts) < 2) {
            throw new Exception("Failed to generate client keys");
        }
        
        return [
            'private' => trim($parts[0]),
            'public' => trim($parts[1])
        ];
    }
    
    /**
     * Get next available client IP
     */
    private static function getNextClientIP(array $serverData): string {
        $pdo = DB::conn();
        
        // Get used IPs from database
        $stmt = $pdo->prepare('SELECT client_ip FROM vpn_clients WHERE server_id = ?');
        $stmt->execute([$serverData['id']]);
        $usedIPs = $stmt->fetchAll(PDO::FETCH_COLUMN);
        
        // Parse subnet
        $parts = explode('/', $serverData['vpn_subnet']);
        $networkLong = ip2long($parts[0]);
        
        // Reserve network address
        $used = ['10.8.1.0' => true];
        foreach ($usedIPs as $ip) {
            $used[$ip] = true;
        }
        
        // Find next free IP starting from .1
        for ($i = 1; $i <= 253; $i++) {
            $candidate = long2ip($networkLong + $i);
            if (!isset($used[$candidate])) {
                return $candidate;
            }
        }
        
        throw new Exception('No free IP addresses in subnet');
    }
    
    /**
     * Build client configuration file
     */
    private static function buildClientConfig(
        string $privateKey,
        string $clientIP,
        string $serverPublicKey,
        string $presharedKey,
        string $serverHost,
        int $serverPort,
        array $awgParams
    ): string {
        $config = "[Interface]\n";
        $config .= "PrivateKey = {$privateKey}\n";
        $config .= "Address = {$clientIP}/32\n";
        $config .= "DNS = 1.1.1.1, 1.0.0.1\n";
        
        // Add AWG parameters
        foreach (['Jc', 'Jmin', 'Jmax', 'S1', 'S2', 'H1', 'H2', 'H3', 'H4'] as $key) {
            if (isset($awgParams[$key])) {
                $config .= "{$key} = {$awgParams[$key]}\n";
            }
        }
        
        // AWG2-specific parameters
        foreach (['cookieReplyPacketJunkSize', 'transportPacketJunkSize'] as $key) {
            if (isset($awgParams[$key])) {
                $config .= "{$key} = {$awgParams[$key]}\n";
            }
        }

        // Special junk i1-i5
        for ($i = 1; $i <= 5; $i++) {
            $k = 'i' . $i;
            if (isset($awgParams[$k])) {
                $config .= "{$k} = {$awgParams[$k]}\n";
            }
        }

        // protocolVersion for AWG2 (must be in [Interface] section)
        if (isset($awgParams['protocolVersion'])) {
            $config .= "protocolVersion = {$awgParams['protocolVersion']}\n";
        }
        
        $config .= "\n[Peer]\n";
        $config .= "PublicKey = {$serverPublicKey}\n";
        $config .= "PresharedKey = {$presharedKey}\n";
        $config .= "Endpoint = {$serverHost}:{$serverPort}\n";
        $config .= "AllowedIPs = 0.0.0.0/0, ::/0\n";
        $config .= "PersistentKeepalive = 25\n";
        
        return $config;
    }
    
    /**
     * Add client to server using official method (append + wg syncconf)
     */
    private static function addClientToServer(
        array $serverData,
        string $publicKey,
        string $clientIP,
        ?string $clientName = null,
        ?string $protocolCode = null
    ): void {
        $containerName = $serverData['container_name'];
        
        // Determine interface and config path based on protocol
        $isAwg2 = str_contains(strtolower($containerName), 'awg2');
        if (!$isAwg2) {
            $awgParams = is_string($serverData['awg_params'] ?? null)
                ? json_decode($serverData['awg_params'], true)
                : ($serverData['awg_params'] ?? []);
            $ver = strtolower(trim((string)($awgParams['protocolVersion'] ?? '')));
            $isAwg2 = ($ver === '2');
        }
        $isWg = str_contains(strtolower($containerName), 'wireguard');

        if ($isWg) {
            $confPath = '/opt/amnezia/wireguard/wg0.conf';
            $iface = 'wg0';
            $tool = 'wg';
        } elseif ($isAwg2) {
            $confPath = '/opt/amnezia/awg/awg0.conf';
            $iface = 'awg0';
            $tool = 'awg';
        } else {
            $confPath = '/opt/amnezia/awg/wg0.conf';
            $iface = 'wg0';
            $tool = 'wg';
        }

        $baseDir = dirname($confPath);
        
        // Build peer block
        $peerBlock = "\n[Peer]\n";
        $peerBlock .= "PublicKey = {$publicKey}\n";
        $peerBlock .= "PresharedKey = {$serverData['preshared_key']}\n";
        $peerBlock .= "AllowedIPs = {$clientIP}/32\n";
        
        $escaped = addslashes($peerBlock);
        $tempFile = '/tmp/' . bin2hex(random_bytes(8)) . '.tmp';
        
        // Create temp file
        $safeContainer = escapeshellarg($containerName);
        $cmd1 = sprintf("docker exec -i %s sh -c 'echo \"%s\" > %s'", $safeContainer, $escaped, $tempFile);
        self::executeServerCommand($serverData, $cmd1, true);
        
        // Append to config
        $cmd2 = sprintf("docker exec -i %s sh -c 'cat %s >> %s'", $safeContainer, $tempFile, $confPath);
        self::executeServerCommand($serverData, $cmd2, true);
        
        // Apply via syncconf
        $cmd3 = sprintf("docker exec -i %s bash -c '%s syncconf %s <(%s-quick strip %s)'", $safeContainer, $tool, $iface, $tool, $confPath);
        self::executeServerCommand($serverData, $cmd3, true);
        
        // Remove temp file
        $cmd4 = sprintf("docker exec -i %s rm -f %s", $safeContainer, $tempFile);
        self::executeServerCommand($serverData, $cmd4, true);
        
        // Update clientsTable
        self::updateClientsTable(
            $serverData,
            $publicKey,
            $clientName !== null && trim($clientName) !== '' ? $clientName : $clientIP,
            $protocolCode
        );
    }
    
    /**
     * Update clientsTable on server
     */
    private static function updateClientsTable(array $serverData, string $publicKey, string $name, ?string $protocolCode = null): void {
        $containerName = $serverData['container_name'];
        $safeContainer = escapeshellarg($containerName);
        $baseDir = self::getContainerBaseDir($serverData);
        $clientsTablePath = $baseDir . '/clientsTable';
        
        // Read current table
        $cmd = sprintf("docker exec -i %s cat %s 2>/dev/null", $safeContainer, $clientsTablePath);
        $tableJson = self::executeServerCommand($serverData, $cmd, true);
        $table = json_decode(trim($tableJson), true);
        
        if (!is_array($table)) {
            $table = [];
        }
        
        // Add new client
        $entry = [
            'clientId' => $publicKey,
            'userData' => [
                'clientName' => $name,
                'creationDate' => date('D M j H:i:s Y')
            ]
        ];

        if ($protocolCode !== null && trim($protocolCode) !== '') {
            $entry['protocol'] = $protocolCode;
            $entry['userData']['protocol'] = $protocolCode;
        }

        $table[] = $entry;
        
        // Save back
        $newTableJson = json_encode($table, JSON_PRETTY_PRINT);
        $escaped = addslashes($newTableJson);
        $updateCmd = sprintf("docker exec -i %s sh -c 'echo \"%s\" > %s'", $safeContainer, $escaped, $clientsTablePath);
        self::executeServerCommand($serverData, $updateCmd, true);
    }
    
    /**
     * Determine base directory for container configs on the server
     */
    private static function getContainerBaseDir(array $serverData): string {
        $cn = strtolower((string)($serverData['container_name'] ?? ''));
        if (str_contains($cn, 'wireguard')) {
            return '/opt/amnezia/wireguard';
        }
        if (str_contains($cn, 'xray')) {
            return '/opt/amnezia/xray';
        }
        if (str_contains($cn, 'openvpn')) {
            return '/opt/amnezia/openvpn';
        }
        return '/opt/amnezia/awg';
    }

    /**
     * Execute command on server
     */
    private static function executeServerCommand(array $serverData, string $command, bool $sudo = false): string {
        if ($sudo && strtolower($serverData['username']) !== 'root') {
            $command = "echo " . escapeshellarg($serverData['password']) . " | sudo -S " . $command;
        }
        
        $escapedCommand = escapeshellarg($command);
        $sshCommand = sprintf(
            "sshpass -p %s ssh -p %d -q -o LogLevel=ERROR -o StrictHostKeyChecking=accept-new -o PreferredAuthentications=password -o PubkeyAuthentication=no %s@%s %s 2>&1",
            escapeshellarg($serverData['password']),
            (int)$serverData['port'],
            escapeshellarg($serverData['username']),
            escapeshellarg($serverData['host']),
            $escapedCommand
        );
        
        return shell_exec($sshCommand) ?? '';
    }
    
    /**
     * Generate QR code for configuration using Amnezia format
     * Uses working QrUtil from /Users/oleg/Documents/amnezia
     */
    private static function generateQRCode(string $config): string {
        require_once __DIR__ . '/QrUtil.php';
        
        try {
            // Use old Amnezia format with Qt/QDataStream encoding
            $payloadOld = QrUtil::encodeOldPayloadFromConf($config);
            $dataUri = QrUtil::pngBase64($payloadOld);
            return $dataUri;
        } catch (Throwable $e) {
            error_log('Failed to generate QR code: ' . $e->getMessage());
            return ''; // QR code generation failed, but continue
        }
    }
    
    /**
     * Get all clients for a server
     */
    public static function listByServer(int $serverId): array {
        $pdo = DB::conn();
        $stmt = $pdo->prepare('SELECT * FROM vpn_clients WHERE server_id = ? ORDER BY created_at DESC');
        $stmt->execute([$serverId]);
        return $stmt->fetchAll();
    }
    
    /**
     * Get all clients for a user
     */
    public static function listByUser(int $userId): array {
        $pdo = DB::conn();
        $stmt = $pdo->prepare('
            SELECT c.*, s.name as server_name, s.host as server_host
            FROM vpn_clients c
            LEFT JOIN vpn_servers s ON c.server_id = s.id
            WHERE c.user_id = ?
            AND (s.status IS NULL OR s.status <> "detached")
            ORDER BY c.created_at DESC
        ');
        $stmt->execute([$userId]);
        return $stmt->fetchAll();
    }
    
    /**
     * Revoke client access (disable without deleting)
     */
    public function revoke(): bool {
        if (!$this->data) {
            throw new Exception('Client not loaded');
        }
        
        // Remove from server
        $server = new VpnServer($this->data['server_id']);
        $serverData = $server->getData();
        
        if ($serverData && $serverData['status'] === 'active') {
            try {
                $proto = strtolower($this->data['peer_protocol'] ?? '');
                if (str_contains($proto, 'xray')) {
                    // Xray: remove UUID from server.json
                    self::removeXrayClientFromServer($serverData, $this->data['client_ip']);
                } else {
                    self::removeClientFromServer($serverData, $this->data['public_key']);
                }
            } catch (Exception $e) {
                error_log('Failed to remove client from server: ' . $e->getMessage());
            }
        }
        
        // Mark as disabled in database
        $pdo = DB::conn();
        $stmt = $pdo->prepare('UPDATE vpn_clients SET status = ? WHERE id = ?');
        return $stmt->execute(['disabled', $this->clientId]);
    }
    
    /**
     * Restore client access
     */
    public function restore(): bool {
        if (!$this->data) {
            throw new Exception('Client not loaded');
        }
        
        // Re-add to server
        $server = new VpnServer($this->data['server_id']);
        $serverData = $server->getData();
        
        if ($serverData && $serverData['status'] === 'active') {
            try {
                $restoredProtocol = trim((string)($this->data['peer_protocol'] ?? ''));
                if ($restoredProtocol === '') {
                    $restoredProtocol = $serverData['container_name'] ?? self::detectServerProtocolCode($serverData);
                }

                if (str_contains(strtolower($restoredProtocol), 'xray')) {
                    // Xray: re-add UUID to server.json
                    $overridden = $serverData;
                    $overridden['container_name'] = $restoredProtocol;
                    self::addXrayClientToServer($overridden, $this->data['client_ip'], (string)($this->data['name'] ?? ''));
                } else {
                    self::addClientToServer(
                        $serverData,
                        $this->data['public_key'],
                        $this->data['client_ip'],
                        (string)($this->data['name'] ?? $this->data['client_ip']),
                        $restoredProtocol
                    );
                }
            } catch (Exception $e) {
                throw new Exception('Failed to restore client on server: ' . $e->getMessage());
            }
        }
        
        // Mark as active in database
        $pdo = DB::conn();
        $stmt = $pdo->prepare('UPDATE vpn_clients SET status = ? WHERE id = ?');
        return $stmt->execute(['active', $this->clientId]);
    }
    
    /**
     * Delete client permanently
     */
    public function delete(): bool {
        if (!$this->data) {
            throw new Exception('Client not loaded');
        }
        
        // First revoke to remove from server
        if ($this->data['status'] === 'active') {
            $this->revoke();
        }
        
        // Delete from database
        $pdo = DB::conn();
        $stmt = $pdo->prepare('DELETE FROM vpn_clients WHERE id = ?');
        return $stmt->execute([$this->clientId]);
    }
    
    /**
     * Remove client from server WireGuard configuration
     */
    private static function removeClientFromServer(array $serverData, string $publicKey): void {
        $containerName = $serverData['container_name'];
        $safeContainer = escapeshellarg($containerName);
        
        // Determine tool and paths based on protocol
        $cn = strtolower($containerName);
        $isAwg2 = str_contains($cn, 'awg2');
        if (!$isAwg2) {
            $awgParams = is_string($serverData['awg_params'] ?? null)
                ? json_decode($serverData['awg_params'], true)
                : ($serverData['awg_params'] ?? []);
            $isAwg2 = (strtolower(trim((string)($awgParams['protocolVersion'] ?? ''))) === '2');
        }
        $isWg = str_contains($cn, 'wireguard');

        if ($isWg) {
            $confPath = '/opt/amnezia/wireguard/wg0.conf';
            $iface = 'wg0';
            $tool = 'wg';
        } elseif ($isAwg2) {
            $confPath = '/opt/amnezia/awg/awg0.conf';
            $iface = 'awg0';
            $tool = 'awg';
        } else {
            $confPath = '/opt/amnezia/awg/wg0.conf';
            $iface = 'wg0';
            $tool = 'wg';
        }
        
        // Live removal
        $removeCmd = sprintf(
            "docker exec -i %s %s set %s peer %s remove",
            $safeContainer,
            $tool,
            $iface,
            escapeshellarg($publicKey)
        );
        self::executeServerCommand($serverData, $removeCmd, true);
        
        // Remove from config file for persistence
        $readCmd = sprintf("docker exec -i %s cat %s", $safeContainer, $confPath);
        $config = self::executeServerCommand($serverData, $readCmd, true);
        
        $newConfig = self::removePeerFromConfig($config, $publicKey);
        
        $escapedConfig = str_replace("'", "'\\''", $newConfig);
        $writeCmd = sprintf(
            "docker exec -i %s sh -c 'echo '\''%s'\'' > %s'",
            $safeContainer,
            $escapedConfig,
            $confPath
        );
        self::executeServerCommand($serverData, $writeCmd, true);
        
        // Save config
        $saveCmd = sprintf("docker exec -i %s %s-quick save %s", $safeContainer, $tool, $iface);
        self::executeServerCommand($serverData, $saveCmd, true);
        
        // Remove from clientsTable
        self::removeFromClientsTable($serverData, $publicKey);
    }

    /**
     * Remove xray client UUID from server.json and restart xray
     */
    private static function removeXrayClientFromServer(array $serverData, string $clientUuid): void {
        $containerName = $serverData['container_name'];
        // Use the client's container if different from active
        $proto = strtolower($containerName);
        if (!str_contains($proto, 'xray')) {
            // The client belongs to an xray container, but server's active might differ
            // Use the peer_protocol as the container name
            $containerName = 'amnezia-xray';
        }
        $containerArg = escapeshellarg($containerName);

        // Read current server.json
        $cmd = sprintf("docker exec -i %s cat /opt/amnezia/xray/server.json", $containerArg);
        $sjson = self::executeServerCommand($serverData, $cmd, true);
        $config = json_decode(trim($sjson), true);
        if (!is_array($config)) {
            throw new Exception('Failed to read xray server.json');
        }

        // Filter out the client by UUID
        $clients = $config['inbounds'][0]['settings']['clients'] ?? [];
        $config['inbounds'][0]['settings']['clients'] = array_values(
            array_filter($clients, fn($c) => ($c['id'] ?? '') !== $clientUuid)
        );

        // Write back
        $newJson = json_encode($config, JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES);
        $tmpFile = '/tmp/xray_cfg_' . bin2hex(random_bytes(4)) . '.json';
        $writeCmd = sprintf(
            "docker exec -i %s sh -c 'cat > %s' <<'XRAYEOF'\n%s\nXRAYEOF",
            $containerArg, $tmpFile, $newJson
        );
        self::executeServerCommand($serverData, $writeCmd, true);

        $mvCmd = sprintf("docker exec -i %s sh -c 'mv %s /opt/amnezia/xray/server.json'", $containerArg, $tmpFile);
        self::executeServerCommand($serverData, $mvCmd, true);

        // Remove from clientsTable too
        $cmd2 = sprintf("docker exec -i %s cat /opt/amnezia/xray/clientsTable 2>/dev/null", $containerArg);
        $tableJson = self::executeServerCommand($serverData, $cmd2, true);
        $table = json_decode(trim($tableJson), true);
        if (is_array($table)) {
            $table = array_values(array_filter($table, function ($entry) use ($clientUuid) {
                return ($entry['clientId'] ?? '') !== $clientUuid;
            }));
            $newTableJson = json_encode($table, JSON_PRETTY_PRINT | JSON_UNESCAPED_UNICODE);
            $tmpFile2 = '/tmp/xray_ct_' . bin2hex(random_bytes(4)) . '.json';
            $writeCmd2 = sprintf(
                "docker exec -i %s sh -c 'cat > %s' <<'XRAYEOF'\n%s\nXRAYEOF",
                $containerArg, $tmpFile2, $newTableJson
            );
            self::executeServerCommand($serverData, $writeCmd2, true);
            $mvCmd2 = sprintf("docker exec -i %s sh -c 'mv %s /opt/amnezia/xray/clientsTable'", $containerArg, $tmpFile2);
            self::executeServerCommand($serverData, $mvCmd2, true);
        }

        // Restart xray to apply
        self::executeServerCommand($serverData, sprintf("docker restart %s", $containerArg), true);
    }
    
    /**
     * Remove peer section from WireGuard config
     */
    private static function removePeerFromConfig(string $config, string $publicKey): string {
        $lines = explode("\n", $config);
        $newLines = [];
        $inPeerBlock = false;
        $skipBlock = false;
        
        foreach ($lines as $line) {
            $trimmed = trim($line);
            
            // Start of new section
            if (strpos($trimmed, '[') === 0) {
                $inPeerBlock = ($trimmed === '[Peer]');
                $skipBlock = false;
            }
            
            // Check if this peer block should be skipped
            if ($inPeerBlock && strpos($trimmed, 'PublicKey') === 0) {
                $parts = explode('=', $line, 2);
                if (count($parts) === 2 && trim($parts[1]) === $publicKey) {
                    $skipBlock = true;
                    // Remove the [Peer] line that was already added
                    array_pop($newLines);
                    continue;
                }
            }
            
            // Skip lines in the block to be removed
            if ($skipBlock && $inPeerBlock) {
                // Empty line ends the peer block
                if (empty($trimmed)) {
                    $skipBlock = false;
                    $inPeerBlock = false;
                }
                continue;
            }
            
            $newLines[] = $line;
        }
        
        return implode("\n", $newLines);
    }
    
    /**
     * Remove client from clientsTable
     */
    private static function removeFromClientsTable(array $serverData, string $publicKey): void {
        $containerName = $serverData['container_name'];
        $safeContainer = escapeshellarg($containerName);
        $baseDir = self::getContainerBaseDir($serverData);
        $clientsTablePath = $baseDir . '/clientsTable';
        
        // Read current table
        $cmd = sprintf("docker exec -i %s cat %s 2>/dev/null", $safeContainer, $clientsTablePath);
        $tableJson = self::executeServerCommand($serverData, $cmd, true);
        $table = json_decode(trim($tableJson), true);
        
        if (!is_array($table)) {
            return;
        }
        
        // Filter out the client
        $table = array_filter($table, function($client) use ($publicKey) {
            return ($client['clientId'] ?? '') !== $publicKey;
        });
        
        // Re-index array
        $table = array_values($table);
        
        // Save back
        $newTableJson = json_encode($table, JSON_PRETTY_PRINT);
        $escaped = addslashes($newTableJson);
        $updateCmd = sprintf("docker exec -i %s sh -c 'echo \"%s\" > %s'", $safeContainer, $escaped, $clientsTablePath);
        self::executeServerCommand($serverData, $updateCmd, true);
    }
    
    /**
     * Get client data
     */
    public function getData(): ?array {
        return $this->data;
    }
    
    /**
     * Get configuration file content
     */
    public function getConfig(): string {
        return $this->data['config'] ?? '';
    }
    
    /**
     * Get QR code
     */
    public function getQRCode(): string {
        return $this->data['qr_code'] ?? '';
    }

    /**
     * Check whether vpn_clients.peer_protocol exists (compatibility with old schemas).
     */
    private static function hasPeerProtocolColumn(): bool {
        if (self::$hasPeerProtocolColumnCache !== null) {
            return self::$hasPeerProtocolColumnCache;
        }

        $pdo = DB::conn();
        $stmt = $pdo->query(
            "SELECT COUNT(*) FROM information_schema.COLUMNS WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME = 'vpn_clients' AND COLUMN_NAME = 'peer_protocol'"
        );

        self::$hasPeerProtocolColumnCache = (bool)$stmt->fetchColumn();
        return self::$hasPeerProtocolColumnCache;
    }

    /**
     * Detect protocol code for the server container/profile used to create new clients.
     */
    private static function detectServerProtocolCode(array $serverData): string {
        $containerName = strtolower((string)($serverData['container_name'] ?? ''));
        $awgParams = $serverData['awg_params'] ?? null;
        $hasAwgParams = false;
        $isAwgV2 = false;

        if (is_string($awgParams) && $awgParams !== '') {
            $decoded = json_decode($awgParams, true);
            $hasAwgParams = json_last_error() === JSON_ERROR_NONE && is_array($decoded) && !empty($decoded);
            if ($hasAwgParams) {
                $version = strtolower(trim((string)($decoded['protocol_version'] ?? $decoded['protocolVersion'] ?? '')));
                $isAwgV2 = ($version === '2' || $version === 'v2' || $version === 'awg2');
            }
        } elseif (is_array($awgParams) && !empty($awgParams)) {
            $hasAwgParams = true;
            $version = strtolower(trim((string)($awgParams['protocol_version'] ?? $awgParams['protocolVersion'] ?? '')));
            $isAwgV2 = ($version === '2' || $version === 'v2' || $version === 'awg2');
        }

        if (str_contains($containerName, 'awg2') || $isAwgV2) {
            return 'awg2';
        }
        if (str_contains($containerName, 'xray')) {
            return 'xray';
        }
        if (str_contains($containerName, 'openvpn') || str_contains($containerName, 'ovpn')) {
            return 'openvpn';
        }
        if (str_contains($containerName, 'ikev2') || str_contains($containerName, 'ipsec')) {
            return 'ikev2';
        }
        if (str_contains($containerName, 'awg') || $hasAwgParams) {
            return 'awg';
        }

        return 'wg';
    }
    
    /**
     * Sync traffic statistics from server
     */
    public function syncStats(): bool {
        if (!$this->data) {
            throw new Exception('Client not loaded');
        }
        
        $server = new VpnServer($this->data['server_id']);
        $serverData = $server->getData();
        
        if (!$serverData || $serverData['status'] !== 'active') {
            return false;
        }
        
        try {
            $stats = self::getClientStatsFromServer($serverData, $this->data['public_key'], $this->data['peer_protocol'] ?? null);
            
            $pdo = DB::conn();
            $stmt = $pdo->prepare('
                UPDATE vpn_clients 
                SET bytes_sent = ?, bytes_received = ?, last_handshake = ?, last_sync_at = NOW()
                WHERE id = ?
            ');
            
            $lastHandshake = $stats['last_handshake'] > 0 
                ? gmdate('Y-m-d H:i:s', $stats['last_handshake']) 
                : null;
            
            return $stmt->execute([
                $stats['bytes_sent'],
                $stats['bytes_received'],
                $lastHandshake,
                $this->clientId
            ]);
        } catch (Exception $e) {
            error_log('Failed to sync client stats: ' . $e->getMessage());
            return false;
        }
    }
    
    /**
     * Find all WG-capable containers on the server from cached data.
     * Returns array of serverData copies, each with container_name overridden.
     */
    private static function resolveWgContainers(array $serverData): array {
        $awgParams = $serverData['awg_params'] ?? null;
        if (is_string($awgParams) && $awgParams !== '') {
            $awgParams = json_decode($awgParams, true);
        }
        if (!is_array($awgParams)) {
            $awgParams = [];
        }

        $installed = $awgParams['installed_containers'] ?? [];
        $wgNames = [];

        foreach ($installed as $ic) {
            $name = (string)($ic['name'] ?? '');
            $proto = strtolower((string)($ic['protocol'] ?? ''));
            $nameLower = strtolower($name);
            if ($name !== '' && (in_array($proto, ['awg2', 'awg', 'wg'], true) || str_contains($nameLower, 'awg') || str_contains($nameLower, 'wireguard'))) {
                $wgNames[] = $name;
            }
        }

        // If current container is WG-capable and not yet in list, add it
        $cn = strtolower((string)($serverData['container_name'] ?? ''));
        if (str_contains($cn, 'awg') || str_contains($cn, 'wireguard')) {
            $currentName = (string)$serverData['container_name'];
            if (!in_array($currentName, $wgNames, true)) {
                array_unshift($wgNames, $currentName);
            }
        }

        if (empty($wgNames)) {
            // Fallback: just use the active container (may not work)
            return [$serverData];
        }

        $result = [];
        foreach ($wgNames as $name) {
            $copy = $serverData;
            $copy['container_name'] = $name;
            $result[] = $copy;
        }
        return $result;
    }

    /**
     * Determine the correct wg/awg tool and interface name for a container
     */
    private static function getWgShowCommand(array $serverData): string {
        $cn = strtolower((string)($serverData['container_name'] ?? ''));
        $containerArg = escapeshellarg($serverData['container_name']);

        if (str_contains($cn, 'awg2')) {
            return sprintf("docker exec -i %s sh -c 'awg show awg0 dump 2>/dev/null || awg show wg0 dump 2>/dev/null || wg show awg0 dump 2>/dev/null || wg show wg0 dump 2>/dev/null || true'", $containerArg);
        }
        if (str_contains($cn, 'awg')) {
            return sprintf("docker exec -i %s sh -c 'wg show wg0 dump 2>/dev/null || wg show awg0 dump 2>/dev/null || awg show awg0 dump 2>/dev/null || true'", $containerArg);
        }
        // Pure WireGuard
        return sprintf("docker exec -i %s sh -c 'wg show wg0 dump 2>/dev/null || true'", $containerArg);
    }

    /**
     * Parse wg/awg dump output into array keyed by public_key
     */
    private static function parseWgDump(string $output): array {
        $peers = [];
        $lines = explode("\n", trim($output));
        // First line is interface, peers start from line 2
        for ($i = 1; $i < count($lines); $i++) {
            $line = trim($lines[$i]);
            if ($line === '') continue;

            $parts = preg_split('/\s+/', $line);
            if (!is_array($parts) || count($parts) < 7) continue;

            $peers[$parts[0]] = [
                'last_handshake' => (int)$parts[4],
                'bytes_sent' => (int)$parts[5],
                'bytes_received' => (int)$parts[6],
            ];
        }
        return $peers;
    }

    /**
     * Get client statistics from server, using client's own container if known
     */
    private static function getClientStatsFromServer(array $serverData, string $publicKey, ?string $clientContainer = null): array {
        // If client has a specific container, query that one first
        if ($clientContainer !== null && $clientContainer !== '') {
            $specific = $serverData;
            $specific['container_name'] = $clientContainer;
            $cmd = self::getWgShowCommand($specific);
            $output = self::executeServerCommand($serverData, $cmd, true);
            $peers = self::parseWgDump($output);
            if (isset($peers[$publicKey])) {
                return $peers[$publicKey];
            }
        }

        // Fallback: try all WG containers
        $wgServers = self::resolveWgContainers($serverData);
        foreach ($wgServers as $wgServer) {
            $cmd = self::getWgShowCommand($wgServer);
            $output = self::executeServerCommand($serverData, $cmd, true);
            $peers = self::parseWgDump($output);
            if (isset($peers[$publicKey])) {
                return $peers[$publicKey];
            }
        }

        return [
            'bytes_sent' => 0,
            'bytes_received' => 0,
            'last_handshake' => 0,
        ];
    }
    
    /**
     * Sync stats for all active clients on a server
     */
    public static function syncAllStatsForServer(int $serverId): int {
        $server = new VpnServer($serverId);
        $serverData = $server->getData();

        if (!$serverData || $serverData['status'] !== 'active') {
            return 0;
        }

        // Group clients by their container (peer_protocol stores container name)
        $pdo = DB::conn();
        $stmt = $pdo->prepare('SELECT id, public_key, peer_protocol FROM vpn_clients WHERE server_id = ? AND status = ?');
        $stmt->execute([$serverId, 'active']);
        $clients = $stmt->fetchAll(PDO::FETCH_ASSOC);

        if (empty($clients)) {
            return 0;
        }

        // Group by container
        $byContainer = [];
        foreach ($clients as $row) {
            $container = trim((string)($row['peer_protocol'] ?? ''));
            $byContainer[$container][] = $row;
        }

        // Load dump per container (one SSH call per container)
        // Skip non-WG containers (xray, etc.) — they don't support `wg show` dumps
        $peersByContainer = [];
        foreach (array_keys($byContainer) as $container) {
            if ($container !== '' && !str_contains(strtolower($container), 'xray')) {
                $overridden = $serverData;
                $overridden['container_name'] = $container;
                $cmd = self::getWgShowCommand($overridden);
                $output = self::executeServerCommand($serverData, $cmd, true);
                $peersByContainer[$container] = self::parseWgDump($output);
            }
        }

        // For clients without a container tag, read all WG containers
        if (isset($byContainer[''])) {
            $wgServers = self::resolveWgContainers($serverData);
            $allPeers = [];
            foreach ($wgServers as $wgServer) {
                $cmd = self::getWgShowCommand($wgServer);
                $output = self::executeServerCommand($serverData, $cmd, true);
                foreach (self::parseWgDump($output) as $pk => $data) {
                    if (!isset($allPeers[$pk])) {
                        $allPeers[$pk] = $data;
                    }
                }
            }
            $peersByContainer[''] = $allPeers;
        }

        $updStmt = $pdo->prepare('
            UPDATE vpn_clients
            SET bytes_sent = ?, bytes_received = ?, last_handshake = ?, last_sync_at = NOW()
            WHERE id = ?
        ');

        $synced = 0;
        foreach ($byContainer as $container => $containerClients) {
            $peers = $peersByContainer[$container] ?? [];
            if (empty($peers)) continue;

            foreach ($containerClients as $row) {
                $pk = (string)$row['public_key'];
                if ($pk === '' || !isset($peers[$pk])) {
                    continue;
                }

                $peer = $peers[$pk];
                $lastHandshake = $peer['last_handshake'] > 0
                    ? gmdate('Y-m-d H:i:s', $peer['last_handshake'])
                    : null;

                try {
                    $updStmt->execute([
                        $peer['bytes_sent'],
                        $peer['bytes_received'],
                        $lastHandshake,
                        (int)$row['id'],
                    ]);
                    $synced++;
                } catch (Exception $e) {
                    error_log('Failed to sync stats for client ' . $row['id'] . ': ' . $e->getMessage());
                }
            }
        }

        return $synced;
    }
    
    /**
     * Get human-readable traffic statistics
     */
    public function getFormattedStats(): array {
        if (!$this->data) {
            return ['sent' => 'N/A', 'received' => 'N/A', 'total' => 'N/A', 'last_seen' => 'Never'];
        }
        
        $sent = $this->formatBytes($this->data['bytes_sent'] ?? 0);
        $received = $this->formatBytes($this->data['bytes_received'] ?? 0);
        $total = $this->formatBytes(($this->data['bytes_sent'] ?? 0) + ($this->data['bytes_received'] ?? 0));
        
        $lastSeen = 'Never';
        if (!empty($this->data['last_handshake'])) {
            $lastHandshake = strtotime($this->data['last_handshake']);
            $diff = time() - $lastHandshake;
            
            if ($diff < 300) {
                $lastSeen = 'Online';
            } elseif ($diff < 3600) {
                $lastSeen = floor($diff / 60) . ' minutes ago';
            } elseif ($diff < 86400) {
                $lastSeen = floor($diff / 3600) . ' hours ago';
            } else {
                $lastSeen = floor($diff / 86400) . ' days ago';
            }
        }
        
        return [
            'sent' => $sent,
            'received' => $received,
            'total' => $total,
            'last_seen' => $lastSeen,
            'is_online' => !empty($this->data['last_handshake']) && (time() - strtotime($this->data['last_handshake'])) < 300
        ];
    }
    
    /**
     * Format bytes to human-readable string (always in GB)
     */
    private function formatBytes(int $bytes): string {
        $gb = $bytes / 1073741824; // 1024 * 1024 * 1024
        return number_format($gb, 2) . ' GB';
    }
    
    /**
     * Set client expiration date
     * 
     * @param int $clientId Client ID
     * @param string|null $expiresAt Expiration date (Y-m-d H:i:s) or null for never expires
     * @return bool Success
     */
    public static function setExpiration(int $clientId, ?string $expiresAt): bool {
        $pdo = DB::conn();
        $stmt = $pdo->prepare('UPDATE vpn_clients SET expires_at = ? WHERE id = ?');
        return $stmt->execute([$expiresAt, $clientId]);
    }
    
    /**
     * Extend client expiration by days
     * 
     * @param int $clientId Client ID
     * @param int $days Days to extend
     * @return bool Success
     */
    public static function extendExpiration(int $clientId, int $days): bool {
        $pdo = DB::conn();
        
        // Get current expiration
        $stmt = $pdo->prepare('SELECT expires_at FROM vpn_clients WHERE id = ?');
        $stmt->execute([$clientId]);
        $client = $stmt->fetch();
        
        if (!$client) {
            return false;
        }
        
        // Calculate new expiration from current or now
        $baseDate = $client['expires_at'] ? strtotime($client['expires_at']) : time();
        $newExpiration = date('Y-m-d H:i:s', strtotime("+{$days} days", $baseDate));
        
        return self::setExpiration($clientId, $newExpiration);
    }
    
    /**
     * Get clients expiring soon
     * 
     * @param int $days Check for clients expiring within N days
     * @return array List of expiring clients
     */
    public static function getExpiringClients(int $days = 7): array {
        $pdo = DB::conn();
        $stmt = $pdo->prepare('
            SELECT c.*, s.name as server_name, s.host, u.name as user_name, u.email
            FROM vpn_clients c
            JOIN vpn_servers s ON c.server_id = s.id
            JOIN users u ON c.user_id = u.id
            WHERE c.expires_at IS NOT NULL 
            AND c.expires_at <= DATE_ADD(NOW(), INTERVAL ? DAY)
            AND c.expires_at > NOW()
            AND c.status = "active"
            ORDER BY c.expires_at ASC
        ');
        $stmt->execute([$days]);
        return $stmt->fetchAll();
    }
    
    /**
     * Get expired clients
     * 
     * @return array List of expired clients
     */
    public static function getExpiredClients(): array {
        $pdo = DB::conn();
        $stmt = $pdo->query('
            SELECT c.*, s.name as server_name, s.host
            FROM vpn_clients c
            JOIN vpn_servers s ON c.server_id = s.id
            WHERE c.expires_at IS NOT NULL 
            AND c.expires_at <= NOW()
            AND c.status = "active"
            ORDER BY c.expires_at DESC
        ');
        return $stmt->fetchAll();
    }
    
    /**
     * Disable expired clients automatically
     * 
     * @return int Number of clients disabled
     */
    public static function disableExpiredClients(): int {
        $expiredClients = self::getExpiredClients();
        $count = 0;
        
        foreach ($expiredClients as $clientData) {
            try {
                $client = new self($clientData['id']);
                $client->revoke();
                $count++;
            } catch (Exception $e) {
                error_log("Failed to disable expired client {$clientData['id']}: " . $e->getMessage());
            }
        }
        
        return $count;
    }
    
    /**
     * Check if client is expired
     * 
     * @return bool True if expired
     */
    public function isExpired(): bool {
        if (!$this->data) {
            return false;
        }
        
        return $this->data['expires_at'] !== null && strtotime($this->data['expires_at']) <= time();
    }
    
    /**
     * Get days until expiration
     * 
     * @return int|null Days until expiration (negative if expired, null if never expires)
     */
    public function getDaysUntilExpiration(): ?int {
        if (!$this->data || $this->data['expires_at'] === null) {
            return null;
        }
        
        $diff = strtotime($this->data['expires_at']) - time();
        return (int)floor($diff / 86400);
    }
    
    /**
     * Set traffic limit for client
     * 
     * @param int|null $limitBytes Traffic limit in bytes (NULL = unlimited)
     * @return bool Success
     */
    public function setTrafficLimit(?int $limitBytes): bool {
        if (!$this->data) {
            throw new Exception('Client not loaded');
        }
        
        $pdo = DB::conn();
        $stmt = $pdo->prepare('UPDATE vpn_clients SET traffic_limit = ? WHERE id = ?');
        $result = $stmt->execute([$limitBytes, $this->clientId]);
        
        if ($result) {
            $this->data['traffic_limit'] = $limitBytes;
        }
        
        return $result;
    }
    
    /**
     * Get total traffic used (sent + received)
     * 
     * @return int Total traffic in bytes
     */
    public function getTotalTraffic(): int {
        if (!$this->data) {
            return 0;
        }
        
        return (int)($this->data['bytes_sent'] ?? 0) + (int)($this->data['bytes_received'] ?? 0);
    }
    
    /**
     * Check if client has exceeded traffic limit
     * 
     * @return bool True if over limit
     */
    public function isOverLimit(): bool {
        if (!$this->data || $this->data['traffic_limit'] === null) {
            return false; // No limit set
        }

        $totalTraffic = $this->getTotalTraffic();
        return $totalTraffic >= (int)$this->data['traffic_limit'];
    }
    
    /**
     * Get traffic limit status
     * 
     * @return array Status info
     */
    public function getTrafficLimitStatus(): array {
        $totalTraffic = $this->getTotalTraffic();
        $limit = $this->data['traffic_limit'] ?? null;
        
        return [
            'total_traffic' => $totalTraffic,
            'traffic_limit' => $limit,
            'is_unlimited' => $limit === null,
            'is_over_limit' => $this->isOverLimit(),
            'percentage_used' => $limit ? min(100, round(($totalTraffic / $limit) * 100, 2)) : 0,
            'remaining' => $limit ? max(0, $limit - $totalTraffic) : null
        ];
    }
    
    /**
     * Get all clients that exceeded their traffic limit
     * 
     * @return array List of client IDs over limit
     */
    public static function getClientsOverLimit(): array {
        $pdo = DB::conn();
        $stmt = $pdo->query('
            SELECT id, name, bytes_sent, bytes_received, traffic_limit 
            FROM vpn_clients 
            WHERE traffic_limit IS NOT NULL 
            AND (bytes_sent + bytes_received) >= traffic_limit 
            AND status = "active"
            ORDER BY id
        ');
        
        return $stmt->fetchAll();
    }
    
    /**
     * Disable all clients that exceeded their traffic limit
     * 
     * @return int Number of clients disabled
     */
    public static function disableClientsOverLimit(): int {
        $clients = self::getClientsOverLimit();
        $disabled = 0;
        
        foreach ($clients as $clientData) {
            try {
                $client = new VpnClient($clientData['id']);
                if ($client->revoke()) {
                    $disabled++;
                    error_log("Client {$clientData['name']} (ID: {$clientData['id']}) disabled: traffic limit exceeded");
                }
            } catch (Exception $e) {
                error_log("Failed to disable client {$clientData['id']}: " . $e->getMessage());
            }
        }
        
        return $disabled;
    }
}


