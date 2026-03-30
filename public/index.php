<?php
/**
 * Amnezia VPN Web Panel
 * Main entry point
 */

session_name(getenv('SESSION_NAME') ?: 'amnezia_panel_session');
session_start();

// Load dependencies
require_once __DIR__ . '/../vendor/autoload.php';
require_once __DIR__ . '/../inc/Config.php';
require_once __DIR__ . '/../inc/DB.php';
require_once __DIR__ . '/../inc/Auth.php';
require_once __DIR__ . '/../inc/Router.php';
require_once __DIR__ . '/../inc/View.php';
require_once __DIR__ . '/../inc/VpnServer.php';
require_once __DIR__ . '/../inc/VpnClient.php';
require_once __DIR__ . '/../inc/Translator.php';
require_once __DIR__ . '/../inc/JWT.php';
require_once __DIR__ . '/../inc/PanelImporter.php';
require_once __DIR__ . '/../inc/ServerMonitoring.php';

// Load environment configuration
Config::load(__DIR__ . '/../.env');

// Test database connection
try {
    DB::conn();
} catch (Throwable $e) {
    die('Database connection error: ' . $e->getMessage());
}

// Seed admin user if not exists
try {
    $adminEmail = Config::get('ADMIN_EMAIL');
    $adminPass = Config::get('ADMIN_PASSWORD');
    if ($adminEmail && $adminPass) {
        Auth::seedAdmin($adminEmail, $adminPass);
    }
} catch (Throwable $e) {
    // Ignore errors
}

// Initialize translator
Translator::init();

// Set timezone
$appTimezone = Config::get('APP_TIMEZONE', 'UTC');
date_default_timezone_set($appTimezone);

// Initialize template engine
$user = Auth::user();
$appName = Config::get('APP_NAME', 'Amnezia VPN Panel');

/**
 * Helper function to authenticate user from JWT or session
 * Returns user array or null if unauthorized
 */
function authenticateRequest(): ?array {
    // Check JWT token in Authorization header
    $authHeader = $_SERVER['HTTP_AUTHORIZATION'] ?? '';
    if ($authHeader && preg_match('/Bearer\s+(.*)$/i', $authHeader, $matches)) {
        $token = $matches[1];
        $user = JWT::verify($token);
        if ($user) {
            return $user;
        }
    }
    
    // Fallback to session
    if (isset($_SESSION['user_id'])) {
        return Auth::user();
    }
    
    return null;
}

function detectServerProtocol(array $serverData): string {
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

function normalizeProtocolCode(?string $raw, string $fallback = 'awg'): string {
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

function formatProtocolLabel(string $code): string {
    return match ($code) {
        'awg2' => 'AWG2',
        'awg' => 'AmneziaWG (legacy)',
        'wg' => 'WireGuard',
        'xray' => 'Xray',
        'openvpn' => 'OpenVPN',
        'ikev2' => 'IKEv2',
        default => strtoupper($code),
    };
}

function protocolBadgeClass(string $code): string {
    return match ($code) {
        'awg2' => 'bg-purple-100 text-purple-800',
        'awg' => 'bg-gray-100 text-gray-600',
        'xray' => 'bg-orange-100 text-orange-800',
        'openvpn' => 'bg-emerald-100 text-emerald-800',
        'ikev2' => 'bg-indigo-100 text-indigo-800',
        default => 'bg-blue-100 text-blue-800',
    };
}

function inferClientProtocolCode(array $clientData, string $fallback): string {
    $candidates = [
        $clientData['peer_protocol'] ?? null,
        $clientData['protocol'] ?? null,
    ];

    foreach ($candidates as $candidate) {
        if (is_string($candidate) && trim($candidate) !== '') {
            return normalizeProtocolCode($candidate, $fallback);
        }
    }

    $rawConfig = $clientData['config'] ?? null;
    if (is_string($rawConfig) && trim($rawConfig) !== '') {
        $decoded = json_decode($rawConfig, true);
        if (is_array($decoded)) {
            $configCandidates = [
                $decoded['protocol'] ?? null,
                $decoded['vpnproto'] ?? null,
                $decoded['protocol_version'] ?? null,
                $decoded['profileType'] ?? null,
                $decoded['clientType'] ?? null,
                $decoded['mode'] ?? null,
                $decoded['container'] ?? null,
            ];

            foreach ($configCandidates as $candidate) {
                if (is_string($candidate) && trim($candidate) !== '') {
                    return normalizeProtocolCode($candidate, $fallback);
                }
            }
        }

        if (preg_match('/"protocol"\s*:\s*"([^"]+)"/i', $rawConfig, $m)) {
            return normalizeProtocolCode($m[1], $fallback);
        }
    }

    $containerCandidate = $clientData['container'] ?? null;
    if (is_string($containerCandidate) && trim($containerCandidate) !== '') {
        return normalizeProtocolCode($containerCandidate, $fallback);
    }

    return $fallback;
}

function csrfToken(): string {
    $existing = $_SESSION['csrf_token'] ?? null;
    if (is_string($existing) && $existing !== '') {
        return $existing;
    }

    $token = bin2hex(random_bytes(32));
    $_SESSION['csrf_token'] = $token;
    return $token;
}

function isValidCsrfToken(?string $token): bool {
    $sessionToken = $_SESSION['csrf_token'] ?? null;
    if (!is_string($sessionToken) || $sessionToken === '' || !is_string($token) || $token === '') {
        return false;
    }

    return hash_equals($sessionToken, $token);
}

function safeInternalRedirectTarget(?string $target, string $fallback = '/servers'): string {
    if (!is_string($target) || trim($target) === '') {
        return $fallback;
    }

    $parsed = parse_url($target);
    if ($parsed === false) {
        return $fallback;
    }

    if (isset($parsed['host']) && $parsed['host'] !== '') {
        $requestHost = strtolower((string)($_SERVER['HTTP_HOST'] ?? ''));
        if ($requestHost === '' || strtolower((string)$parsed['host']) !== $requestHost) {
            return $fallback;
        }
    }

    $path = (string)($parsed['path'] ?? '');
    if ($path === '' || $path[0] !== '/' || substr($path, 0, 2) === '//') {
        return $fallback;
    }

    $query = isset($parsed['query']) && $parsed['query'] !== ''
        ? '?' . $parsed['query']
        : '';

    return $path . $query;
}

function resolvePhpCliBinary(): string {
    $isCommandAvailable = static function (string $command): bool {
        if ($command === '' || preg_match('/\s/', $command)) {
            return false;
        }

        $probe = 'command -v ' . escapeshellarg($command) . ' >/dev/null 2>&1; echo $?';
        return trim((string)shell_exec($probe)) === '0';
    };

    $candidates = [
        trim((string)Config::get('PHP_CLI_BIN', '')),
        defined('PHP_BINARY') ? trim((string)PHP_BINARY) : '',
        '/usr/local/bin/php',
        '/usr/bin/php',
        'php',
    ];

    foreach ($candidates as $candidate) {
        if ($candidate === '') {
            continue;
        }

        // Bare command name relies on PATH resolution.
        if (!str_contains($candidate, '/')) {
            if ($isCommandAvailable($candidate)) {
                return $candidate;
            }
            continue;
        }

        if (is_file($candidate) && is_executable($candidate)) {
            return $candidate;
        }
    }

    return 'php';
}

function runPhpScript(string $scriptPath, array $args = []): string {
    if (!is_file($scriptPath)) {
        throw new RuntimeException('Script not found: ' . $scriptPath);
    }

    $parts = [
        escapeshellarg(resolvePhpCliBinary()),
        escapeshellarg($scriptPath),
    ];

    foreach ($args as $arg) {
        $parts[] = escapeshellarg((string)$arg);
    }

    $command = implode(' ', $parts) . ' 2>&1';
    return trim((string)shell_exec($command));
}

function requireValidCsrfToken(): void {
    $token = $_POST['_csrf'] ?? null;
    if (!isValidCsrfToken(is_string($token) ? $token : null)) {
        $accept = strtolower((string)($_SERVER['HTTP_ACCEPT'] ?? ''));
        if (str_contains($accept, 'application/json')) {
            http_response_code(419);
            header('Content-Type: application/json');
            echo json_encode(['error' => 'Invalid CSRF token']);
            exit;
        }

        $_SESSION['error_message'] = 'Session expired. Please retry the action.';
        $referer = $_SERVER['HTTP_REFERER'] ?? '/servers';
        redirect(safeInternalRedirectTarget($referer, '/servers'));
        exit;
    }
}

View::init(__DIR__ . '/../templates', [
    'app_name' => $appName,
    'app_timezone' => $appTimezone,
    'csrf_token' => csrfToken(),
    'user' => $user,
    'current_language' => Translator::getCurrentLanguage(),
    'languages' => Translator::getSupportedLanguages(),
    'current_uri' => $_SERVER['REQUEST_URI'] ?? '/dashboard',
    't' => function($key, $params = []) {
        return Translator::t($key, $params);
    }
]);

// Helper function for redirects
function redirect(string $to): void {
    header('Location: ' . $to);
    exit;
}

// Helper function to require authentication
function requireAuth(): void {
    if (!Auth::check()) {
        redirect('/login');
    }
}

// Helper function to require admin
function requireAdmin(): void {
    requireAuth();
    if (!Auth::isAdmin()) {
        http_response_code(403);
        echo 'Forbidden: Admin access required';
        exit;
    }
}

// Helper function to get authenticated user (JWT or session)
function getAuthUser(): ?array {
    // Try JWT first
    $token = JWT::getTokenFromHeader();
    if ($token !== null) {
        $user = JWT::verify($token);
        if ($user !== null) {
            return $user;
        }
    }
    
    // Fall back to session
    if (Auth::check()) {
        return Auth::user();
    }
    
    return null;
}

// Helper function to require authentication (JWT or session) for API
function requireApiAuth(): ?array {
    $user = getAuthUser();
    
    if ($user === null) {
        http_response_code(401);
        header('Content-Type: application/json');
        echo json_encode(['error' => 'Authentication required']);
        return null;
    }
    
    return $user;
}

/**
 * PUBLIC ROUTES
 */

// Home page
Router::get('/', function () {
    if (!Auth::check()) {
        redirect('/login');
    }
    redirect('/dashboard');
});

// Login page
Router::get('/login', function () {
    if (Auth::check()) {
        redirect('/dashboard');
    }
    View::render('login.twig');
});

Router::post('/login', function () {
    $email = trim($_POST['email'] ?? '');
    $password = $_POST['password'] ?? '';
    
    if (Auth::login($email, $password)) {
        redirect('/dashboard');
    }
    
    View::render('login.twig', ['error' => 'Invalid credentials']);
});

// Register page
Router::get('/register', function () {
    if (Auth::check()) {
        redirect('/dashboard');
    }
    View::render('register.twig');
});

Router::post('/register', function () {
    $name = trim($_POST['name'] ?? '');
    $email = trim($_POST['email'] ?? '');
    $password = $_POST['password'] ?? '';
    
    if (!filter_var($email, FILTER_VALIDATE_EMAIL)) {
        View::render('register.twig', ['error' => 'Invalid email address']);
        return;
    }
    
    if (strlen($password) < 6) {
        View::render('register.twig', ['error' => 'Password must be at least 6 characters']);
        return;
    }
    
    try {
        $success = Auth::register($name, $email, $password);
        if ($success) {
            Auth::login($email, $password);
            redirect('/dashboard');
        }
    } catch (Throwable $e) {
        // Email already exists or other error
    }
    
    View::render('register.twig', ['error' => 'Registration failed. Email may already be in use.']);
});

// Logout
Router::get('/logout', function () {
    Auth::logout();
    redirect('/login');
});

/**
 * AUTHENTICATED ROUTES
 */

// Dashboard
Router::get('/dashboard', function () {
    requireAuth();
    $user = Auth::user();
    
    // Get user's servers
    $servers = VpnServer::listByUser($user['id']);
    
    // Get user's clients
    $clients = VpnClient::listByUser($user['id']);
    
    View::render('dashboard.twig', [
        'servers' => $servers,
        'clients' => $clients,
    ]);
});

// Servers list
Router::get('/servers', function () {
    requireAuth();
    $user = Auth::user();
    
    $servers = Auth::isAdmin() 
        ? VpnServer::listAll() 
        : VpnServer::listByUser($user['id']);
    
    View::render('servers/index.twig', ['servers' => $servers]);
});

// Create server page
Router::get('/servers/create', function () {
    requireAuth();
    View::render('servers/create.twig');
});

// Create server action
Router::post('/servers/create', function () {
    requireAuth();
    $user = Auth::user();
    
    $serverMode = trim($_POST['server_mode'] ?? 'deploy');
    $name = trim($_POST['name'] ?? '');
    $host = trim($_POST['host'] ?? '');
    $port = (int)($_POST['port'] ?? 22);
    $username = trim($_POST['username'] ?? 'root');
    $password = $_POST['password'] ?? '';
    
    if (empty($name) || empty($host) || empty($password)) {
        View::render('servers/create.twig', ['error' => 'All fields are required']);
        return;
    }
    
    try {
        $serverId = VpnServer::create([
            'user_id' => $user['id'],
            'name' => $name,
            'host' => $host,
            'port' => $port,
            'username' => $username,
            'password' => $password,
        ]);

        if ($serverMode === 'attach') {
            $attachScript = __DIR__ . '/../bin/attach_existing_server.php';
            $attachOutput = runPhpScript($attachScript, [(string)((int)$serverId)]);

            if (strpos($attachOutput, 'ATTACH_OK') !== false) {
                $_SESSION['success_message'] = 'Server attached successfully. Existing VPN configuration is now monitored by panel.';
                redirect('/servers/' . $serverId);
                return;
            }

            $errorText = $attachOutput !== '' ? substr($attachOutput, 0, 1000) : 'Unknown attach error';
            DB::conn()->prepare('UPDATE vpn_servers SET status = ?, error_message = ? WHERE id = ?')
                ->execute(['error', 'Attach failed: ' . $errorText, $serverId]);

            View::render('servers/create.twig', [
                'error' => 'Failed to attach existing server: ' . $errorText,
            ]);
            return;
        }
        
        // Handle import if enabled
        if (!empty($_POST['enable_import']) && !empty($_POST['panel_type']) && isset($_FILES['backup_file'])) {
            $panelType = $_POST['panel_type'];
            
            if (in_array($panelType, ['wg-easy', '3x-ui']) && $_FILES['backup_file']['error'] === UPLOAD_ERR_OK) {
                // Store import info in session for processing after deployment
                $_SESSION['pending_import'] = [
                    'server_id' => $serverId,
                    'panel_type' => $panelType,
                    'backup_file' => $_FILES['backup_file']['tmp_name'],
                    'backup_name' => $_FILES['backup_file']['name']
                ];
            }
        }
        
        redirect('/servers/' . $serverId . '/deploy');
    } catch (Exception $e) {
        View::render('servers/create.twig', ['error' => $e->getMessage()]);
    }
});

// Switch active container — instant from cached config, no SSH
Router::post('/servers/{id}/switch-container', function ($params) {
    requireAuth();
    requireValidCsrfToken();
    $user = Auth::user();
    $serverId = (int)$params['id'];

    try {
        $server = new VpnServer($serverId);
        $serverData = $server->getData();

        if ($serverData['user_id'] != $user['id'] && !Auth::isAdmin()) {
            http_response_code(403);
            echo 'Forbidden';
            return;
        }

        $requestedContainer = trim($_POST['container'] ?? '');
        if ($requestedContainer === '' || !preg_match('/^[a-zA-Z0-9][a-zA-Z0-9_.-]*$/', $requestedContainer)) {
            $_SESSION['error_message'] = 'Invalid container name.';
            redirect('/servers/' . $serverId);
            return;
        }

        if ($requestedContainer === ($serverData['container_name'] ?? '')) {
            redirect('/servers/' . $serverId);
            return;
        }

        // Read cached container configs from awg_params
        $awgParams = [];
        if (!empty($serverData['awg_params'])) {
            $awgParams = is_array($serverData['awg_params'])
                ? $serverData['awg_params']
                : (json_decode($serverData['awg_params'], true) ?: []);
        }

        $cachedContainers = $awgParams['containers'] ?? [];
        $targetConfig = $cachedContainers[$requestedContainer] ?? null;

        if ($targetConfig === null) {
            $_SESSION['error_message'] = 'Container "' . htmlspecialchars($requestedContainer) . '" config not cached. Run re-attach first.';
            redirect('/servers/' . $serverId);
            return;
        }

        // Update top-level awg_params with target container's params
        $newAwg = [];
        foreach ($targetConfig as $k => $v) {
            if (!in_array($k, ['server_public_key', 'preshared_key', 'listen_port'], true) && !is_array($v)) {
                $newAwg[$k] = $v;
            }
        }
        // Preserve cached containers and metadata
        $newAwg['containers'] = $cachedContainers;
        if (isset($awgParams['installed_protocols'])) {
            $newAwg['installed_protocols'] = $awgParams['installed_protocols'];
        }
        if (isset($awgParams['installed_containers'])) {
            $newAwg['installed_containers'] = $awgParams['installed_containers'];
        }

        $vpnPort = $targetConfig['vpn_port'] ?? $serverData['vpn_port'];
        $vpnSubnet = $targetConfig['vpn_subnet'] ?? $serverData['vpn_subnet'];
        $publicKey = $targetConfig['server_public_key'] ?? $serverData['server_public_key'];
        $presharedKey = $targetConfig['preshared_key'] ?? $serverData['preshared_key'];

        $pdo = DB::conn();
        $pdo->prepare('UPDATE vpn_servers SET container_name = ?, vpn_port = ?, vpn_subnet = ?, server_public_key = ?, preshared_key = ?, awg_params = ? WHERE id = ?')
            ->execute([
                $requestedContainer,
                $vpnPort,
                $vpnSubnet,
                $publicKey ?: null,
                $presharedKey ?: null,
                json_encode($newAwg, JSON_UNESCAPED_UNICODE),
                $serverId,
            ]);

        $_SESSION['success_message'] = 'Switched to ' . htmlspecialchars($requestedContainer) . ' (instant, from cache).';
        redirect('/servers/' . $serverId);
    } catch (Exception $e) {
        $_SESSION['error_message'] = 'Switch failed: ' . $e->getMessage();
        redirect('/servers/' . $serverId);
    }
});

// Re-attach: re-read server config and update parameters
Router::post('/servers/{id}/reattach', function ($params) {
    requireAuth();
    requireValidCsrfToken();
    $user = Auth::user();
    $serverId = (int)$params['id'];

    try {
        $server = new VpnServer($serverId);
        $serverData = $server->getData();

        if ($serverData['user_id'] != $user['id'] && !Auth::isAdmin()) {
            http_response_code(403);
            echo 'Forbidden';
            return;
        }

        // If user selected a different container, update it before re-attach
        $requestedContainer = trim($_POST['container'] ?? '');
        if ($requestedContainer !== '' && preg_match('/^[a-zA-Z0-9][a-zA-Z0-9_.-]*$/', $requestedContainer)) {
            if ($requestedContainer !== ($serverData['container_name'] ?? '')) {
                $pdo = DB::conn();
                $pdo->prepare('UPDATE vpn_servers SET container_name = ? WHERE id = ?')
                    ->execute([$requestedContainer, $serverId]);
            }
        }

        $attachScript = __DIR__ . '/../bin/attach_existing_server.php';
        $attachOutput = runPhpScript($attachScript, [(string)$serverId]);

        if (strpos($attachOutput, 'ATTACH_OK') !== false) {
            $_SESSION['success_message'] = 'Server re-attached successfully. Configuration re-read from remote server.';
            // Show attach output details in session for debugging
            $_SESSION['reattach_output'] = $attachOutput;
        } else {
            $errorText = $attachOutput !== '' ? substr($attachOutput, 0, 1000) : 'Unknown re-attach error';
            $_SESSION['error_message'] = 'Re-attach failed: ' . $errorText;
        }

        redirect('/servers/' . $serverId);
    } catch (Exception $e) {
        $_SESSION['error_message'] = 'Re-attach failed: ' . $e->getMessage();
        redirect('/servers/' . $serverId);
    }
});

// Detach server from panel monitoring (without deleting remote VPN server)
Router::post('/servers/{id}/detach', function ($params) {
    requireAuth();
    requireValidCsrfToken();
    $user = Auth::user();
    $serverId = (int)$params['id'];

    try {
        $server = new VpnServer($serverId);
        $serverData = $server->getData();

        // Check ownership or admin
        if ($serverData['user_id'] != $user['id'] && !Auth::isAdmin()) {
            http_response_code(403);
            echo 'Forbidden';
            return;
        }

        $detachScript = __DIR__ . '/../bin/detach_server.php';
        $detachOutput = runPhpScript($detachScript, [(string)$serverId, '--delete-clients']);

        if (strpos($detachOutput, 'DETACH_OK') !== false) {
            $deletedClients = 0;
            if (preg_match('/deleted_clients=(\d+)/', $detachOutput, $m)) {
                $deletedClients = (int)$m[1];
            }
            $_SESSION['success_message'] = 'Server detached from panel monitoring. Remote VPN server was NOT deleted. Local panel clients removed: ' . $deletedClients . '.';
        } else {
            $errorText = $detachOutput !== '' ? substr($detachOutput, 0, 1000) : 'Unknown detach error';
            $_SESSION['error_message'] = 'Failed to detach server: ' . $errorText;
        }

        redirect('/servers');
    } catch (Exception $e) {
        $_SESSION['error_message'] = 'Detach failed: ' . $e->getMessage();
        redirect('/servers');
    }
});

// Delete server action
Router::post('/servers/{id}/delete', function ($params) {
    requireAuth();
    requireValidCsrfToken();
    $user = Auth::user();
    $serverId = (int)$params['id'];
    
    try {
        $server = new VpnServer($serverId);
        $serverData = $server->getData();
        
        // Check ownership or admin
        if ($serverData['user_id'] != $user['id'] && !Auth::isAdmin()) {
            http_response_code(403);
            echo 'Forbidden';
            return;
        }
        
        $server->delete();
        $_SESSION['success_message'] = 'Server deleted successfully';
        redirect('/servers');
    } catch (Exception $e) {
        $_SESSION['error_message'] = $e->getMessage();
        redirect('/servers');
    }
});

// Deploy server page
Router::get('/servers/{id}/deploy', function ($params) {
    requireAuth();
    $serverId = (int)$params['id'];
    
    try {
        $server = new VpnServer($serverId);
        $serverData = $server->getData();
        
        // Check ownership
        $user = Auth::user();
        if ($serverData['user_id'] != $user['id'] && !Auth::isAdmin()) {
            http_response_code(403);
            echo 'Forbidden';
            return;
        }
        
        View::render('servers/deploy.twig', ['server' => $serverData]);
    } catch (Exception $e) {
        http_response_code(404);
        echo 'Server not found';
    }
});

// Deploy server action (AJAX)
Router::post('/servers/{id}/deploy', function ($params) {
    requireAuth();
    header('Content-Type: application/json');
    
    $serverId = (int)$params['id'];
    
    try {
        $server = new VpnServer($serverId);
        $serverData = $server->getData();
        
        // Check ownership
        $user = Auth::user();
        if ($serverData['user_id'] != $user['id'] && !Auth::isAdmin()) {
            http_response_code(403);
            echo json_encode(['error' => 'Forbidden']);
            return;
        }
        
        $result = $server->deploy();
        echo json_encode($result);
    } catch (Exception $e) {
        http_response_code(500);
        echo json_encode(['error' => $e->getMessage()]);
    }
});

// View server
Router::get('/servers/{id}', function ($params) {
    requireAuth();
    $serverId = (int)$params['id'];
    
    try {
        $server = new VpnServer($serverId);
        $serverData = $server->getData();
        $serverProtocolCode = detectServerProtocol($serverData);
        $serverProtocolLabel = formatProtocolLabel($serverProtocolCode);
        $serverProtocolBadgeClass = protocolBadgeClass($serverProtocolCode);
        
        // Check ownership
        $user = Auth::user();
        if ($serverData['user_id'] != $user['id'] && !Auth::isAdmin()) {
            http_response_code(403);
            echo 'Forbidden';
            return;
        }
        
        $displayTimezone = new DateTimeZone(Config::get('APP_TIMEZONE', 'UTC'));
        $normalizeClientHandshakeTime = function (array $rows) use ($displayTimezone, $serverProtocolCode): array {
            foreach ($rows as &$client) {
                $client['last_handshake_local'] = null;
                $clientProtocolCode = inferClientProtocolCode($client, $serverProtocolCode);
                $client['peer_protocol_code'] = $clientProtocolCode;
                $client['peer_protocol_label'] = formatProtocolLabel($clientProtocolCode);
                $client['peer_protocol_badge_class'] = protocolBadgeClass($clientProtocolCode);

                if (empty($client['last_handshake']) || $client['last_handshake'] === '0000-00-00 00:00:00') {
                    continue;
                }

                try {
                    $utc = new DateTimeImmutable($client['last_handshake'], new DateTimeZone('UTC'));
                    $client['last_handshake_local'] = $utc->setTimezone($displayTimezone)->format('Y-m-d H:i:s');
                } catch (Exception $e) {
                    $client['last_handshake_local'] = null;
                }
            }

            return $rows;
        };

        // Get clients for this server
        $clients = $normalizeClientHandshakeTime(VpnClient::listByServer($serverId));
        
        // Check for pending import
        $importMessage = null;
        if (!empty($_SESSION['pending_import']) && $_SESSION['pending_import']['server_id'] == $serverId) {
            $pendingImport = $_SESSION['pending_import'];
            
            // Only process import if server is active
            if ($serverData['status'] === 'active') {
                try {
                    $backupContent = file_get_contents($pendingImport['backup_file']);
                    
                    $importer = new PanelImporter($serverId, $user['id'], $pendingImport['panel_type']);
                    $importer->parseBackupFile($backupContent);
                    $result = $importer->import();
                    
                    if ($result['success']) {
                        $importMessage = [
                            'type' => 'success',
                            'text' => "Successfully imported {$result['imported_count']} clients"
                        ];
                    }
                    
                    // Clean up
                    @unlink($pendingImport['backup_file']);
                    unset($_SESSION['pending_import']);
                    
                } catch (Exception $e) {
                    $importMessage = [
                        'type' => 'error',
                        'text' => 'Import failed: ' . $e->getMessage()
                    ];
                    unset($_SESSION['pending_import']);
                }
                
                // Refresh clients list after import
                $clients = $normalizeClientHandshakeTime(VpnClient::listByServer($serverId));
            }
        }
        
        $reattachOutput = null;
        if (!empty($_SESSION['reattach_output'])) {
            $reattachOutput = $_SESSION['reattach_output'];
            unset($_SESSION['reattach_output']);
        }

        // Decode awg_params for template display
        $awgParamsDecoded = [];
        if (!empty($serverData['awg_params'])) {
            $awgParamsDecoded = is_array($serverData['awg_params'])
                ? $serverData['awg_params']
                : (json_decode($serverData['awg_params'], true) ?: []);
        }

        // CONTRACT-2: Show only clients for the active container
        $activeContainer = $serverData['container_name'] ?? '';
        $clients = array_values(array_filter($clients, function ($c) use ($activeContainer) {
            return ($c['peer_protocol'] ?? '') === $activeContainer;
        }));

        View::render('servers/view.twig', [
            'server' => $serverData,
            'server_protocol_code' => $serverProtocolCode,
            'server_protocol_label' => $serverProtocolLabel,
            'server_protocol_badge_class' => $serverProtocolBadgeClass,
            'clients' => $clients,
            'import_message' => $importMessage,
            'reattach_output' => $reattachOutput,
            'awg_params' => $awgParamsDecoded,
        ]);
    } catch (Exception $e) {
        error_log('Server view error: ' . $e->getMessage() . ' at ' . $e->getFile() . ':' . $e->getLine());
        http_response_code(404);
        echo 'Server not found: ' . htmlspecialchars($e->getMessage());
    }
});

// Server monitoring page
Router::get('/servers/{id}/monitoring', function ($params) {
    requireAuth();
    $serverId = (int)$params['id'];
    
    try {
        $server = new VpnServer($serverId);
        $serverData = $server->getData();
        
        // Check ownership
        $user = Auth::user();
        if ($serverData['user_id'] != $user['id'] && !Auth::isAdmin()) {
            http_response_code(403);
            echo 'Forbidden';
            return;
        }
        
        // Get clients for this server
        $clients = VpnClient::listByServer($serverId);
        
        View::render('servers/monitoring.twig', [
            'server' => $serverData,
            'clients' => $clients,
        ]);
    } catch (Exception $e) {
        http_response_code(404);
        echo 'Server not found';
    }
});

// Create client for server
Router::post('/servers/{id}/clients/create', function ($params) {
    requireAuth();
    $serverId = (int)$params['id'];
    $clientName = trim($_POST['name'] ?? '');
    
    // Handle expiration: either from dropdown (days) or custom input (seconds)
    $expiresInDays = null;
    if (!empty($_POST['expires_in_seconds'])) {
        // Convert seconds to days (round up)
        $expiresInDays = (int)ceil((int)$_POST['expires_in_seconds'] / 86400);
    } elseif (!empty($_POST['expires_in_days']) && $_POST['expires_in_days'] !== 'custom') {
        $expiresInDays = (int)$_POST['expires_in_days'];
    }
    
    // Handle traffic limit: either from dropdown (GB) or custom input (MB)
    $trafficLimitBytes = null;
    if (!empty($_POST['traffic_limit_mb'])) {
        // Convert MB to bytes
        $trafficLimitBytes = (int)((float)$_POST['traffic_limit_mb'] * 1048576);
    } elseif (!empty($_POST['traffic_limit_gb']) && $_POST['traffic_limit_gb'] !== 'custom') {
        // Convert GB to bytes
        $trafficLimitBytes = (int)((float)$_POST['traffic_limit_gb'] * 1073741824);
    }
    
    if (empty($clientName)) {
        redirect('/servers/' . $serverId . '?error=Client+name+is+required');
        return;
    }
    
    try {
        $server = new VpnServer($serverId);
        $serverData = $server->getData();
        
        // Check ownership
        $user = Auth::user();
        if ($serverData['user_id'] != $user['id'] && !Auth::isAdmin()) {
            http_response_code(403);
            echo 'Forbidden';
            return;
        }
        
        $clientId = VpnClient::create($serverId, $user['id'], $clientName, $expiresInDays);
        
        // Set traffic limit if specified
        if ($trafficLimitBytes !== null && $trafficLimitBytes > 0) {
            $client = new VpnClient($clientId);
            $client->setTrafficLimit($trafficLimitBytes);
        }
        
        redirect('/clients/' . $clientId);
    } catch (Exception $e) {
        redirect('/servers/' . $serverId . '?error=' . urlencode($e->getMessage()));
    }
});

// View client
Router::get('/clients/{id}', function ($params) {
    requireAuth();
    $clientId = (int)$params['id'];
    
    try {
        $client = new VpnClient($clientId);
        $clientData = $client->getData();
        $server = new VpnServer((int)$clientData['server_id']);
        $serverData = $server->getData();
        $defaultProtocolCode = detectServerProtocol($serverData);
        $peerProtocolCode = inferClientProtocolCode($clientData, $defaultProtocolCode);
        $peerProtocolLabel = formatProtocolLabel($peerProtocolCode);
        $peerProtocolBadgeClass = protocolBadgeClass($peerProtocolCode);
        
        // Check ownership
        $user = Auth::user();
        if ($clientData['user_id'] != $user['id'] && !Auth::isAdmin()) {
            http_response_code(403);
            echo 'Forbidden';
            return;
        }
        
        View::render('clients/view.twig', [
            'client' => $clientData,
            'peer_protocol_code' => $peerProtocolCode,
            'peer_protocol_label' => $peerProtocolLabel,
            'peer_protocol_badge_class' => $peerProtocolBadgeClass,
        ]);
    } catch (Exception $e) {
        http_response_code(404);
        echo 'Client not found';
    }
});

// Download client config
Router::get('/clients/{id}/download', function ($params) {
    requireAuth();
    $clientId = (int)$params['id'];
    
    try {
        $client = new VpnClient($clientId);
        $clientData = $client->getData();
        
        // Check ownership
        $user = Auth::user();
        if ($clientData['user_id'] != $user['id'] && !Auth::isAdmin()) {
            http_response_code(403);
            echo 'Forbidden';
            return;
        }
        
        $config = $client->getConfig();
        
        // Check if name contains non-Latin characters
        $hasNonLatin = preg_match('/[^a-zA-Z0-9_-]/', $clientData['name']);
        if ($hasNonLatin) {
            // Use user_(client_id)_s(server_id).conf format for non-Latin names
            $filename = 'user_' . $clientData['id'] . '_s' . $clientData['server_id'] . '.conf';
        } else {
            // Use client name for Latin characters
            $filename = $clientData['name'] . '.conf';
        }
        
        header('Content-Type: application/octet-stream');
        header('Content-Disposition: attachment; filename="' . $filename . '"');
        header('Content-Length: ' . strlen($config));
        echo $config;
    } catch (Exception $e) {
        http_response_code(404);
        echo 'Client not found';
    }
});

// Revoke client access
Router::post('/clients/{id}/revoke', function ($params) {
    requireAuth();
    $clientId = (int)$params['id'];
    
    try {
        $client = new VpnClient($clientId);
        $clientData = $client->getData();
        
        // Check ownership
        $user = Auth::user();
        if ($clientData['user_id'] != $user['id'] && !Auth::isAdmin()) {
            http_response_code(403);
            echo 'Forbidden';
            return;
        }
        
        if ($client->revoke()) {
            redirect('/servers/' . $clientData['server_id'] . '?success=Client+revoked');
        } else {
            redirect('/servers/' . $clientData['server_id'] . '?error=Failed+to+revoke+client');
        }
    } catch (Exception $e) {
        redirect('/dashboard?error=' . urlencode($e->getMessage()));
    }
});

// Restore client access
Router::post('/clients/{id}/restore', function ($params) {
    requireAuth();
    $clientId = (int)$params['id'];
    
    try {
        $client = new VpnClient($clientId);
        $clientData = $client->getData();
        
        // Check ownership
        $user = Auth::user();
        if ($clientData['user_id'] != $user['id'] && !Auth::isAdmin()) {
            http_response_code(403);
            echo 'Forbidden';
            return;
        }
        
        if ($client->restore()) {
            redirect('/servers/' . $clientData['server_id'] . '?success=Client+restored');
        } else {
            redirect('/servers/' . $clientData['server_id'] . '?error=Failed+to+restore+client');
        }
    } catch (Exception $e) {
        redirect('/dashboard?error=' . urlencode($e->getMessage()));
    }
});

// Delete client
Router::post('/clients/{id}/delete', function ($params) {
    requireAuth();
    $clientId = (int)$params['id'];
    
    try {
        $client = new VpnClient($clientId);
        $clientData = $client->getData();
        
        // Check ownership
        $user = Auth::user();
        if ($clientData['user_id'] != $user['id'] && !Auth::isAdmin()) {
            http_response_code(403);
            echo 'Forbidden';
            return;
        }
        
        $serverId = $clientData['server_id'];
        
        if ($client->delete()) {
            redirect('/servers/' . $serverId . '?success=Client+deleted');
        } else {
            redirect('/servers/' . $serverId . '?error=Failed+to+delete+client');
        }
    } catch (Exception $e) {
        redirect('/dashboard?error=' . urlencode($e->getMessage()));
    }
});

// Sync client stats
Router::post('/clients/{id}/sync-stats', function ($params) {
    requireAuth();
    $clientId = (int)$params['id'];
    
    header('Content-Type: application/json');
    
    try {
        $client = new VpnClient($clientId);
        $clientData = $client->getData();
        
        // Check ownership
        $user = Auth::user();
        if ($clientData['user_id'] != $user['id'] && !Auth::isAdmin()) {
            http_response_code(403);
            echo json_encode(['error' => 'Forbidden']);
            return;
        }
        
        if ($client->syncStats()) {
            // Reload client data
            $client = new VpnClient($clientId);
            $stats = $client->getFormattedStats();
            echo json_encode(['success' => true, 'stats' => $stats]);
        } else {
            echo json_encode(['success' => false, 'error' => 'Failed to sync stats']);
        }
    } catch (Exception $e) {
        http_response_code(500);
        echo json_encode(['error' => $e->getMessage()]);
    }
});

// Sync all stats for server
Router::post('/servers/{id}/sync-stats', function ($params) {
    requireAuth();
    $serverId = (int)$params['id'];
    
    header('Content-Type: application/json');
    
    try {
        $server = new VpnServer($serverId);
        $serverData = $server->getData();
        
        // Check ownership
        $user = Auth::user();
        if ($serverData['user_id'] != $user['id'] && !Auth::isAdmin()) {
            http_response_code(403);
            echo json_encode(['error' => 'Forbidden']);
            return;
        }
        
        $synced = VpnClient::syncAllStatsForServer($serverId);
        echo json_encode(['success' => true, 'synced' => $synced]);
    } catch (Exception $e) {
        http_response_code(500);
        echo json_encode(['error' => $e->getMessage()]);
    }
});

/**
 * API ROUTES (for Telegram bot integration)
 */

// API: Generate JWT token
Router::post('/api/auth/token', function () {
    header('Content-Type: application/json');
    
    $email = $_POST['email'] ?? '';
    $password = $_POST['password'] ?? '';
    
    if (empty($email) || empty($password)) {
        http_response_code(400);
        echo json_encode(['error' => 'Email and password are required']);
        return;
    }
    
    $user = Auth::getUserByEmail($email);
    if (!$user || !password_verify($password, $user['password_hash'])) {
        http_response_code(401);
        echo json_encode(['error' => 'Invalid credentials']);
        return;
    }
    
    try {
        $token = JWT::generate($user['id']);
        echo json_encode([
            'success' => true,
            'token' => $token,
            'type' => 'Bearer',
            'expires_in' => 30 * 24 * 3600 // 30 days
        ]);
    } catch (Exception $e) {
        http_response_code(500);
        echo json_encode(['error' => 'Token generation failed']);
    }
});

// API: Create persistent API token
Router::post('/api/tokens', function () {
    header('Content-Type: application/json');
    
    $user = JWT::requireAuth();
    if (!$user) return;
    
    $name = $_POST['name'] ?? 'API Token';
    $expiresIn = isset($_POST['expires_in']) ? (int)$_POST['expires_in'] : 2592000; // 30 days default
    
    try {
        $tokenData = JWT::createApiToken($user['id'], $name, $expiresIn);
        echo json_encode([
            'success' => true,
            'token' => $tokenData
        ]);
    } catch (Exception $e) {
        http_response_code(500);
        echo json_encode(['error' => $e->getMessage()]);
    }
});

// API: List user's API tokens
Router::get('/api/tokens', function () {
    header('Content-Type: application/json');
    
    $user = JWT::requireAuth();
    if (!$user) return;
    
    $stmt = DB::get()->prepare("
        SELECT id, name, token, expires_at, created_at, last_used_at
        FROM api_tokens
        WHERE user_id = ? AND revoked_at IS NULL
        ORDER BY created_at DESC
    ");
    $stmt->execute([$user['id']]);
    $tokens = $stmt->fetchAll();
    
    // Don't expose full token in list
    foreach ($tokens as &$token) {
        $token['token'] = substr($token['token'], 0, 10) . '...';
    }
    
    echo json_encode(['tokens' => $tokens]);
});

// API: Revoke API token
Router::delete('/api/tokens/{id}', function ($params) {
    header('Content-Type: application/json');
    
    $user = JWT::requireAuth();
    if (!$user) return;
    
    try {
        JWT::revokeApiToken($params['id'], $user['id']);
        echo json_encode(['success' => true]);
    } catch (Exception $e) {
        http_response_code(404);
        echo json_encode(['error' => $e->getMessage()]);
    }
});

// API: List servers
Router::get('/api/servers', function () {
    header('Content-Type: application/json');
    
    $user = JWT::requireAuth();
    if (!$user) return;
    
    $servers = VpnServer::listByUser($user['id']);
    echo json_encode(['servers' => $servers]);
});

// API: Create server
Router::post('/api/servers/create', function () {
    header('Content-Type: application/json');
    
    $user = JWT::requireAuth();
    if (!$user) return;
    
    $input = json_decode(file_get_contents('php://input'), true);
    
    $name = trim($input['name'] ?? '');
    $host = trim($input['host'] ?? '');
    $port = (int)($input['port'] ?? 22);
    $username = trim($input['username'] ?? 'root');
    $password = $input['password'] ?? '';
    
    if (empty($name) || empty($host) || empty($password)) {
        http_response_code(400);
        echo json_encode(['error' => 'Missing required fields: name, host, password']);
        return;
    }
    
    try {
        $serverId = VpnServer::create([
            'user_id' => $user['id'],
            'name' => $name,
            'host' => $host,
            'port' => $port,
            'username' => $username,
            'password' => $password,
        ]);
        
        http_response_code(201);
        echo json_encode([
            'success' => true,
            'server_id' => $serverId,
            'message' => 'Server created successfully'
        ]);
    } catch (Exception $e) {
        http_response_code(500);
        echo json_encode(['error' => $e->getMessage()]);
    }
});

// API: Delete server
Router::delete('/api/servers/{id}/delete', function ($params) {
    header('Content-Type: application/json');
    
    $user = JWT::requireAuth();

// API: Import from existing panel
Router::post('/api/servers/{id}/import', function ($params) {
    header('Content-Type: application/json');
    
    $user = JWT::requireAuth();
    if (!$user) return;
    
    $serverId = (int)$params['id'];
    
    // Validate server ownership
    $server = VpnServer::getById($serverId);
    if (!$server || $server['user_id'] != $user['id']) {
        http_response_code(404);
        echo json_encode(['error' => 'Server not found']);
        return;
    }
    
    $panelType = $_POST['panel_type'] ?? '';
    
    if (!in_array($panelType, ['wg-easy', '3x-ui'])) {
        http_response_code(400);
        echo json_encode(['error' => 'Invalid panel type. Supported: wg-easy, 3x-ui']);
        return;
    }
    
    // Handle file upload
    if (!isset($_FILES['backup_file']) || $_FILES['backup_file']['error'] !== UPLOAD_ERR_OK) {
        http_response_code(400);
        echo json_encode(['error' => 'No backup file uploaded']);
        return;
    }
    
    $backupContent = file_get_contents($_FILES['backup_file']['tmp_name']);
    
    try {
        $importer = new PanelImporter($serverId, $user['id'], $panelType);
        
        if (!$importer->parseBackupFile($backupContent)) {
            http_response_code(400);
            echo json_encode(['error' => 'Invalid backup file format']);
            return;
        }
        
        $result = $importer->import();
        
        echo json_encode($result);
        
    } catch (Exception $e) {
        http_response_code(500);
        echo json_encode([
            'success' => false,
            'error' => $e->getMessage()
        ]);
    }
});

// API: Get import history
Router::get('/api/servers/{id}/imports', function ($params) {
    header('Content-Type: application/json');
    
    $user = JWT::requireAuth();
    if (!$user) return;
    
    $serverId = (int)$params['id'];
    
    // Validate server ownership
    $server = VpnServer::getById($serverId);
    if (!$server || $server['user_id'] != $user['id']) {
        http_response_code(404);
        echo json_encode(['error' => 'Server not found']);
        return;
    }
    
    $imports = PanelImporter::getImportHistory($serverId);
    
    echo json_encode([
        'success' => true,
        'imports' => $imports
    ]);
});
    if (!$user) return;
    
    $serverId = (int)$params['id'];
    
    try {
        $server = new VpnServer($serverId);
        $serverData = $server->getData();
        
        // Check ownership or admin
        if ($serverData['user_id'] != $user['id'] && $user['role'] !== 'admin') {
            http_response_code(403);
            echo json_encode(['error' => 'Forbidden']);
            return;
        }
        
        $server->delete();
        echo json_encode([
            'success' => true,
            'message' => 'Server deleted successfully'
        ]);
    } catch (Exception $e) {
        http_response_code(500);
        echo json_encode(['error' => $e->getMessage()]);
    }
});

// API: Create backup
Router::post('/api/servers/{id}/backup', function ($params) {
    header('Content-Type: application/json');
    
    $user = requireApiAuth();
    if (!$user) return;
    
    $serverId = (int)$params['id'];
    
    try {
        $server = new VpnServer($serverId);
        $serverData = $server->getData();
        
        // Check ownership or admin
        if ($serverData['user_id'] != $user['id'] && $user['role'] !== 'admin') {
            http_response_code(403);
            echo json_encode(['error' => 'Forbidden']);
            return;
        }
        
        $backupId = $server->createBackup($user['id'], 'manual');
        $backup = VpnServer::getBackup($backupId);
        
        echo json_encode([
            'success' => true,
            'backup' => $backup
        ]);
    } catch (Exception $e) {
        http_response_code(500);
        echo json_encode(['error' => $e->getMessage()]);
    }
});

// API: List backups
Router::get('/api/servers/{id}/backups', function ($params) {
    header('Content-Type: application/json');
    
    $user = requireApiAuth();
    if (!$user) return;
    
    $serverId = (int)$params['id'];
    
    try {
        $server = new VpnServer($serverId);
        $serverData = $server->getData();
        
        // Check ownership or admin
        if ($serverData['user_id'] != $user['id'] && $user['role'] !== 'admin') {
            http_response_code(403);
            echo json_encode(['error' => 'Forbidden']);
            return;
        }
        
        $backups = $server->listBackups();
        
        echo json_encode([
            'success' => true,
            'backups' => $backups,
            'count' => count($backups)
        ]);
    } catch (Exception $e) {
        http_response_code(500);
        echo json_encode(['error' => $e->getMessage()]);
    }
});

// API: Restore backup
Router::post('/api/servers/{id}/restore', function ($params) {
    header('Content-Type: application/json');
    
    $user = requireApiAuth();
    if (!$user) return;
    
    $serverId = (int)$params['id'];
    $raw = file_get_contents('php://input');
    $data = json_decode($raw, true);
    
    $backupId = (int)($data['backup_id'] ?? 0);
    
    if ($backupId <= 0) {
        http_response_code(400);
        echo json_encode(['error' => 'backup_id is required']);
        return;
    }
    
    try {
        $server = new VpnServer($serverId);
        $serverData = $server->getData();
        
        // Check ownership or admin
        if ($serverData['user_id'] != $user['id'] && $user['role'] !== 'admin') {
            http_response_code(403);
            echo json_encode(['error' => 'Forbidden']);
            return;
        }
        
        $result = $server->restoreBackup($backupId);
        
        // Log the result for debugging
        error_log('Restore backup result: ' . json_encode($result));
        
        // Always return the result, even if success is false
        echo json_encode($result);
    } catch (Exception $e) {
        error_log('Restore backup exception: ' . $e->getMessage());
        http_response_code(500);
        echo json_encode(['error' => $e->getMessage(), 'success' => false]);
    }
});

// API: Delete backup
Router::delete('/api/backups/{id}', function ($params) {
    header('Content-Type: application/json');
    
    $user = requireApiAuth();
    if (!$user) return;
    
    $backupId = (int)$params['id'];
    
    try {
        $backup = VpnServer::getBackup($backupId);
        
        if (!$backup) {
            http_response_code(404);
            echo json_encode(['error' => 'Backup not found']);
            return;
        }
        
        // Get server to check ownership
        $server = new VpnServer($backup['server_id']);
        $serverData = $server->getData();
        
        // Check ownership or admin
        if ($serverData['user_id'] != $user['id'] && $user['role'] !== 'admin') {
            http_response_code(403);
            echo json_encode(['error' => 'Forbidden']);
            return;
        }
        
        VpnServer::deleteBackup($backupId);
        
        echo json_encode([
            'success' => true,
            'message' => 'Backup deleted successfully'
        ]);
    } catch (Exception $e) {
        http_response_code(500);
        echo json_encode(['error' => $e->getMessage()]);
    }
});

// API: List clients
Router::get('/api/clients', function () {
    header('Content-Type: application/json');
    
    $user = JWT::requireAuth();
    if (!$user) return;
    
    $clients = VpnClient::listByUser($user['id']);
    echo json_encode(['clients' => $clients]);
});

// API: Get client details with stats
Router::get('/api/clients/{id}/details', function ($params) {
    header('Content-Type: application/json');
    
    $user = JWT::requireAuth();
    if (!$user) return;
    
    $clientId = (int)$params['id'];
    
    try {
        $client = new VpnClient($clientId);
        $clientData = $client->getData();
        
        // Check ownership
        if ($clientData['user_id'] != $user['id']) {
            http_response_code(403);
            echo json_encode(['error' => 'Forbidden']);
            return;
        }
        
        // Sync stats before returning
        $client->syncStats();
        
        // Reload data
        $client = new VpnClient($clientId);
        $clientData = $client->getData();
        $stats = $client->getFormattedStats();
        
        echo json_encode([
            'success' => true,
            'client' => [
                'id' => $clientData['id'],
                'name' => $clientData['name'],
                'server_id' => $clientData['server_id'],
                'client_ip' => $clientData['client_ip'],
                'status' => $clientData['status'],
                'created_at' => $clientData['created_at'],
                'stats' => $stats,
                'bytes_sent' => $clientData['bytes_sent'],
                'bytes_received' => $clientData['bytes_received'],
                'last_handshake' => $clientData['last_handshake'],
                'config' => $clientData['config'],
                'qr_code' => $clientData['qr_code'],
            ]
        ]);
    } catch (Exception $e) {
        http_response_code(404);
        echo json_encode(['error' => 'Client not found']);
    }
});

// API: Update client local metadata (name/description in panel DB only)
Router::post('/api/clients/{id}/metadata', function ($params) {
    header('Content-Type: application/json');

    $user = getAuthUser();
    if (!$user) {
        http_response_code(401);
        echo json_encode(['error' => 'Unauthorized']);
        return;
    }

    $clientId = (int)$params['id'];
    $raw = file_get_contents('php://input');
    $data = json_decode($raw, true) ?: [];

    $name = trim((string)($data['name'] ?? ''));
    $description = isset($data['description']) ? trim((string)$data['description']) : null;

    if ($name === '') {
        http_response_code(400);
        echo json_encode(['error' => 'Name is required']);
        return;
    }

    if (mb_strlen($name) > 255) {
        http_response_code(400);
        echo json_encode(['error' => 'Name is too long']);
        return;
    }

    if ($description !== null && mb_strlen($description) > 2000) {
        http_response_code(400);
        echo json_encode(['error' => 'Description is too long']);
        return;
    }

    if ($description === '') {
        $description = null;
    }

    try {
        $client = new VpnClient($clientId);
        $clientData = $client->getData();

        // Check ownership
        if ($clientData['user_id'] != $user['id'] && $user['role'] !== 'admin') {
            http_response_code(403);
            echo json_encode(['error' => 'Forbidden']);
            return;
        }

        $pdo = DB::conn();
        $stmt = $pdo->prepare('UPDATE vpn_clients SET name = ?, description = ? WHERE id = ?');
        $stmt->execute([$name, $description, $clientId]);

        echo json_encode([
            'success' => true,
            'name' => $name,
            'description' => $description
        ]);
    } catch (Exception $e) {
        http_response_code(500);
        echo json_encode(['error' => $e->getMessage()]);
    }
});

// API: Get client QR code
Router::get('/api/clients/{id}/qr', function ($params) {
    header('Content-Type: application/json');
    
    $user = JWT::requireAuth();
    if (!$user) return;
    
    $clientId = (int)$params['id'];
    
    try {
        $client = new VpnClient($clientId);
        $clientData = $client->getData();
        
        // Check ownership
        if ($clientData['user_id'] != $user['id']) {
            http_response_code(403);
            echo json_encode(['error' => 'Forbidden']);
            return;
        }
        
        echo json_encode([
            'success' => true,
            'qr_code' => $clientData['qr_code'],
            'client_name' => $clientData['name']
        ]);
    } catch (Exception $e) {
        http_response_code(404);
        echo json_encode(['error' => 'Client not found']);
    }
});

// API: Revoke client
Router::post('/api/clients/{id}/revoke', function ($params) {
    header('Content-Type: application/json');
    
    $user = JWT::requireAuth();
    if (!$user) return;
    
    $clientId = (int)$params['id'];
    
    try {
        $client = new VpnClient($clientId);
        $clientData = $client->getData();
        
        // Check ownership
        if ($clientData['user_id'] != $user['id']) {
            http_response_code(403);
            echo json_encode(['error' => 'Forbidden']);
            return;
        }
        
        if ($client->revoke()) {
            echo json_encode(['success' => true, 'message' => 'Client revoked']);
        } else {
            http_response_code(500);
            echo json_encode(['error' => 'Failed to revoke client']);
        }
    } catch (Exception $e) {
        http_response_code(500);
        echo json_encode(['error' => $e->getMessage()]);
    }
});

// API: Restore client
Router::post('/api/clients/{id}/restore', function ($params) {
    header('Content-Type: application/json');
    
    $user = JWT::requireAuth();
    if (!$user) return;
    
    $clientId = (int)$params['id'];
    
    try {
        $client = new VpnClient($clientId);
        $clientData = $client->getData();
        
        // Check ownership
        if ($clientData['user_id'] != $user['id']) {
            http_response_code(403);
            echo json_encode(['error' => 'Forbidden']);
            return;
        }
        
        if ($client->restore()) {
            echo json_encode(['success' => true, 'message' => 'Client restored']);
        } else {
            http_response_code(500);
            echo json_encode(['error' => 'Failed to restore client']);
        }
    } catch (Exception $e) {
        http_response_code(500);
        echo json_encode(['error' => $e->getMessage()]);
    }
});

// API: Get server metrics
Router::get('/api/servers/{id}/metrics', function ($params) {
    header('Content-Type: application/json');
    
    // Check authentication - either JWT or session
    $user = null;
    $authHeader = $_SERVER['HTTP_AUTHORIZATION'] ?? '';
    
    if ($authHeader && preg_match('/Bearer\s+(.*)$/i', $authHeader, $matches)) {
        // JWT authentication
        $token = $matches[1];
        $user = JWT::verify($token);
    } else if (isset($_SESSION['user_id'])) {
        // Session authentication
        $user = Auth::user();
    }
    
    if (!$user) {
        http_response_code(401);
        echo json_encode(['error' => 'Unauthorized']);
        return;
    }
    
    $serverId = (int)$params['id'];
    $hours = isset($_GET['hours']) ? (float)$_GET['hours'] : 24;
    
    try {
        $server = new VpnServer($serverId);
        $serverData = $server->getData();
        
        // Check ownership
        if ($serverData['user_id'] != $user['id'] && $user['role'] !== 'admin') {
            http_response_code(403);
            echo json_encode(['error' => 'Forbidden']);
            return;
        }
        
        $metrics = ServerMonitoring::getServerMetrics($serverId, $hours);
        
        echo json_encode(['success' => true, 'metrics' => $metrics]);
    } catch (Exception $e) {
        http_response_code(500);
        echo json_encode(['error' => $e->getMessage()]);
    }
});

// API: Get client metrics
Router::get('/api/clients/{id}/metrics', function ($params) {
    header('Content-Type: application/json');
    
    // Check authentication - either JWT or session
    $user = null;
    $authHeader = $_SERVER['HTTP_AUTHORIZATION'] ?? '';
    
    if ($authHeader && preg_match('/Bearer\s+(.*)$/i', $authHeader, $matches)) {
        // JWT authentication
        $token = $matches[1];
        $user = JWT::verify($token);
    } else if (isset($_SESSION['user_id'])) {
        // Session authentication
        $user = Auth::user();
    }
    
    if (!$user) {
        http_response_code(401);
        echo json_encode(['error' => 'Unauthorized']);
        return;
    }
    
    $clientId = (int)$params['id'];
    $hours = isset($_GET['hours']) ? (float)$_GET['hours'] : 24;
    
    try {
        $client = new VpnClient($clientId);
        $clientData = $client->getData();
        
        // Get server to check ownership
        $server = new VpnServer($clientData['server_id']);
        $serverData = $server->getData();
        
        // Check ownership
        if ($serverData['user_id'] != $user['id'] && $user['role'] !== 'admin') {
            http_response_code(403);
            echo json_encode(['error' => 'Forbidden']);
            return;
        }
        
        $metrics = ServerMonitoring::getClientMetrics($clientId, $hours);
        
        echo json_encode(['success' => true, 'metrics' => $metrics]);
    } catch (Exception $e) {
        http_response_code(500);
        echo json_encode(['error' => $e->getMessage()]);
    }
});

// API: Get server clients
Router::get('/api/servers/{id}/clients', function ($params) {
    header('Content-Type: application/json');
    
    $user = authenticateRequest();
    if (!$user) {
        http_response_code(401);
        echo json_encode(['error' => 'Unauthorized']);
        return;
    }
    
    $serverId = (int)$params['id'];
    
    try {
        $server = new VpnServer($serverId);
        $serverData = $server->getData();
        
        // Check ownership
        if ($serverData['user_id'] != $user['id'] && $user['role'] !== 'admin') {
            http_response_code(403);
            echo json_encode(['error' => 'Forbidden']);
            return;
        }
        
        // Sync all stats first
        VpnClient::syncAllStatsForServer($serverId);
        
        $clients = VpnClient::listByServer($serverId);
        $clientsData = [];
        
        foreach ($clients as $clientData) {
            $client = new VpnClient($clientData['id']);
            $stats = $client->getFormattedStats();
            
            $clientsData[] = [
                'id' => $clientData['id'],
                'name' => $clientData['name'],
                'client_ip' => $clientData['client_ip'],
                'status' => $clientData['status'],
                'created_at' => $clientData['created_at'],
                'stats' => $stats,
                'bytes_sent' => $clientData['bytes_sent'],
                'bytes_received' => $clientData['bytes_received'],
                'last_handshake' => $clientData['last_handshake'],
            ];
        }
        
        echo json_encode(['success' => true, 'clients' => $clientsData]);
    } catch (Exception $e) {
        http_response_code(500);
        echo json_encode(['error' => $e->getMessage()]);
    }
});

// API: Create client
Router::post('/api/clients/create', function () {
    header('Content-Type: application/json');
    
    $user = JWT::requireAuth();
    if (!$user) return;
    
    $raw = file_get_contents('php://input');
    $data = json_decode($raw, true);
    
    $serverId = (int)($data['server_id'] ?? 0);
    $name = trim($data['name'] ?? '');
    $expiresInDays = isset($data['expires_in_days']) ? (int)$data['expires_in_days'] : null;
    
    if ($serverId <= 0 || empty($name)) {
        http_response_code(400);
        echo json_encode(['error' => 'server_id and name are required']);
        return;
    }
    
    try {
        $clientId = VpnClient::create($serverId, $user['id'], $name, $expiresInDays);
        
        $client = new VpnClient($clientId);
        $clientData = $client->getData();
        
        // Return client data with config and QR code
        echo json_encode([
            'success' => true,
            'client' => [
                'id' => $clientData['id'],
                'name' => $clientData['name'],
                'server_id' => $clientData['server_id'],
                'client_ip' => $clientData['client_ip'],
                'status' => $clientData['status'],
                'expires_at' => $clientData['expires_at'],
                'created_at' => $clientData['created_at'],
                'config' => $clientData['config'],
                'qr_code' => $clientData['qr_code'],
            ]
        ]);
    } catch (Exception $e) {
        http_response_code(500);
        echo json_encode(['error' => $e->getMessage()]);
    }
});

// Set client expiration
Router::post('/api/clients/{id}/set-expiration', function ($params) {
    header('Content-Type: application/json');
    
    $user = JWT::requireAuth();
    if (!$user) return;
    
    $clientId = (int)$params['id'];
    $raw = file_get_contents('php://input');
    $data = json_decode($raw, true);
    
    $expiresAt = $data['expires_at'] ?? null; // Y-m-d H:i:s format or null
    
    try {
        $client = new VpnClient($clientId);
        $clientData = $client->getData();
        
        // Check ownership
        if ($clientData['user_id'] != $user['id'] && $user['role'] !== 'admin') {
            http_response_code(403);
            echo json_encode(['error' => 'Forbidden']);
            return;
        }
        
        VpnClient::setExpiration($clientId, $expiresAt);
        
        echo json_encode([
            'success' => true,
            'expires_at' => $expiresAt
        ]);
    } catch (Exception $e) {
        http_response_code(500);
        echo json_encode(['error' => $e->getMessage()]);
    }
});

// Extend client expiration
Router::post('/api/clients/{id}/extend', function ($params) {
    header('Content-Type: application/json');
    
    $user = JWT::requireAuth();
    if (!$user) return;
    
    $clientId = (int)$params['id'];
    $raw = file_get_contents('php://input');
    $data = json_decode($raw, true);
    
    $days = (int)($data['days'] ?? 30);
    
    if ($days <= 0) {
        http_response_code(400);
        echo json_encode(['error' => 'days must be positive']);
        return;
    }
    
    try {
        $client = new VpnClient($clientId);
        $clientData = $client->getData();
        
        // Check ownership
        if ($clientData['user_id'] != $user['id'] && $user['role'] !== 'admin') {
            http_response_code(403);
            echo json_encode(['error' => 'Forbidden']);
            return;
        }
        
        VpnClient::extendExpiration($clientId, $days);
        
        // Get updated expiration
        $client = new VpnClient($clientId);
        $updated = $client->getData();
        
        echo json_encode([
            'success' => true,
            'expires_at' => $updated['expires_at'],
            'extended_days' => $days
        ]);
    } catch (Exception $e) {
        http_response_code(500);
        echo json_encode(['error' => $e->getMessage()]);
    }
});

// Get expiring clients
Router::get('/api/clients/expiring', function () {
    header('Content-Type: application/json');
    
    $user = JWT::requireAuth();
    if (!$user) return;
    
    $days = (int)($_GET['days'] ?? 7);
    
    try {
        $clients = VpnClient::getExpiringClients($days);
        
        // Filter by user if not admin
        if ($user['role'] !== 'admin') {
            $clients = array_filter($clients, function($c) use ($user) {
                return $c['user_id'] == $user['id'];
            });
        }
        
        echo json_encode([
            'success' => true,
            'clients' => array_values($clients),
            'count' => count($clients)
        ]);
    } catch (Exception $e) {
        http_response_code(500);
        echo json_encode(['error' => $e->getMessage()]);
    }
});

// Set client traffic limit
Router::post('/api/clients/{id}/set-traffic-limit', function ($params) {
    header('Content-Type: application/json');
    
    $user = JWT::requireAuth();
    if (!$user) return;
    
    $clientId = (int)$params['id'];
    $raw = file_get_contents('php://input');
    $data = json_decode($raw, true);
    
    // limit_bytes can be null (unlimited) or positive integer
    $limitBytes = isset($data['limit_bytes']) ? (int)$data['limit_bytes'] : null;
    
    if ($limitBytes !== null && $limitBytes < 0) {
        http_response_code(400);
        echo json_encode(['error' => 'limit_bytes must be positive or null for unlimited']);
        return;
    }
    
    try {
        $client = new VpnClient($clientId);
        $clientData = $client->getData();
        
        // Check ownership
        if ($clientData['user_id'] != $user['id'] && $user['role'] !== 'admin') {
            http_response_code(403);
            echo json_encode(['error' => 'Forbidden']);
            return;
        }
        
        $client->setTrafficLimit($limitBytes);
        
        echo json_encode([
            'success' => true,
            'limit_bytes' => $limitBytes,
            'limit_gb' => $limitBytes ? round($limitBytes / 1073741824, 2) : null
        ]);
    } catch (Exception $e) {
        http_response_code(500);
        echo json_encode(['error' => $e->getMessage()]);
    }
});

// Check client traffic limit status
Router::get('/api/clients/{id}/traffic-limit-status', function ($params) {
    header('Content-Type: application/json');
    
    $user = JWT::requireAuth();
    if (!$user) return;
    
    $clientId = (int)$params['id'];
    
    try {
        $client = new VpnClient($clientId);
        $clientData = $client->getData();
        
        // Check ownership
        if ($clientData['user_id'] != $user['id'] && $user['role'] !== 'admin') {
            http_response_code(403);
            echo json_encode(['error' => 'Forbidden']);
            return;
        }
        
        $status = $client->getTrafficLimitStatus();
        
        echo json_encode([
            'success' => true,
            'status' => $status
        ]);
    } catch (Exception $e) {
        http_response_code(500);
        echo json_encode(['error' => $e->getMessage()]);
    }
});

// Get clients over traffic limit
Router::get('/api/clients/overlimit', function () {
    header('Content-Type: application/json');
    
    $user = JWT::requireAuth();
    if (!$user) return;
    
    try {
        $clients = VpnClient::getClientsOverLimit();
        
        // Filter by user if not admin
        if ($user['role'] !== 'admin') {
            $clients = array_filter($clients, function($c) use ($user) {
                return $c['user_id'] == $user['id'];
            });
        }
        
        echo json_encode([
            'success' => true,
            'clients' => array_values($clients),
            'count' => count($clients)
        ]);
    } catch (Exception $e) {
        http_response_code(500);
        echo json_encode(['error' => $e->getMessage()]);
    }
});

/**
 * SETTINGS ROUTES
 */

// Settings page
Router::get('/settings', function () {
    requireAuth();
    
    require_once __DIR__ . '/../controllers/SettingsController.php';
    $controller = new SettingsController();
    $controller->index();
});

// Save API key
Router::post('/settings/api-key', function () {
    requireAdmin();
    
    require_once __DIR__ . '/../controllers/SettingsController.php';
    $controller = new SettingsController();
    $controller->saveApiKey();
});

// Change password
Router::post('/settings/change-password', function () {
    requireAuth();
    
    require_once __DIR__ . '/../controllers/SettingsController.php';
    $controller = new SettingsController();
    $controller->changePassword();
});

// Add user
Router::post('/settings/add-user', function () {
    requireAdmin();
    
    require_once __DIR__ . '/../controllers/SettingsController.php';
    $controller = new SettingsController();
    $controller->addUser();
});

// Delete user
Router::post('/settings/delete-user/{id}', function ($params) {
    requireAdmin();
    
    require_once __DIR__ . '/../controllers/SettingsController.php';
    $controller = new SettingsController();
    $controller->deleteUser($params['id']);
});

// LDAP settings page
Router::get('/settings/ldap', function () {
    requireAdmin();
    
    require_once __DIR__ . '/../controllers/SettingsController.php';
    require_once __DIR__ . '/../inc/LdapSync.php';
    $controller = new SettingsController();
    $controller->ldapSettings();
});

// Save LDAP settings
Router::post('/settings/ldap/save', function () {
    requireAdmin();
    
    require_once __DIR__ . '/../controllers/SettingsController.php';
    require_once __DIR__ . '/../inc/LdapSync.php';
    $controller = new SettingsController();
    $controller->saveLdapSettings();
});

// Test LDAP connection
Router::post('/settings/ldap/test', function () {
    requireAdmin();
    
    require_once __DIR__ . '/../controllers/SettingsController.php';
    require_once __DIR__ . '/../inc/LdapSync.php';
    $controller = new SettingsController();
    $controller->testLdapConnection();
});

Router::post('/settings/system', function () {
    requireAdmin();
    require_once __DIR__ . '/../controllers/SettingsController.php';
    $controller = new SettingsController();
    $controller->saveSystem();
});

/**
 * LANGUAGE ROUTES
 */

// Change language
Router::post('/language/change', function () {
    $lang = $_POST['language'] ?? '';
    
    if (Translator::setLanguage($lang)) {
        $_SESSION['success'] = 'Language changed successfully';
    } else {
        $_SESSION['error'] = 'Invalid language';
    }
    
    $redirect = $_POST['redirect'] ?? '/dashboard';
    redirect($redirect);
});

Router::get('/language/change', function () {
    redirect('/dashboard');
});

// API: Get translation statistics
Router::get('/api/translations/stats', function () {
    header('Content-Type: application/json');
    
    $user = JWT::requireAuth();
    if (!$user) return;
    
    $stats = Translator::getStatistics();
    echo json_encode(['stats' => $stats]);
});

// API: Auto-translate missing keys
Router::post('/api/translations/auto-translate', function () {
    header('Content-Type: application/json');
    
    $user = JWT::requireAuth();
    if (!$user) return;
    
    $raw = file_get_contents('php://input');
    $data = json_decode($raw, true);
    
    $targetLang = $data['language'] ?? '';
    
    if (empty($targetLang)) {
        http_response_code(400);
        echo json_encode(['error' => 'Language is required']);
        return;
    }
    
    try {
        $stats = Translator::translateMissingKeys($targetLang);
        echo json_encode([
            'success' => true,
            'stats' => $stats
        ]);
    } catch (Exception $e) {
        http_response_code(500);
        echo json_encode(['error' => $e->getMessage()]);
    }
});

// API: Export translations
Router::get('/api/translations/export/{lang}', function ($params) {
    header('Content-Type: application/json');
    
    $user = JWT::requireAuth();
    if (!$user) return;
    
    $lang = $params['lang'];
    
    try {
        $json = Translator::exportToJson($lang);
        header('Content-Disposition: attachment; filename="translations_' . $lang . '.json"');
        echo $json;
    } catch (Exception $e) {
        http_response_code(500);
        echo json_encode(['error' => $e->getMessage()]);
    }
});

// Dispatch router
Router::dispatch($_SERVER['REQUEST_METHOD'], $_SERVER['REQUEST_URI']);
