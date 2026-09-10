<?php
class LogialogSecurityBridgeInventoryModuleFrontController extends ModuleFrontController
{
    public $ssl = true;
    public $ajax = true;

    public function initContent()
    {
        parent::initContent();
        if ($_SERVER['REQUEST_METHOD'] !== 'GET') {
            $this->respond(405, ['error' => 'method_not_allowed']);
        }
        if (!Tools::usingSecureMode()) {
            $this->respond(400, ['error' => 'https_required']);
        }
        $timestamp = isset($_SERVER['HTTP_X_LOGIALOG_TIMESTAMP']) ? (string) $_SERVER['HTTP_X_LOGIALOG_TIMESTAMP'] : '';
        $signature = isset($_SERVER['HTTP_X_LOGIALOG_SIGNATURE']) ? strtolower((string) $_SERVER['HTTP_X_LOGIALOG_SIGNATURE']) : '';
        if (!ctype_digit($timestamp) || abs(time() - (int) $timestamp) > 300 || !preg_match('/^[a-f0-9]{64}$/', $signature)) {
            $this->respond(401, ['error' => 'invalid_authentication']);
        }
        $secret = (string) Configuration::get('LOGIALOG_SECURITY_BRIDGE_SECRET');
        $path = (string) parse_url($_SERVER['REQUEST_URI'], PHP_URL_PATH);
        $expected = hash_hmac('sha256', "GET\n" . $path . "\n" . $timestamp, $secret);
        if ($secret === '' || !hash_equals($expected, $signature)) {
            $this->respond(401, ['error' => 'invalid_authentication']);
        }

        $modules = [];
        foreach (Module::getModulesInstalled() as $row) {
            $name = isset($row['name']) ? (string) $row['name'] : '';
            if ($name === '' || !Module::isEnabled($name)) {
                continue;
            }
            $instance = Module::getInstanceByName($name);
            $modules[] = ['name' => $name, 'version' => $instance ? (string) $instance->version : null, 'active' => true];
        }
        usort($modules, function ($left, $right) { return strcmp($left['name'], $right['name']); });

        $shops = [];
        foreach (Shop::getShops(false, null, false) as $row) {
            $shop = new Shop((int) $row['id_shop']);
            $shops[] = ['id' => (int) $row['id_shop'], 'name' => (string) $row['name'], 'url' => $shop->getBaseURL(true), 'active' => (bool) $row['active']];
        }
        usort($shops, function ($left, $right) { return $left['id'] <=> $right['id']; });

        $this->respond(200, ['schema_version' => '1.0', 'generated_at' => gmdate('c'), 'prestashop_version' => _PS_VERSION_, 'modules' => $modules, 'shops' => $shops]);
    }

    private function respond($status, array $payload)
    {
        http_response_code((int) $status);
        header('Content-Type: application/json; charset=utf-8');
        header('Cache-Control: no-store');
        header('X-Content-Type-Options: nosniff');
        echo json_encode($payload);
        exit;
    }
}
