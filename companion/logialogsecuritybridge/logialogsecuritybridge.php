<?php
if (!defined('_PS_VERSION_')) {
    exit;
}

class LogialogSecurityBridge extends Module
{
    public function __construct()
    {
        $this->name = 'logialogsecuritybridge';
        $this->tab = 'administration';
        $this->version = '1.0.0';
        $this->author = 'LOGIALOG';
        $this->need_instance = 0;
        $this->bootstrap = true;
        $this->ps_versions_compliancy = ['min' => '1.7.8.0', 'max' => '8.99.99'];
        parent::__construct();
        $this->displayName = $this->l('LOGIALOG Security Bridge');
        $this->description = $this->l('Provides an authenticated, read-only inventory endpoint.');
    }

    public function install()
    {
        return parent::install()
            && Configuration::updateValue('LOGIALOG_SECURITY_BRIDGE_SECRET', bin2hex(random_bytes(32)));
    }

    public function uninstall()
    {
        return Configuration::deleteByName('LOGIALOG_SECURITY_BRIDGE_SECRET') && parent::uninstall();
    }

    public function getContent()
    {
        $output = '';
        if (Tools::isSubmit('submitLogialogSecurityBridgeRotate')) {
            $secret = bin2hex(random_bytes(32));
            Configuration::updateValue('LOGIALOG_SECURITY_BRIDGE_SECRET', $secret);
            $output .= $this->displayConfirmation($this->l('The HMAC secret was rotated. Copy it now; it will not be displayed again.'));
            $output .= '<div class="alert alert-warning"><code>' . Tools::safeOutput($secret) . '</code></div>';
        }
        $endpoint = $this->context->link->getModuleLink($this->name, 'inventory', [], true);
        $output .= '<div class="panel"><h3>' . $this->l('Read-only inventory endpoint') . '</h3><p><code>' . Tools::safeOutput($endpoint) . '</code></p>';
        $output .= '<p>' . $this->l('Requests require HTTPS and a timestamped HMAC signature. No customer, order, employee, credential or configuration value is returned.') . '</p>';
        $output .= '<form method="post"><button class="btn btn-warning" type="submit" name="submitLogialogSecurityBridgeRotate">' . $this->l('Rotate and reveal secret once') . '</button></form></div>';
        return $output;
    }
}
