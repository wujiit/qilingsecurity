<?php
/**
 * Plugin Name: 启灵安全防护
 * Plugin URI: https://www.jingxialai.com
 * Description: 启灵专属 WordPress 深度安全自检与防护插件 - 支持恶意代码查杀、权限审计、敏感文件保护等。
 * Version: 2.2.1
 * Author: summer
 * Author URI: https://www.jingxialai.com
 * License: GPLv2 or later
 */

if ( ! defined( 'ABSPATH' ) ) {
    exit; // Exit if accessed directly.
}

// 定义常量
define( 'QS_VERSION', '1.16.2' );
define( 'QS_PLUGIN_DIR', plugin_dir_path( __FILE__ ) );
define( 'QS_PLUGIN_URL', plugin_dir_url( __FILE__ ) );

// 加载核心类
require_once QS_PLUGIN_DIR . 'includes/class-qs-db.php';
require_once QS_PLUGIN_DIR . 'includes/class-qs-session-manager.php';
require_once QS_PLUGIN_DIR . 'includes/class-qs-rules.php';
require_once QS_PLUGIN_DIR . 'includes/class-qs-admin.php';
require_once QS_PLUGIN_DIR . 'includes/class-qs-scanner.php';
require_once QS_PLUGIN_DIR . 'includes/class-qs-ajax.php';
require_once QS_PLUGIN_DIR . 'includes/class-qs-protection.php';
require_once QS_PLUGIN_DIR . 'includes/class-qs-phone-location.php';
require_once QS_PLUGIN_DIR . 'includes/class-qs-ip-risk-profile.php';
require_once QS_PLUGIN_DIR . 'includes/class-qs-audit.php';
require_once QS_PLUGIN_DIR . 'includes/class-qs-rate-limiter.php';
require_once QS_PLUGIN_DIR . 'includes/class-qs-domain-replace.php';

/**
 * 插件激活回调：初始化数据表
 */
register_activation_hook( __FILE__, [ 'QS_DB', 'install' ] );

add_filter(
    'plugin_action_links_' . plugin_basename( __FILE__ ),
    function( $links ) {
        $settings_link = '<a href="' . esc_url( admin_url( 'admin.php?page=qiling-security#tab-protection' ) ) . '">设置</a>';
        array_unshift( $links, $settings_link );

        return $links;
    }
);

/**
 * 初始化插件
 */
add_action( 'plugins_loaded', function() {
    QS_DB::maybe_install();
    QS_Protection::init();
    QS_Protection::maybe_sync_rest_plugin_isolation_rules();
    QS_Rate_Limiter::init();
    QS_Admin::init();
    QS_Ajax::init();
    QS_Audit::init();
    QS_Phone_Location::init();
    QS_IP_Risk_Profile::init();
} );
