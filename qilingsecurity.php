<?php
/**
 * Plugin Name: 启灵安全防护
 * Plugin URI: https://www.jingxialai.com
 * Description: 启灵专属 WordPress 深度安全自检与防护插件 - 支持恶意代码查杀、权限审计、敏感文件保护等。
 * Version: 2.2.8
 * Requires at least: 5.8
 * Requires PHP: 7.4
 * Author: summer
 * Author URI: https://www.jingxialai.com
 * License: GPLv2 or later
 * License URI: https://www.gnu.org/licenses/gpl-2.0.html
 * Text Domain: qilingsecurity
 * Domain Path: /languages
 */

if ( ! defined( 'ABSPATH' ) ) {
    exit; // 禁止直接访问
}

// 定义常量
define( 'QS_VERSION', '2.2.8' );
define( 'QS_PLUGIN_DIR', plugin_dir_path( __FILE__ ) );
define( 'QS_PLUGIN_URL', plugin_dir_url( __FILE__ ) );

// 加载核心类
require_once QS_PLUGIN_DIR . 'includes/class-qs-db.php';
require_once QS_PLUGIN_DIR . 'includes/class-qs-session-manager.php';
require_once QS_PLUGIN_DIR . 'includes/class-qs-rules.php';
require_once QS_PLUGIN_DIR . 'includes/class-qs-redis-cache.php';
require_once QS_PLUGIN_DIR . 'includes/class-qs-alert-center.php';
require_once QS_PLUGIN_DIR . 'includes/class-qs-health-check.php';
require_once QS_PLUGIN_DIR . 'includes/class-qs-admin.php';
require_once QS_PLUGIN_DIR . 'includes/class-qs-scanner.php';
require_once QS_PLUGIN_DIR . 'includes/class-qs-ajax.php';
require_once QS_PLUGIN_DIR . 'includes/class-qs-rest-isolation.php';
require_once QS_PLUGIN_DIR . 'includes/class-qs-localization-mode.php';
require_once QS_PLUGIN_DIR . 'includes/class-qs-protection-settings.php';
require_once QS_PLUGIN_DIR . 'includes/class-qs-protection.php';
require_once QS_PLUGIN_DIR . 'includes/class-qs-phone-location.php';
require_once QS_PLUGIN_DIR . 'includes/class-qs-ip-risk-profile.php';
require_once QS_PLUGIN_DIR . 'includes/class-qs-audit.php';
require_once QS_PLUGIN_DIR . 'includes/class-qs-ip-geo-blocker.php';
require_once QS_PLUGIN_DIR . 'includes/class-qs-rate-limiter.php';
require_once QS_PLUGIN_DIR . 'includes/class-qs-db-toolkit.php';

/**
 * 插件激活回调：初始化数据表
 */
register_activation_hook(
    __FILE__,
    function() {
        QS_DB::install();
        if ( class_exists( 'QS_DB_Toolkit' ) ) {
            QS_DB_Toolkit::install();
        }
    }
);

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
    load_plugin_textdomain( 'qilingsecurity', false, dirname( plugin_basename( __FILE__ ) ) . '/languages' );
    QS_DB::maybe_install();
    $settings = QS_Protection::get_settings();

    QS_Protection::init();

    if ( QS_Protection::should_sync_rest_plugin_isolation_rules_in_current_request() ) {
        QS_Protection::maybe_sync_rest_plugin_isolation_rules();
    }

    if ( ! empty( QS_Protection::get_rate_limit_rules( $settings ) ) ) {
        QS_Rate_Limiter::init();
    }

    QS_Alert_Center::init();
    QS_Admin::init();
    QS_DB_Toolkit::init();

    if ( is_admin() || ( function_exists( 'wp_doing_ajax' ) && wp_doing_ajax() ) ) {
        QS_Ajax::init();
    }

    QS_Audit::init();

    if ( QS_Protection::is_ip_risk_profile_enabled( $settings ) ) {
        QS_IP_Risk_Profile::init();
    }
} );
