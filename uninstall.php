<?php
/**
 * 启灵安全防护 - 插件卸载数据清理逻辑
 *
 * @package QilingSecurity
 */

if ( ! defined( 'WP_UNINSTALL_PLUGIN' ) ) {
    exit;
}

$settings = get_option( 'qs_protection_settings', [] );

if ( empty( $settings['delete_data_on_uninstall'] ) ) {
    return;
}

global $wpdb;

$tables = [
    $wpdb->prefix . 'qilingsecurity_scans',
    $wpdb->prefix . 'qilingsecurity_results',
    $wpdb->prefix . 'qilingsecurity_audit',
    $wpdb->prefix . 'qilingsecurity_ban_ips',
    $wpdb->prefix . 'qilingsecurity_baseline_files',
    $wpdb->prefix . 'qilingsecurity_phone_location_cache',
    $wpdb->prefix . 'qilingsecurity_ip_geo_cache',
    $wpdb->prefix . 'qilingsecurity_geo_block_logs',
    $wpdb->prefix . 'qilingsecurity_rest_isolation_logs',
    $wpdb->prefix . 'qilingsecurity_ip_risk_profiles',
    $wpdb->prefix . 'qilingsecurity_ip_risk_events',
    $wpdb->prefix . 'qilingsecurity_db_toolkit_logs',
];

foreach ( $tables as $table_name ) {
    $wpdb->query( 'DROP TABLE IF EXISTS ' . $table_name );
}

delete_option( 'qs_db_schema_version' );
delete_option( 'qs_protection_settings' );
delete_option( 'qs_rule_package_active' );
delete_option( 'qs_rule_package_previous' );
delete_option( 'qs_rest_plugin_isolation_monitor_logs' );
delete_option( 'qs_rest_plugin_isolation_rule_sync_signature' );
delete_option( 'qs_redis_cache_runtime' );
delete_option( 'qs_health_check_last_report' );
delete_option( 'qs_db_toolkit_schema_version' );

$dropin_path = trailingslashit( defined( 'WP_CONTENT_DIR' ) ? WP_CONTENT_DIR : ABSPATH . 'wp-content' ) . 'object-cache.php';
if ( file_exists( $dropin_path ) && is_readable( $dropin_path ) ) {
    $dropin_contents = file_get_contents( $dropin_path );
    if ( false !== $dropin_contents && false !== strpos( $dropin_contents, 'Qiling Security Redis Object Cache Drop-In' ) && is_writable( $dropin_path ) ) {
        wp_delete_file( $dropin_path );
    }
}
