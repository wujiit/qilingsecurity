<?php
/**
 * Plugin uninstall cleanup.
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
    $wpdb->prefix . 'qilingsecurity_ip_risk_profiles',
    $wpdb->prefix . 'qilingsecurity_ip_risk_events',
];

foreach ( $tables as $table_name ) {
    $wpdb->query( 'DROP TABLE IF EXISTS ' . $table_name );
}

delete_option( 'qs_db_schema_version' );
delete_option( 'qs_protection_settings' );
delete_option( 'qs_rule_package_active' );
delete_option( 'qs_rule_package_previous' );
