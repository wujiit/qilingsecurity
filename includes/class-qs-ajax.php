<?php
/**
 * 安全防护插件 - AJAX 接口
 */
if ( ! defined( 'ABSPATH' ) ) {
    exit;
}

class QS_Ajax {

    const SCAN_STEP_STATE_TTL = 43200;

    public static function init() {
        add_action( 'wp_ajax_qs_run_scan', [ __CLASS__, 'handle_run_scan' ] );
        add_action( 'wp_ajax_qs_save_protection', [ __CLASS__, 'handle_save_protection' ] );
        add_action( 'wp_ajax_qs_unban_ip', [ __CLASS__, 'handle_unban_ip' ] );
        add_action( 'wp_ajax_qs_update_result_status', [ __CLASS__, 'handle_update_result_status' ] );
        add_action( 'wp_ajax_qs_cleanup_data', [ __CLASS__, 'handle_cleanup_data' ] );
        add_action( 'wp_ajax_qs_clear_all_history', [ __CLASS__, 'handle_clear_all_history' ] );
        add_action( 'wp_ajax_qs_cleanup_ip_geo_cache', [ __CLASS__, 'handle_cleanup_ip_geo_cache' ] );
        add_action( 'wp_ajax_qs_clear_ip_geo_cache', [ __CLASS__, 'handle_clear_ip_geo_cache' ] );
        add_action( 'wp_ajax_qs_cleanup_geo_block_logs', [ __CLASS__, 'handle_cleanup_geo_block_logs' ] );
        add_action( 'wp_ajax_qs_clear_geo_block_logs', [ __CLASS__, 'handle_clear_geo_block_logs' ] );
        add_action( 'wp_ajax_qs_clear_audit_logs', [ __CLASS__, 'handle_clear_audit_logs' ] );
        add_action( 'wp_ajax_qs_rebuild_file_baseline', [ __CLASS__, 'handle_rebuild_file_baseline' ] );
        add_action( 'wp_ajax_qs_import_rules_package', [ __CLASS__, 'handle_import_rules_package' ] );
        add_action( 'wp_ajax_qs_rollback_rules_package', [ __CLASS__, 'handle_rollback_rules_package' ] );
        add_action( 'wp_ajax_qs_destroy_session', [ __CLASS__, 'handle_destroy_session' ] );
        add_action( 'wp_ajax_qs_destroy_user_sessions', [ __CLASS__, 'handle_destroy_user_sessions' ] );
        add_action( 'wp_ajax_qs_destroy_all_sessions', [ __CLASS__, 'handle_destroy_all_sessions' ] );

        add_action( 'wp_ajax_qs_get_ip_risk_profile_detail', [ __CLASS__, 'handle_get_ip_risk_profile_detail' ] );
        add_action( 'wp_ajax_qs_clear_ip_risk_data', [ __CLASS__, 'handle_clear_ip_risk_data' ] );
        add_action( 'wp_ajax_qs_delete_ip_risk_profile', [ __CLASS__, 'handle_delete_ip_risk_profile' ] );
        add_action( 'wp_ajax_qs_clear_route_isolation_logs', [ __CLASS__, 'handle_clear_route_isolation_logs' ] );
        add_action( 'wp_ajax_qs_flush_redis_cache', [ __CLASS__, 'handle_flush_redis_cache' ] );
        add_action( 'wp_ajax_qs_run_redis_cache_probe', [ __CLASS__, 'handle_run_redis_cache_probe' ] );
        add_action( 'wp_ajax_qs_sync_redis_dropin', [ __CLASS__, 'handle_sync_redis_dropin' ] );
        add_action( 'wp_ajax_qs_run_health_check', [ __CLASS__, 'handle_run_health_check' ] );
        add_action( 'wp_ajax_qs_send_security_alert_test', [ __CLASS__, 'handle_send_security_alert_test' ] );
        add_action( 'wp_ajax_qs_load_admin_tab', [ __CLASS__, 'handle_load_admin_tab' ] );
    }

    public static function handle_load_admin_tab() {
        check_ajax_referer( 'qs_ajax_nonce', 'nonce' );

        if ( ! current_user_can( 'manage_options' ) ) {
            wp_send_json_error( '权限不足，拒绝访问。' );
        }

        $tab_key = isset( $_POST['tab'] ) ? sanitize_key( wp_unslash( $_POST['tab'] ) ) : '';
        $markup  = QS_Admin::get_admin_tab_markup( $tab_key );

        if ( is_wp_error( $markup ) ) {
            wp_send_json_error( $markup->get_error_message() );
        }

        wp_send_json_success(
            [
                'tab'  => $tab_key,
                'html' => $markup,
            ]
        );
    }

    public static function handle_run_scan() {
        check_ajax_referer( 'qs_ajax_nonce', 'nonce' );

        if ( ! current_user_can( 'manage_options' ) ) {
            wp_send_json_error( '权限不足，拒绝访问。' );
        }

        $step    = isset( $_POST['step'] ) ? sanitize_text_field( wp_unslash( $_POST['step'] ) ) : '';
        $scan_id = isset( $_POST['scan_id'] ) ? absint( $_POST['scan_id'] ) : 0;
        $scanner = new QS_Scanner();
        $steps   = self::get_registered_scan_steps( $scanner );

        if ( 'start' === $step ) {
            $new_id = QS_DB::create_scan();
            self::clear_scan_runtime_states( $new_id, array_keys( $steps ) );
            wp_send_json_success(
                [
                    'scan_id' => $new_id,
                    'message' => '扫描任务已创建。',
                ]
            );
        }

        if ( 'finish' === $step ) {
            QS_DB::finish_scan( $scan_id );
            self::clear_scan_runtime_states( $scan_id, array_keys( $steps ) );

            $scan_results   = QS_DB::get_results( $scan_id );
            $critical_count = 0;
            $warning_count  = 0;

            foreach ( (array) $scan_results as $scan_result ) {
                $severity = isset( $scan_result->severity ) ? sanitize_key( (string) $scan_result->severity ) : '';

                if ( 'critical' === $severity ) {
                    $critical_count++;
                } elseif ( 'warning' === $severity ) {
                    $warning_count++;
                }
            }

            if ( ( $critical_count + $warning_count ) > 0 ) {
                QS_Alert_Center::trigger_event(
                    'scan_risk',
                    '全盘安全体检发现风险',
                    [
                        sprintf( '本次扫描共发现 %d 项安全风险（其中严重风险 %d 项，告警风险 %d 项）。', $critical_count + $warning_count, $critical_count, $warning_count ),
                        '请及时登录 WordPress 后台【启灵安全防护】查看详细体检报告并处理。',
                    ],
                    [
                        'scan_id'      => $scan_id,
                        'issue_count'  => $critical_count + $warning_count,
                        'critical'     => $critical_count,
                        'warning'      => $warning_count,
                        'fingerprint'  => 'scan-' . absint( $scan_id ),
                    ]
                );
            }

            wp_send_json_success( [ 'msg' => '全盘体检结束' ] );
        }

        if ( ! $scan_id ) {
            wp_send_json_error( '无效的扫描任务 ID。' );
        }

        if ( ! isset( $steps[ $step ] ) ) {
            wp_send_json_error( '未知的扫描步骤。' );
        }

        $step_config = $steps[ $step ];
        $method      = $step_config['method'];
        $state       = self::get_scan_step_state( $scan_id, $step );
        $result      = $scanner->execute_scan_step( $step, $method, $scan_id, $state );

        if ( isset( $result['error'] ) ) {
            self::delete_scan_step_state( $scan_id, $step );
            wp_send_json_error( $result['error'] );
        }

        if ( ! empty( $result['done'] ) ) {
            self::delete_scan_step_state( $scan_id, $step );
        } else {
            self::set_scan_step_state( $scan_id, $step, isset( $result['state'] ) ? (array) $result['state'] : [] );
        }

        $results  = isset( $result['results'] ) ? array_values( (array) $result['results'] ) : [];
        $progress = isset( $result['progress'] ) && is_array( $result['progress'] ) ? $result['progress'] : [];

        wp_send_json_success(
            [
                'done'     => ! empty( $result['done'] ),
                'count'    => isset( $result['count'] ) ? (int) $result['count'] : count( $results ),
                'msg'      => ! empty( $step_config['success_message'] ) ? $step_config['success_message'] : $step_config['name'] . '完成',
                'data'     => $results,
                'progress' => $progress,
            ]
        );
    }

    public static function handle_save_protection() {
        check_ajax_referer( 'qs_ajax_nonce', 'nonce' );

        if ( ! current_user_can( 'manage_options' ) ) {
            wp_send_json_error( '权限不足，拒绝访问。' );
        }

        $raw_settings      = isset( $_POST['settings'] ) ? wp_unslash( $_POST['settings'] ) : [];
        $existing_settings = QS_Protection::get_settings();
        $merged_settings   = array_merge(
            is_array( $existing_settings ) ? $existing_settings : [],
            is_array( $raw_settings ) ? $raw_settings : []
        );
        $settings          = QS_Protection::sanitize_settings( $merged_settings );

        update_option( 'qs_protection_settings', $settings );
        QS_Protection::clear_settings_cache();

        $message    = '保存成功。';
        $tone       = 'success';
        $redis_sync = QS_Redis_Cache::sync_dropin( $settings );

        if ( is_wp_error( $redis_sync ) ) {
            $message = '保存成功，但 Redis 对象缓存同步失败：' . $redis_sync->get_error_message();
            $tone = 'warning';
        }

        wp_send_json_success(
            [
                'msg'  => $message,
                'tone' => $tone,
            ]
        );
    }

    public static function handle_flush_redis_cache() {
        check_ajax_referer( 'qs_ajax_nonce', 'nonce' );

        if ( ! current_user_can( 'manage_options' ) ) {
            wp_send_json_error( '权限不足，拒绝访问。' );
        }

        $redis_status = QS_Redis_Cache::get_status();
        if ( ! $redis_status['enabled'] ) {
            wp_send_json_error( '当前尚未启用 Redis 对象缓存。' );
        }

        if ( $redis_status['dropin_exists'] && ! $redis_status['dropin_managed'] ) {
            wp_send_json_error( '当前 object-cache.php 不由启灵安全防护托管，已跳过刷新以避免影响其他缓存方案。' );
        }

        $result = QS_Redis_Cache::flush_cache();

        if ( is_wp_error( $result ) ) {
            wp_send_json_error( $result->get_error_message() );
        }

        if ( class_exists( 'QS_Audit' ) ) {
            QS_Audit::record_manual_event( '刷新 Redis 缓存', '管理员手动刷新了 Redis 持久对象缓存，并同步了缓存 drop-in。' );
        }

        wp_send_json_success(
            [
                'msg'       => isset( $result['message'] ) ? $result['message'] : 'Redis 对象缓存已刷新。',
                'refreshed' => isset( $result['refreshed'] ) ? array_values( (array) $result['refreshed'] ) : [],
            ]
        );
    }

    public static function handle_run_redis_cache_probe() {
        check_ajax_referer( 'qs_ajax_nonce', 'nonce' );

        if ( ! current_user_can( 'manage_options' ) ) {
            wp_send_json_error( '权限不足，拒绝访问。' );
        }

        $result = QS_Redis_Cache::run_probe();

        if ( empty( $result['ok'] ) ) {
            wp_send_json_error(
                [
                    'message' => ! empty( $result['message'] ) ? $result['message'] : 'Redis 缓存自检未通过。',
                    'steps'   => ! empty( $result['steps'] ) ? array_values( (array) $result['steps'] ) : [],
                ]
            );
        }

        if ( class_exists( 'QS_Audit' ) ) {
            QS_Audit::record_manual_event( 'Redis 缓存自检', '管理员执行了 Redis 持久对象缓存自检探测（测试写入、读取、删除及分组刷新）。' );
        }

        wp_send_json_success(
            [
                'msg'   => ! empty( $result['message'] ) ? $result['message'] : 'Redis 缓存自检已通过。',
                'steps' => ! empty( $result['steps'] ) ? array_values( (array) $result['steps'] ) : [],
            ]
        );
    }

    public static function handle_sync_redis_dropin() {
        check_ajax_referer( 'qs_ajax_nonce', 'nonce' );

        if ( ! current_user_can( 'manage_options' ) ) {
            wp_send_json_error( '权限不足，拒绝访问。' );
        }

        $result = QS_Redis_Cache::sync_dropin();

        if ( is_wp_error( $result ) ) {
            wp_send_json_error( $result->get_error_message() );
        }

        if ( class_exists( 'QS_Audit' ) ) {
            QS_Audit::record_manual_event( '同步 Redis Drop-in', '管理员手动重新同步了 wp-content/object-cache.php 文件。' );
        }

        wp_send_json_success(
            [
                'msg'     => ! empty( $result['message'] ) ? $result['message'] : 'Redis drop-in 已重新同步。',
                'changed' => ! empty( $result['changed'] ),
            ]
        );
    }

    public static function handle_run_health_check() {
        check_ajax_referer( 'qs_ajax_nonce', 'nonce' );

        if ( ! current_user_can( 'manage_options' ) ) {
            wp_send_json_error( '权限不足，拒绝访问。' );
        }

        $settings = QS_Protection::get_settings();
        $report   = QS_Health_Check::run_checks( $settings );
        $summary  = isset( $report['summary'] ) && is_array( $report['summary'] ) ? $report['summary'] : [];

        if ( class_exists( 'QS_Audit' ) ) {
            QS_Audit::record_manual_event( '插件健康自检', '管理员执行了插件健康自检（检查数据表、规则签名、异步任务及 Redis 集成）。' );
        }

        wp_send_json_success(
            [
                'msg'    => sprintf(
                    '插件健康自检已完成：%d 项通过，%d 项告警，%d 项严重。',
                    isset( $summary['success'] ) ? (int) $summary['success'] : 0,
                    isset( $summary['warning'] ) ? (int) $summary['warning'] : 0,
                    isset( $summary['critical'] ) ? (int) $summary['critical'] : 0
                ),
                'report' => $report,
            ]
        );
    }

    public static function handle_send_security_alert_test() {
        check_ajax_referer( 'qs_ajax_nonce', 'nonce' );

        if ( ! current_user_can( 'manage_options' ) ) {
            wp_send_json_error( '权限不足，拒绝访问。' );
        }

        $result  = QS_Alert_Center::send_test_alert();
        $message = QS_Alert_Center::summarize_dispatch_result( $result );

        if ( class_exists( 'QS_Audit' ) ) {
            QS_Audit::record_manual_event( '发送测试告警', '管理员手动发送了安全测试告警（验证邮件、飞书或钉钉通道连通性）。' );
        }

        if ( empty( $result['success'] ) ) {
            wp_send_json_error( $message );
        }

        wp_send_json_success(
            [
                'msg'    => $message,
                'result' => $result,
            ]
        );
    }

    public static function handle_unban_ip() {
        check_ajax_referer( 'qs_ajax_nonce', 'nonce' );

        if ( ! current_user_can( 'manage_options' ) ) {
            wp_send_json_error( '权限不足，拒绝访问。' );
        }

        $ip = isset( $_POST['ip'] ) ? sanitize_text_field( wp_unslash( $_POST['ip'] ) ) : '';
        if ( $ip ) {
            QS_DB::unban_ip( $ip );
            QS_Audit::record_manual_event( '解封 IP', "手动解除封禁 IP: {$ip}" );
            wp_send_json_success( [ 'msg' => 'IP 解封成功。' ] );
        }

        wp_send_json_error( '无效的 IP 地址。' );
    }

    public static function handle_update_result_status() {
        check_ajax_referer( 'qs_ajax_nonce', 'nonce' );

        if ( ! current_user_can( 'manage_options' ) ) {
            wp_send_json_error( '权限不足，拒绝访问。' );
        }

        $result_id = isset( $_POST['result_id'] ) ? absint( $_POST['result_id'] ) : 0;
        $status    = isset( $_POST['status'] ) ? sanitize_key( wp_unslash( $_POST['status'] ) ) : '';

        if ( ! $result_id || ! in_array( $status, [ 'open', 'resolved', 'ignored' ], true ) ) {
            wp_send_json_error( '请求参数无效。' );
        }

        if ( ! QS_DB::update_result_status( $result_id, $status ) ) {
            wp_send_json_error( '更新扫描结果状态失败。' );
        }

        QS_Audit::record_manual_event( '更新扫描结果状态', "扫描结果 #{$result_id} 标记为: {$status}" );

        wp_send_json_success(
            [
                'status' => $status,
                'label'  => QS_Admin::get_result_status_label( $status ),
                'class'  => QS_Admin::get_result_status_class( $status ),
            ]
        );
    }

    public static function handle_cleanup_data() {
        check_ajax_referer( 'qs_ajax_nonce', 'nonce' );

        if ( ! current_user_can( 'manage_options' ) ) {
            wp_send_json_error( '权限不足，拒绝访问。' );
        }

        $settings = QS_Protection::get_settings();
        $summary  = QS_DB::cleanup_history( $settings );

        QS_Audit::record_manual_event(
            '清理安全历史数据',
            sprintf(
                '已清理 %d 次扫描记录、%d 条扫描结果、%d 条审计日志、%d 条过期封禁、%d 条地区拦截日志以及 %d 条路由隔离日志。',
                $summary['scans'],
                $summary['results'],
                $summary['audit'],
                $summary['bans'],
                isset( $summary['geo_block_logs'] ) ? $summary['geo_block_logs'] : 0,
                isset( $summary['rest_isolation_logs'] ) ? $summary['rest_isolation_logs'] : 0
            )
        );

        wp_send_json_success(
            [
                'msg'     => '已清理过期历史数据。',
                'summary' => $summary,
            ]
        );
    }

    public static function handle_clear_all_history() {
        check_ajax_referer( 'qs_ajax_nonce', 'nonce' );

        if ( ! current_user_can( 'manage_options' ) ) {
            wp_send_json_error( '权限不足，拒绝访问。' );
        }

        $summary = QS_DB::clear_all_history();

        wp_send_json_success(
            [
                'msg'     => '所有历史数据已清空。',
                'summary' => $summary,
            ]
        );
    }

    public static function handle_cleanup_ip_geo_cache() {
        check_ajax_referer( 'qs_ajax_nonce', 'nonce' );

        if ( ! current_user_can( 'manage_options' ) ) {
            wp_send_json_error( '权限不足，拒绝访问。' );
        }

        $deleted = QS_DB::cleanup_expired_ip_geo_cache( 180 );

        QS_Audit::record_manual_event(
            '清理 IP 地区缓存',
            sprintf( '已清理 %d 条过期 IP 地区缓存记录。', $deleted )
        );

        wp_send_json_success(
            [
                'msg'     => '已清理过期 IP 地区缓存。',
                'deleted' => $deleted,
                'summary' => QS_DB::get_storage_summary(),
            ]
        );
    }

    public static function handle_clear_ip_geo_cache() {
        check_ajax_referer( 'qs_ajax_nonce', 'nonce' );

        if ( ! current_user_can( 'manage_options' ) ) {
            wp_send_json_error( '权限不足，拒绝访问。' );
        }

        $deleted = QS_DB::clear_ip_geo_cache();

        QS_Audit::record_manual_event(
            '清空 IP 地区缓存',
            sprintf( '已清空 %d 条 IP 地区缓存记录。', $deleted )
        );

        wp_send_json_success(
            [
                'msg'     => 'IP 地区缓存已清空。',
                'deleted' => $deleted,
                'summary' => QS_DB::get_storage_summary(),
            ]
        );
    }

    public static function handle_cleanup_geo_block_logs() {
        check_ajax_referer( 'qs_ajax_nonce', 'nonce' );

        if ( ! current_user_can( 'manage_options' ) ) {
            wp_send_json_error( '权限不足，拒绝访问。' );
        }

        $settings = QS_Protection::get_settings();
        $days     = isset( $settings['geo_block_log_retention_days'] ) ? absint( $settings['geo_block_log_retention_days'] ) : 180;
        $deleted  = QS_DB::cleanup_expired_geo_block_logs( $days );

        QS_Audit::record_manual_event(
            '清理地区限制日志',
            sprintf( '已清理 %d 条过期地区限制日志。', $deleted )
        );

        wp_send_json_success(
            [
                'msg'     => '已清理过期地区限制日志。',
                'deleted' => $deleted,
                'summary' => QS_DB::get_storage_summary(),
            ]
        );
    }

    public static function handle_clear_geo_block_logs() {
        check_ajax_referer( 'qs_ajax_nonce', 'nonce' );

        if ( ! current_user_can( 'manage_options' ) ) {
            wp_send_json_error( '权限不足，拒绝访问。' );
        }

        $deleted = QS_DB::clear_geo_block_logs();

        QS_Audit::record_manual_event(
            '清空地区限制日志',
            sprintf( '已清空 %d 条地区限制日志。', $deleted )
        );

        wp_send_json_success(
            [
                'msg'     => '地区限制日志已清空。',
                'deleted' => $deleted,
                'summary' => QS_DB::get_storage_summary(),
            ]
        );
    }

    public static function handle_clear_audit_logs() {
        check_ajax_referer( 'qs_ajax_nonce', 'nonce' );

        if ( ! current_user_can( 'manage_options' ) ) {
            wp_send_json_error( '权限不足，拒绝访问。' );
        }

        $actor_id   = get_current_user_id();
        $actor      = wp_get_current_user();
        $actor_name = ( $actor && $actor->exists() ) ? (string) $actor->user_login : 'System/Guest';
        $actor_name = substr( sanitize_text_field( $actor_name ), 0, 60 );
        $actor_ip   = class_exists( 'QS_Audit' ) ? sanitize_text_field( (string) QS_Audit::get_real_ip() ) : '';

        $deleted = QS_DB::clear_audit_logs();

        QS_DB::insert_audit_log(
            $actor_id,
            '' !== $actor_name ? $actor_name : 'System/Guest',
            '审计日志清空',
            sprintf( 'An administrator cleared audit logs and removed %d records.', (int) $deleted ),
            '' !== $actor_ip ? $actor_ip : '0.0.0.0'
        );

        wp_send_json_success(
            [
                'msg'     => sprintf( 'Audit logs cleared. Removed %d records this time.', $deleted ),
                'deleted' => $deleted,
            ]
        );
    }

    public static function handle_rebuild_file_baseline() {
        check_ajax_referer( 'qs_ajax_nonce', 'nonce' );

        if ( ! current_user_can( 'manage_options' ) ) {
            wp_send_json_error( '权限不足，拒绝访问。' );
        }

        $scanner = new QS_Scanner();
        $result  = $scanner->rebuild_file_integrity_baseline();
        $count   = isset( $result['count'] ) ? absint( $result['count'] ) : 0;

        QS_Audit::record_manual_event( '重建文件基线', sprintf( '已重建文件完整性基线，共记录 %d 个文件特征。', $count ) );

        wp_send_json_success(
            [
                'msg'       => sprintf( '已为 %d 个核心及插件文件重建完整性基线。', $count ),
                'count'     => $count,
                'truncated' => ! empty( $result['truncated'] ),
            ]
        );
    }

    public static function handle_import_rules_package() {
        check_ajax_referer( 'qs_ajax_nonce', 'nonce' );

        if ( ! current_user_can( 'manage_options' ) ) {
            wp_send_json_error( '权限不足，拒绝访问。' );
        }

        $file   = isset( $_FILES['package'] ) ? $_FILES['package'] : [];
        $result = QS_Rules::import_package_from_upload( $file );

        if ( empty( $result['success'] ) ) {
            wp_send_json_error( ! empty( $result['message'] ) ? $result['message'] : '导入官方规则包失败。' );
        }

        $version = ! empty( $result['package']['version'] ) ? $result['package']['version'] : 'unknown';
        QS_Audit::record_manual_event( '导入官方规则包', sprintf( '管理员导入并启用了版本为 [%s] 的官方防护规则包。', $version ) );

        wp_send_json_success(
            [
                'msg'    => ! empty( $result['message'] ) ? $result['message'] : '官方规则包导入并启用成功。',
                'status' => QS_Rules::get_package_status(),
            ]
        );
    }

    public static function handle_rollback_rules_package() {
        check_ajax_referer( 'qs_ajax_nonce', 'nonce' );

        if ( ! current_user_can( 'manage_options' ) ) {
            wp_send_json_error( '权限不足，拒绝访问。' );
        }

        $result = QS_Rules::rollback_to_previous_package();

        if ( empty( $result['success'] ) ) {
            wp_send_json_error( ! empty( $result['message'] ) ? $result['message'] : '回滚官方规则包失败。' );
        }

        $version = isset( $result['status']['version'] ) ? (string) $result['status']['version'] : 'builtin';
        QS_Audit::record_manual_event( '回滚官方规则包', sprintf( '管理员回滚了官方安全规则包，当前激活版本为: [%s]。', $version ) );

        wp_send_json_success(
            [
                'msg'    => ! empty( $result['message'] ) ? $result['message'] : '官方规则包已成功回滚。',
                'status' => QS_Rules::get_package_status(),
            ]
        );
    }

    public static function handle_destroy_session() {
        check_ajax_referer( 'qs_ajax_nonce', 'nonce' );

        if ( ! current_user_can( 'manage_options' ) ) {
            wp_send_json_error( '权限不足，拒绝访问。' );
        }

        $user_id  = isset( $_POST['user_id'] ) ? absint( $_POST['user_id'] ) : 0;
        $verifier = isset( $_POST['verifier'] ) ? sanitize_text_field( wp_unslash( $_POST['verifier'] ) ) : '';

        if ( ! $user_id || '' === $verifier ) {
            wp_send_json_error( '请求参数无效。' );
        }

        if ( ! QS_Session_Manager::destroy_session( $user_id, $verifier ) ) {
            wp_send_json_error( '指定的登录会话不存在或已失效。' );
        }

        $user = get_userdata( $user_id );
        QS_Audit::record_manual_event( '强制注销单会话', sprintf( '强制终结了用户 [%s] 的 1 个活动登录会话。', $user ? $user->user_login : $user_id ) );

        wp_send_json_success( [ 'msg' => '会话已成功终止。' ] );
    }

    public static function handle_destroy_user_sessions() {
        check_ajax_referer( 'qs_ajax_nonce', 'nonce' );

        if ( ! current_user_can( 'manage_options' ) ) {
            wp_send_json_error( '权限不足，拒绝访问。' );
        }

        $user_id          = isset( $_POST['user_id'] ) ? absint( $_POST['user_id'] ) : 0;
        $preserve_current = ! empty( $_POST['preserve_current'] ) && '0' !== (string) wp_unslash( $_POST['preserve_current'] );

        if ( ! $user_id ) {
            wp_send_json_error( '请求参数无效。' );
        }

        $deleted = QS_Session_Manager::destroy_user_sessions( $user_id, $preserve_current );
        $user    = get_userdata( $user_id );
        $label   = $user ? $user->user_login : $user_id;

        QS_Audit::record_manual_event(
            '注销用户全部会话',
            sprintf( '已清理用户 [%s] 的活动会话，共注销 %d 个会话%s。', $label, $deleted, $preserve_current ? '（已保留当前管理会话）' : '' )
        );

        wp_send_json_success(
            [
                'msg'     => sprintf( '已注销 %d 个会话。', $deleted ),
                'deleted' => $deleted,
            ]
        );
    }

    public static function handle_destroy_all_sessions() {
        check_ajax_referer( 'qs_ajax_nonce', 'nonce' );

        if ( ! current_user_can( 'manage_options' ) ) {
            wp_send_json_error( '权限不足，拒绝访问。' );
        }

        $summary = QS_Session_Manager::destroy_all_sessions_except_current();

        QS_Audit::record_manual_event(
            '强制全部用户重新登录',
            sprintf( '已强制注销 %1$d 位用户的共计 %2$d 个活动登录会话（已保留当前管理会话）。', isset( $summary['users'] ) ? absint( $summary['users'] ) : 0, isset( $summary['sessions'] ) ? absint( $summary['sessions'] ) : 0 )
        );

        wp_send_json_success(
            [
                'msg'      => '其他所有用户的登录会话已全部强制失效。',
                'users'    => isset( $summary['users'] ) ? absint( $summary['users'] ) : 0,
                'sessions' => isset( $summary['sessions'] ) ? absint( $summary['sessions'] ) : 0,
            ]
        );
    }

    public static function handle_get_ip_risk_profile_detail() {
        check_ajax_referer( 'qs_ajax_nonce', 'nonce' );

        if ( ! current_user_can( 'manage_options' ) ) {
            wp_send_json_error( '权限不足，拒绝访问。' );
        }

        $ip_address = isset( $_POST['ip_address'] ) ? sanitize_text_field( wp_unslash( $_POST['ip_address'] ) ) : '';
        $ip_address = filter_var( trim( (string) $ip_address ), FILTER_VALIDATE_IP );

        if ( ! $ip_address ) {
            wp_send_json_error( 'IP 地址参数无效。' );
        }

        $profile = QS_DB::get_ip_risk_profile( $ip_address );
        if ( class_exists( 'QS_IP_Risk_Profile' ) && method_exists( 'QS_IP_Risk_Profile', 'refresh_profile_for_admin' ) ) {
            $refreshed_profile = QS_IP_Risk_Profile::refresh_profile_for_admin( $ip_address, 'admin_detail' );
            if ( ! empty( $refreshed_profile ) && is_array( $refreshed_profile ) ) {
                $profile = $refreshed_profile;
            }
        }

        $events = QS_DB::get_ip_risk_events_by_ip( $ip_address, 20 );
        if ( empty( $profile ) && empty( $events ) ) {
            wp_send_json_error( '暂无该 IP 的画像缓存数据，请先触发相关访问或登录事件。' );
        }

        if ( empty( $profile ) && ! empty( $events ) ) {
            $latest = isset( $events[0] ) && is_array( $events[0] ) ? $events[0] : [];
            $profile = [
                'id'             => 0,
                'ip_address'     => $ip_address,
                'ip_version'     => false !== strpos( $ip_address, ':' ) ? 6 : 4,
                'risk_score'     => isset( $latest['risk_score'] ) ? (int) $latest['risk_score'] : 0,
                'risk_level'     => isset( $latest['risk_level'] ) ? (string) $latest['risk_level'] : 'unknown',
                'provider_count' => isset( $latest['provider_count'] ) ? (int) $latest['provider_count'] : 0,
                'query_status'   => isset( $latest['profile_status'] ) ? (string) $latest['profile_status'] : 'unknown',
                'hit_count'      => count( $events ),
                'first_seen'     => '',
                'last_seen'      => isset( $latest['time'] ) ? (string) $latest['time'] : '',
                'updated_at'     => isset( $latest['time'] ) ? (string) $latest['time'] : '',
                'last_event_type' => isset( $latest['event_type'] ) ? (string) $latest['event_type'] : '',
                'summary'        => [],
                'providers'      => [],
            ];
        }

        $providers     = self::sanitize_ip_risk_provider_details( isset( $profile['providers'] ) ? $profile['providers'] : [] );
        $summary       = isset( $profile['summary'] ) && is_array( $profile['summary'] ) ? $profile['summary'] : [];
        $provider_plan = self::sanitize_ip_risk_provider_plan( isset( $summary['provider_plan'] ) && is_array( $summary['provider_plan'] ) ? $summary['provider_plan'] : [] );
        $profile_score = isset( $profile['risk_score'] ) ? max( 0, min( 100, (int) $profile['risk_score'] ) ) : 0;
        $profile_provider_count = isset( $profile['provider_count'] ) ? max( 0, (int) $profile['provider_count'] ) : 0;
        $provider_ok_count      = 0;
        $provider_score_samples = [];

        foreach ( $providers as $provider_item ) {
            if ( ! is_array( $provider_item ) ) {
                continue;
            }

            if ( isset( $provider_item['status'] ) && 'ok' === sanitize_key( (string) $provider_item['status'] ) ) {
                $provider_ok_count++;
            }

            if ( isset( $provider_item['risk_score'] ) && null !== $provider_item['risk_score'] && is_numeric( $provider_item['risk_score'] ) ) {
                $provider_score_samples[] = max( 0, min( 100, (int) $provider_item['risk_score'] ) );
            }
        }

        if ( $profile_score <= 0 && ! empty( $provider_score_samples ) ) {
            $profile_score = (int) round( array_sum( $provider_score_samples ) / count( $provider_score_samples ) );
        }

        $profile_provider_count = max( $profile_provider_count, $provider_ok_count );
        $profile_level = self::normalize_risk_level_for_output(
            isset( $profile['risk_level'] ) ? (string) $profile['risk_level'] : 'unknown',
            $profile_score,
            $profile_provider_count
        );

        wp_send_json_success(
            [
                'profile' => [
                    'id'             => isset( $profile['id'] ) ? absint( $profile['id'] ) : 0,
                    'ip_address'     => isset( $profile['ip_address'] ) ? (string) $profile['ip_address'] : $ip_address,
                    'ip_version'     => isset( $profile['ip_version'] ) ? absint( $profile['ip_version'] ) : 0,
                    'risk_score'     => $profile_score,
                    'risk_level'     => $profile_level,
                    'provider_count' => $profile_provider_count,
                    'query_status'   => isset( $profile['query_status'] ) ? sanitize_key( (string) $profile['query_status'] ) : 'unknown',
                    'hit_count'      => isset( $profile['hit_count'] ) ? max( 0, (int) $profile['hit_count'] ) : 0,
                    'first_seen'     => isset( $profile['first_seen'] ) ? (string) $profile['first_seen'] : '',
                    'last_seen'      => isset( $profile['last_seen'] ) ? (string) $profile['last_seen'] : '',
                    'updated_at'     => isset( $profile['updated_at'] ) ? (string) $profile['updated_at'] : '',
                    'last_event_type' => isset( $profile['last_event_type'] ) ? sanitize_key( (string) $profile['last_event_type'] ) : '',
                    'signals'        => isset( $summary['signals'] ) && is_array( $summary['signals'] ) ? array_values( array_filter( array_map( 'sanitize_key', $summary['signals'] ) ) ) : [],
                    'provider_plan'  => $provider_plan,
                    'event_only'     => empty( $providers ),
                ],
                'providers' => $providers,
                'events'    => $events,
            ]
        );
    }

    private static function normalize_risk_level_for_output( $level, $score = 0, $provider_count = 0 ) {
        $level          = sanitize_key( (string) $level );
        $score          = max( 0, min( 100, (int) $score ) );
        $provider_count = max( 0, (int) $provider_count );

        if ( in_array( $level, [ 'safe', 'low', 'medium', 'high', 'critical' ], true ) ) {
            return $level;
        }

        if ( 'unknown' === $level ) {
            if ( $score > 0 ) {
                $level = '';
            } elseif ( $provider_count > 0 ) {
                return 'safe';
            } else {
                return 'unknown';
            }
        }

        if ( $score >= 80 ) {
            return 'critical';
        }
        if ( $score >= 60 ) {
            return 'high';
        }
        if ( $score >= 35 ) {
            return 'medium';
        }
        if ( $score >= 15 ) {
            return 'low';
        }

        return $provider_count > 0 ? 'safe' : 'unknown';
    }

    public static function handle_clear_ip_risk_data() {
        check_ajax_referer( 'qs_ajax_nonce', 'nonce' );

        if ( ! current_user_can( 'manage_options' ) ) {
            wp_send_json_error( '权限不足，拒绝访问。' );
        }

        $target = isset( $_POST['target'] ) ? sanitize_key( wp_unslash( $_POST['target'] ) ) : 'all';
        if ( ! in_array( $target, [ 'profiles', 'events', 'all' ], true ) ) {
            $target = 'all';
        }

        $summary = QS_DB::clear_ip_risk_data( $target );
        QS_Audit::record_manual_event(
            '清理 IP 风险画像数据',
            sprintf( '清理范围 [%s]：已清理 %d 条画像缓存及 %d 条画像事件记录。', $target, isset( $summary['profiles'] ) ? (int) $summary['profiles'] : 0, isset( $summary['events'] ) ? (int) $summary['events'] : 0 )
        );

        wp_send_json_success(
            [
                'msg'     => 'IP 风险画像数据已清空。',
                'summary' => $summary,
                'target'  => $target,
            ]
        );
    }

    public static function handle_clear_route_isolation_logs() {
        check_ajax_referer( 'qs_ajax_nonce', 'nonce' );

        if ( ! current_user_can( 'manage_options' ) ) {
            wp_send_json_error( '权限不足，拒绝访问。' );
        }

        $deleted = QS_Protection::clear_rest_plugin_isolation_monitor_logs();
        QS_Audit::record_manual_event( '清空路由隔离日志', sprintf( '管理员清空了 REST 路由隔离监控日志，共清理 %d 条记录。', (int) $deleted ) );

        wp_send_json_success(
            [
                'msg'     => sprintf( 'REST 路由隔离监控日志已清空，共清理 %d 条记录。', (int) $deleted ),
                'deleted' => (int) $deleted,
            ]
        );
    }

    public static function handle_delete_ip_risk_profile() {
        check_ajax_referer( 'qs_ajax_nonce', 'nonce' );

        if ( ! current_user_can( 'manage_options' ) ) {
            wp_send_json_error( '权限不足，拒绝访问。' );
        }

        $ip_address = isset( $_POST['ip_address'] ) ? sanitize_text_field( wp_unslash( $_POST['ip_address'] ) ) : '';
        $ip_address = filter_var( trim( (string) $ip_address ), FILTER_VALIDATE_IP );
        if ( ! $ip_address ) {
            wp_send_json_error( 'IP 地址参数无效。' );
        }

        $delete_events = ! empty( $_POST['delete_events'] );
        $summary       = QS_DB::delete_ip_risk_profile( $ip_address, $delete_events );

        QS_Audit::record_manual_event(
            '删除单个 IP 画像记录',
            sprintf( '目标 IP [%s]：已清理 %d 条画像缓存及 %d 条画像事件记录。', $ip_address, isset( $summary['profiles'] ) ? (int) $summary['profiles'] : 0, isset( $summary['events'] ) ? (int) $summary['events'] : 0 )
        );

        wp_send_json_success(
            [
                'msg'       => '该 IP 画像记录已成功删除。',
                'summary'   => $summary,
                'ip_address' => $ip_address,
            ]
        );
    }

    private static function sanitize_ip_risk_provider_details( $providers ) {
        $providers = is_array( $providers ) ? $providers : [];
        $sanitized = [];
        $supported = self::get_supported_ip_risk_provider_ids();

        foreach ( $providers as $provider ) {
            if ( ! is_array( $provider ) ) {
                continue;
            }

            $provider_id  = isset( $provider['provider'] ) ? sanitize_key( (string) $provider['provider'] ) : 'unknown';
            if ( ! in_array( $provider_id, $supported, true ) ) {
                continue;
            }
            $data         = isset( $provider['data'] ) && is_array( $provider['data'] ) ? $provider['data'] : [];
            $signals      = isset( $provider['signals'] ) && is_array( $provider['signals'] ) ? array_values( array_filter( array_map( 'sanitize_key', $provider['signals'] ) ) ) : [];
            $status       = isset( $provider['status'] ) ? sanitize_key( (string) $provider['status'] ) : 'unknown';
            $risk_score   = null;

            if ( array_key_exists( 'risk_score', $provider ) && null !== $provider['risk_score'] && is_numeric( $provider['risk_score'] ) ) {
                $risk_score = max( 0, min( 100, (int) $provider['risk_score'] ) );
            }

            $sanitized[] = [
                'provider'    => $provider_id,
                'provider_label' => self::get_ip_risk_provider_label( $provider_id ),
                'status'      => $status,
                'reason'      => isset( $provider['reason'] ) ? sanitize_text_field( (string) $provider['reason'] ) : '',
                'risk_score'  => $risk_score,
                'signals'     => $signals,
                'highlights'  => self::build_ip_risk_provider_highlights( $provider_id, $data, $signals, $status ),
                'sections'    => self::build_ip_risk_provider_sections( $provider_id, $data ),
            ];
        }

        return $sanitized;
    }

    private static function sanitize_ip_risk_provider_plan( $plan ) {
        $plan             = is_array( $plan ) ? $plan : [];
        $supported        = self::get_supported_ip_risk_provider_ids();
        $requires_key_set = self::get_ip_risk_key_required_provider_ids();

        $selected = isset( $plan['selected'] ) && is_array( $plan['selected'] ) ? $plan['selected'] : [];
        $selected = array_map(
            static function( $item ) {
                return sanitize_key( str_replace( '-', '_', (string) $item ) );
            },
            $selected
        );
        $selected = array_values(
            array_filter(
                array_unique( $selected ),
                static function( $item ) use ( $supported ) {
                    return in_array( $item, $supported, true );
                }
            )
        );

        $missing_key = isset( $plan['missing_key'] ) && is_array( $plan['missing_key'] ) ? $plan['missing_key'] : [];
        $missing_key = array_map(
            static function( $item ) {
                return sanitize_key( str_replace( '-', '_', (string) $item ) );
            },
            $missing_key
        );
        $missing_key = array_values(
            array_filter(
                array_unique( $missing_key ),
                static function( $item ) use ( $supported, $requires_key_set ) {
                    return in_array( $item, $supported, true ) && in_array( $item, $requires_key_set, true );
                }
            )
        );

        return [
            'selected'             => $selected,
            'missing_key'          => $missing_key,
            'used_public_fallback' => ! empty( $plan['used_public_fallback'] ),
        ];
    }

    private static function get_ip_risk_provider_label( $provider_id ) {
        $provider_id = sanitize_key( (string) $provider_id );
        $map         = [
            'ipdata' => 'IPData',
            'ip_api' => 'IP-API',
            'ipinfo' => 'IPinfo',
        ];

        return isset( $map[ $provider_id ] ) ? $map[ $provider_id ] : ( '' !== $provider_id ? strtoupper( $provider_id ) : 'Unknown' );
    }

    private static function get_supported_ip_risk_provider_ids() {
        return [ 'ipdata', 'ip_api', 'ipinfo' ];
    }

    private static function get_ip_risk_key_required_provider_ids() {
        return [ 'ipdata' ];
    }

    private static function build_ip_risk_provider_sections( $provider_id, $data ) {
        $provider_id = sanitize_key( (string) $provider_id );
        $data        = is_array( $data ) ? $data : [];
        $sections    = [];

        switch ( $provider_id ) {
            case 'ipdata':
                $asn    = isset( $data['asn'] ) && is_array( $data['asn'] ) ? $data['asn'] : [];
                $threat = isset( $data['threat'] ) && is_array( $data['threat'] ) ? $data['threat'] : [];

                $sections[] = self::build_ip_risk_section(
                    '位置',
                    [
                        [ 'label' => 'IP', 'value' => isset( $data['ip'] ) ? $data['ip'] : '' ],
                        [ 'label' => '国家/地区', 'value' => isset( $data['country_name'] ) ? $data['country_name'] : '' ],
                        [ 'label' => '国家代码', 'value' => isset( $data['country_code'] ) ? $data['country_code'] : '' ],
                        [ 'label' => '省州', 'value' => isset( $data['region'] ) ? $data['region'] : '' ],
                        [ 'label' => '城市', 'value' => isset( $data['city'] ) ? $data['city'] : '' ],
                        [ 'label' => 'Lat/Lng', 'value' => self::format_ip_risk_latlng( isset( $data['latitude'] ) ? $data['latitude'] : '', isset( $data['longitude'] ) ? $data['longitude'] : '' ) ],
                    ]
                );
                $sections[] = self::build_ip_risk_section(
                    '网络',
                    [
                        [ 'label' => 'ASN', 'value' => isset( $asn['asn'] ) ? $asn['asn'] : '' ],
                        [ 'label' => '网络', 'value' => isset( $asn['route'] ) ? $asn['route'] : '' ],
                        [ 'label' => '类型', 'value' => isset( $asn['type'] ) ? $asn['type'] : '' ],
                        [ 'label' => 'Organization', 'value' => isset( $asn['name'] ) ? $asn['name'] : '' ],
                        [ 'label' => '域名', 'value' => isset( $asn['domain'] ) ? $asn['domain'] : '' ],
                    ]
                );
                $sections[] = self::build_ip_risk_section(
                    '安全',
                    [
                        [ 'label' => '代理', 'value' => self::format_ip_risk_bool( isset( $threat['is_proxy'] ) ? $threat['is_proxy'] : null ) ],
                        [ 'label' => 'Tor', 'value' => self::format_ip_risk_bool( isset( $threat['is_tor'] ) ? $threat['is_tor'] : null ) ],
                        [ 'label' => '匿名', 'value' => self::format_ip_risk_bool( isset( $threat['is_anonymous'] ) ? $threat['is_anonymous'] : null ) ],
                        [ 'label' => '数据中心', 'value' => self::format_ip_risk_bool( isset( $threat['is_datacenter'] ) ? $threat['is_datacenter'] : null ) ],
                        [ 'label' => 'Known attacker', 'value' => self::format_ip_risk_bool( isset( $threat['is_known_attacker'] ) ? $threat['is_known_attacker'] : null ) ],
                        [ 'label' => 'Known abuser', 'value' => self::format_ip_risk_bool( isset( $threat['is_known_abuser'] ) ? $threat['is_known_abuser'] : null ) ],
                    ]
                );
                break;

            case 'ip_api':
                $sections[] = self::build_ip_risk_section(
                    '位置',
                    [
                        [ 'label' => 'Continent', 'value' => isset( $data['continent'] ) ? $data['continent'] : '' ],
                        [ 'label' => '国家/地区', 'value' => isset( $data['country'] ) ? $data['country'] : '' ],
                        [ 'label' => '国家代码', 'value' => isset( $data['countryCode'] ) ? $data['countryCode'] : '' ],
                        [ 'label' => '省州', 'value' => isset( $data['regionName'] ) ? $data['regionName'] : '' ],
                        [ 'label' => '省州代码', 'value' => isset( $data['region'] ) ? $data['region'] : '' ],
                        [ 'label' => '城市', 'value' => isset( $data['city'] ) ? $data['city'] : '' ],
                        [ 'label' => '邮编', 'value' => isset( $data['zip'] ) ? $data['zip'] : '' ],
                        [ 'label' => 'Lat/Lng', 'value' => self::format_ip_risk_latlng( isset( $data['lat'] ) ? $data['lat'] : '', isset( $data['lon'] ) ? $data['lon'] : '' ) ],
                    ]
                );
                $sections[] = self::build_ip_risk_section(
                    '网络',
                    [
                        [ 'label' => 'Organization', 'value' => isset( $data['org'] ) ? $data['org'] : '' ],
                        [ 'label' => 'ISP', 'value' => isset( $data['isp'] ) ? $data['isp'] : '' ],
                        [ 'label' => '时区', 'value' => isset( $data['timezone'] ) ? $data['timezone'] : '' ],
                    ]
                );
                break;

            case 'ipinfo':
                $asn_raw = isset( $data['asn'] ) ? $data['asn'] : '';
                $asn     = is_array( $asn_raw ) ? $asn_raw : [];
                $privacy = isset( $data['privacy'] ) && is_array( $data['privacy'] ) ? $data['privacy'] : [];
                $asn_id  = '';

                if ( is_string( $asn_raw ) ) {
                    $asn_id = $asn_raw;
                } elseif ( is_array( $asn_raw ) && isset( $asn_raw['asn'] ) ) {
                    $asn_id = (string) $asn_raw['asn'];
                }

                if ( '' === $asn_id && isset( $data['asn_code'] ) ) {
                    $asn_id = (string) $data['asn_code'];
                }

                $asn_name = isset( $data['as_name'] ) ? $data['as_name'] : '';
                if ( '' === (string) $asn_name ) {
                    $asn_name = isset( $asn['name'] ) ? $asn['name'] : ( isset( $data['org'] ) ? $data['org'] : '' );
                }

                $asn_domain = isset( $data['as_domain'] ) ? $data['as_domain'] : '';
                if ( '' === (string) $asn_domain ) {
                    $asn_domain = isset( $asn['domain'] ) ? $asn['domain'] : '';
                }

                $sections[] = self::build_ip_risk_section(
                    '位置',
                    [
                        [ 'label' => 'IP', 'value' => isset( $data['ip'] ) ? $data['ip'] : '' ],
                        [ 'label' => '国家/地区', 'value' => isset( $data['country'] ) ? $data['country'] : '' ],
                        [ 'label' => '国家代码', 'value' => isset( $data['country_code'] ) ? $data['country_code'] : '' ],
                        [ 'label' => 'Continent', 'value' => isset( $data['continent'] ) ? $data['continent'] : '' ],
                        [ 'label' => 'Continent code', 'value' => isset( $data['continent_code'] ) ? $data['continent_code'] : '' ],
                        [ 'label' => '省州', 'value' => isset( $data['region'] ) ? $data['region'] : '' ],
                        [ 'label' => '城市', 'value' => isset( $data['city'] ) ? $data['city'] : '' ],
                        [ 'label' => '时区', 'value' => isset( $data['timezone'] ) ? $data['timezone'] : '' ],
                        [ 'label' => 'Lat/Lng', 'value' => isset( $data['loc'] ) ? $data['loc'] : '' ],
                    ]
                );
                $sections[] = self::build_ip_risk_section(
                    '网络',
                    [
                        [ 'label' => 'ASN', 'value' => $asn_id ],
                        [ 'label' => 'Organization', 'value' => $asn_name ],
                        [ 'label' => '域名', 'value' => $asn_domain ],
                        [ 'label' => '类型', 'value' => isset( $asn['type'] ) ? $asn['type'] : '' ],
                    ]
                );
                $sections[] = self::build_ip_risk_section(
                    '安全',
                    [
                        [ 'label' => 'Bogon', 'value' => self::format_ip_risk_bool( isset( $data['bogon'] ) ? $data['bogon'] : null ) ],
                        [ 'label' => 'VPN', 'value' => self::format_ip_risk_bool( isset( $privacy['vpn'] ) ? $privacy['vpn'] : null ) ],
                        [ 'label' => '代理', 'value' => self::format_ip_risk_bool( isset( $privacy['proxy'] ) ? $privacy['proxy'] : null ) ],
                        [ 'label' => 'Tor', 'value' => self::format_ip_risk_bool( isset( $privacy['tor'] ) ? $privacy['tor'] : null ) ],
                        [ 'label' => '托管网络', 'value' => self::format_ip_risk_bool( isset( $privacy['hosting'] ) ? $privacy['hosting'] : null ) ],
                    ]
                );
                break;

        }

        $sections = array_values(
            array_filter(
                $sections,
                static function( $section ) {
                    return is_array( $section ) && ! empty( $section['items'] );
                }
            )
        );

        if ( empty( $sections ) ) {
            $sections[] = self::build_ip_risk_section(
                '基础信息',
                [
                    [ 'label' => '说明', 'value' => '该来源暂无可展示字段' ],
                ]
            );
        }

        return $sections;
    }

    private static function build_ip_risk_provider_highlights( $provider_id, $data, $signals, $status ) {
        $provider_id = sanitize_key( (string) $provider_id );
        $data        = is_array( $data ) ? $data : [];
        $signals     = is_array( $signals ) ? $signals : [];
        $status      = sanitize_key( (string) $status );
        $items       = [];

        if ( 'ok' !== $status ) {
            return $items;
        }

        switch ( $provider_id ) {
            case 'ipdata':
                $threat = isset( $data['threat'] ) && is_array( $data['threat'] ) ? $data['threat'] : [];
                self::append_ip_risk_bool_highlight( $items, 'VPN', isset( $threat['is_vpn'] ) ? $threat['is_vpn'] : null, true );
                self::append_ip_risk_bool_highlight( $items, 'Tor', isset( $threat['is_tor'] ) ? $threat['is_tor'] : null, true );
                self::append_ip_risk_bool_highlight( $items, '代理', isset( $threat['is_proxy'] ) ? $threat['is_proxy'] : null, true );
                self::append_ip_risk_bool_highlight( $items, '匿名', isset( $threat['is_anonymous'] ) ? $threat['is_anonymous'] : null, true );
                self::append_ip_risk_bool_highlight( $items, '数据中心', isset( $threat['is_datacenter'] ) ? $threat['is_datacenter'] : null, true );
                self::append_ip_risk_bool_highlight( $items, 'Attacker', isset( $threat['is_known_attacker'] ) ? $threat['is_known_attacker'] : null, true );
                self::append_ip_risk_bool_highlight( $items, 'Abuser', isset( $threat['is_known_abuser'] ) ? $threat['is_known_abuser'] : null, true );
                break;

            case 'ip_api':
                // ip-api 免费接口仅展示地理字段，匿名字段不参与高亮。
                break;

            case 'ipinfo':
                $privacy = isset( $data['privacy'] ) && is_array( $data['privacy'] ) ? $data['privacy'] : [];
                self::append_ip_risk_bool_highlight( $items, 'VPN', isset( $privacy['vpn'] ) ? $privacy['vpn'] : null, true );
                self::append_ip_risk_bool_highlight( $items, 'Tor', isset( $privacy['tor'] ) ? $privacy['tor'] : null, true );
                self::append_ip_risk_bool_highlight( $items, '代理', isset( $privacy['proxy'] ) ? $privacy['proxy'] : null, true );
                self::append_ip_risk_bool_highlight( $items, '数据中心', isset( $privacy['hosting'] ) ? $privacy['hosting'] : null, true );
                self::append_ip_risk_bool_highlight( $items, 'Bogon', isset( $data['bogon'] ) ? $data['bogon'] : null, true );
                break;

        }

        foreach ( $signals as $signal ) {
            $signal = sanitize_key( (string) $signal );
            if ( '' === $signal ) {
                continue;
            }

            $items[] = [
                'label' => '信号',
                'state' => in_array( $signal, [ 'abuse_high', 'bogon', 'tor', 'proxy', 'vpn', 'abuse_medium' ], true ) ? 'danger' : 'info',
                'value' => $signal,
            ];
        }

        $items = array_values(
            array_filter(
                $items,
                static function( $item ) {
                    return is_array( $item ) && ! empty( $item['label'] ) && ! empty( $item['value'] );
                }
            )
        );

        return array_slice( $items, 0, 16 );
    }

    private static function append_ip_risk_bool_highlight( &$items, $label, $value, $risky = true, $positive_label = 'Yes' ) {
        $state = self::parse_ip_risk_boolean( $value );
        if ( 'unknown' === $state ) {
            return;
        }

        $tone  = 'neutral';
        $text  = 'Unknown';
        $label = sanitize_text_field( (string) $label );
        $positive_label = sanitize_text_field( (string) $positive_label );

        if ( 'true' === $state ) {
            $tone = $risky ? 'danger' : 'info';
            $text = $risky ? 'Matched' : $positive_label;
        } elseif ( 'false' === $state ) {
            $tone = $risky ? 'ok' : 'neutral';
            $text = $risky ? 'Not matched' : 'No';
        }

        $items[] = [
            'label' => $label,
            'state' => $tone,
            'value' => $text,
        ];
    }

    private static function parse_ip_risk_boolean( $value ) {
        if ( null === $value || '' === $value ) {
            return 'unknown';
        }

        if ( is_bool( $value ) ) {
            return $value ? 'true' : 'false';
        }

        if ( is_numeric( $value ) ) {
            return (int) $value > 0 ? 'true' : 'false';
        }

        if ( is_string( $value ) ) {
            $value = strtolower( trim( $value ) );
            if ( in_array( $value, [ '1', 'true', 'yes', 'y', 'on' ], true ) ) {
                return 'true';
            }
            if ( in_array( $value, [ '0', 'false', 'no', 'n', 'off' ], true ) ) {
                return 'false';
            }
        }

        return 'unknown';
    }

    private static function build_ip_risk_section( $title, $items ) {
        $normalized_items = [];

        foreach ( (array) $items as $item ) {
            if ( ! is_array( $item ) ) {
                continue;
            }

            $label = isset( $item['label'] ) ? sanitize_text_field( (string) $item['label'] ) : '';
            $value = self::normalize_ip_risk_value( isset( $item['value'] ) ? $item['value'] : '' );
            if ( '' === $label || '' === $value ) {
                continue;
            }

            $normalized_items[] = [
                'label' => $label,
                'value' => $value,
            ];
        }

        return [
            'title' => sanitize_text_field( (string) $title ),
            'items' => $normalized_items,
        ];
    }

    private static function normalize_ip_risk_value( $value ) {
        if ( is_bool( $value ) ) {
            return $value ? 'Yes' : 'No';
        }

        if ( is_numeric( $value ) ) {
            return (string) $value;
        }

        if ( is_string( $value ) ) {
            return sanitize_text_field( trim( $value ) );
        }

        if ( is_array( $value ) ) {
            $parts = array_filter(
                array_map(
                    static function( $v ) {
                        if ( is_scalar( $v ) ) {
                            return sanitize_text_field( (string) $v );
                        }
                        return '';
                    },
                    $value
                )
            );

            return implode( ', ', $parts );
        }

        return '';
    }

    private static function format_ip_risk_bool( $value ) {
        if ( null === $value || '' === $value ) {
            return '';
        }

        if ( is_array( $value ) || is_object( $value ) ) {
            return '';
        }

        if ( is_bool( $value ) ) {
            return $value ? 'Yes' : 'No';
        }

        if ( is_numeric( $value ) ) {
            return (int) $value > 0 ? 'Yes' : 'No';
        }

        $value = strtolower( trim( (string) $value ) );
        if ( '' === $value ) {
            return '';
        }

        if ( in_array( $value, [ '1', 'true', 'yes', 'y', 'on' ], true ) ) {
            return 'Yes';
        }
        if ( in_array( $value, [ '0', 'false', 'no', 'n', 'off' ], true ) ) {
            return 'No';
        }

        return sanitize_text_field( (string) $value );
    }

    private static function format_ip_risk_latlng( $lat, $lng ) {
        $lat = self::normalize_ip_risk_value( $lat );
        $lng = self::normalize_ip_risk_value( $lng );

        if ( '' === $lat || '' === $lng ) {
            return '';
        }

        return $lat . ', ' . $lng;
    }

    private static function get_registered_scan_steps( $scanner ) {
        $registered_steps = [];

        foreach ( QS_Scanner::get_scan_steps() as $step ) {
            if ( empty( $step['id'] ) || empty( $step['method'] ) || ! method_exists( $scanner, $step['method'] ) ) {
                continue;
            }

            $registered_steps[ $step['id'] ] = $step;
        }

        return $registered_steps;
    }

    private static function get_scan_step_state_key( $scan_id, $step ) {
        return 'qs_scan_state_' . absint( $scan_id ) . '_' . sanitize_key( (string) $step );
    }

    private static function get_scan_step_state( $scan_id, $step ) {
        $state = get_transient( self::get_scan_step_state_key( $scan_id, $step ) );

        return is_array( $state ) ? $state : [];
    }

    private static function set_scan_step_state( $scan_id, $step, $state ) {
        set_transient( self::get_scan_step_state_key( $scan_id, $step ), is_array( $state ) ? $state : [], self::SCAN_STEP_STATE_TTL );
    }

    private static function delete_scan_step_state( $scan_id, $step ) {
        delete_transient( self::get_scan_step_state_key( $scan_id, $step ) );
    }

    private static function clear_scan_runtime_states( $scan_id, $steps ) {
        foreach ( (array) $steps as $step ) {
            self::delete_scan_step_state( $scan_id, $step );
        }
    }
}
