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
        add_action( 'wp_ajax_qs_clear_audit_logs', [ __CLASS__, 'handle_clear_audit_logs' ] );
        add_action( 'wp_ajax_qs_rebuild_file_baseline', [ __CLASS__, 'handle_rebuild_file_baseline' ] );
        add_action( 'wp_ajax_qs_import_rules_package', [ __CLASS__, 'handle_import_rules_package' ] );
        add_action( 'wp_ajax_qs_rollback_rules_package', [ __CLASS__, 'handle_rollback_rules_package' ] );
        add_action( 'wp_ajax_qs_destroy_session', [ __CLASS__, 'handle_destroy_session' ] );
        add_action( 'wp_ajax_qs_destroy_user_sessions', [ __CLASS__, 'handle_destroy_user_sessions' ] );
        add_action( 'wp_ajax_qs_destroy_all_sessions', [ __CLASS__, 'handle_destroy_all_sessions' ] );
        add_action( 'wp_ajax_qs_domain_replace', [ __CLASS__, 'handle_domain_replace' ] );
        add_action( 'wp_ajax_qs_get_ip_risk_profile_detail', [ __CLASS__, 'handle_get_ip_risk_profile_detail' ] );
        add_action( 'wp_ajax_qs_clear_ip_risk_data', [ __CLASS__, 'handle_clear_ip_risk_data' ] );
        add_action( 'wp_ajax_qs_delete_ip_risk_profile', [ __CLASS__, 'handle_delete_ip_risk_profile' ] );
        add_action( 'wp_ajax_qs_clear_route_isolation_logs', [ __CLASS__, 'handle_clear_route_isolation_logs' ] );
    }

    public static function handle_run_scan() {
        check_ajax_referer( 'qs_ajax_nonce', 'nonce' );

        if ( ! current_user_can( 'manage_options' ) ) {
            wp_send_json_error( 'Permission denied.' );
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
                    'message' => '任务已创建',
                ]
            );
        }

        if ( 'finish' === $step ) {
            QS_DB::finish_scan( $scan_id );
            self::clear_scan_runtime_states( $scan_id, array_keys( $steps ) );
            wp_send_json_success( [ 'msg' => '全盘体检结束' ] );
        }

        if ( ! $scan_id ) {
            wp_send_json_error( '无效的扫描任务 ID。' );
        }

        if ( ! isset( $steps[ $step ] ) ) {
            wp_send_json_error( '未知的扫描步骤' );
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
            wp_send_json_error( 'Permission denied.' );
        }

        $raw_settings = isset( $_POST['settings'] ) ? wp_unslash( $_POST['settings'] ) : [];
        $settings     = QS_Protection::sanitize_settings( $raw_settings );

        update_option( 'qs_protection_settings', $settings );

        wp_send_json_success( [ 'msg' => '防护设置已成功保存！可能需要刷新页面生效。' ] );
    }

    public static function handle_unban_ip() {
        check_ajax_referer( 'qs_ajax_nonce', 'nonce' );

        if ( ! current_user_can( 'manage_options' ) ) {
            wp_send_json_error( 'Permission denied.' );
        }

        $ip = isset( $_POST['ip'] ) ? sanitize_text_field( wp_unslash( $_POST['ip'] ) ) : '';
        if ( $ip ) {
            QS_DB::unban_ip( $ip );
            QS_Audit::record_manual_event( '解封 IP', "手动解除封禁 IP: {$ip}" );
            wp_send_json_success( [ 'msg' => 'IP 解封成功！' ] );
        }

        wp_send_json_error( 'IP 无效。' );
    }

    public static function handle_update_result_status() {
        check_ajax_referer( 'qs_ajax_nonce', 'nonce' );

        if ( ! current_user_can( 'manage_options' ) ) {
            wp_send_json_error( 'Permission denied.' );
        }

        $result_id = isset( $_POST['result_id'] ) ? absint( $_POST['result_id'] ) : 0;
        $status    = isset( $_POST['status'] ) ? sanitize_key( wp_unslash( $_POST['status'] ) ) : '';

        if ( ! $result_id || ! in_array( $status, [ 'open', 'resolved', 'ignored' ], true ) ) {
            wp_send_json_error( '参数无效。' );
        }

        if ( ! QS_DB::update_result_status( $result_id, $status ) ) {
            wp_send_json_error( '处理状态更新失败。' );
        }

        QS_Audit::record_manual_event( '更新扫描结果状态', "结果 #{$result_id} 已标记为 {$status}" );

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
            wp_send_json_error( 'Permission denied.' );
        }

        $settings = QS_Protection::get_settings();
        $summary  = QS_DB::cleanup_history( $settings );

        QS_Audit::record_manual_event(
            '清理安全历史数据',
            sprintf(
                '删除扫描 %d 条、结果 %d 条、审计 %d 条、过期封禁 %d 条。',
                $summary['scans'],
                $summary['results'],
                $summary['audit'],
                $summary['bans']
            )
        );

        wp_send_json_success(
            [
                'msg'     => '过期历史数据清理完成。',
                'summary' => $summary,
            ]
        );
    }

    public static function handle_clear_all_history() {
        check_ajax_referer( 'qs_ajax_nonce', 'nonce' );

        if ( ! current_user_can( 'manage_options' ) ) {
            wp_send_json_error( 'Permission denied.' );
        }

        $summary = QS_DB::clear_all_history();

        wp_send_json_success(
            [
                'msg'     => '全部历史数据已清空。',
                'summary' => $summary,
            ]
        );
    }

    public static function handle_clear_audit_logs() {
        check_ajax_referer( 'qs_ajax_nonce', 'nonce' );

        if ( ! current_user_can( 'manage_options' ) ) {
            wp_send_json_error( 'Permission denied.' );
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
            sprintf( '管理员手动清空操作审计日志，删除 %d 条历史记录。', (int) $deleted ),
            '' !== $actor_ip ? $actor_ip : '0.0.0.0'
        );

        wp_send_json_success(
            [
                'msg'     => sprintf( '审计日志已清空，本次删除 %d 条记录。', $deleted ),
                'deleted' => $deleted,
            ]
        );
    }

    public static function handle_rebuild_file_baseline() {
        check_ajax_referer( 'qs_ajax_nonce', 'nonce' );

        if ( ! current_user_can( 'manage_options' ) ) {
            wp_send_json_error( 'Permission denied.' );
        }

        $scanner = new QS_Scanner();
        $result  = $scanner->rebuild_file_integrity_baseline();
        $count   = isset( $result['count'] ) ? absint( $result['count'] ) : 0;

        QS_Audit::record_manual_event( '重建文件基线', sprintf( '手动重建文件完整性基线，共写入 %d 条记录。', $count ) );

        wp_send_json_success(
            [
                'msg'       => sprintf( '文件基线已重建，共记录 %d 个文件。', $count ),
                'count'     => $count,
                'truncated' => ! empty( $result['truncated'] ),
            ]
        );
    }

    public static function handle_import_rules_package() {
        check_ajax_referer( 'qs_ajax_nonce', 'nonce' );

        if ( ! current_user_can( 'manage_options' ) ) {
            wp_send_json_error( 'Permission denied.' );
        }

        $file   = isset( $_FILES['package'] ) ? $_FILES['package'] : [];
        $result = QS_Rules::import_package_from_upload( $file );

        if ( empty( $result['success'] ) ) {
            wp_send_json_error( ! empty( $result['message'] ) ? $result['message'] : '规则包导入失败。' );
        }

        $version = ! empty( $result['package']['version'] ) ? $result['package']['version'] : 'unknown';
        QS_Audit::record_manual_event( '导入官方规则包', sprintf( '管理员导入并启用了官方规则包版本 [%s]。', $version ) );

        wp_send_json_success(
            [
                'msg'    => ! empty( $result['message'] ) ? $result['message'] : '规则包导入成功。',
                'status' => QS_Rules::get_package_status(),
            ]
        );
    }

    public static function handle_rollback_rules_package() {
        check_ajax_referer( 'qs_ajax_nonce', 'nonce' );

        if ( ! current_user_can( 'manage_options' ) ) {
            wp_send_json_error( 'Permission denied.' );
        }

        $result = QS_Rules::rollback_to_previous_package();

        if ( empty( $result['success'] ) ) {
            wp_send_json_error( ! empty( $result['message'] ) ? $result['message'] : '规则包回滚失败。' );
        }

        $version = isset( $result['status']['version'] ) ? (string) $result['status']['version'] : 'builtin';
        QS_Audit::record_manual_event( '回滚官方规则包', sprintf( '管理员执行官方规则回滚，当前生效版本 [%s]。', $version ) );

        wp_send_json_success(
            [
                'msg'    => ! empty( $result['message'] ) ? $result['message'] : '规则包回滚成功。',
                'status' => QS_Rules::get_package_status(),
            ]
        );
    }

    public static function handle_destroy_session() {
        check_ajax_referer( 'qs_ajax_nonce', 'nonce' );

        if ( ! current_user_can( 'manage_options' ) ) {
            wp_send_json_error( 'Permission denied.' );
        }

        $user_id  = isset( $_POST['user_id'] ) ? absint( $_POST['user_id'] ) : 0;
        $verifier = isset( $_POST['verifier'] ) ? sanitize_text_field( wp_unslash( $_POST['verifier'] ) ) : '';

        if ( ! $user_id || '' === $verifier ) {
            wp_send_json_error( '参数无效。' );
        }

        if ( ! QS_Session_Manager::destroy_session( $user_id, $verifier ) ) {
            wp_send_json_error( '指定会话不存在或销毁失败。' );
        }

        $user = get_userdata( $user_id );
        QS_Audit::record_manual_event( '踢下线单个会话', sprintf( '已下线用户 [%s] 的一个活跃会话。', $user ? $user->user_login : $user_id ) );

        wp_send_json_success( [ 'msg' => '会话已强制下线。' ] );
    }

    public static function handle_destroy_user_sessions() {
        check_ajax_referer( 'qs_ajax_nonce', 'nonce' );

        if ( ! current_user_can( 'manage_options' ) ) {
            wp_send_json_error( 'Permission denied.' );
        }

        $user_id          = isset( $_POST['user_id'] ) ? absint( $_POST['user_id'] ) : 0;
        $preserve_current = ! empty( $_POST['preserve_current'] ) && '0' !== (string) wp_unslash( $_POST['preserve_current'] );

        if ( ! $user_id ) {
            wp_send_json_error( '参数无效。' );
        }

        $deleted = QS_Session_Manager::destroy_user_sessions( $user_id, $preserve_current );
        $user    = get_userdata( $user_id );
        $label   = $user ? $user->user_login : $user_id;

        QS_Audit::record_manual_event(
            '踢下线用户全部会话',
            sprintf( '已清理用户 [%s] 的 %d 个活跃会话%s。', $label, $deleted, $preserve_current ? '（保留当前会话）' : '' )
        );

        wp_send_json_success(
            [
                'msg'     => sprintf( '已清理 %d 个会话。', $deleted ),
                'deleted' => $deleted,
            ]
        );
    }

    public static function handle_destroy_all_sessions() {
        check_ajax_referer( 'qs_ajax_nonce', 'nonce' );

        if ( ! current_user_can( 'manage_options' ) ) {
            wp_send_json_error( 'Permission denied.' );
        }

        $summary = QS_Session_Manager::destroy_all_sessions_except_current();

        QS_Audit::record_manual_event(
            '强制全部用户重新登录',
            sprintf( '已清理 %d 个用户的 %d 个活跃会话，并保留当前管理员会话。', isset( $summary['users'] ) ? absint( $summary['users'] ) : 0, isset( $summary['sessions'] ) ? absint( $summary['sessions'] ) : 0 )
        );

        wp_send_json_success(
            [
                'msg'      => '已强制其余会话全部失效。',
                'users'    => isset( $summary['users'] ) ? absint( $summary['users'] ) : 0,
                'sessions' => isset( $summary['sessions'] ) ? absint( $summary['sessions'] ) : 0,
            ]
        );
    }

    public static function handle_get_ip_risk_profile_detail() {
        check_ajax_referer( 'qs_ajax_nonce', 'nonce' );

        if ( ! current_user_can( 'manage_options' ) ) {
            wp_send_json_error( 'Permission denied.' );
        }

        $ip_address = isset( $_POST['ip_address'] ) ? sanitize_text_field( wp_unslash( $_POST['ip_address'] ) ) : '';
        $ip_address = filter_var( trim( (string) $ip_address ), FILTER_VALIDATE_IP );

        if ( ! $ip_address ) {
            wp_send_json_error( 'IP 参数无效。' );
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
            wp_send_json_error( '该 IP 暂无缓存画像数据，请先触发一次登录事件。' );
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
            wp_send_json_error( 'Permission denied.' );
        }

        $target = isset( $_POST['target'] ) ? sanitize_key( wp_unslash( $_POST['target'] ) ) : 'all';
        if ( ! in_array( $target, [ 'profiles', 'events', 'all' ], true ) ) {
            $target = 'all';
        }

        $summary = QS_DB::clear_ip_risk_data( $target );
        QS_Audit::record_manual_event(
            '清理 IP 风险画像数据',
            sprintf( '目标[%s]，删除画像缓存 %d 条，删除画像事件 %d 条。', $target, isset( $summary['profiles'] ) ? (int) $summary['profiles'] : 0, isset( $summary['events'] ) ? (int) $summary['events'] : 0 )
        );

        wp_send_json_success(
            [
                'msg'     => 'IP 风险画像数据已清理。',
                'summary' => $summary,
                'target'  => $target,
            ]
        );
    }

    public static function handle_clear_route_isolation_logs() {
        check_ajax_referer( 'qs_ajax_nonce', 'nonce' );

        if ( ! current_user_can( 'manage_options' ) ) {
            wp_send_json_error( 'Permission denied.' );
        }

        $deleted = QS_Protection::clear_rest_plugin_isolation_monitor_logs();
        QS_Audit::record_manual_event( '清空路由隔离监控日志', sprintf( '管理员清空路由隔离监控日志，共删除 %d 条。', (int) $deleted ) );

        wp_send_json_success(
            [
                'msg'     => sprintf( '路由隔离监控日志已清空，共删除 %d 条。', (int) $deleted ),
                'deleted' => (int) $deleted,
            ]
        );
    }

    public static function handle_delete_ip_risk_profile() {
        check_ajax_referer( 'qs_ajax_nonce', 'nonce' );

        if ( ! current_user_can( 'manage_options' ) ) {
            wp_send_json_error( 'Permission denied.' );
        }

        $ip_address = isset( $_POST['ip_address'] ) ? sanitize_text_field( wp_unslash( $_POST['ip_address'] ) ) : '';
        $ip_address = filter_var( trim( (string) $ip_address ), FILTER_VALIDATE_IP );
        if ( ! $ip_address ) {
            wp_send_json_error( 'IP 参数无效。' );
        }

        $delete_events = ! empty( $_POST['delete_events'] );
        $summary       = QS_DB::delete_ip_risk_profile( $ip_address, $delete_events );

        QS_Audit::record_manual_event(
            '删除单个 IP 画像记录',
            sprintf( 'IP[%s]：删除画像缓存 %d 条，删除画像事件 %d 条。', $ip_address, isset( $summary['profiles'] ) ? (int) $summary['profiles'] : 0, isset( $summary['events'] ) ? (int) $summary['events'] : 0 )
        );

        wp_send_json_success(
            [
                'msg'       => '该 IP 画像记录已删除。',
                'summary'   => $summary,
                'ip_address' => $ip_address,
            ]
        );
    }

    public static function handle_domain_replace() {
        check_ajax_referer( 'qs_ajax_nonce', 'nonce' );

        if ( ! current_user_can( 'manage_options' ) ) {
            wp_send_json_error( 'Permission denied.' );
        }

        if ( ! class_exists( 'QS_Domain_Replace' ) ) {
            wp_send_json_error( 'Domain replace class missing.' );
        }

        $old  = isset( $_POST['old_domain'] ) ? sanitize_text_field( wp_unslash( $_POST['old_domain'] ) ) : '';
        $new  = isset( $_POST['new_domain'] ) ? sanitize_text_field( wp_unslash( $_POST['new_domain'] ) ) : '';
        $target_key = isset( $_POST['target'] ) ? sanitize_key( wp_unslash( $_POST['target'] ) ) : '';
        $last_id = isset( $_POST['last_id'] ) ? absint( $_POST['last_id'] ) : 0;
        $limit   = isset( $_POST['limit'] ) ? absint( $_POST['limit'] ) : 200;
        $dry_run = ! empty( $_POST['dry_run'] );
        $include_protocols = empty( $_POST['include_protocols'] ) ? false : true;
        $log_step = ! empty( $_POST['log'] );

        if ( '' === $old || '' === $new ) {
            wp_send_json_error( '请输入旧域名和新域名。' );
        }

        $target = QS_Domain_Replace::get_target( $target_key );
        if ( ! $target ) {
            wp_send_json_error( '无效的替换范围。' );
        }

        $pairs = QS_Domain_Replace::build_search_pairs( $old, $new, $include_protocols );
        if ( empty( $pairs['search'] ) ) {
            wp_send_json_error( '替换规则为空，请检查输入。' );
        }

        $stats = QS_Domain_Replace::replace_in_target(
            $target,
            $pairs['search'],
            $pairs['replace'],
            $last_id,
            $limit,
            $dry_run,
            $pairs['needle']
        );

        if ( isset( $stats['error'] ) ) {
            wp_send_json_error( $stats['error'] );
        }

        if ( ! $dry_run && $log_step ) {
            $detail = sprintf(
                '已执行域名安全替换：旧 [%s] -> 新 [%s]；本轮累计扫描 %d 行，更新 %d 行。',
                $old,
                $new,
                (int) $stats['scanned'],
                (int) $stats['updated']
            );
            if ( class_exists( 'QS_Audit' ) ) {
                QS_Audit::record_manual_event( '域名安全替换', $detail );
            }
        }

        if ( ! $dry_run && ! empty( $stats['updated'] ) ) {
            self::maybe_refresh_qilingshop_domain_replace_cache( $target_key );
            self::maybe_refresh_qibbs_domain_replace_cache( $target_key );
        }

        wp_send_json_success( $stats );
    }

    private static function maybe_refresh_qilingshop_domain_replace_cache( $target_key ) {
        $target_key = sanitize_key( (string) $target_key );
        if ( 0 !== strpos( $target_key, 'qilingshop_' ) ) {
            return;
        }

        $new_version = sprintf( '%.0f', microtime( true ) * 1000000 ) . '-' . wp_rand( 1000, 9999 );
        update_option( 'qls_shop_product_cache_version', $new_version );
        update_option( 'qls_shop_category_cache_version', $new_version );
    }

    private static function maybe_refresh_qibbs_domain_replace_cache( $target_key ) {
        $target_key = sanitize_key( (string) $target_key );
        if ( 0 !== strpos( $target_key, 'qibbs_' ) ) {
            return;
        }

        if ( class_exists( 'Qibbs_Cache_Service' ) ) {
            Qibbs_Cache_Service::invalidate_all();
        }

        $new_version = sprintf( '%.0f', microtime( true ) * 1000000 ) . '-' . wp_rand( 1000, 9999 );
        update_option( 'qibbs_cache_version', $new_version );
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
            'ipregistry' => 'IPRegistry',
            'ipdata'     => 'IPData',
            'ip_api'     => 'IP-API',
            'ipinfo'     => 'IPinfo',
            'ip_sb'      => 'IP.SB',
            'ipbset'     => 'IPBSET (即时数科)',
        ];

        return isset( $map[ $provider_id ] ) ? $map[ $provider_id ] : ( '' !== $provider_id ? strtoupper( $provider_id ) : 'Unknown' );
    }

    private static function get_supported_ip_risk_provider_ids() {
        return [ 'ipregistry', 'ipdata', 'ip_api', 'ipinfo', 'ip_sb', 'ipbset' ];
    }

    private static function get_ip_risk_key_required_provider_ids() {
        return [ 'ipregistry', 'ipdata', 'ipbset' ];
    }

    private static function build_ip_risk_provider_sections( $provider_id, $data ) {
        $provider_id = sanitize_key( (string) $provider_id );
        $data        = is_array( $data ) ? $data : [];
        $sections    = [];

        switch ( $provider_id ) {
            case 'ipregistry':
                $location = isset( $data['location'] ) && is_array( $data['location'] ) ? $data['location'] : [];
                $country  = isset( $location['country'] ) && is_array( $location['country'] ) ? $location['country'] : [];
                $region   = isset( $location['region'] ) && is_array( $location['region'] ) ? $location['region'] : [];
                $city     = isset( $location['city'] ) && is_array( $location['city'] ) ? $location['city'] : [];
                $tz       = isset( $location['time_zone'] ) && is_array( $location['time_zone'] ) ? $location['time_zone'] : [];
                $conn     = isset( $data['connection'] ) && is_array( $data['connection'] ) ? $data['connection'] : [];
                $security = isset( $data['security'] ) && is_array( $data['security'] ) ? $data['security'] : [];

                $sections[] = self::build_ip_risk_section(
                    '位置',
                    [
                        [ 'label' => 'IP', 'value' => isset( $data['ip'] ) ? $data['ip'] : '' ],
                        [ 'label' => '国家/地区', 'value' => isset( $country['name'] ) ? $country['name'] : '' ],
                        [ 'label' => '国家代码', 'value' => isset( $country['code'] ) ? $country['code'] : '' ],
                        [ 'label' => '省州', 'value' => isset( $region['name'] ) ? $region['name'] : '' ],
                        [ 'label' => '城市', 'value' => isset( $city['name'] ) ? $city['name'] : '' ],
                        [ 'label' => '时区', 'value' => isset( $tz['id'] ) ? $tz['id'] : '' ],
                    ]
                );
                $sections[] = self::build_ip_risk_section(
                    '网络',
                    [
                        [ 'label' => '连接类型', 'value' => isset( $conn['type'] ) ? $conn['type'] : '' ],
                        [ 'label' => 'ASN', 'value' => isset( $conn['asn'] ) ? $conn['asn'] : '' ],
                        [ 'label' => '运营商', 'value' => isset( $conn['organization'] ) ? $conn['organization'] : '' ],
                        [ 'label' => 'ISP', 'value' => isset( $conn['isp'] ) ? $conn['isp'] : '' ],
                    ]
                );
                $sections[] = self::build_ip_risk_section(
                    '安全',
                    [
                        [ 'label' => '代理', 'value' => self::format_ip_risk_bool( isset( $security['is_proxy'] ) ? $security['is_proxy'] : null ) ],
                        [ 'label' => 'Tor', 'value' => self::format_ip_risk_bool( isset( $security['is_tor'] ) ? $security['is_tor'] : null ) ],
                        [ 'label' => '匿名', 'value' => self::format_ip_risk_bool( isset( $security['is_anonymous'] ) ? $security['is_anonymous'] : null ) ],
                        [ 'label' => '滥用者', 'value' => self::format_ip_risk_bool( isset( $security['is_abuser'] ) ? $security['is_abuser'] : null ) ],
                        [ 'label' => '攻击者', 'value' => self::format_ip_risk_bool( isset( $security['is_attacker'] ) ? $security['is_attacker'] : null ) ],
                    ]
                );
                break;

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
                        [ 'label' => '经纬度', 'value' => self::format_ip_risk_latlng( isset( $data['latitude'] ) ? $data['latitude'] : '', isset( $data['longitude'] ) ? $data['longitude'] : '' ) ],
                    ]
                );
                $sections[] = self::build_ip_risk_section(
                    '网络',
                    [
                        [ 'label' => 'ASN', 'value' => isset( $asn['asn'] ) ? $asn['asn'] : '' ],
                        [ 'label' => '网络', 'value' => isset( $asn['route'] ) ? $asn['route'] : '' ],
                        [ 'label' => '类型', 'value' => isset( $asn['type'] ) ? $asn['type'] : '' ],
                        [ 'label' => '运营商', 'value' => isset( $asn['name'] ) ? $asn['name'] : '' ],
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
                        [ 'label' => '已知攻击者', 'value' => self::format_ip_risk_bool( isset( $threat['is_known_attacker'] ) ? $threat['is_known_attacker'] : null ) ],
                        [ 'label' => '已知滥用者', 'value' => self::format_ip_risk_bool( isset( $threat['is_known_abuser'] ) ? $threat['is_known_abuser'] : null ) ],
                    ]
                );
                break;

            case 'ip_api':
                $sections[] = self::build_ip_risk_section(
                    '位置',
                    [
                        [ 'label' => '洲', 'value' => isset( $data['continent'] ) ? $data['continent'] : '' ],
                        [ 'label' => '国家/地区', 'value' => isset( $data['country'] ) ? $data['country'] : '' ],
                        [ 'label' => '国家代码', 'value' => isset( $data['countryCode'] ) ? $data['countryCode'] : '' ],
                        [ 'label' => '省州', 'value' => isset( $data['regionName'] ) ? $data['regionName'] : '' ],
                        [ 'label' => '省州代码', 'value' => isset( $data['region'] ) ? $data['region'] : '' ],
                        [ 'label' => '城市', 'value' => isset( $data['city'] ) ? $data['city'] : '' ],
                        [ 'label' => '邮编', 'value' => isset( $data['zip'] ) ? $data['zip'] : '' ],
                        [ 'label' => '经纬度', 'value' => self::format_ip_risk_latlng( isset( $data['lat'] ) ? $data['lat'] : '', isset( $data['lon'] ) ? $data['lon'] : '' ) ],
                    ]
                );
                $sections[] = self::build_ip_risk_section(
                    '网络',
                    [
                        [ 'label' => '运营商', 'value' => isset( $data['org'] ) ? $data['org'] : '' ],
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
                        [ 'label' => '洲', 'value' => isset( $data['continent'] ) ? $data['continent'] : '' ],
                        [ 'label' => '洲代码', 'value' => isset( $data['continent_code'] ) ? $data['continent_code'] : '' ],
                        [ 'label' => '省州', 'value' => isset( $data['region'] ) ? $data['region'] : '' ],
                        [ 'label' => '城市', 'value' => isset( $data['city'] ) ? $data['city'] : '' ],
                        [ 'label' => '时区', 'value' => isset( $data['timezone'] ) ? $data['timezone'] : '' ],
                        [ 'label' => '经纬度', 'value' => isset( $data['loc'] ) ? $data['loc'] : '' ],
                    ]
                );
                $sections[] = self::build_ip_risk_section(
                    '网络',
                    [
                        [ 'label' => 'ASN', 'value' => $asn_id ],
                        [ 'label' => '运营商', 'value' => $asn_name ],
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

            case 'ip_sb':
                $sections[] = self::build_ip_risk_section(
                    '位置',
                    [
                        [ 'label' => 'IP', 'value' => isset( $data['ip'] ) ? $data['ip'] : '' ],
                        [ 'label' => '国家/地区', 'value' => isset( $data['country'] ) ? $data['country'] : '' ],
                        [ 'label' => '省州', 'value' => isset( $data['region'] ) ? $data['region'] : '' ],
                        [ 'label' => '城市', 'value' => isset( $data['city'] ) ? $data['city'] : '' ],
                        [ 'label' => '时区', 'value' => isset( $data['timezone'] ) ? $data['timezone'] : '' ],
                    ]
                );
                $sections[] = self::build_ip_risk_section(
                    '网络',
                    [
                        [ 'label' => 'ASN', 'value' => isset( $data['asn'] ) ? $data['asn'] : '' ],
                        [ 'label' => '运营商', 'value' => isset( $data['asn_organization'] ) ? $data['asn_organization'] : '' ],
                        [ 'label' => '组织', 'value' => isset( $data['organization'] ) ? $data['organization'] : '' ],
                        [ 'label' => 'ISP', 'value' => isset( $data['isp'] ) ? $data['isp'] : '' ],
                        [ 'label' => '网络类型', 'value' => isset( $data['type'] ) ? $data['type'] : '' ],
                    ]
                );
                break;

            case 'ipbset':
                $sections[] = self::build_ip_risk_section(
                    '位置',
                    [
                        [ 'label' => 'IP', 'value' => isset( $data['ipAddress'] ) ? $data['ipAddress'] : '' ],
                    ]
                );
                $sections[] = self::build_ip_risk_section(
                    '评估',
                    [
                        [ 'label' => '风险评分', 'value' => isset( $data['score'] ) ? $data['score'] : '' ],
                        [ 'label' => '风险等级', 'value' => isset( $data['level'] ) ? $data['level'] : '' ],
                    ]
                );
                $sections[] = self::build_ip_risk_section(
                    '安全详情',
                    [
                        [ 'label' => '代理', 'value' => self::format_ip_risk_bool( isset( $data['proxy'] ) ? $data['proxy'] : ( isset( $data['isProxy'] ) ? $data['isProxy'] : null ) ) ],
                        [ 'label' => 'Tor', 'value' => self::format_ip_risk_bool( isset( $data['tor'] ) ? $data['tor'] : null ) ],
                        [ 'label' => 'VPN', 'value' => self::format_ip_risk_bool( isset( $data['vpn'] ) ? $data['vpn'] : null ) ],
                        [ 'label' => 'IDC', 'value' => self::format_ip_risk_bool( isset( $data['idc'] ) ? $data['idc'] : null ) ],
                        [ 'label' => '滥用', 'value' => self::format_ip_risk_bool( isset( $data['bot'] ) ? $data['bot'] : ( isset( $data['spam'] ) ? $data['spam'] : null ) ) ],
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
            case 'ipregistry':
                $security = isset( $data['security'] ) && is_array( $data['security'] ) ? $data['security'] : [];
                self::append_ip_risk_bool_highlight( $items, 'VPN', isset( $security['is_vpn'] ) ? $security['is_vpn'] : null, true );
                self::append_ip_risk_bool_highlight( $items, 'Tor', isset( $security['is_tor'] ) ? $security['is_tor'] : null, true );
                self::append_ip_risk_bool_highlight( $items, '代理', isset( $security['is_proxy'] ) ? $security['is_proxy'] : null, true );
                self::append_ip_risk_bool_highlight( $items, '匿名', isset( $security['is_anonymous'] ) ? $security['is_anonymous'] : null, true );
                self::append_ip_risk_bool_highlight( $items, '数据中心', isset( $security['is_cloud_provider'] ) ? $security['is_cloud_provider'] : null, true );
                self::append_ip_risk_bool_highlight( $items, '攻击者', isset( $security['is_attacker'] ) ? $security['is_attacker'] : null, true );
                self::append_ip_risk_bool_highlight( $items, '滥用者', isset( $security['is_abuser'] ) ? $security['is_abuser'] : null, true );
                break;

            case 'ipdata':
                $threat = isset( $data['threat'] ) && is_array( $data['threat'] ) ? $data['threat'] : [];
                self::append_ip_risk_bool_highlight( $items, 'VPN', isset( $threat['is_vpn'] ) ? $threat['is_vpn'] : null, true );
                self::append_ip_risk_bool_highlight( $items, 'Tor', isset( $threat['is_tor'] ) ? $threat['is_tor'] : null, true );
                self::append_ip_risk_bool_highlight( $items, '代理', isset( $threat['is_proxy'] ) ? $threat['is_proxy'] : null, true );
                self::append_ip_risk_bool_highlight( $items, '匿名', isset( $threat['is_anonymous'] ) ? $threat['is_anonymous'] : null, true );
                self::append_ip_risk_bool_highlight( $items, '数据中心', isset( $threat['is_datacenter'] ) ? $threat['is_datacenter'] : null, true );
                self::append_ip_risk_bool_highlight( $items, '攻击者', isset( $threat['is_known_attacker'] ) ? $threat['is_known_attacker'] : null, true );
                self::append_ip_risk_bool_highlight( $items, '滥用者', isset( $threat['is_known_abuser'] ) ? $threat['is_known_abuser'] : null, true );
                break;

            case 'ip_api':
                // Geolocation fields only, anonymity fields removed due to timeout issues on free endpoint
                break;

            case 'ipinfo':
                $privacy = isset( $data['privacy'] ) && is_array( $data['privacy'] ) ? $data['privacy'] : [];
                self::append_ip_risk_bool_highlight( $items, 'VPN', isset( $privacy['vpn'] ) ? $privacy['vpn'] : null, true );
                self::append_ip_risk_bool_highlight( $items, 'Tor', isset( $privacy['tor'] ) ? $privacy['tor'] : null, true );
                self::append_ip_risk_bool_highlight( $items, '代理', isset( $privacy['proxy'] ) ? $privacy['proxy'] : null, true );
                self::append_ip_risk_bool_highlight( $items, '数据中心', isset( $privacy['hosting'] ) ? $privacy['hosting'] : null, true );
                self::append_ip_risk_bool_highlight( $items, 'Bogon', isset( $data['bogon'] ) ? $data['bogon'] : null, true );
                break;

            case 'ip_sb':
                $type = isset( $data['type'] ) ? strtolower( trim( (string) $data['type'] ) ) : '';
                if ( '' !== $type ) {
                    $items[] = [
                        'label' => '网络类型',
                        'state' => 'info',
                        'value' => sanitize_text_field( (string) $data['type'] ),
                    ];
                }
                break;

            case 'ipbset':
                self::append_ip_risk_bool_highlight( $items, 'VPN', isset( $data['vpn'] ) ? $data['vpn'] : null, true );
                self::append_ip_risk_bool_highlight( $items, 'Tor', isset( $data['tor'] ) ? $data['tor'] : null, true );
                self::append_ip_risk_bool_highlight( $items, '代理', isset( $data['proxy'] ) ? $data['proxy'] : ( isset( $data['isProxy'] ) ? $data['isProxy'] : null ), true );
                self::append_ip_risk_bool_highlight( $items, 'IDC', isset( $data['idc'] ) ? $data['idc'] : null, true );
                self::append_ip_risk_bool_highlight( $items, '滥用', isset( $data['bot'] ) ? $data['bot'] : ( isset( $data['spam'] ) ? $data['spam'] : null ), true );
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

    private static function append_ip_risk_bool_highlight( &$items, $label, $value, $risky = true, $positive_label = '未命中' ) {
        $state = self::parse_ip_risk_boolean( $value );
        if ( 'unknown' === $state ) {
            return;
        }

        $tone  = 'neutral';
        $text  = '未知';
        $label = sanitize_text_field( (string) $label );
        $positive_label = sanitize_text_field( (string) $positive_label );

        if ( 'true' === $state ) {
            $tone = $risky ? 'danger' : 'info';
            $text = $risky ? '命中' : $positive_label;
        } elseif ( 'false' === $state ) {
            $tone = $risky ? 'ok' : 'neutral';
            $text = $risky ? '未命中' : '否';
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
            if ( in_array( $value, [ '1', 'true', 'yes', 'y', 'on', '是' ], true ) ) {
                return 'true';
            }
            if ( in_array( $value, [ '0', 'false', 'no', 'n', 'off', '否' ], true ) ) {
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
            return $value ? '是' : '否';
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
            return $value ? '是' : '否';
        }

        if ( is_numeric( $value ) ) {
            return (int) $value > 0 ? '是' : '否';
        }

        $value = strtolower( trim( (string) $value ) );
        if ( '' === $value ) {
            return '';
        }

        if ( in_array( $value, [ '1', 'true', 'yes', 'y', 'on' ], true ) ) {
            return '是';
        }
        if ( in_array( $value, [ '0', 'false', 'no', 'n', 'off' ], true ) ) {
            return '否';
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
