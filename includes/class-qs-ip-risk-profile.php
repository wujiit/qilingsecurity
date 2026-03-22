<?php
/**
 * 启灵安全防护 - 登录链路 IP 风险画像
 */
if ( ! defined( 'ABSPATH' ) ) {
    exit;
}

class QS_IP_Risk_Profile {

    const EVENT_LOGIN_SUCCESS = 'login_success';
    const EVENT_LOGIN_FAILED  = 'login_failed';
    const ASYNC_REFRESH_HOOK  = 'qs_ip_risk_refresh_profile';
    const EXTERNAL_TASK_QUERY = 'qs_ip_risk_task';
    const EXTERNAL_TASK_KEY   = 'key';

    private static $runtime_cache = [];
    private static $lookup_context = [];

    public static function init() {
        add_action( 'wp_login', [ __CLASS__, 'handle_login_success' ], 35, 2 );
        add_action( 'wp_login_failed', [ __CLASS__, 'handle_login_failed' ], 35, 1 );
        add_action( self::ASYNC_REFRESH_HOOK, [ __CLASS__, 'handle_async_refresh' ], 10, 2 );
        add_action( 'init', [ __CLASS__, 'maybe_handle_external_cron_request' ], 1 );
    }

    public static function handle_login_success( $user_login, $user ) {
        $user_id = isset( $user->ID ) ? absint( $user->ID ) : 0;
        $context = [
            'user_id'  => $user_id,
            'username' => sanitize_user( (string) $user_login, true ),
        ];

        self::capture_login_event( self::EVENT_LOGIN_SUCCESS, $context );
    }

    public static function handle_login_failed( $username ) {
        $context = [
            'user_id'  => 0,
            'username' => sanitize_user( (string) $username, true ),
        ];

        self::capture_login_event( self::EVENT_LOGIN_FAILED, $context );
    }

    public static function handle_async_refresh( $ip_address, $event_type = '' ) {
        $settings = QS_Protection::get_settings();
        if ( ! QS_Protection::is_ip_risk_profile_enabled( $settings ) ) {
            return;
        }
        if ( 'external' === QS_Protection::get_ip_risk_query_mode( $settings ) ) {
            return;
        }

        $ip_address = self::normalize_ip_address( $ip_address );
        if ( '' === $ip_address ) {
            return;
        }

        $event_type = sanitize_key( (string) $event_type );
        if ( '' === $event_type ) {
            $event_type = 'async_refresh';
        }

        self::refresh_profile( $ip_address, $settings, $event_type );
    }

    public static function maybe_handle_external_cron_request() {
        $task = isset( $_GET[ self::EXTERNAL_TASK_QUERY ] ) ? sanitize_key( wp_unslash( $_GET[ self::EXTERNAL_TASK_QUERY ] ) ) : '';
        if ( '' === $task ) {
            return;
        }

        nocache_headers();

        $settings = QS_Protection::get_settings();
        if ( ! QS_Protection::is_ip_risk_profile_enabled( $settings ) ) {
            wp_send_json_error( [ 'message' => 'ip_risk_profile_disabled' ], 503 );
        }

        $provided_key = isset( $_GET[ self::EXTERNAL_TASK_KEY ] ) ? sanitize_text_field( wp_unslash( $_GET[ self::EXTERNAL_TASK_KEY ] ) ) : '';
        $expected_key = QS_Protection::get_ip_risk_external_cron_key( $settings, true );

        if ( '' === $provided_key || '' === $expected_key ) {
            wp_send_json_error( [ 'message' => 'missing_task_key' ], 403 );
        }

        $is_valid = function_exists( 'hash_equals' ) ? hash_equals( $expected_key, $provided_key ) : ( $expected_key === $provided_key );
        if ( ! $is_valid ) {
            wp_send_json_error( [ 'message' => 'invalid_task_key' ], 403 );
        }

        switch ( $task ) {
            case 'run':
                self::handle_external_run_task( $settings );
                break;
            case 'cleanup':
                self::handle_external_cleanup_task( $settings );
                break;
            default:
                wp_send_json_error( [ 'message' => 'invalid_task' ], 400 );
        }
    }

    private static function handle_external_run_task( $settings ) {
        if ( 'external' !== QS_Protection::get_ip_risk_query_mode( $settings ) ) {
            wp_send_json_error( [ 'message' => 'query_mode_not_external' ], 409 );
        }

        $limit = isset( $_GET['limit'] ) ? absint( $_GET['limit'] ) : QS_Protection::get_ip_risk_external_batch_size( $settings );
        $limit = max( 1, min( 200, $limit ) );

        if ( ! method_exists( 'QS_DB', 'get_pending_ip_risk_addresses' ) ) {
            wp_send_json_error( [ 'message' => 'pending_queue_unavailable' ], 500 );
        }

        $pending_ips = QS_DB::get_pending_ip_risk_addresses( $limit );
        $result      = [
            'limit'      => $limit,
            'queued'     => count( $pending_ips ),
            'processed'  => 0,
            'completed'  => 0,
            'still_wait' => 0,
            'failed'     => 0,
            'sample'     => [],
        ];

        foreach ( $pending_ips as $ip_address ) {
            $ip_address = self::normalize_ip_address( $ip_address );
            if ( '' === $ip_address ) {
                continue;
            }

            $result['processed']++;
            $profile = self::refresh_profile( $ip_address, $settings, 'external_cron' );
            $status  = sanitize_key( isset( $profile['query_status'] ) ? (string) $profile['query_status'] : 'unknown' );

            if ( in_array( $status, [ 'pending', 'pending_async', 'pending_external', 'missing' ], true ) ) {
                $result['still_wait']++;
            } elseif ( ! empty( $profile ) ) {
                $result['completed']++;
            } else {
                $result['failed']++;
            }

            if ( count( $result['sample'] ) < 8 ) {
                $result['sample'][] = [
                    'ip'             => $ip_address,
                    'risk_level'     => isset( $profile['risk_level'] ) ? sanitize_key( (string) $profile['risk_level'] ) : 'unknown',
                    'risk_score'     => isset( $profile['risk_score'] ) ? (int) $profile['risk_score'] : 0,
                    'provider_count' => isset( $profile['provider_count'] ) ? (int) $profile['provider_count'] : 0,
                    'query_status'   => $status,
                ];
            }
        }

        $next_queue             = QS_DB::get_pending_ip_risk_addresses( 1 );
        $result['has_more']     = ! empty( $next_queue );
        $result['next_run_hint'] = ! empty( $next_queue ) ? 'queue_not_empty' : 'queue_empty';
        $result['timestamp']    = current_time( 'mysql' );

        do_action( 'qs_ip_risk_external_cron_processed', $result, $pending_ips, $settings );
        wp_send_json_success( $result );
    }

    private static function handle_external_cleanup_task( $settings ) {
        $days    = isset( $_GET['days'] ) ? absint( $_GET['days'] ) : 30;
        $summary = QS_DB::cleanup_expired_ip_risk_data( $days );
        
        $result = [
            'task'      => 'cleanup',
            'days'      => $days,
            'summary'   => $summary,
            'timestamp' => current_time( 'mysql' ),
        ];

        do_action( 'qs_ip_risk_external_cleanup_processed', $result, $settings );
        wp_send_json_success( $result );
    }

    private static function capture_login_event( $event_type, $context = [] ) {
        $event_type = sanitize_key( (string) $event_type );
        $settings   = QS_Protection::get_settings();

        if ( ! QS_Protection::is_ip_risk_profile_enabled( $settings ) ) {
            return;
        }

        if ( ! QS_Protection::should_capture_ip_risk_for_event( $event_type, $settings ) ) {
            return;
        }

        $ip_address = self::normalize_ip_address( QS_Audit::get_real_ip( $settings ) );
        if ( '' === $ip_address ) {
            return;
        }

        if ( QS_Audit::is_ip_whitelisted( $ip_address, $settings ) ) {
            return;
        }

        $profile          = QS_DB::get_ip_risk_profile( $ip_address );
        $existing_profile = $profile;
        $ttl              = QS_Protection::get_ip_risk_cache_ttl_seconds( $settings );
        $fresh            = self::is_profile_fresh( $profile, $ttl );
        $stale            = ! empty( $profile ) && ! $fresh;

        if ( $fresh ) {
            QS_DB::touch_ip_risk_profile( $ip_address, $event_type );
        } else {
            $query_mode = QS_Protection::get_ip_risk_query_mode( $settings );

            if ( 'sync' === $query_mode ) {
                $profile = self::refresh_profile(
                    $ip_address,
                    $settings,
                    $event_type,
                    [
                        'query_mode'     => 'sync',
                        'force_short_io' => true,
                    ]
                );

                if ( self::should_fail_open_sync_lookup( $profile ) ) {
                    self::schedule_profile_refresh( $ip_address, $event_type );

                    if ( ! empty( $existing_profile ) ) {
                        $profile = $existing_profile;
                        $stale   = ! self::is_profile_fresh( $existing_profile, $ttl );
                    } else {
                        $profile = self::build_pending_profile( $ip_address, $event_type, 'pending_async' );
                        QS_DB::upsert_ip_risk_profile( $ip_address, $profile );
                    }
                } elseif ( empty( $profile ) && ! empty( $existing_profile ) ) {
                    $profile = $existing_profile;
                }
            } elseif ( 'external' === $query_mode ) {
                self::unschedule_profile_refresh( $ip_address, $event_type );
                if ( empty( $profile ) ) {
                    $profile = self::build_pending_profile( $ip_address, $event_type, 'pending_external' );
                    QS_DB::upsert_ip_risk_profile( $ip_address, $profile );
                    $stored_profile = QS_DB::get_ip_risk_profile( $ip_address );
                    if ( ! empty( $stored_profile ) ) {
                        $profile = $stored_profile;
                    }
                }
            } else {
                self::schedule_profile_refresh( $ip_address, $event_type );

                if ( empty( $profile ) ) {
                    $profile = self::build_pending_profile( $ip_address, $event_type, 'pending_async' );
                    QS_DB::upsert_ip_risk_profile( $ip_address, $profile );
                    $stored_profile = QS_DB::get_ip_risk_profile( $ip_address );
                    if ( ! empty( $stored_profile ) ) {
                        $profile = $stored_profile;
                    }
                }

                if ( defined( 'DISABLE_WP_CRON' ) && DISABLE_WP_CRON ) {
                    $refreshed_profile = self::refresh_profile( $ip_address, $settings, $event_type );
                    if ( ! empty( $refreshed_profile ) ) {
                        $profile = $refreshed_profile;
                        $stale   = false;
                    }
                }
            }
        }

        $decision = self::make_action_decision( $profile );
        $profile  = self::normalize_profile_for_event( $profile, $stale, $ip_address, $event_type );
        $context  = self::build_event_context( $context, $settings, $event_type );

        $event_id = QS_DB::insert_ip_risk_event(
            [
                'event_type'     => $event_type,
                'ip_address'     => $ip_address,
                'user_id'        => isset( $context['user_id'] ) ? absint( $context['user_id'] ) : 0,
                'username'       => isset( $context['username'] ) ? (string) $context['username'] : '',
                'risk_score'     => isset( $profile['risk_score'] ) ? (int) $profile['risk_score'] : 0,
                'risk_level'     => isset( $profile['risk_level'] ) ? (string) $profile['risk_level'] : 'unknown',
                'profile_status' => isset( $profile['query_status'] ) ? (string) $profile['query_status'] : 'unknown',
                'provider_count' => isset( $profile['provider_count'] ) ? (int) $profile['provider_count'] : 0,
                'action'         => $decision['action'],
                'profile_id'     => isset( $profile['id'] ) ? absint( $profile['id'] ) : 0,
                'context'        => $context,
            ]
        );

        do_action( 'qs_ip_risk_login_event_captured', $event_id, $event_type, $ip_address, $profile, $context, $decision );
        do_action( 'qs_ip_risk_action_decision', $decision, $profile, $event_type, $context );

        self::record_audit_if_needed( $event_type, $ip_address, $profile, $context, $decision );
    }

    private static function refresh_profile( $ip_address, $settings, $event_type, $context = [] ) {
        $ip_address = self::normalize_ip_address( $ip_address );
        if ( '' === $ip_address ) {
            return [];
        }

        if ( isset( self::$runtime_cache[ $ip_address ] ) && is_array( self::$runtime_cache[ $ip_address ] ) ) {
            return self::$runtime_cache[ $ip_address ];
        }

        $previous_context      = self::$lookup_context;
        self::$lookup_context  = is_array( $context ) ? $context : [];
        self::$lookup_context['event_type'] = sanitize_key( (string) $event_type );
        self::$lookup_context['query_mode'] = isset( self::$lookup_context['query_mode'] )
            ? sanitize_key( (string) self::$lookup_context['query_mode'] )
            : QS_Protection::get_ip_risk_query_mode( $settings );

        $profile = self::build_profile( $ip_address, $settings, $event_type );
        self::$lookup_context = $previous_context;

        if ( empty( $profile ) ) {
            return [];
        }

        QS_DB::upsert_ip_risk_profile( $ip_address, $profile );
        $stored = QS_DB::get_ip_risk_profile( $ip_address );
        $stored = ! empty( $stored ) ? $stored : $profile;

        if ( ! empty( $stored ) && is_array( $stored ) && method_exists( 'QS_DB', 'refresh_pending_ip_risk_events' ) ) {
            QS_DB::refresh_pending_ip_risk_events( $ip_address, $stored );
        }

        self::$runtime_cache[ $ip_address ] = $stored;

        do_action( 'qs_ip_risk_profile_refreshed', $ip_address, $stored, $event_type, $settings );

        return $stored;
    }

    public static function refresh_profile_for_admin( $ip_address, $event_type = 'admin_detail' ) {
        $settings = QS_Protection::get_settings();

        if ( ! QS_Protection::is_ip_risk_profile_enabled( $settings ) ) {
            return [];
        }

        $ip_address = self::normalize_ip_address( $ip_address );
        if ( '' === $ip_address ) {
            return [];
        }

        // Try cache first to reduce redundant API calls
        $profile = QS_DB::get_ip_risk_profile( $ip_address );
        $ttl     = QS_Protection::get_ip_risk_cache_ttl_seconds( $settings );

        if ( ! empty( $profile ) && self::is_profile_fresh( $profile, $ttl ) ) {
            return $profile;
        }

        $event_type = sanitize_key( (string) $event_type );
        if ( '' === $event_type ) {
            $event_type = 'admin_detail';
        }

        $profile = self::refresh_profile( $ip_address, $settings, $event_type );

        if ( empty( $profile ) ) {
            $profile = QS_DB::get_ip_risk_profile( $ip_address );
        }

        return is_array( $profile ) ? $profile : [];
    }

    private static function build_profile( $ip_address, $settings, $event_type ) {
        $ip_address = self::normalize_ip_address( $ip_address );
        if ( '' === $ip_address ) {
            return [];
        }

        if ( ! self::is_public_ip( $ip_address ) ) {
            return self::build_pending_profile( $ip_address, $event_type, 'private_ip' );
        }

        $providers = QS_Protection::get_ip_risk_provider_list( $settings );
        $providers = apply_filters( 'qs_ip_risk_provider_list', $providers, $settings, $event_type, $ip_address );
        $providers = is_array( $providers ) ? array_values( $providers ) : [];
        $providers = array_map(
            static function( $provider ) {
                return sanitize_key( str_replace( '-', '_', (string) $provider ) );
            },
            $providers
        );
        $providers = array_values( array_unique( array_filter( $providers ) ) );
        list( $providers, $provider_plan ) = self::resolve_lookup_providers( $providers, $settings, $event_type );

        do_action( 'qs_ip_risk_before_lookup', $ip_address, $providers, $event_type, $settings );

        $provider_results = [];
        $scores           = [];
        $signals          = [];
        $success_count    = 0;
        $error_count      = 0;

        foreach ( $providers as $provider ) {
            $result = self::query_provider( $provider, $ip_address, $settings );
            $result = apply_filters( 'qs_ip_risk_provider_result', $result, $provider, $ip_address, $event_type, $settings );
            $result = self::normalize_provider_result( $provider, $result );

            $provider_results[] = $result;

            if ( 'ok' === $result['status'] ) {
                $success_count++;
                if ( isset( $result['risk_score'] ) && is_numeric( $result['risk_score'] ) ) {
                    $scores[] = max( 0, min( 100, (int) $result['risk_score'] ) );
                }
                if ( ! empty( $result['signals'] ) && is_array( $result['signals'] ) ) {
                    foreach ( $result['signals'] as $signal ) {
                        $signal = sanitize_key( (string) $signal );
                        if ( '' !== $signal ) {
                            $signals[] = $signal;
                        }
                    }
                }
            } elseif ( 'error' === $result['status'] ) {
                $error_count++;
            }

            do_action( 'qs_ip_risk_provider_lookup_finished', $provider, $result, $ip_address, $event_type, $settings );
        }

        $signal_unique = array_values( array_unique( $signals ) );
        $risk_score    = self::compose_risk_score( $scores, $signal_unique, $success_count );
        $risk_level    = self::compose_risk_level( $risk_score, $success_count );
        $query_status  = $success_count > 0 ? 'ready' : ( $error_count > 0 ? 'failed' : 'skipped' );
        $profile       = [
            'ip_address'      => $ip_address,
            'ip_version'      => false !== strpos( $ip_address, ':' ) ? 6 : 4,
            'risk_score'      => $risk_score,
            'risk_level'      => $risk_level,
            'provider_count'  => $success_count,
            'query_status'    => $query_status,
            'providers'       => $provider_results,
            'summary'         => [
                'signals'       => $signal_unique,
                'providers'     => count( $provider_results ),
                'success_count' => $success_count,
                'error_count'   => $error_count,
                'score_samples' => $scores,
                'provider_plan' => $provider_plan,
            ],
            'source'          => 'ip_risk_profile',
            'last_event_type' => sanitize_key( (string) $event_type ),
        ];

        do_action( 'qs_ip_risk_profile_computed', $profile, $ip_address, $event_type, $settings );

        return $profile;
    }

    private static function resolve_lookup_providers( $providers, $settings, $event_type = '' ) {
        $providers = is_array( $providers ) ? array_values( array_unique( array_filter( $providers ) ) ) : [];
        $max_calls = QS_Protection::get_ip_risk_max_provider_calls( $settings );
        $event_type = sanitize_key( (string) $event_type );

        if ( empty( $providers ) ) {
            $providers = QS_Protection::get_ip_risk_provider_list( $settings );
            $providers = is_array( $providers ) ? array_values( array_unique( array_filter( $providers ) ) ) : [];
        }

        // In admin detail view, prefer complete data to avoid "single source looks empty" confusion.
        if ( 'admin_detail' === $event_type ) {
            $max_calls = max( $max_calls, count( $providers ) );
        }

        $credentials        = QS_Protection::get_ip_risk_provider_credentials( $settings );
        $resolved_providers = [];
        $missing_key        = [];

        foreach ( $providers as $provider ) {
            if ( self::provider_requires_api_key( $provider ) && ! self::provider_has_credential( $provider, $credentials ) ) {
                $missing_key[] = $provider;
                continue;
            }

            $resolved_providers[] = $provider;
        }

        $used_public_fallback = false;
        if ( empty( $resolved_providers ) ) {
            $fallback            = self::get_public_fallback_providers( $providers );
            $resolved_providers  = $fallback;
            $used_public_fallback = ! empty( $fallback );
        }

        $resolved_providers = array_slice( array_values( array_unique( array_filter( $resolved_providers ) ) ), 0, $max_calls );
        $provider_plan      = [
            'selected'             => $resolved_providers,
            'missing_key'          => array_values( array_unique( array_filter( $missing_key ) ) ),
            'used_public_fallback' => $used_public_fallback,
        ];

        $resolved_providers = apply_filters( 'qs_ip_risk_resolved_providers', $resolved_providers, $providers, $settings, $provider_plan );
        $resolved_providers = is_array( $resolved_providers ) ? array_values( array_unique( array_filter( $resolved_providers ) ) ) : [];
        $resolved_providers = array_slice( $resolved_providers, 0, $max_calls );
        $provider_plan['selected'] = $resolved_providers;

        return [ $resolved_providers, $provider_plan ];
    }

    private static function provider_requires_api_key( $provider ) {
        return in_array( (string) $provider, [ 'ipregistry', 'ipdata', 'ipbset' ], true );
    }

    private static function provider_has_credential( $provider, $credentials ) {
        $credentials = is_array( $credentials ) ? $credentials : [];
        $map         = [
            'ipregistry' => 'ipregistry_key',
            'ipdata'     => 'ipdata_key',
            'ipbset'     => 'ipbset_key',
        ];

        if ( ! isset( $map[ $provider ] ) ) {
            return true;
        }

        $credential_key = $map[ $provider ];
        return ! empty( $credentials[ $credential_key ] );
    }

    private static function get_public_fallback_providers( $providers = [] ) {
        $providers         = is_array( $providers ) ? $providers : [];
        $public_candidates = [];

        foreach ( $providers as $provider ) {
            if ( ! self::provider_requires_api_key( $provider ) ) {
                $public_candidates[] = $provider;
            }
        }

        $public_candidates = array_merge( $public_candidates, [ 'ip_api', 'ipinfo', 'ip_sb' ] );

        return array_values(
            array_filter(
                array_unique(
                    array_map(
                        static function( $provider ) {
                            return sanitize_key( str_replace( '-', '_', (string) $provider ) );
                        },
                        $public_candidates
                    )
                )
            )
        );
    }

    private static function query_provider( $provider, $ip_address, $settings ) {
        switch ( $provider ) {
            case 'ipregistry':
                return self::query_ipregistry( $ip_address, $settings );
            case 'ipdata':
                return self::query_ipdata( $ip_address, $settings );
            case 'ip_api':
                return self::query_ip_api( $ip_address, $settings );
            case 'ipinfo':
                return self::query_ipinfo( $ip_address, $settings );
            case 'ip_sb':
                return self::query_ip_sb( $ip_address, $settings );
            case 'ipbset':
                return self::query_ipbset( $ip_address, $settings );
            default:
                return [
                    'provider'   => $provider,
                    'status'     => 'skipped',
                    'reason'     => 'unsupported_provider',
                    'risk_score' => null,
                    'signals'    => [],
                    'data'       => [],
                ];
        }
    }

    private static function query_ipregistry( $ip_address, $settings ) {
        $credentials = QS_Protection::get_ip_risk_provider_credentials( $settings );
        $api_key     = isset( $credentials['ipregistry_key'] ) ? trim( (string) $credentials['ipregistry_key'] ) : '';
        if ( '' === $api_key ) {
            $api_key = 'tryout';
        }

        $base_url = 'https://api.ipregistry.co/' . rawurlencode( $ip_address ) . '?key=' . rawurlencode( $api_key );
        $response = self::http_get_json( $base_url, $settings );

        // If custom key failed, fallback to documented public tryout key.
        if ( ! $response['ok'] && 'tryout' !== $api_key ) {
            $api_key  = 'tryout';
            $base_url = 'https://api.ipregistry.co/' . rawurlencode( $ip_address ) . '?key=' . rawurlencode( $api_key );
            $response = self::http_get_json( $base_url, $settings );
        }

        if ( ! $response['ok'] ) {
            return self::build_error_result( 'ipregistry', $response['error'] );
        }

        $data     = is_array( $response['data'] ) ? $response['data'] : [];
        $security = isset( $data['security'] ) && is_array( $data['security'] ) ? $data['security'] : [];

        if ( empty( $security ) ) {
            $security_url  = 'https://api.ipregistry.co/' . rawurlencode( $ip_address ) . '?key=' . rawurlencode( $api_key ) . '&fields=security';
            $security_resp = self::http_get_json( $security_url, $settings );

            if ( ! empty( $security_resp['ok'] ) && is_array( $security_resp['data'] ) ) {
                $security_data = isset( $security_resp['data']['security'] ) && is_array( $security_resp['data']['security'] ) ? $security_resp['data']['security'] : [];
                if ( ! empty( $security_data ) ) {
                    $security         = $security_data;
                    $data['security'] = $security_data;
                }
            }
        }

        $conn    = isset( $data['connection'] ) && is_array( $data['connection'] ) ? $data['connection'] : [];
        $signals = [];
        $score   = 0;

        $score = max( $score, self::score_from_bool( $security, 'is_proxy', 60, 'proxy', $signals ) );
        $score = max( $score, self::score_from_bool( $security, 'is_tor', 85, 'tor', $signals ) );
        $score = max( $score, self::score_from_bool( $security, 'is_tor_exit', 88, 'tor', $signals ) );
        $score = max( $score, self::score_from_bool( $security, 'is_anonymous', 55, 'anonymous', $signals ) );
        $score = max( $score, self::score_from_bool( $security, 'is_vpn', 70, 'vpn', $signals ) );
        $score = max( $score, self::score_from_bool( $security, 'is_relay', 58, 'anonymous', $signals ) );
        $score = max( $score, self::score_from_bool( $security, 'is_cloud_provider', 42, 'datacenter', $signals ) );
        $score = max( $score, self::score_from_bool( $security, 'is_abuser', 75, 'abuse_medium', $signals ) );
        $score = max( $score, self::score_from_bool( $security, 'is_attacker', 82, 'abuse_high', $signals ) );
        $score = max( $score, self::score_from_bool( $security, 'is_threat', 82, 'abuse_high', $signals ) );
        $score = max( $score, self::score_from_bool( $security, 'is_bogon', 92, 'bogon', $signals ) );

        $connection_type = isset( $conn['type'] ) ? strtolower( (string) $conn['type'] ) : '';
        if ( self::contains_any_keyword( $connection_type, [ 'hosting', 'data center', 'cloud', 'dch', 'transit' ] ) ) {
            $score     = max( $score, 40 );
            $signals[] = 'datacenter';
        }

        return self::build_ok_result( 'ipregistry', $score, $signals, $data );
    }

    private static function query_ipdata( $ip_address, $settings ) {
        $credentials = QS_Protection::get_ip_risk_provider_credentials( $settings );
        $api_key     = isset( $credentials['ipdata_key'] ) ? trim( (string) $credentials['ipdata_key'] ) : '';

        if ( '' === $api_key ) {
            return self::build_skipped_result( 'ipdata', 'missing_api_key' );
        }

        $geo_url  = 'https://api.ipdata.co/' . rawurlencode( $ip_address ) . '?api-key=' . rawurlencode( $api_key ) . '&fields=ip,is_eu,city,region,region_code,country_name,country_code,continent_name,continent_code,latitude,longitude,postal,calling_code,flag,emoji_flag,emoji_unicode,time_zone,asn,threat';
        $geo_resp = self::http_get_json( $geo_url, $settings );

        if ( ! $geo_resp['ok'] ) {
            return self::build_error_result( 'ipdata', $geo_resp['error'] );
        }

        $threat_url  = 'https://api.ipdata.co/' . rawurlencode( $ip_address ) . '/threat?api-key=' . rawurlencode( $api_key );
        $threat_resp = self::http_get_json( $threat_url, $settings );

        $data   = is_array( $geo_resp['data'] ) ? $geo_resp['data'] : [];
        $threat = isset( $data['threat'] ) && is_array( $data['threat'] ) ? $data['threat'] : [];
        if ( $threat_resp['ok'] && is_array( $threat_resp['data'] ) ) {
            $threat         = array_merge( $threat, $threat_resp['data'] );
            $data['threat'] = $threat;
        }

        $asn = isset( $data['asn'] ) && is_array( $data['asn'] ) ? $data['asn'] : [];
        $signals = [];
        $score   = 0;

        $score = max( $score, self::score_from_bool( $threat, 'is_proxy', 60, 'proxy', $signals ) );
        $score = max( $score, self::score_from_bool( $threat, 'is_tor', 85, 'tor', $signals ) );
        $score = max( $score, self::score_from_bool( $threat, 'is_anonymous', 55, 'anonymous', $signals ) );
        $score = max( $score, self::score_from_bool( $threat, 'is_known_abuser', 75, 'abuse_medium', $signals ) );
        $score = max( $score, self::score_from_bool( $threat, 'is_known_attacker', 82, 'abuse_high', $signals ) );
        $score = max( $score, self::score_from_bool( $threat, 'is_bogon', 92, 'bogon', $signals ) );
        $score = max( $score, self::score_from_bool( $threat, 'is_datacenter', 42, 'datacenter', $signals ) );

        $asn_type = isset( $asn['type'] ) ? strtolower( (string) $asn['type'] ) : '';
        if ( self::contains_any_keyword( $asn_type, [ 'hosting', 'data center', 'cloud', 'transit' ] ) ) {
            $score     = max( $score, 40 );
            $signals[] = 'datacenter';
        }

        return self::build_ok_result( 'ipdata', $score, $signals, $data );
    }

    private static function query_ip_api( $ip_address, $settings ) {
        // Use optimized fields to avoid timeouts on public endpoint
        $fields   = 'status,message,continent,country,countryCode,region,regionName,city,zip,lat,lon,timezone,isp,org';
        $url      = 'http://ip-api.com/json/' . rawurlencode( $ip_address ) . '?fields=' . $fields;
        $response = self::http_get_json( $url, $settings, [ 'sslverify' => false ] );

        if ( ! $response['ok'] ) {
            return self::build_error_result( 'ip_api', $response['error'] );
        }

        $data = $response['data'];
        if ( isset( $data['status'] ) && 'success' !== (string) $data['status'] ) {
            return self::build_error_result( 'ip_api', isset( $data['message'] ) ? (string) $data['message'] : 'query_failed' );
        }

        $signals = [];
        $score   = 0;

        // Anonymity fields (proxy, hosting) are often missing or cause delays on free endpoint,
        // so we focus on geolocation/ISP data as per user feedback.

        return self::build_ok_result( 'ip_api', $score, $signals, $data );
    }

    private static function query_ipinfo( $ip_address, $settings ) {
        $credentials = QS_Protection::get_ip_risk_provider_credentials( $settings );
        $token       = isset( $credentials['ipinfo_token'] ) ? trim( (string) $credentials['ipinfo_token'] ) : '';
        $urls        = [];
        $ip_segment  = rawurlencode( $ip_address );
        $is_ipv6     = false !== strpos( $ip_address, ':' );
        $lite_hosts  = [ 'https://api.ipinfo.io' ];
        $lite_hosts[] = $is_ipv6 ? 'https://v6.api.ipinfo.io' : 'https://v4.api.ipinfo.io';

        foreach ( $lite_hosts as $lite_host ) {
            $url = rtrim( (string) $lite_host, '/' ) . '/lite/' . $ip_segment;
            if ( '' !== $token ) {
                $url .= '?token=' . rawurlencode( $token );
            }
            $urls[] = $url;
        }

        if ( '' !== $token ) {
            $urls[] = 'https://ipinfo.io/' . $ip_segment . '/json?token=' . rawurlencode( $token );
        } else {
            $urls[] = 'https://ipinfo.io/' . $ip_segment . '/json';
        }

        $urls = array_values( array_unique( array_filter( $urls ) ) );

        $response = [ 'ok' => false, 'error' => 'query_failed' ];
        foreach ( $urls as $url ) {
            $response = self::http_get_json( $url, $settings );
            if ( ! empty( $response['ok'] ) ) {
                break;
            }
        }

        if ( empty( $response['ok'] ) ) {
            return self::build_error_result( 'ipinfo', isset( $response['error'] ) ? $response['error'] : 'query_failed' );
        }

        $data       = is_array( $response['data'] ) ? $response['data'] : [];

        // Handle nested "geo" object in newer Lite API
        if ( isset( $data['geo'] ) && is_array( $data['geo'] ) ) {
            foreach ( [ 'country', 'country_code', 'continent', 'continent_code', 'region', 'city', 'timezone'] as $f ) {
                if ( isset( $data['geo'][$f] ) && ! isset( $data[$f] ) ) {
                    $data[$f] = $data['geo'][$f];
                }
            }
        }

        // Handle nested "as" or "asn" objects
        $asn_raw = isset( $data['as'] ) ? $data['as'] : ( isset( $data['asn'] ) ? $data['asn'] : [] );
        if ( ! is_array( $asn_raw ) && isset( $data['asn'] ) ) {
             $asn_raw = $data['asn']; // Could be a string in some versions
        }

        $privacy    = isset( $data['privacy'] ) && is_array( $data['privacy'] ) ? $data['privacy'] : [];
        $signals    = [];
        $score      = 0;
        $asn        = is_array( $asn_raw ) ? $asn_raw : [];
        $asn_code   = '';
        $asn_name   = '';
        $asn_domain = '';

        if ( is_string( $asn_raw ) ) {
            $asn_code = trim( $asn_raw );
        } elseif ( is_array( $asn_raw ) && isset( $asn_raw['asn'] ) ) {
            $asn_code = trim( (string) $asn_raw['asn'] );
        }

        if ( '' === $asn_code && isset( $data['asn_code'] ) ) {
            $asn_code = trim( (string) $data['asn_code'] );
        }

        $asn_name = isset( $data['as_name'] ) ? trim( (string) $data['as_name'] ) : '';
        if ( '' === $asn_name ) {
            if ( isset( $asn['name'] ) ) {
                $asn_name = trim( (string) $asn['name'] );
            } elseif ( isset( $data['org'] ) ) {
                $asn_name = trim( (string) $data['org'] );
            }
        }

        $asn_domain = isset( $data['as_domain'] ) ? trim( (string) $data['as_domain'] ) : '';
        if ( '' === $asn_domain && isset( $asn['domain'] ) ) {
            $asn_domain = trim( (string) $asn['domain'] );
        }

        if ( '' !== $asn_code ) {
            $data['asn'] = $asn_code;
        }
        if ( '' !== $asn_name ) {
            $data['as_name'] = $asn_name;
        }
        if ( '' !== $asn_domain ) {
            $data['as_domain'] = $asn_domain;
        }

        if ( self::to_bool( isset( $data['bogon'] ) ? $data['bogon'] : null ) ) {
            $score     = max( $score, 92 );
            $signals[] = 'bogon';
        }

        $score = max( $score, self::score_from_bool( $privacy, 'vpn', 70, 'vpn', $signals ) );
        $score = max( $score, self::score_from_bool( $privacy, 'proxy', 60, 'proxy', $signals ) );
        $score = max( $score, self::score_from_bool( $privacy, 'tor', 85, 'tor', $signals ) );
        $score = max( $score, self::score_from_bool( $privacy, 'hosting', 42, 'datacenter', $signals ) );
        $score = max( $score, self::score_from_bool( $privacy, 'relay', 58, 'anonymous', $signals ) );

        $org_hint = strtolower(
            trim(
                implode(
                    ' ',
                    array_filter(
                        [
                            isset( $data['org'] ) ? (string) $data['org'] : '',
                            $asn_name,
                            $asn_domain,
                            isset( $asn['type'] ) ? (string) $asn['type'] : '',
                        ]
                    )
                )
            )
        );
        if ( self::contains_any_keyword( $org_hint, [ 'hosting', 'data center', 'cloud', 'vps' ] ) ) {
            $score     = max( $score, 38 );
            $signals[] = 'datacenter';
        }

        return self::build_ok_result( 'ipinfo', $score, $signals, $data );
    }

    private static function query_ip_sb( $ip_address, $settings ) {
        $ip_address = self::normalize_ip_address( $ip_address );
        if ( '' === $ip_address ) {
            return self::build_skipped_result( 'ip_sb', 'invalid_ip' );
        }

        // According to official documentation: https://api.ip.sb/geoip/185.222.222.222
        $url  = 'https://api.ip.sb/geoip/' . str_replace( '%3A', ':', rawurlencode( $ip_address ) );
        $args = [
            'headers' => [
                'Accept' => 'application/json',
            ],
            // Some free services return visitor IP when called with a generic or missing User-Agent.
            'user-agent' => 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36 QilingSecurity/' . ( defined( 'QS_VERSION' ) ? QS_VERSION : '1.0' ),
        ];

        $response = self::http_get_json( $url, $settings, $args );

        if ( empty( $response['ok'] ) ) {
            return self::build_error_result( 'ip_sb', isset( $response['error'] ) ? $response['error'] : 'query_failed' );
        }

        $data      = $response['data'];
        $type      = isset( $data['type'] ) ? strtolower( (string) $data['type'] ) : '';
        $org       = strtolower(
            trim(
                implode(
                    ' ',
                    array_filter(
                        [
                            isset( $data['organization'] ) ? (string) $data['organization'] : '',
                            isset( $data['asn_organization'] ) ? (string) $data['asn_organization'] : '',
                            isset( $data['isp'] ) ? (string) $data['isp'] : '',
                        ]
                    )
                )
            )
        );
        $signals   = [];
        $score     = null;

        if ( self::contains_any_keyword( $type, [ 'hosting', 'data center', 'cloud', 'proxy', 'vps' ] ) || self::contains_any_keyword( $org, [ 'hosting', 'data center', 'cloud', 'vps' ] ) ) {
            $signals[] = 'datacenter';
            $score     = 38;
        }

        return self::build_ok_result( 'ip_sb', $score, $signals, $data );
    }
    private static function query_ipbset( $ip_address, $settings ) {
        $credentials = QS_Protection::get_ip_risk_provider_credentials( $settings );
        $api_key     = isset( $credentials['ipbset_key'] ) ? trim( (string) $credentials['ipbset_key'] ) : '';

        if ( '' === $api_key ) {
            return self::build_skipped_result( 'ipbset', 'missing_api_key' );
        }

        $url = add_query_arg(
            [
                'key'       => $api_key,
                'ipAddress' => $ip_address,
            ],
            'https://api.jishishuke.com/api/jsap/ipl/ipv4/risk/lite/v1'
        );

        $response = self::http_get_json( $url, $settings, [ 'headers' => [ 'Content-Type' => 'application/x-www-form-urlencoded;charset:utf-8' ] ] );

        if ( ! $response['ok'] ) {
            return self::build_error_result( 'ipbset', $response['error'] );
        }

        $json = $response['data'];
        if ( empty( $json['code'] ) || 200 !== (int) $json['code'] ) {
            return self::build_error_result( 'ipbset', ! empty( $json['msg'] ) ? (string) $json['msg'] : 'api_error' );
        }

        $data    = isset( $json['data'] ) ? $json['data'] : [];
        $signals = [];
        $score   = isset( $data['score'] ) ? (int) $data['score'] : 0;

        // Map boolean fields to signals
        self::score_from_bool( $data, 'isProxy', 0, 'proxy', $signals );
        self::score_from_bool( $data, 'proxy', 0, 'proxy', $signals );
        self::score_from_bool( $data, 'vpn', 0, 'vpn', $signals );
        self::score_from_bool( $data, 'tor', 0, 'tor', $signals );
        self::score_from_bool( $data, 'torExit', 0, 'tor', $signals );
        self::score_from_bool( $data, 'relay', 0, 'anonymous', $signals );
        self::score_from_bool( $data, 'anonymous', 0, 'anonymous', $signals );
        self::score_from_bool( $data, 'attacker', 0, 'abuse_high', $signals );
        self::score_from_bool( $data, 'bot', 0, 'abuse_medium', $signals );
        self::score_from_bool( $data, 'spam', 0, 'abuse_medium', $signals );
        self::score_from_bool( $data, 'idc', 0, 'datacenter', $signals );
        self::score_from_bool( $data, 'bogon', 0, 'bogon', $signals );

        return self::build_ok_result( 'ipbset', $score, $signals, $data );
    }


    private static function http_get_json( $url, $settings, $args = [] ) {
        $headers = isset( $args['headers'] ) && is_array( $args['headers'] ) ? $args['headers'] : [];
        $timeout = QS_Protection::get_ip_risk_provider_timeout_seconds( $settings );
        if ( ! empty( self::$lookup_context['force_short_io'] ) || 'sync' === ( isset( self::$lookup_context['query_mode'] ) ? self::$lookup_context['query_mode'] : '' ) ) {
            $timeout = min( $timeout, 1.5 );
        }
        $request = [
            'timeout'    => $timeout,
            'redirection' => 2,
            'sslverify'  => isset( $args['sslverify'] ) ? (bool) $args['sslverify'] : true,
            'headers'    => $headers,
            'user-agent' => isset( $args['user-agent'] ) ? (string) $args['user-agent'] : 'QilingSecurity/' . ( defined( 'QS_VERSION' ) ? QS_VERSION : '1.0.0' ),
        ];

        $response = wp_remote_get( $url, $request );
        if ( is_wp_error( $response ) ) {
            return [
                'ok'    => false,
                'error' => $response->get_error_message(),
            ];
        }

        $code = (int) wp_remote_retrieve_response_code( $response );
        $body = wp_remote_retrieve_body( $response );
        $json = json_decode( (string) $body, true );

        if ( ! is_array( $json ) ) {
            $body_text = trim( (string) $body );

            // JSONP fallback: callback({...});
            if ( preg_match( '/^[A-Za-z0-9_$]+\((.*)\)\s*;?$/s', $body_text, $matches ) && isset( $matches[1] ) ) {
                $json = json_decode( (string) $matches[1], true );
            }

            // Some providers may return trailing commas in object/array payload.
            if ( ! is_array( $json ) && '' !== $body_text ) {
                $normalized = preg_replace( '/,\s*([}\]])/', '$1', $body_text );
                if ( is_string( $normalized ) ) {
                    $json = json_decode( $normalized, true );
                }
            }
        }

        if ( $code < 200 || $code >= 300 ) {
            $detail = is_array( $json ) && ! empty( $json['message'] ) ? (string) $json['message'] : 'http_' . $code;
            return [
                'ok'    => false,
                'error' => $detail,
            ];
        }

        if ( ! is_array( $json ) ) {
            return [
                'ok'    => false,
                'error' => 'invalid_json',
            ];
        }

        return [
            'ok'   => true,
            'data' => $json,
        ];
    }

    private static function build_ok_result( $provider, $risk_score, $signals, $data ) {
        $signals = is_array( $signals ) ? array_values( array_unique( array_filter( array_map( 'sanitize_key', $signals ) ) ) ) : [];
        $score   = null;

        if ( null !== $risk_score && is_numeric( $risk_score ) ) {
            $score = max( 0, min( 100, (int) $risk_score ) );
        }

        return [
            'provider'   => sanitize_key( (string) $provider ),
            'status'     => 'ok',
            'reason'     => '',
            'risk_score' => $score,
            'signals'    => $signals,
            'data'       => self::limit_provider_data( $data ),
        ];
    }

    private static function build_skipped_result( $provider, $reason ) {
        return [
            'provider'   => sanitize_key( (string) $provider ),
            'status'     => 'skipped',
            'reason'     => sanitize_key( (string) $reason ),
            'risk_score' => null,
            'signals'    => [],
            'data'       => [],
        ];
    }

    private static function build_error_result( $provider, $error ) {
        return [
            'provider'   => sanitize_key( (string) $provider ),
            'status'     => 'error',
            'reason'     => sanitize_text_field( (string) $error ),
            'risk_score' => null,
            'signals'    => [],
            'data'       => [],
        ];
    }

    private static function normalize_provider_result( $provider, $result ) {
        if ( ! is_array( $result ) ) {
            return self::build_error_result( $provider, 'invalid_provider_result' );
        }

        $status = isset( $result['status'] ) ? sanitize_key( (string) $result['status'] ) : 'error';
        if ( ! in_array( $status, [ 'ok', 'error', 'skipped' ], true ) ) {
            $status = 'error';
        }

        $provider_name = isset( $result['provider'] ) ? sanitize_key( (string) $result['provider'] ) : sanitize_key( (string) $provider );
        $signals       = isset( $result['signals'] ) && is_array( $result['signals'] ) ? array_map( 'sanitize_key', $result['signals'] ) : [];
        $signals       = array_values( array_unique( array_filter( $signals ) ) );
        $risk_score    = null;
        if ( array_key_exists( 'risk_score', $result ) && null !== $result['risk_score'] && is_numeric( $result['risk_score'] ) ) {
            $risk_score = max( 0, min( 100, (int) $result['risk_score'] ) );
        }

        return [
            'provider'   => $provider_name,
            'status'     => $status,
            'reason'     => isset( $result['reason'] ) ? sanitize_text_field( (string) $result['reason'] ) : '',
            'risk_score' => $risk_score,
            'signals'    => $signals,
            'data'       => self::limit_provider_data( isset( $result['data'] ) ? $result['data'] : [] ),
        ];
    }

    private static function compose_risk_score( $scores, $signals, $success_count ) {
        $scores = array_values(
            array_filter(
                array_map(
                    static function( $value ) {
                        if ( null === $value || ! is_numeric( $value ) ) {
                            return null;
                        }

                        return max( 0, min( 100, (int) $value ) );
                    },
                    (array) $scores
                ),
                static function( $value ) {
                    return null !== $value;
                }
            )
        );

        if ( empty( $scores ) ) {
            $score = $success_count > 0 ? 0 : 0;
        } else {
            $score = (int) round( array_sum( $scores ) / count( $scores ) );
        }

        return self::apply_signal_floor( $score, (array) $signals );
    }

    private static function compose_risk_level( $score, $success_count ) {
        $score = max( 0, min( 100, (int) $score ) );

        if ( $success_count <= 0 ) {
            return 'unknown';
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

        return 'safe';
    }

    private static function apply_signal_floor( $score, $signals ) {
        $score   = max( 0, min( 100, (int) $score ) );
        $signals = array_values( array_unique( array_filter( array_map( 'sanitize_key', (array) $signals ) ) ) );

        if ( in_array( 'bogon', $signals, true ) ) {
            $score = max( $score, 90 );
        }
        if ( in_array( 'abuse_high', $signals, true ) ) {
            $score = max( $score, 80 );
        }
        if ( in_array( 'tor', $signals, true ) ) {
            $score = max( $score, 78 );
        }
        if ( in_array( 'abuse_medium', $signals, true ) ) {
            $score = max( $score, 62 );
        }
        if ( in_array( 'vpn', $signals, true ) ) {
            $score = max( $score, 58 );
        }
        if ( in_array( 'proxy', $signals, true ) ) {
            $score = max( $score, 52 );
        }
        if ( in_array( 'datacenter', $signals, true ) ) {
            $score = max( $score, 35 );
        }

        return $score;
    }

    private static function build_pending_profile( $ip_address, $event_type, $status = 'pending' ) {
        $ip_address = self::normalize_ip_address( $ip_address );

        return [
            'ip_address'      => $ip_address,
            'ip_version'      => '' === $ip_address ? 0 : ( false !== strpos( $ip_address, ':' ) ? 6 : 4 ),
            'risk_score'      => 0,
            'risk_level'      => 'unknown',
            'provider_count'  => 0,
            'query_status'    => sanitize_key( (string) $status ),
            'providers'       => [],
            'summary'         => [],
            'source'          => 'ip_risk_profile',
            'last_event_type' => sanitize_key( (string) $event_type ),
        ];
    }

    private static function should_fail_open_sync_lookup( $profile ) {
        if ( empty( $profile ) || ! is_array( $profile ) ) {
            return true;
        }

        $status = isset( $profile['query_status'] ) ? sanitize_key( (string) $profile['query_status'] ) : '';

        return in_array( $status, [ 'failed', 'missing', 'pending', 'pending_async', 'pending_external' ], true );
    }

    private static function normalize_profile_for_event( $profile, $stale = false, $ip_address = '', $event_type = '' ) {
        $profile = is_array( $profile ) ? $profile : [];

        if ( empty( $profile ) ) {
            return self::build_pending_profile( $ip_address, $event_type, 'missing' );
        }

        $profile['risk_score']     = isset( $profile['risk_score'] ) ? max( 0, min( 100, (int) $profile['risk_score'] ) ) : 0;
        $profile['risk_level']     = isset( $profile['risk_level'] ) ? sanitize_key( (string) $profile['risk_level'] ) : 'unknown';
        $profile['provider_count'] = isset( $profile['provider_count'] ) ? max( 0, (int) $profile['provider_count'] ) : 0;
        $profile['query_status']   = isset( $profile['query_status'] ) ? sanitize_key( (string) $profile['query_status'] ) : 'unknown';

        if ( $stale && 'ready' === $profile['query_status'] ) {
            $profile['query_status'] = 'stale';
        }

        return $profile;
    }

    private static function is_profile_fresh( $profile, $ttl_seconds ) {
        if ( empty( $profile ) || ! is_array( $profile ) ) {
            return false;
        }

        $status = isset( $profile['query_status'] ) ? sanitize_key( (string) $profile['query_status'] ) : '';
        if ( in_array( $status, [ 'pending', 'pending_async', 'pending_external', 'missing' ], true ) ) {
            return false;
        }

        $updated_at = isset( $profile['updated_at'] ) ? (string) $profile['updated_at'] : '';
        if ( '' === $updated_at && ! empty( $profile['last_seen'] ) ) {
            $updated_at = (string) $profile['last_seen'];
        }

        $updated_ts = strtotime( $updated_at );
        if ( ! $updated_ts ) {
            return false;
        }

        return ( time() - $updated_ts ) <= max( HOUR_IN_SECONDS, (int) $ttl_seconds );
    }

    private static function schedule_profile_refresh( $ip_address, $event_type ) {
        if ( ! function_exists( 'wp_schedule_single_event' ) ) {
            return;
        }

        if ( 'external' === QS_Protection::get_ip_risk_query_mode() ) {
            return;
        }

        $ip_address = self::normalize_ip_address( $ip_address );
        $event_type = sanitize_key( (string) $event_type );
        if ( '' === $ip_address || '' === $event_type ) {
            return;
        }

        if ( wp_next_scheduled( self::ASYNC_REFRESH_HOOK, [ $ip_address, $event_type ] ) ) {
            return;
        }

        wp_schedule_single_event( time() + 5, self::ASYNC_REFRESH_HOOK, [ $ip_address, $event_type ] );

        if ( function_exists( 'spawn_cron' ) ) {
            if ( ! function_exists( 'wp_doing_cron' ) || ! wp_doing_cron() ) {
                spawn_cron( time() );
            }
        }
    }

    private static function unschedule_profile_refresh( $ip_address, $event_type ) {
        if ( ! function_exists( 'wp_next_scheduled' ) || ! function_exists( 'wp_unschedule_event' ) ) {
            return;
        }

        $args = [ $ip_address, $event_type ];

        while ( true ) {
            $timestamp = wp_next_scheduled( self::ASYNC_REFRESH_HOOK, $args );
            if ( empty( $timestamp ) ) {
                break;
            }

            wp_unschedule_event( $timestamp, self::ASYNC_REFRESH_HOOK, $args );
        }
    }

    private static function make_action_decision( $profile ) {
        $profile = is_array( $profile ) ? $profile : [];
        $level   = isset( $profile['risk_level'] ) ? sanitize_key( (string) $profile['risk_level'] ) : 'unknown';
        $score   = isset( $profile['risk_score'] ) ? (int) $profile['risk_score'] : 0;
        $action  = 'observe';

        if ( in_array( $level, [ 'high', 'critical' ], true ) ) {
            $action = 'alert';
        }

        return [
            'action' => $action,
            'level'  => $level,
            'score'  => $score,
        ];
    }

    private static function build_event_context( $context, $settings, $event_type ) {
        $context = is_array( $context ) ? $context : [];

        $context['event_type']    = sanitize_key( (string) $event_type );
        $context['query_mode']    = QS_Protection::get_ip_risk_query_mode( $settings );
        $context['scope']         = QS_Protection::get_ip_risk_scope( $settings );
        $context['request_path']  = QS_Audit::get_request_path();
        $context['user_agent']    = isset( $_SERVER['HTTP_USER_AGENT'] ) ? substr( sanitize_text_field( wp_unslash( $_SERVER['HTTP_USER_AGENT'] ) ), 0, 255 ) : '';
        $context['provider_list'] = QS_Protection::get_ip_risk_provider_list( $settings );

        if ( empty( $context['username'] ) ) {
            $context['username'] = 'unknown';
        }

        $context['username'] = substr( sanitize_user( (string) $context['username'], true ), 0, 60 );
        $context['user_id']  = isset( $context['user_id'] ) ? absint( $context['user_id'] ) : 0;

        return $context;
    }

    private static function record_audit_if_needed( $event_type, $ip_address, $profile, $context, $decision ) {
        $risk_level = isset( $profile['risk_level'] ) ? (string) $profile['risk_level'] : 'unknown';
        $status     = isset( $profile['query_status'] ) ? (string) $profile['query_status'] : 'unknown';

        if ( ! in_array( $risk_level, [ 'high', 'critical' ], true ) && ! in_array( $status, [ 'failed', 'stale' ], true ) ) {
            return;
        }

        $username = isset( $context['username'] ) ? (string) $context['username'] : 'unknown';
        $user_id  = isset( $context['user_id'] ) ? absint( $context['user_id'] ) : 0;
        $score    = isset( $profile['risk_score'] ) ? (int) $profile['risk_score'] : 0;
        $detail   = sprintf(
            '事件=%s，用户=%s，IP=%s，风险等级=%s，分数=%d，状态=%s，动作=%s',
            sanitize_key( (string) $event_type ),
            $username,
            $ip_address,
            sanitize_key( $risk_level ),
            $score,
            sanitize_key( $status ),
            sanitize_key( isset( $decision['action'] ) ? $decision['action'] : 'observe' )
        );

        QS_Audit::record_event(
            '登录 IP 风险画像命中',
            $detail,
            [
                'user_id'  => $user_id,
                'username' => $username,
                'ip'       => $ip_address,
            ]
        );
    }

    private static function score_from_bool( $data, $key, $score, $signal, &$signals ) {
        if ( ! is_array( $data ) || ! array_key_exists( $key, $data ) ) {
            return 0;
        }

        if ( self::to_bool( $data[ $key ] ) ) {
            $signals[] = sanitize_key( (string) $signal );
            return max( 0, min( 100, (int) $score ) );
        }

        return 0;
    }

    private static function to_bool( $value ) {
        if ( is_bool( $value ) ) {
            return $value;
        }

        if ( is_numeric( $value ) ) {
            return (int) $value > 0;
        }

        if ( is_string( $value ) ) {
            $value = strtolower( trim( $value ) );
            return in_array( $value, [ '1', 'true', 'yes', 'y', 'on' ], true );
        }

        return false;
    }

    private static function contains_any_keyword( $text, $keywords ) {
        $text = strtolower( trim( (string) $text ) );
        if ( '' === $text ) {
            return false;
        }

        foreach ( (array) $keywords as $keyword ) {
            $keyword = strtolower( trim( (string) $keyword ) );
            if ( '' === $keyword ) {
                continue;
            }

            if ( false !== strpos( $text, $keyword ) ) {
                return true;
            }
        }

        return false;
    }

    private static function is_public_ip( $ip_address ) {
        $flags = FILTER_FLAG_NO_PRIV_RANGE | FILTER_FLAG_NO_RES_RANGE;
        return (bool) filter_var( $ip_address, FILTER_VALIDATE_IP, $flags );
    }

    private static function normalize_ip_address( $ip_address ) {
        $ip_address = filter_var( trim( (string) $ip_address ), FILTER_VALIDATE_IP );
        return $ip_address ? $ip_address : '';
    }

    private static function limit_provider_data( $data ) {
        if ( ! is_array( $data ) ) {
            return [];
        }

        $json = wp_json_encode( $data );
        if ( ! is_string( $json ) || '' === $json ) {
            return [];
        }

        if ( strlen( $json ) <= 5000 ) {
            return $data;
        }

        return [
            'truncated' => true,
            'size'      => strlen( $json ),
            'hash'      => md5( $json ),
        ];
    }
}
