<?php
/**
 * 安全防护插件 - 行为型请求限速
 */
if ( ! defined( 'ABSPATH' ) ) {
    exit;
}

class QS_Rate_Limiter {

    public static function init() {
        add_action( 'init', [ __CLASS__, 'maybe_handle_request' ], 3 );
    }

    public static function maybe_handle_request() {
        if ( is_admin() || self::is_runtime_exempt() ) {
            return;
        }

        $settings = QS_Protection::get_settings();
        $rules    = QS_Protection::get_rate_limit_rules( $settings );

        if ( empty( $rules ) ) {
            return;
        }

        if ( QS_Audit::is_current_request_trusted( $settings ) ) {
            return;
        }

        if ( is_user_logged_in() && current_user_can( 'edit_posts' ) ) {
            return;
        }

        $ip = QS_Audit::get_real_ip( $settings );

        if ( empty( $ip ) || '0.0.0.0' === $ip ) {
            return;
        }

        foreach ( $rules as $rule ) {
            if ( ! self::rule_matches_current_request( $rule ) ) {
                continue;
            }

            if ( ! empty( $rule['guest_only'] ) && is_user_logged_in() ) {
                continue;
            }

            $state = self::register_hit( $rule, $ip );

            if ( $state['count'] <= $rule['max_requests'] ) {
                continue;
            }

            self::record_rate_limit_event( $rule, $ip, $state );

            if ( 'observe' === $rule['mode'] ) {
                continue;
            }

            if ( 'ban' === $rule['mode'] ) {
                QS_DB::ban_ip( $ip, '触发行为限速规则：' . $rule['label'], $rule['ban_hours'] );
            }

            self::deny_request( $rule, $state );
        }
    }

    private static function is_runtime_exempt() {
        if ( function_exists( 'wp_doing_ajax' ) && wp_doing_ajax() ) {
            return true;
        }

        if ( function_exists( 'wp_doing_cron' ) && wp_doing_cron() ) {
            return true;
        }

        if ( defined( 'WP_CLI' ) && WP_CLI ) {
            return true;
        }

        return false;
    }

    private static function rule_matches_current_request( $rule ) {
        $match = isset( $rule['match'] ) ? (string) $rule['match'] : '';
        $path  = QS_Audit::get_request_path();
        $path  = '/' . ltrim( $path, '/' );

        switch ( $match ) {
            case 'xmlrpc':
                return 'xmlrpc.php' === basename( $path );

            case 'rest':
                return in_array( self::get_request_method(), [ 'GET', 'HEAD' ], true ) && self::is_rest_request_path( $path );

            case 'search':
                return 'GET' === self::get_request_method() && isset( $_GET['s'] );

            case 'comment':
                return 'POST' === self::get_request_method() && 'wp-comments-post.php' === basename( $path );
        }

        return false;
    }

    private static function is_rest_request_path( $path ) {
        $path        = '/' . ltrim( (string) $path, '/' );
        $rest_prefix = '/' . trim( rest_get_url_prefix(), '/' );

        if ( $path === $rest_prefix || false !== strpos( trailingslashit( $path ), trailingslashit( $rest_prefix ) ) ) {
            return true;
        }

        if ( isset( $_GET['rest_route'] ) ) {
            $rest_route = sanitize_text_field( wp_unslash( $_GET['rest_route'] ) );

            if ( '' !== trim( $rest_route ) ) {
                return true;
            }
        }

        return false;
    }

    private static function get_request_method() {
        $method = isset( $_SERVER['REQUEST_METHOD'] ) ? strtoupper( (string) wp_unslash( $_SERVER['REQUEST_METHOD'] ) ) : 'GET';

        return in_array( $method, [ 'GET', 'POST', 'PUT', 'PATCH', 'DELETE', 'HEAD', 'OPTIONS' ], true ) ? $method : 'GET';
    }

    private static function register_hit( $rule, $ip ) {
        $window_seconds = max( 60, absint( $rule['window_minutes'] ) * MINUTE_IN_SECONDS );
        $key            = self::get_bucket_key( $rule['id'], $ip );
        $now            = current_time( 'timestamp' );
        $entries        = get_transient( $key );
        $entries        = is_array( $entries ) ? $entries : [];
        $entries        = array_filter(
            $entries,
            static function( $timestamp ) use ( $now, $window_seconds ) {
                return absint( $timestamp ) > ( $now - $window_seconds );
            }
        );

        $entries[] = $now;
        set_transient( $key, array_values( $entries ), $window_seconds + MINUTE_IN_SECONDS );

        return [
            'count'          => count( $entries ),
            'window_seconds' => $window_seconds,
        ];
    }

    private static function record_rate_limit_event( $rule, $ip, $state ) {
        $lock_key = self::get_notice_lock_key( $rule['id'], $ip );

        if ( get_transient( $lock_key ) ) {
            return;
        }

        set_transient( $lock_key, 1, max( 60, absint( $state['window_seconds'] ) ) );

        $detail = sprintf(
            '规则 [%s] 命中；请求 %s %s；窗口 %d 分钟内第 %d 次访问，阈值 %d；动作 %s。',
            $rule['label'],
            self::get_request_method(),
            QS_Audit::get_request_path(),
            max( 1, absint( $rule['window_minutes'] ) ),
            absint( $state['count'] ),
            absint( $rule['max_requests'] ),
            self::get_mode_label( $rule['mode'] )
        );

        if ( 'ban' === $rule['mode'] ) {
            $detail .= sprintf( ' 已尝试封禁 %d 小时。', max( 1, absint( $rule['ban_hours'] ) ) );
        }

        QS_Audit::record_event(
            '行为限速触发',
            $detail,
            [
                'ip' => $ip,
            ]
        );
    }

    private static function deny_request( $rule, $state ) {
        status_header( 429 );
        nocache_headers();

        $message = sprintf(
            '<h1>请求过于频繁</h1><p>启灵安全防护已触发限速规则：<strong>%s</strong>。</p><p>在 %d 分钟内累计访问 %d 次，超过阈值 %d 次，请稍后再试。</p>',
            esc_html( $rule['label'] ),
            max( 1, absint( $rule['window_minutes'] ) ),
            absint( $state['count'] ),
            absint( $rule['max_requests'] )
        );

        if ( 'ban' === $rule['mode'] ) {
            $message .= sprintf( '<p>来源 IP 已被临时封禁 %d 小时。</p>', max( 1, absint( $rule['ban_hours'] ) ) );
        }

        wp_die( $message, 'Too Many Requests', [ 'response' => 429 ] );
    }

    private static function get_mode_label( $mode ) {
        $labels = [
            'observe' => '仅观察记录',
            'block'   => '直接拦截',
            'ban'     => '拦截并临时封禁',
        ];

        return isset( $labels[ $mode ] ) ? $labels[ $mode ] : '仅观察记录';
    }

    private static function get_bucket_key( $rule_id, $ip ) {
        return 'qs_rate_limit_' . sanitize_key( (string) $rule_id ) . '_' . md5( (string) $ip );
    }

    private static function get_notice_lock_key( $rule_id, $ip ) {
        return 'qs_rate_limit_notice_' . sanitize_key( (string) $rule_id ) . '_' . md5( (string) $ip );
    }
}
