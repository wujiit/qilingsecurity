<?php
/**
 * 安全防护插件 - 操作审计日志与 IP 获取
 */
if ( ! defined( 'ABSPATH' ) ) exit;

class QS_Audit {

    public static function init() {
        $options = QS_Protection::get_settings();
        
        // 只有开启了审计日志才挂载钩子
        if ( empty($options['enable_audit_log']) ) {
            return;
        }

        // 用户登录与登出
        add_action('wp_login', [__CLASS__, 'log_login'], 10, 2);
        add_action('wp_login_failed', [__CLASS__, 'log_login_failed'], 20, 1);
        add_action('wp_logout', [__CLASS__, 'log_logout'], 10, 1);

        // 插件启用与停用
        add_action('activated_plugin', [__CLASS__, 'log_plugin_activation']);
        add_action('deactivated_plugin', [__CLASS__, 'log_plugin_deactivation']);

        // 重要选项更新 (避免全量记录，过滤掉瞬态和定时任务)
        add_action('updated_option', [__CLASS__, 'log_option_update'], 10, 3);
        
        // 文章与页面的删除操作
        add_action('delete_post', [__CLASS__, 'log_post_deletion'], 10, 2);
        add_action('trash_post', [__CLASS__, 'log_post_trash'], 10, 2);

        // 核心程序更新
        add_action('_core_updated_successfully', [__CLASS__, 'log_core_update']);
    }

    /**
     * 获取真实客户端 IP，穿透 CDN 和 WAF
     */
    public static function get_real_ip( $settings = null ) {
        $settings          = is_array( $settings ) ? $settings : QS_Protection::get_settings();
        $remote_addr       = self::get_remote_addr();
        $strict_proxy_mode = self::should_require_trusted_proxy( $settings );

        if ( $strict_proxy_mode && ! self::is_trusted_proxy( $remote_addr, $settings ) ) {
            return $remote_addr;
        }

        $forwarded_ip = self::get_forwarded_ip( $settings );

        return $forwarded_ip ? $forwarded_ip : $remote_addr;
    }

    public static function get_whitelisted_ips( $settings = null ) {
        $settings = is_array( $settings ) ? $settings : QS_Protection::get_settings();
        $ips      = QS_Protection::parse_list_setting( $settings['trusted_ips'] );

        return apply_filters( 'qs_trusted_ips', $ips, $settings );
    }

    public static function is_ip_whitelisted( $ip = '', $settings = null ) {
        $settings = is_array( $settings ) ? $settings : QS_Protection::get_settings();
        $ip       = $ip ? $ip : self::get_real_ip( $settings );

        if ( empty( $ip ) || '0.0.0.0' === $ip ) {
            return false;
        }

        foreach ( self::get_whitelisted_ips( $settings ) as $rule ) {
            if ( self::ip_matches_rule( $ip, $rule ) ) {
                return true;
            }
        }

        return false;
    }

    public static function get_request_path() {
        $request_uri = isset( $_SERVER['REQUEST_URI'] ) ? wp_unslash( $_SERVER['REQUEST_URI'] ) : '/';
        $path        = wp_parse_url( $request_uri, PHP_URL_PATH );
        $path        = is_string( $path ) ? $path : '/';

        return '/' . ltrim( $path, '/' );
    }

    public static function get_trusted_request_paths( $settings = null ) {
        $settings = is_array( $settings ) ? $settings : QS_Protection::get_settings();
        $paths    = QS_Protection::parse_list_setting( $settings['trusted_request_paths'] );

        return apply_filters( 'qs_trusted_request_paths', $paths, $settings );
    }

    public static function is_request_path_whitelisted( $path = '', $settings = null ) {
        $settings = is_array( $settings ) ? $settings : QS_Protection::get_settings();
        $path     = $path ? $path : self::get_request_path();
        $path     = '/' . ltrim( (string) $path, '/' );

        foreach ( self::get_trusted_request_paths( $settings ) as $rule ) {
            $rule = '/' . ltrim( trim( (string) $rule ), '/' );

            if ( '' === trim( $rule, '/' ) ) {
                continue;
            }

            if ( '*' === substr( $rule, -1 ) ) {
                $rule = rtrim( $rule, '*' );
            }

            if ( untrailingslashit( $path ) === untrailingslashit( $rule ) ) {
                return true;
            }

            if ( 0 === strpos( trailingslashit( $path ), trailingslashit( $rule ) ) ) {
                return true;
            }
        }

        return false;
    }

    public static function is_current_request_trusted( $settings = null ) {
        $settings = is_array( $settings ) ? $settings : QS_Protection::get_settings();

        return self::is_ip_whitelisted( '', $settings ) || self::is_request_path_whitelisted( '', $settings );
    }

    public static function get_ip_resolution_debug_info( $settings = null ) {
        $settings          = is_array( $settings ) ? $settings : QS_Protection::get_settings();
        $remote_addr       = self::get_remote_addr();
        $strict_proxy_mode = self::should_require_trusted_proxy( $settings );
        $proxy_trusted     = self::is_trusted_proxy( $remote_addr, $settings );
        $details           = self::get_forwarded_ip_details( $settings );
        $headers_seen      = self::has_forwarded_headers( $settings );
        $resolved_ip       = $remote_addr;

        if ( ! empty( $details['ip'] ) ) {
            if ( $strict_proxy_mode ) {
                $resolved_ip = $proxy_trusted ? $details['ip'] : $remote_addr;
            } else {
                $resolved_ip = $details['ip'];
            }
        }

        return [
            'remote_addr'    => $remote_addr,
            'resolved_ip'    => $resolved_ip,
            'forwarded_ip'   => ! empty( $details['ip'] ) ? $details['ip'] : '',
            'forwarded_from' => ! empty( $details['header'] ) ? $details['header'] : '',
            'proxy_trusted'  => $proxy_trusted,
            'strict_proxy_mode' => $strict_proxy_mode,
            'headers_seen'   => $headers_seen,
            'proxy_rules'    => self::get_trusted_proxy_rules( $settings ),
        ];
    }

    private static function get_remote_addr() {
        $remote_addr = isset( $_SERVER['REMOTE_ADDR'] ) ? wp_unslash( $_SERVER['REMOTE_ADDR'] ) : '0.0.0.0';
        $remote_addr = filter_var( $remote_addr, FILTER_VALIDATE_IP );

        return $remote_addr ? $remote_addr : '0.0.0.0';
    }

    private static function get_forwarded_ip( $settings = null ) {
        $details = self::get_forwarded_ip_details( $settings );

        return ! empty( $details['ip'] ) ? $details['ip'] : '';
    }

    private static function get_forwarded_ip_details( $settings = null ) {
        $settings          = is_array( $settings ) ? $settings : QS_Protection::get_settings();
        $headers           = apply_filters( 'qs_trusted_proxy_headers', QS_Protection::get_trusted_proxy_headers( $settings ) );
        $proxies           = self::get_trusted_proxy_rules( $settings );
        $strict_proxy_mode = self::should_require_trusted_proxy( $settings );

        foreach ( (array) $headers as $header_name ) {
            if ( empty( $_SERVER[ $header_name ] ) ) {
                continue;
            }

            $raw_value  = wp_unslash( $_SERVER[ $header_name ] );
            $candidate  = self::resolve_forwarded_header_ip( $header_name, $raw_value, $proxies, $strict_proxy_mode );

            if ( $candidate ) {
                return [
                    'ip'     => $candidate,
                    'header' => $header_name,
                ];
            }
        }

        return [
            'ip'     => '',
            'header' => '',
        ];
    }

    private static function is_trusted_proxy( $remote_addr, $settings = null ) {
        if ( empty( $remote_addr ) || '0.0.0.0' === $remote_addr ) {
            return false;
        }

        $settings        = is_array( $settings ) ? $settings : QS_Protection::get_settings();
        $trusted_proxies = self::get_trusted_proxy_rules( $settings );

        foreach ( (array) $trusted_proxies as $proxy_rule ) {
            if ( self::ip_matches_rule( $remote_addr, $proxy_rule ) ) {
                return true;
            }
        }

        return false;
    }

    private static function should_require_trusted_proxy( $settings = null ) {
        $settings = is_array( $settings ) ? $settings : QS_Protection::get_settings();

        return empty( $settings['trust_proxy_headers_without_ip'] );
    }

    private static function has_forwarded_headers( $settings = null ) {
        $settings = is_array( $settings ) ? $settings : QS_Protection::get_settings();
        $headers  = apply_filters( 'qs_trusted_proxy_headers', QS_Protection::get_trusted_proxy_headers( $settings ) );

        foreach ( (array) $headers as $header_name ) {
            if ( ! empty( $_SERVER[ $header_name ] ) ) {
                return true;
            }
        }

        return false;
    }

    private static function get_trusted_proxy_rules( $settings = null ) {
        $settings = is_array( $settings ) ? $settings : QS_Protection::get_settings();
        $proxies  = array_merge(
            QS_Protection::get_trusted_proxy_ips( $settings ),
            (array) apply_filters( 'qs_trusted_proxy_ips', [], $settings )
        );

        $proxies = array_map( 'trim', array_map( 'strval', $proxies ) );
        $proxies = array_values( array_unique( array_filter( $proxies ) ) );

        return $proxies;
    }

    private static function resolve_forwarded_header_ip( $header_name, $raw_value, $trusted_proxies, $strict_proxy_mode = true ) {
        if ( 'HTTP_X_FORWARDED_FOR' !== $header_name ) {
            $candidate = filter_var( trim( (string) $raw_value ), FILTER_VALIDATE_IP );

            return $candidate ? $candidate : '';
        }

        if ( ! $strict_proxy_mode ) {
            $candidates = array_map( 'trim', explode( ',', (string) $raw_value ) );

            foreach ( $candidates as $candidate ) {
                $candidate = filter_var( $candidate, FILTER_VALIDATE_IP );

                if ( $candidate ) {
                    return $candidate;
                }
            }

            return '';
        }

        $candidates = array_reverse( array_map( 'trim', explode( ',', (string) $raw_value ) ) );

        foreach ( $candidates as $candidate ) {
            $candidate = filter_var( $candidate, FILTER_VALIDATE_IP );

            if ( ! $candidate ) {
                continue;
            }

            if ( self::matches_any_ip_rule( $candidate, $trusted_proxies ) ) {
                continue;
            }

            return $candidate;
        }

        return '';
    }

    private static function matches_any_ip_rule( $ip, $rules ) {
        foreach ( (array) $rules as $rule ) {
            if ( self::ip_matches_rule( $ip, $rule ) ) {
                return true;
            }
        }

        return false;
    }

    private static function ip_matches_rule( $ip, $rule ) {
        $rule = trim( (string) $rule );

        if ( '' === $rule ) {
            return false;
        }

        if ( false === strpos( $rule, '/' ) ) {
            return $ip === $rule;
        }

        list( $subnet, $mask_bits ) = explode( '/', $rule, 2 );
        $ip_binary     = @inet_pton( $ip );
        $subnet_binary = @inet_pton( $subnet );
        $mask_bits     = (int) $mask_bits;

        if ( false === $ip_binary || false === $subnet_binary || strlen( $ip_binary ) !== strlen( $subnet_binary ) ) {
            return false;
        }

        $max_bits = strlen( $ip_binary ) * 8;
        if ( $mask_bits < 0 || $mask_bits > $max_bits ) {
            return false;
        }

        $full_bytes = intdiv( $mask_bits, 8 );
        $extra_bits = $mask_bits % 8;

        if ( $full_bytes > 0 && substr( $ip_binary, 0, $full_bytes ) !== substr( $subnet_binary, 0, $full_bytes ) ) {
            return false;
        }

        if ( 0 === $extra_bits ) {
            return true;
        }

        $mask = ( 0xFF << ( 8 - $extra_bits ) ) & 0xFF;

        return ( ord( $ip_binary[ $full_bytes ] ) & $mask ) === ( ord( $subnet_binary[ $full_bytes ] ) & $mask );
    }

    /**
     * 底层日志插入辅助函数
     */
    private static function insert_log_entry( $action_type, $detail = '', $context = [] ) {
        $context  = is_array( $context ) ? $context : [];
        $user_id  = isset( $context['user_id'] ) ? absint( $context['user_id'] ) : get_current_user_id();
        $username = isset( $context['username'] ) ? self::normalize_audit_username( $context['username'] ) : '';
        $ip       = isset( $context['ip'] ) ? sanitize_text_field( (string) $context['ip'] ) : self::get_real_ip();

        if ( '' === $username ) {
            $user     = wp_get_current_user();
            $username = $user->exists() ? $user->user_login : 'System/Guest';
        }

        QS_DB::insert_audit_log( $user_id, $username, $action_type, $detail, $ip );
    }

    private static function insert_log( $action_type, $detail = '' ) {
        self::insert_log_entry( $action_type, $detail );
    }

    private static function normalize_audit_username( $username ) {
        $username = sanitize_text_field( (string) $username );

        if ( '' === $username ) {
            return '';
        }

        return substr( $username, 0, 60 );
    }

    private static function build_login_attempt_suffix( $ip ) {
        $parts = [];
        $path  = self::get_request_path();

        if ( $path ) {
            $parts[] = "入口 [{$path}]";
        }

        if ( $ip && '0.0.0.0' !== $ip ) {
            $settings = QS_Protection::get_settings();

            if ( ! empty( $settings['limit_login_attempts'] ) ) {
                $fail_count = (int) get_transient( 'qs_login_fails_' . md5( $ip ) );

                if ( $fail_count > 0 ) {
                    $parts[] = "当前连续失败 {$fail_count} 次";
                }

                if ( QS_DB::is_ip_banned( $ip ) ) {
                    $parts[] = '来源 IP 已被临时封禁';
                }
            }
        }

        return empty( $parts ) ? '' : '；' . implode( '；', $parts );
    }

    public static function record_manual_event( $action_type, $detail = '' ) {
        $settings = QS_Protection::get_settings();

        if ( empty( $settings['enable_audit_log'] ) ) {
            return;
        }

        self::insert_log( $action_type, $detail );
    }

    public static function record_event( $action_type, $detail = '', $context = [] ) {
        $settings = QS_Protection::get_settings();

        if ( empty( $settings['enable_audit_log'] ) ) {
            return;
        }

        self::insert_log_entry( $action_type, $detail, $context );
    }

    public static function log_login( $user_login, $user ) {
        $user_login = self::normalize_audit_username( $user_login );
        $detail     = "身份验证通过 [{$user_login}]";
        $path       = self::get_request_path();

        if ( $path ) {
            $detail .= "；入口 [{$path}]";
        }

        self::insert_log_entry(
            '登录成功',
            $detail,
            [
                'user_id'  => isset( $user->ID ) ? absint( $user->ID ) : 0,
                'username' => $user_login,
            ]
        );
    }

    public static function log_login_failed( $username ) {
        $username = self::normalize_audit_username( $username );
        $ip       = self::get_real_ip();
        $detail   = '身份验证失败';

        if ( '' !== $username ) {
            $detail .= " [{$username}]";
        }

        $detail .= self::build_login_attempt_suffix( $ip );

        self::insert_log_entry(
            '登录失败',
            $detail,
            [
                'user_id'  => 0,
                'username' => $username ? $username : 'Unknown User',
                'ip'       => $ip,
            ]
        );
    }

    public static function log_logout( $user_id = 0 ) {
        self::insert_log( '登出系统', '用户主动终止会话' );
    }

    public static function log_plugin_activation( $plugin ) {
        self::insert_log( '启用插件', "插件路径: {$plugin}" );
    }

    public static function log_plugin_deactivation( $plugin ) {
        self::insert_log( '停用插件', "插件路径: {$plugin}" );
    }

    public static function log_option_update( $option, $old_value, $value ) {
        // 忽略缓存、定时任务、用户会话等极高频且无审计价值的 option
        if ( strpos($option, '_transient') !== false || strpos($option, 'session') !== false || $option === 'cron' ) {
            return;
        }
        $detail = "配置项 [{$option}] 被更新。";
        self::insert_log( '系统设置变更', $detail );
    }

    public static function log_post_deletion( $post_id, $post ) {
        if ( !in_array($post->post_type, ['post', 'page']) ) return;
        self::insert_log( '永久删除内容', "ID: {$post_id}, 标题: {$post->post_title}" );
    }

    public static function log_post_trash( $post_id, $post ) {
        if ( !in_array($post->post_type, ['post', 'page']) ) return;
        self::insert_log( '移至回收站', "ID: {$post_id}, 标题: {$post->post_title}" );
    }

    public static function log_core_update( $wp_version ) {
        self::insert_log( '核心系统升级', "已自动/手动更新至 WordPress v{$wp_version}" );
    }
}
