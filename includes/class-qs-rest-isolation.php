<?php
/**
 * 启灵安全防护 - REST 路由隔离与 API 防护模块
 *
 * @package QilingSecurity
 */

if ( ! defined( 'ABSPATH' ) ) {
    exit;
}

class QS_Rest_Isolation {

public static function get_rest_plugin_isolation_mu_plugin_filename() {
        return 'qs-route-isolation-loader.php';
    }

public static function get_rest_plugin_isolation_mu_plugin_path() {
        $mu_plugin_dir = defined( 'WPMU_PLUGIN_DIR' ) ? WPMU_PLUGIN_DIR : ( defined( 'WP_CONTENT_DIR' ) ? WP_CONTENT_DIR . '/mu-plugins' : ABSPATH . 'wp-content/mu-plugins' );

        return rtrim( (string) $mu_plugin_dir, "/\\" ) . '/' . self::get_rest_plugin_isolation_mu_plugin_filename();
    }

public static function is_rest_plugin_isolation_mu_plugin_installed() {
        $path = self::get_rest_plugin_isolation_mu_plugin_path();

        return '' !== $path && file_exists( $path );
    }

public static function get_rest_plugin_isolation_default_rule_lines() {
        $default_lines = [
            '/qilingtxt/v1/ => qilingtxt/qilingtxt.php',
        ];
        $default_lines = apply_filters( 'qs_rest_plugin_isolation_default_rule_lines', $default_lines );
        $default_lines = is_array( $default_lines ) ? $default_lines : [];

        $normalized = [];

        foreach ( $default_lines as $line ) {
            $rule = self::parse_rest_plugin_isolation_rule_line( $line );

            if ( empty( $rule ) ) {
                continue;
            }

            $normalized[] = $rule['route'] . ' => ' . implode( ', ', $rule['plugins'] );
        }

        if ( empty( $normalized ) ) {
            $normalized[] = '/qilingtxt/v1/ => qilingtxt/qilingtxt.php';
        }

        return array_values( array_unique( $normalized ) );
    }

public static function get_rest_plugin_isolation_default_rules_as_text() {
        return implode( "\n", self::get_rest_plugin_isolation_default_rule_lines() );
    }

public static function maybe_sync_rest_plugin_isolation_rules() {
        if ( ! self::should_sync_rest_plugin_isolation_rules_in_current_request() ) {
            return;
        }

        $default_lines = self::get_rest_plugin_isolation_default_rule_lines();
        $default_rules = self::parse_rest_plugin_isolation_rules_setting( implode( "\n", $default_lines ) );

        if ( empty( $default_rules ) ) {
            return;
        }

        $normalized_default_lines = [];
        foreach ( $default_rules as $rule ) {
            if ( empty( $rule['route'] ) || empty( $rule['plugins'] ) ) {
                continue;
            }

            $normalized_default_lines[] = $rule['route'] . ' => ' . implode( ', ', $rule['plugins'] );
        }

        if ( empty( $normalized_default_lines ) ) {
            return;
        }

        $signature_option_key = 'qs_rest_plugin_isolation_rule_sync_signature';
        $signature            = md5( implode( "\n", $normalized_default_lines ) );
        $saved_signature      = (string) get_option( $signature_option_key, '' );

        if ( $saved_signature === $signature ) {
            return;
        }

        $settings     = QS_Protection_Settings::load_settings_option_from_db();
        $settings     = is_array( $settings ) ? $settings : [];
        $current_text = isset( $settings['rest_plugin_isolation_rules'] ) ? (string) $settings['rest_plugin_isolation_rules'] : '';
        $current_text = self::sanitize_rest_plugin_isolation_rules_setting( $current_text );
        $current_rules = self::parse_rest_plugin_isolation_rules_setting( $current_text );

        $rule_map = [];

        foreach ( $current_rules as $rule ) {
            $route = isset( $rule['route'] ) ? (string) $rule['route'] : '';
            if ( '' === $route ) {
                continue;
            }

            $plugins = isset( $rule['plugins'] ) ? (array) $rule['plugins'] : [];
            if ( ! isset( $rule_map[ $route ] ) ) {
                $rule_map[ $route ] = [];
            }

            $rule_map[ $route ] = array_values( array_unique( array_merge( $rule_map[ $route ], $plugins ) ) );
        }

        foreach ( $default_rules as $rule ) {
            $route = isset( $rule['route'] ) ? (string) $rule['route'] : '';
            if ( '' === $route ) {
                continue;
            }

            $plugins = isset( $rule['plugins'] ) ? (array) $rule['plugins'] : [];
            if ( ! isset( $rule_map[ $route ] ) ) {
                $rule_map[ $route ] = [];
            }

            $rule_map[ $route ] = array_values( array_unique( array_merge( $rule_map[ $route ], $plugins ) ) );
        }

        $merged_rules = [];
        foreach ( $rule_map as $route => $plugins ) {
            $plugins = array_values( array_unique( array_filter( $plugins ) ) );
            if ( '' === $route || empty( $plugins ) ) {
                continue;
            }

            $merged_rules[] = [
                'route'   => $route,
                'plugins' => $plugins,
            ];
        }

        usort(
            $merged_rules,
            static function( $left, $right ) {
                return strlen( $right['route'] ) <=> strlen( $left['route'] );
            }
        );

        $merged_lines = [];
        foreach ( $merged_rules as $rule ) {
            $merged_lines[] = $rule['route'] . ' => ' . implode( ', ', $rule['plugins'] );
        }
        $merged_text = implode( "\n", $merged_lines );

        if ( $merged_text !== $current_text ) {
            $settings['rest_plugin_isolation_rules'] = $merged_text;
            update_option( 'qs_protection_settings', QS_Protection_Settings::sanitize_settings( $settings ) );
            QS_Protection_Settings::clear_settings_cache();
        }

        update_option( $signature_option_key, $signature, false );
    }

public static function should_sync_rest_plugin_isolation_rules_in_current_request() {
        if ( defined( 'WP_CLI' ) && WP_CLI ) {
            return true;
        }

        if ( function_exists( 'wp_doing_ajax' ) && wp_doing_ajax() ) {
            return true;
        }

        return is_admin();
    }

public static function get_rest_plugin_isolation_monitor_option_key() {
        return 'qs_rest_plugin_isolation_monitor_logs';
    }

public static function normalize_plugin_basename_setting( $value ) {
        $value = trim( str_replace( '\\', '/', (string) $value ) );
        $value = ltrim( $value, '/' );

        if ( '' === $value || false !== strpos( $value, '..' ) ) {
            return '';
        }

        if ( ! preg_match( '#^[A-Za-z0-9._-]+(?:/[A-Za-z0-9._-]+)*\.php$#', $value ) ) {
            return '';
        }

        return $value;
    }

public static function parse_plugin_basename_list_setting( $value ) {
        $items = QS_Protection_Settings::parse_list_setting( $value );
        $items = array_map( [ __CLASS__, 'normalize_plugin_basename_setting' ], $items );
        $items = array_values( array_unique( array_filter( $items ) ) );

        return $items;
    }

public static function sanitize_plugin_basename_list_setting( $value ) {
        return implode( "\n", self::parse_plugin_basename_list_setting( $value ) );
    }

public static function normalize_rest_isolation_route_prefix( $value ) {
        $value = trim( (string) $value );

        if ( '' === $value ) {
            return '';
        }

        $value = str_replace( '\\', '/', $value );
        $value = preg_replace( '#^https?://[^/]+#i', '', $value );
        $value = preg_replace( '/\s+/', '', $value );

        if ( false !== strpos( $value, '?' ) ) {
            $value = (string) strtok( $value, '?' );
        }

        if ( 0 === strpos( $value, '/wp-json' ) ) {
            $value = substr( $value, 8 );
        } elseif ( 0 === strpos( $value, 'wp-json/' ) ) {
            $value = substr( $value, 7 );
        }

        $value = rtrim( $value, '*' );
        $value = preg_replace( '#/+#', '/', $value );

        if ( '' === $value || '/' === $value ) {
            return '/';
        }

        if ( '/' !== substr( $value, 0, 1 ) ) {
            $value = '/' . $value;
        }

        return $value;
    }

public static function parse_rest_plugin_isolation_rule_line( $line ) {
        $line = trim( (string) $line );

        if ( '' === $line || 0 === strpos( $line, '#' ) || false === strpos( $line, '=>' ) ) {
            return [];
        }

        list( $route_part, $plugins_part ) = array_map( 'trim', explode( '=>', $line, 2 ) );
        $route   = self::normalize_rest_isolation_route_prefix( $route_part );
        $plugins = self::parse_plugin_basename_list_setting( $plugins_part );

        // 路由隔离仅作用于 REST API，不处理 admin-ajax action。
        if ( '/admin-ajax' === $route || 0 === strpos( $route, '/admin-ajax/' ) ) {
            return [];
        }

        if ( '' === $route || empty( $plugins ) ) {
            return [];
        }

        return [
            'route'   => $route,
            'plugins' => $plugins,
        ];
    }

public static function parse_rest_plugin_isolation_rules_setting( $value ) {
        if ( is_array( $value ) ) {
            $value = implode( "\n", array_map( 'strval', $value ) );
        }

        $lines = preg_split( '/\r\n|\r|\n/', (string) $value );
        $rules = [];

        foreach ( $lines as $line ) {
            $rule = self::parse_rest_plugin_isolation_rule_line( $line );

            if ( empty( $rule ) ) {
                continue;
            }

            $route = $rule['route'];

            if ( ! isset( $rules[ $route ] ) ) {
                $rules[ $route ] = [];
            }

            $rules[ $route ] = array_values( array_unique( array_merge( $rules[ $route ], $rule['plugins'] ) ) );
        }

        $normalized_rules = [];

        foreach ( $rules as $route => $plugins ) {
            $normalized_rules[] = [
                'route'   => $route,
                'plugins' => array_values( array_unique( array_filter( $plugins ) ) ),
            ];
        }

        usort(
            $normalized_rules,
            static function( $left, $right ) {
                return strlen( $right['route'] ) <=> strlen( $left['route'] );
            }
        );

        return $normalized_rules;
    }

public static function sanitize_rest_plugin_isolation_rules_setting( $value ) {
        $rules = self::parse_rest_plugin_isolation_rules_setting( $value );
        $lines = [];

        foreach ( $rules as $rule ) {
            if ( empty( $rule['route'] ) || empty( $rule['plugins'] ) ) {
                continue;
            }

            $lines[] = $rule['route'] . ' => ' . implode( ', ', $rule['plugins'] );
        }

        return implode( "\n", $lines );
    }

public static function get_rest_plugin_isolation_core_plugins( $settings = null ) {
        $settings = is_array( $settings ) ? $settings : QS_Protection_Settings::get_settings();
        $plugins  = self::parse_plugin_basename_list_setting( isset( $settings['rest_plugin_isolation_core_plugins'] ) ? $settings['rest_plugin_isolation_core_plugins'] : '' );

        if ( ! in_array( 'qilingsecurity/qilingsecurity.php', $plugins, true ) ) {
            $plugins[] = 'qilingsecurity/qilingsecurity.php';
        }

        return apply_filters( 'qs_rest_plugin_isolation_core_plugins', array_values( array_unique( $plugins ) ), $settings );
    }

public static function get_rest_plugin_isolation_rules( $settings = null ) {
        $settings = is_array( $settings ) ? $settings : QS_Protection_Settings::get_settings();
        $rules    = self::parse_rest_plugin_isolation_rules_setting( isset( $settings['rest_plugin_isolation_rules'] ) ? $settings['rest_plugin_isolation_rules'] : '' );

        return apply_filters( 'qs_rest_plugin_isolation_rules', $rules, $settings );
    }

public static function get_rest_plugin_isolation_monitor_max_entries( $settings = null ) {
        $settings = is_array( $settings ) ? $settings : QS_Protection_Settings::get_settings();
        $max      = isset( $settings['rest_plugin_isolation_monitor_max_entries'] ) ? absint( $settings['rest_plugin_isolation_monitor_max_entries'] ) : 100;

        return max( 20, min( 500, $max ) );
    }

public static function get_rest_plugin_isolation_monitor_logs( $limit = 100 ) {
        $limit = absint( $limit );
        if ( $limit <= 0 ) {
            $limit = self::get_rest_plugin_isolation_monitor_max_entries();
        }
        $limit = max( 1, min( 500, $limit ) );

        if ( class_exists( 'QS_DB' ) && method_exists( 'QS_DB', 'get_rest_isolation_logs' ) ) {
            $logs = QS_DB::get_rest_isolation_logs( $limit );
        } else {
            $logs = get_option( self::get_rest_plugin_isolation_monitor_option_key(), [] );
            $logs = is_array( $logs ) ? array_slice( $logs, 0, $limit ) : [];
        }

        $sanitized_logs = [];

        foreach ( $logs as $log ) {
            if ( ! is_array( $log ) ) {
                continue;
            }

            $route        = self::normalize_rest_isolation_route_prefix( isset( $log['route'] ) ? $log['route'] : '' );
            $matched_rule = self::normalize_rest_isolation_route_prefix( isset( $log['matched_rule'] ) ? $log['matched_rule'] : '' );
            $mode         = isset( $log['mode'] ) ? sanitize_key( (string) $log['mode'] ) : 'matched_only';
            $decision     = isset( $log['decision'] ) ? sanitize_key( (string) $log['decision'] ) : 'unknown';

            if ( ! in_array( $mode, [ 'matched_only', 'all_rest' ], true ) ) {
                $mode = 'matched_only';
            }

            $sanitized_logs[] = [
                'time'            => isset( $log['time'] ) ? sanitize_text_field( (string) $log['time'] ) : '',
                'route'           => '' !== $route ? $route : '/',
                'mode'            => $mode,
                'decision'        => $decision,
                'matched_rule'    => $matched_rule,
                'before_count'    => isset( $log['before_count'] ) ? max( 0, (int) $log['before_count'] ) : 0,
                'after_count'     => isset( $log['after_count'] ) ? max( 0, (int) $log['after_count'] ) : 0,
                'matched_plugins' => self::parse_plugin_basename_list_setting( isset( $log['matched_plugins'] ) ? $log['matched_plugins'] : [] ),
                'final_plugins'   => self::parse_plugin_basename_list_setting( isset( $log['final_plugins'] ) ? $log['final_plugins'] : [] ),
            ];
        }

        return $sanitized_logs;
    }

public static function clear_rest_plugin_isolation_monitor_logs() {
        $count = 0;

        if ( class_exists( 'QS_DB' ) && method_exists( 'QS_DB', 'clear_rest_isolation_logs' ) ) {
            $count += (int) QS_DB::clear_rest_isolation_logs();
        }

        $key         = self::get_rest_plugin_isolation_monitor_option_key();
        $legacy_logs = get_option( $key, [] );
        $count      += is_array( $legacy_logs ) ? count( $legacy_logs ) : 0;

        delete_option( $key );

        return $count;
    }

public static function normalize_rest_route_prefix( $prefix ) {
        $prefix = trim( (string) $prefix );

        if ( '' === $prefix ) {
            return '';
        }

        $parsed_path = wp_parse_url( $prefix, PHP_URL_PATH );
        if ( is_string( $parsed_path ) && '' !== $parsed_path ) {
            $prefix = $parsed_path;
        }

        $prefix = str_replace( '\\', '/', $prefix );
        $prefix = preg_replace( '#/+#', '/', $prefix );
        $prefix = '/' . ltrim( (string) $prefix, '/' );

        if ( 0 === strpos( $prefix, '/index.php/wp-json/' ) ) {
            $prefix = substr( $prefix, strlen( '/index.php/wp-json' ) );
        } elseif ( '/index.php/wp-json' === $prefix ) {
            return '';
        }

        if ( 0 === strpos( $prefix, '/wp-json/' ) ) {
            $prefix = substr( $prefix, strlen( '/wp-json' ) );
        } elseif ( '/wp-json' === $prefix ) {
            return '';
        }

        $prefix = '/' . trim( $prefix, '/' );

        return '/' === $prefix ? '' : $prefix;
    }

public static function route_matches_prefix_rules( $route, $rules ) {
        $route = self::normalize_rest_route_prefix( $route );

        if ( '' === $route ) {
            return false;
        }

        foreach ( (array) $rules as $rule ) {
            $rule = self::normalize_rest_route_prefix( $rule );

            if ( '' === $rule ) {
                continue;
            }

            if ( untrailingslashit( $route ) === untrailingslashit( $rule ) ) {
                return true;
            }

            if ( 0 === strpos( trailingslashit( $route ), trailingslashit( $rule ) ) ) {
                return true;
            }
        }

        return false;
    }

public static function record_rest_guard_event( $action_type, $route, $method, $settings, $extra = '' ) {
        $route = self::normalize_rest_route_prefix( $route );

        if ( '' === $route ) {
            return;
        }

        $method        = strtoupper( sanitize_text_field( (string) $method ) );
        $ip            = QS_Audit::get_real_ip( $settings );
        $transient_ttl = (int) apply_filters( 'qs_rest_guard_event_ttl', 600, $action_type, $route, $method, $settings );
        $transient_key = 'qs_rest_guard_' . md5( $action_type . '|' . $route . '|' . $method . '|' . $ip );

        if ( $transient_ttl > 0 && get_transient( $transient_key ) ) {
            return;
        }

        if ( $transient_ttl > 0 ) {
            set_transient( $transient_key, 1, $transient_ttl );
        }

        $detail = '游客访问 REST 路由 [' . $route . ']；方法 [' . $method . ']';

        if ( '' !== $extra ) {
            $detail .= '；' . sanitize_text_field( (string) $extra );
        }

        QS_Audit::record_event(
            $action_type,
            $detail,
            [
                'ip' => $ip,
            ]
        );

        QS_Alert_Center::trigger_event(
            'rest_guard',
            $action_type,
            [ $detail ],
            [
                'ip'          => $ip,
                'route'       => $route,
                'method'      => $method,
                'fingerprint' => 'rest-guard|' . $action_type . '|' . $route . '|' . $method . '|' . $ip,
            ]
        );
    }

public static function handle_rest_api_guard( $result, $server, $request, $settings ) {
        if ( $result instanceof WP_Error || is_user_logged_in() || QS_Audit::is_current_request_trusted( $settings ) ) {
            return $result;
        }

        if ( ! is_object( $request ) || ! method_exists( $request, 'get_route' ) ) {
            return $result;
        }

        $route = self::normalize_rest_route_prefix( $request->get_route() );

        if ( '' === $route ) {
            return $result;
        }

        $method           = method_exists( $request, 'get_method' ) ? strtoupper( (string) $request->get_method() ) : 'GET';
        $guard_mode       = QS_Protection_Settings::get_rest_api_guard_mode( $settings );
        $blocked_prefixes = QS_Protection_Settings::get_rest_api_public_block_prefixes( $settings );

        if ( self::route_matches_prefix_rules( $route, $blocked_prefixes ) ) {
            self::record_rest_guard_event( 'REST 敏感路由命中', $route, $method, $settings, '命中敏感公开路由规则。' );

            if ( 'block' === $guard_mode ) {
                return new WP_Error(
                    'qs_rest_guard_blocked',
                    '启灵安全防护：当前游客访问的 REST 路由属于敏感接口，已被策略拦截。',
                    [ 'status' => 403 ]
                );
            }

            return $result;
        }

        if ( empty( $settings['rest_api_observe_unknown_public'] ) || ! in_array( $method, [ 'GET', 'HEAD' ], true ) ) {
            return $result;
        }

        $allowed_prefixes = QS_Protection_Settings::get_rest_api_public_allow_prefixes( $settings );

        if ( self::route_matches_prefix_rules( $route, $allowed_prefixes ) ) {
            return $result;
        }

        self::record_rest_guard_event( 'REST 未知路由访问', $route, $method, $settings, '该路由不在允许公开前缀名单中，建议确认是否确需对游客开放。' );

        return $result;
    }
}
