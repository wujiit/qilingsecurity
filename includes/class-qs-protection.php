<?php
/**
 * 启灵安全防护 - 核心防护引擎与运行时拦截
 *
 * @package QilingSecurity
 */

if ( ! defined( 'ABSPATH' ) ) {
    exit;
}

require_once dirname( __FILE__ ) . '/class-qs-rest-isolation.php';
require_once dirname( __FILE__ ) . '/class-qs-localization-mode.php';
require_once dirname( __FILE__ ) . '/class-qs-protection-settings.php';

class QS_Protection extends QS_Protection_Settings {

    // =========================================================================
    // REST 路由隔离与 API 防护向前兼容转发
    // =========================================================================

    public static function get_rest_plugin_isolation_mu_plugin_filename(  ) {
        return QS_Rest_Isolation::get_rest_plugin_isolation_mu_plugin_filename(  );
    }

    public static function get_rest_plugin_isolation_mu_plugin_path(  ) {
        return QS_Rest_Isolation::get_rest_plugin_isolation_mu_plugin_path(  );
    }

    public static function is_rest_plugin_isolation_mu_plugin_installed(  ) {
        return QS_Rest_Isolation::is_rest_plugin_isolation_mu_plugin_installed(  );
    }

    public static function get_rest_plugin_isolation_default_rule_lines(  ) {
        return QS_Rest_Isolation::get_rest_plugin_isolation_default_rule_lines(  );
    }

    public static function get_rest_plugin_isolation_default_rules_as_text(  ) {
        return QS_Rest_Isolation::get_rest_plugin_isolation_default_rules_as_text(  );
    }

    public static function maybe_sync_rest_plugin_isolation_rules(  ) {
        return QS_Rest_Isolation::maybe_sync_rest_plugin_isolation_rules(  );
    }

    public static function should_sync_rest_plugin_isolation_rules_in_current_request(  ) {
        return QS_Rest_Isolation::should_sync_rest_plugin_isolation_rules_in_current_request(  );
    }

    public static function get_rest_plugin_isolation_monitor_option_key(  ) {
        return QS_Rest_Isolation::get_rest_plugin_isolation_monitor_option_key(  );
    }

    public static function normalize_plugin_basename_setting(  ) {
        return QS_Rest_Isolation::normalize_plugin_basename_setting(  );
    }

    public static function parse_plugin_basename_list_setting(  ) {
        return QS_Rest_Isolation::parse_plugin_basename_list_setting(  );
    }

    public static function sanitize_plugin_basename_list_setting(  ) {
        return QS_Rest_Isolation::sanitize_plugin_basename_list_setting(  );
    }

    public static function normalize_rest_isolation_route_prefix(  ) {
        return QS_Rest_Isolation::normalize_rest_isolation_route_prefix(  );
    }

    public static function parse_rest_plugin_isolation_rule_line(  ) {
        return QS_Rest_Isolation::parse_rest_plugin_isolation_rule_line(  );
    }

    public static function parse_rest_plugin_isolation_rules_setting(  ) {
        return QS_Rest_Isolation::parse_rest_plugin_isolation_rules_setting(  );
    }

    public static function sanitize_rest_plugin_isolation_rules_setting(  ) {
        return QS_Rest_Isolation::sanitize_rest_plugin_isolation_rules_setting(  );
    }

    public static function get_rest_plugin_isolation_core_plugins(  $settings = null  ) {
        return QS_Rest_Isolation::get_rest_plugin_isolation_core_plugins( $settings );
    }

    public static function get_rest_plugin_isolation_rules(  $settings = null  ) {
        return QS_Rest_Isolation::get_rest_plugin_isolation_rules( $settings );
    }

    public static function get_rest_plugin_isolation_monitor_max_entries(  $settings = null  ) {
        return QS_Rest_Isolation::get_rest_plugin_isolation_monitor_max_entries( $settings );
    }

    public static function get_rest_plugin_isolation_monitor_logs(  $limit = 100  ) {
        return QS_Rest_Isolation::get_rest_plugin_isolation_monitor_logs( $limit );
    }

    public static function clear_rest_plugin_isolation_monitor_logs(  ) {
        return QS_Rest_Isolation::clear_rest_plugin_isolation_monitor_logs(  );
    }

    public static function normalize_rest_route_prefix(  ) {
        return QS_Rest_Isolation::normalize_rest_route_prefix(  );
    }

    public static function route_matches_prefix_rules(  ) {
        return QS_Rest_Isolation::route_matches_prefix_rules(  );
    }

    public static function record_rest_guard_event(  ) {
        return QS_Rest_Isolation::record_rest_guard_event(  );
    }

    public static function handle_rest_api_guard(  ) {
        return QS_Rest_Isolation::handle_rest_api_guard(  );
    }

    // =========================================================================
    // 本地化与白标模式向前兼容转发
    // =========================================================================

    public static function is_localization_mode_enabled(  $settings = null  ) {
        return QS_Localization_Mode::is_localization_mode_enabled( $settings );
    }

    public static function get_localization_brand_label(  $settings = null  ) {
        return QS_Localization_Mode::get_localization_brand_label( $settings );
    }

    public static function strip_wordpress_brand_text(  $text  ) {
        return QS_Localization_Mode::strip_wordpress_brand_text( $text );
    }

    public static function get_empty_core_update_transient(  $pre = null  ) {
        return QS_Localization_Mode::get_empty_core_update_transient( $pre );
    }

    public static function get_empty_plugin_update_transient(  $pre = null  ) {
        return QS_Localization_Mode::get_empty_plugin_update_transient( $pre );
    }

    public static function get_empty_theme_update_transient(  $pre = null  ) {
        return QS_Localization_Mode::get_empty_theme_update_transient( $pre );
    }

    public static function is_wp_official_url(  $url  ) {
        return QS_Localization_Mode::is_wp_official_url( $url );
    }

    public static function maybe_block_wp_official_http_request(  $preempt, $args, $url  ) {
        return QS_Localization_Mode::maybe_block_wp_official_http_request( $preempt, $args, $url );
    }

    public static function remove_wp_update_hooks(  ) {
        return QS_Localization_Mode::remove_wp_update_hooks(  );
    }

    public static function apply_localization_mode(  $settings  ) {
        return QS_Localization_Mode::apply_localization_mode( $settings );
    }

    public static function remove_localization_admin_bar_nodes(  $wp_admin_bar  ) {
        return QS_Localization_Mode::remove_localization_admin_bar_nodes( $wp_admin_bar );
    }

    public static function print_localization_admin_css(  ) {
        return QS_Localization_Mode::print_localization_admin_css(  );
    }

    public static function remove_localization_admin_notices(  ) {
        return QS_Localization_Mode::remove_localization_admin_notices(  );
    }

    public static function remove_localization_dashboard_widgets(  ) {
        return QS_Localization_Mode::remove_localization_dashboard_widgets(  );
    }

    public static function print_localization_login_css(  $brand_label  ) {
        return QS_Localization_Mode::print_localization_login_css( $brand_label );
    }

    public static function block_localization_directory_api(  $result = null, $action = '', $args = null  ) {
        return QS_Localization_Mode::block_localization_directory_api( $result, $action, $args );
    }

    // =========================================================================
    // 核心主动防护引擎运行时与逻辑
    // =========================================================================

private static function get_login_gate_cookie_name() {
        return 'qs_login_gate_' . md5( home_url( '/' ) );
    }

private static function get_login_gate_cookie_value( $secret_key ) {
        return wp_hash( $secret_key . '|' . home_url( '/' ), 'auth' );
    }

private static function set_login_gate_cookie( $secret_key ) {
        $cookie_name  = self::get_login_gate_cookie_name();
        $cookie_value = self::get_login_gate_cookie_value( $secret_key );
        $expires      = time() + ( 12 * HOUR_IN_SECONDS );
        $cookie_path  = COOKIEPATH ? COOKIEPATH : '/';
        $secure       = is_ssl();

        setcookie( $cookie_name, $cookie_value, $expires, $cookie_path, COOKIE_DOMAIN, $secure, true );

        if ( SITECOOKIEPATH && SITECOOKIEPATH !== $cookie_path ) {
            setcookie( $cookie_name, $cookie_value, $expires, SITECOOKIEPATH, COOKIE_DOMAIN, $secure, true );
        }

        $_COOKIE[ $cookie_name ] = $cookie_value;
    }

private static function has_login_gate_cookie( $secret_key ) {
        $cookie_name = self::get_login_gate_cookie_name();

        if ( empty( $_COOKIE[ $cookie_name ] ) ) {
            return false;
        }

        $cookie_value = sanitize_text_field( wp_unslash( $_COOKIE[ $cookie_name ] ) );

        return hash_equals( self::get_login_gate_cookie_value( $secret_key ), $cookie_value );
    }

private static function is_wp_login_request() {
        $script_name = isset( $_SERVER['SCRIPT_NAME'] ) ? wp_unslash( $_SERVER['SCRIPT_NAME'] ) : '';

        return 'wp-login.php' === basename( $script_name );
    }

private static function get_login_request_action() {
        $action = isset( $_REQUEST['action'] ) ? sanitize_key( wp_unslash( $_REQUEST['action'] ) ) : '';

        return $action ? $action : 'login';
    }

private static function is_login_action_allowed_without_secret( $action ) {
        $allowed_actions = [
            'logout',
            'lostpassword',
            'retrievepassword',
            'resetpass',
            'rp',
            'postpass',
            'register',
            'checkemail',
            'confirm_admin_email',
        ];

        return in_array( $action, $allowed_actions, true ) || isset( $_REQUEST['interim-login'] );
    }

private static function append_secret_to_url( $url, $secret_key ) {
        if ( empty( $url ) ) {
            return $url;
        }

        $query = wp_parse_url( $url, PHP_URL_QUERY );
        if ( $query ) {
            parse_str( $query, $query_args );
            if ( isset( $query_args[ $secret_key ] ) ) {
                return $url;
            }
        }

        return add_query_arg( $secret_key, '1', $url );
    }

private static function protect_custom_login_url( $secret_key ) {
        if ( ! self::is_wp_login_request() ) {
            return;
        }

        if ( isset( $_GET[ $secret_key ] ) ) {
            self::set_login_gate_cookie( $secret_key );
        }

        if ( self::has_login_gate_cookie( $secret_key ) || is_user_logged_in() ) {
            return;
        }

        if ( self::is_login_action_allowed_without_secret( self::get_login_request_action() ) ) {
            return;
        }

        status_header( 404 );
        nocache_headers();
        wp_die( '<h1>404 Not Found</h1><p>The requested URL was not found on this server.</p>', 'Not Found', [ 'response' => 404 ] );
    }

private static function flatten_request_values( $value ) {
        if ( is_array( $value ) ) {
            $values = [];

            foreach ( $value as $nested_value ) {
                $values = array_merge( $values, self::flatten_request_values( $nested_value ) );
            }

            return $values;
        }

        if ( is_scalar( $value ) ) {
            return [ (string) $value ];
        }

        return [];
    }

private static function filter_upload_prefilter( $file, $settings ) {
        $file = is_array( $file ) ? $file : [];

        if ( ! empty( $file['error'] ) || empty( $file['name'] ) ) {
            return $file;
        }

        $filename             = sanitize_file_name( wp_basename( (string) $file['name'] ) );
        $extension            = strtolower( pathinfo( $filename, PATHINFO_EXTENSION ) );
        $disallowed_exts      = self::get_upload_disallowed_extensions( $settings );
        $mime_ignored_exts    = self::get_upload_mime_ignored_extensions( $settings );
        $tmp_name             = isset( $file['tmp_name'] ) ? (string) $file['tmp_name'] : '';

        if ( ! empty( $settings['block_bad_uploads'] ) && self::has_disallowed_upload_extension( $filename, $disallowed_exts ) ) {
            $message = '启灵上传防护：该文件命中了危险后缀或双后缀伪装规则，已被拦截。';
            self::record_upload_block_event( '危险上传后缀', $filename );
            $file['error'] = $message;

            return $file;
        }

        if ( ! empty( $settings['block_svg_uploads'] ) && 'svg' === $extension ) {
            $message = '启灵上传防护：当前站点已禁止上传 SVG 文件。';
            self::record_upload_block_event( 'SVG 上传拦截', $filename );
            $file['error'] = $message;

            return $file;
        }

        if ( empty( $settings['strict_upload_validation'] ) ) {
            return $file;
        }

        if ( '' === $tmp_name || ! is_readable( $tmp_name ) ) {
            return $file;
        }

        $validation_error = self::validate_upload_mime_consistency( $filename, $tmp_name, $extension, $mime_ignored_exts );

        if ( is_wp_error( $validation_error ) ) {
            self::record_upload_block_event( '上传内容校验失败', $filename, $validation_error->get_error_message() );
            $file['error'] = $validation_error->get_error_message();
        }

        return $file;
    }

private static function has_disallowed_upload_extension( $filename, $disallowed_extensions ) {
        $segments = array_values( array_filter( explode( '.', strtolower( (string) $filename ) ) ) );

        if ( count( $segments ) < 2 ) {
            return false;
        }

        $extensions_to_check = array_slice( $segments, 1 );

        foreach ( $extensions_to_check as $extension ) {
            if ( in_array( $extension, (array) $disallowed_extensions, true ) ) {
                return true;
            }
        }

        return false;
    }

private static function validate_upload_mime_consistency( $filename, $tmp_name, $extension, $ignored_extensions ) {
        $extension = strtolower( trim( (string) $extension ) );

        if ( '' === $extension || in_array( $extension, (array) $ignored_extensions, true ) ) {
            return true;
        }

        if ( 'svg' === $extension ) {
            return self::validate_svg_upload_contents( $filename, $tmp_name );
        }

        $image_extensions = apply_filters(
            'qs_upload_image_extensions',
            [ 'jpg', 'jpeg', 'jpe', 'png', 'gif', 'webp', 'bmp', 'avif', 'heic', 'heif' ]
        );

        if ( ! in_array( $extension, $image_extensions, true ) ) {
            return true;
        }

        $detected_image_mime = function_exists( 'wp_get_image_mime' ) ? wp_get_image_mime( $tmp_name ) : false;
        $filetype_check      = wp_check_filetype_and_ext( $tmp_name, $filename, get_allowed_mime_types() );
        $reported_type       = ! empty( $filetype_check['type'] ) ? strtolower( (string) $filetype_check['type'] ) : '';

        if ( false === $detected_image_mime || '' === $detected_image_mime ) {
            return new WP_Error( 'qs_upload_image_mismatch', '启灵上传防护：文件扩展名看起来像图片，但内容未通过真实图片校验，已拦截。' );
        }

        $detected_image_mime = strtolower( (string) $detected_image_mime );

        if ( 0 !== strpos( $detected_image_mime, 'image/' ) ) {
            return new WP_Error( 'qs_upload_image_mismatch', '启灵上传防护：文件扩展名看起来像图片，但真实 MIME 类型不是图片，已拦截。' );
        }

        if ( '' !== $reported_type && 0 !== strpos( $reported_type, 'image/' ) ) {
            return new WP_Error( 'qs_upload_image_mismatch', '启灵上传防护：文件扩展名与内容 MIME 类型不一致，已拦截伪装上传。' );
        }

        return true;
    }

private static function validate_svg_upload_contents( $filename, $tmp_name ) {
        $content = self::read_upload_temp_excerpt( $tmp_name, 131072 );

        if ( '' === $content ) {
            return new WP_Error( 'qs_upload_svg_invalid', '启灵上传防护：SVG 文件无法读取或内容为空，已拒绝上传。' );
        }

        if ( false === stripos( $content, '<svg' ) ) {
            return new WP_Error( 'qs_upload_svg_invalid', '启灵上传防护：该文件扩展名为 SVG，但内容不包含有效的 <svg> 根标签，已拦截。' );
        }

        if ( preg_match( '/<(script|foreignObject)\b|onload\s*=|onerror\s*=|javascript:/i', $content ) ) {
            return new WP_Error( 'qs_upload_svg_scripted', '启灵上传防护：检测到包含脚本或事件处理器的高风险 SVG，已拦截。' );
        }

        $filetype_check = wp_check_filetype_and_ext( $tmp_name, $filename, get_allowed_mime_types() );
        $reported_type  = ! empty( $filetype_check['type'] ) ? strtolower( (string) $filetype_check['type'] ) : '';

        if ( '' !== $reported_type && false === strpos( $reported_type, 'svg' ) && false === strpos( $reported_type, 'xml' ) ) {
            return new WP_Error( 'qs_upload_svg_mismatch', '启灵上传防护：SVG 扩展名与实际 MIME 类型不匹配，已拦截。' );
        }

        return true;
    }

private static function read_upload_temp_excerpt( $file_path, $max_bytes = 65535 ) {
        $file_path = (string) $file_path;

        if ( '' === $file_path || ! is_file( $file_path ) || ! is_readable( $file_path ) ) {
            return '';
        }

        $handle = @fopen( $file_path, 'rb' );

        if ( false === $handle ) {
            return '';
        }

        $content = @fread( $handle, max( 256, absint( $max_bytes ) ) );
        fclose( $handle );

        return is_string( $content ) ? $content : '';
    }

private static function record_upload_block_event( $action_type, $filename, $detail = '' ) {
        $message = '文件 [' . sanitize_file_name( (string) $filename ) . '] 上传被拦截。';

        if ( '' !== $detail ) {
            $message .= ' ' . sanitize_text_field( (string) $detail );
        }

        QS_Audit::record_event( $action_type, $message );

        QS_Alert_Center::trigger_event(
            'upload_block',
            $action_type,
            [ $message ],
            [
                'request_path' => QS_Audit::get_request_path(),
                'fingerprint'  => 'upload-block|' . md5( sanitize_file_name( (string) $filename ) . '|' . (string) $action_type ),
            ]
        );
    }

public static function init() {
        $settings = self::get_settings();
        $localization_mode = self::is_localization_mode_enabled( $settings );

        if ( $localization_mode ) {
            self::apply_localization_mode( $settings );
        }

        // 优先修复全局 REMOTE_ADDR，确保 WP 核心会话、评论等逻辑与插件识别的真实 IP 一致
        $_SERVER['REMOTE_ADDR'] = QS_Audit::get_real_ip( $settings );

        $current_ip = $_SERVER['REMOTE_ADDR'];
        if ( QS_DB::is_ip_banned( $current_ip ) ) {
            header( 'HTTP/1.1 403 Forbidden' );
            die( 'Access Denied: Your IP [' . esc_html( $current_ip ) . '] has been locked by Qiling Security Firewall due to malicious activity.' );
        }

        if ( class_exists( 'QS_IP_Geo_Blocker' ) ) {
            QS_IP_Geo_Blocker::maybe_block_current_request( $settings );
        }

        if ( ! empty( $settings['disable_xmlrpc'] ) ) {
            add_filter( 'xmlrpc_enabled', '__return_false' );
            add_filter( 'pings_open', '__return_false' );
        }

        if ( $localization_mode || ! empty( $settings['hide_wp_version'] ) ) {
            remove_action( 'wp_head', 'wp_generator' );
            add_filter( 'the_generator', '__return_empty_string' );
        }

        if ( ! empty( $settings['block_user_enum'] ) ) {
            add_filter(
                'rest_endpoints',
                function( $endpoints ) {
                    if ( isset( $endpoints['/wp/v2/users'] ) && ! current_user_can( 'list_users' ) ) {
                        unset( $endpoints['/wp/v2/users'] );
                    }

                    if ( isset( $endpoints['/wp/v2/users/(?P<id>[\d]+)'] ) && ! current_user_can( 'list_users' ) ) {
                        unset( $endpoints['/wp/v2/users/(?P<id>[\d]+)'] );
                    }

                    return $endpoints;
                }
            );

            add_filter(
                'rest_pre_dispatch',
                function( $result, $server, $request ) {
                    if ( $result instanceof WP_Error || current_user_can( 'list_users' ) ) {
                        return $result;
                    }

                    if ( ! is_object( $request ) || ! method_exists( $request, 'get_route' ) ) {
                        return $result;
                    }

                    $route = self::normalize_rest_route_prefix( $request->get_route() );

                    if ( 0 === strpos( $route, '/wp/v2/users' ) ) {
                        return new WP_Error(
                            'qs_user_enum_blocked',
                            '启灵安全防护：当前接口不对游客开放。',
                            [ 'status' => 403 ]
                        );
                    }

                    return $result;
                },
                4,
                3
            );

            add_filter(
                'wp_sitemaps_add_provider',
                function( $provider, $name ) {
                    if ( 'users' === (string) $name && ! current_user_can( 'list_users' ) ) {
                        return false;
                    }

                    return $provider;
                },
                10,
                2
            );

            if ( ! is_admin() && isset( $_REQUEST['author'] ) ) {
                wp_die( '启灵安全防护：已阻止用户枚举与探测请求。', 'Forbidden', [ 'response' => 403 ] );
            }
        }

        if ( ! empty( $settings['enable_rest_api_guard'] ) ) {
            add_filter(
                'rest_pre_dispatch',
                function( $result, $server, $request ) use ( $settings ) {
                    return self::handle_rest_api_guard( $result, $server, $request, $settings );
                },
                5,
                3
            );
        }

        if ( ! empty( $settings['disable_file_editor'] ) && ! defined( 'DISALLOW_FILE_EDIT' ) ) {
            add_filter(
                'map_meta_cap',
                function( $caps, $cap ) {
                    if ( in_array( $cap, [ 'edit_files', 'edit_plugins', 'edit_themes' ], true ) ) {
                        return [ 'do_not_allow' ];
                    }

                    return $caps;
                },
                10,
                2
            );
        }

        if ( ! empty( $settings['disable_app_passwords'] ) ) {
            add_filter( 'wp_is_application_passwords_available', '__return_false' );
            add_filter( 'wp_is_application_passwords_available_for_user', '__return_false' );
        }

        if ( $localization_mode || ! empty( $settings['disable_emoji'] ) ) {
            remove_action( 'wp_head', 'print_emoji_detection_script', 7 );
            remove_action( 'admin_print_scripts', 'print_emoji_detection_script' );
            remove_action( 'wp_print_styles', 'print_emoji_styles' );
            remove_action( 'admin_print_styles', 'print_emoji_styles' );
            remove_filter( 'the_content_feed', 'wp_staticize_emoji' );
            remove_filter( 'comment_text_rss', 'wp_staticize_emoji' );
            remove_filter( 'wp_mail', 'wp_staticize_emoji_for_email' );

            add_filter(
                'tiny_mce_plugins',
                function( $plugins ) {
                    return is_array( $plugins ) ? array_diff( $plugins, [ 'wpemoji' ] ) : [];
                }
            );

            add_filter(
                'wp_resource_hints',
                function( $urls, $relation_type ) {
                    if ( 'dns-prefetch' !== $relation_type || ! is_array( $urls ) ) {
                        return $urls;
                    }

                    return array_values(
                        array_filter(
                            $urls,
                            function( $url ) {
                                return false === strpos( (string) $url, 'https://s.w.org/images/core/emoji/' );
                            }
                        )
                    );
                },
                10,
                2
            );
        }

        if ( $localization_mode || ! empty( $settings['disable_embeds'] ) ) {
            remove_action( 'rest_api_init', 'wp_oembed_register_route' );
            remove_filter( 'oembed_dataparse', 'wp_filter_oembed_result', 10 );
            remove_action( 'wp_head', 'wp_oembed_add_discovery_links' );
            remove_action( 'wp_head', 'wp_oembed_add_host_js' );
            add_filter( 'embed_oembed_discover', '__return_false' );
            add_filter(
                'rewrite_rules_array',
                function( $rules ) {
                    if ( ! is_array( $rules ) ) {
                        return $rules;
                    }

                    foreach ( $rules as $rule => $rewrite ) {
                        if ( false !== strpos( (string) $rewrite, 'embed=true' ) ) {
                            unset( $rules[ $rule ] );
                        }
                    }

                    return $rules;
                }
            );
        }

        if ( $localization_mode || ! empty( $settings['remove_shortlink'] ) ) {
            remove_action( 'wp_head', 'wp_shortlink_wp_head', 10, 0 );
            remove_action( 'template_redirect', 'wp_shortlink_header', 11 );
        }

        if ( $localization_mode || ! empty( $settings['remove_rsd_wlw'] ) ) {
            remove_action( 'wp_head', 'rsd_link' );
            remove_action( 'wp_head', 'wlwmanifest_link' );
        }

        if ( $localization_mode || ! empty( $settings['clean_meta_tags'] ) ) {
            remove_action( 'wp_head', 'rsd_link' );
            remove_action( 'wp_head', 'wlwmanifest_link' );
            remove_action( 'wp_head', 'wp_shortlink_wp_head', 10, 0 );
            remove_action( 'wp_head', 'rest_output_link_wp_head', 10 );
            remove_action( 'wp_head', 'wp_oembed_add_discovery_links', 10 );
        }

        if ( ! empty( $settings['waf_core'] ) ) {
            add_action(
                'init',
                function() use ( $settings ) {
                    if ( QS_Audit::is_current_request_trusted( $settings ) ) {
                        return;
                    }

                    if ( is_user_logged_in() && current_user_can( 'edit_posts' ) ) {
                        return;
                    }

                    $waf_rules      = self::get_waf_rules( $settings );
                    $request_scopes = [
                        'get'    => $_GET,
                        'post'   => $_POST,
                        'cookie' => $_COOKIE,
                    ];

                    foreach ( $request_scopes as $scope => $superglobal ) {
                        foreach ( self::flatten_request_values( $superglobal ) as $value ) {
                            $lower_val = strtolower( $value );

                            foreach ( $waf_rules as $rule ) {
                                if ( empty( $rule['needle'] ) || empty( $rule['scopes'] ) || ! in_array( $scope, (array) $rule['scopes'], true ) ) {
                                    continue;
                                }

                                if ( false === strpos( $lower_val, strtolower( (string) $rule['needle'] ) ) ) {
                                    continue;
                                }

                                $ip          = QS_Audit::get_real_ip();
                                $ban_message = '当前请求已被阻断，但不会自动封禁。';

                                if ( ! empty( $rule['ban'] ) && ! is_user_logged_in() ) {
                                    QS_DB::ban_ip( $ip, '触发高置信度 WAF 规则: ' . $rule['needle'], 24 );
                                    $ban_message = '异常来源 IP 已被临时封禁 24 小时。';
                                }

                                $detail = sprintf(
                                    '请求作用域 [%s] 命中特征 [%s]。%s',
                                    strtoupper( $scope ),
                                    sanitize_text_field( (string) $rule['needle'] ),
                                    $ban_message
                                );

                                QS_Audit::record_event(
                                    'WAF 命中拦截',
                                    $detail,
                                    [
                                        'ip' => $ip,
                                    ]
                                );

                                QS_Alert_Center::trigger_event(
                                    'waf_block',
                                    'WAF 命中并阻断',
                                    [ $detail ],
                                    [
                                        'ip'           => $ip,
                                        'needle'       => isset( $rule['needle'] ) ? (string) $rule['needle'] : '',
                                        'request_path' => QS_Audit::get_request_path(),
                                        'fingerprint'  => 'waf-block|' . $scope . '|' . ( isset( $rule['needle'] ) ? (string) $rule['needle'] : '' ) . '|' . $ip,
                                    ]
                                );

                                wp_die(
                                    '<h1>安全警告</h1><p>启灵安全防火墙已拦截可疑请求。</p><p>特征命中：<code>' . esc_html( $rule['needle'] ) . '</code></p><p>' . esc_html( $ban_message ) . '</p>',
                                    'WAF Intercepted',
                                    [ 'response' => 403 ]
                                );
                            }
                        }
                    }
                },
                1
            );
        }

        if ( ! empty( $settings['block_bad_uploads'] ) || ! empty( $settings['strict_upload_validation'] ) || ! empty( $settings['block_svg_uploads'] ) ) {
            add_filter(
                'wp_handle_upload_prefilter',
                function( $file ) use ( $settings ) {
                    return self::filter_upload_prefilter( $file, $settings );
                }
            );

            add_filter(
                'wp_handle_sideload_prefilter',
                function( $file ) use ( $settings ) {
                    return self::filter_upload_prefilter( $file, $settings );
                }
            );
        }

        if ( ! empty( $settings['block_bad_scanners'] ) ) {
            add_action(
                'init',
                function() use ( $settings ) {
                    if ( QS_Audit::is_current_request_trusted( $settings ) ) {
                        return;
                    }

                    $ua       = isset( $_SERVER['HTTP_USER_AGENT'] ) ? strtolower( (string) wp_unslash( $_SERVER['HTTP_USER_AGENT'] ) ) : '';
                    $bad_bots = self::get_bad_bot_signatures( $settings );

                    if ( '' === $ua ) {
                        return;
                    }

                    foreach ( $bad_bots as $bot ) {
                        if ( '' !== $bot && false !== strpos( $ua, strtolower( $bot ) ) ) {
                            wp_die( '启灵安全黑名单防护：拒绝自动化漏洞扫描器和恶意机器爬虫的异常请求。', 'Access Denied', [ 'response' => 403 ] );
                        }
                    }
                },
                1
            );
        }

        if ( ! empty( $settings['add_security_headers'] ) ) {
            add_action(
                'send_headers',
                function() use ( $settings ) {
                    if ( headers_sent() ) {
                        return;
                    }

                    foreach ( self::get_security_headers( $settings ) as $header_name => $header_value ) {
                        header( $header_name . ': ' . $header_value );
                    }
                }
            );
        }

        if ( ! empty( $settings['disable_pingback'] ) ) {
            add_filter(
                'xmlrpc_methods',
                function( $methods ) {
                    unset( $methods['pingback.ping'] );
                    unset( $methods['pingback.extensions.getPingbacks'] );
                    return $methods;
                }
            );

            add_filter(
                'wp_headers',
                function( $headers ) {
                    unset( $headers['X-Pingback'] );
                    return $headers;
                }
            );
        }

        if ( $localization_mode || ! empty( $settings['admin_disable_remote_block_patterns'] ) ) {
            add_filter( 'should_load_remote_block_patterns', '__return_false' );
        }

        if ( $localization_mode || ! empty( $settings['admin_disable_block_directory'] ) ) {
            add_filter( 'block_directory_enabled', '__return_false' );
            add_filter(
                'block_editor_settings_all',
                function( $editor_settings ) {
                    if ( is_array( $editor_settings ) ) {
                        $editor_settings['enableBlockDirectory'] = false;
                    }

                    return $editor_settings;
                },
                20
            );
        }

        if ( $localization_mode || ! empty( $settings['admin_disable_openverse'] ) ) {
            add_filter(
                'block_editor_settings_all',
                function( $editor_settings ) {
                    if ( is_array( $editor_settings ) ) {
                        $editor_settings['enableOpenverseMediaCategory'] = false;
                    }

                    return $editor_settings;
                },
                20
            );
        }

        if ( $localization_mode || ! empty( $settings['admin_reduce_editor_preload'] ) ) {
            add_filter(
                'block_editor_rest_api_preload_paths',
                function( $preload_paths ) {
                    if ( ! is_array( $preload_paths ) ) {
                        return $preload_paths;
                    }

                    $skip_needles = [
                        '/wp/v2/block-directory/search',
                        '/wp/v2/pattern-directory/patterns',
                    ];
                    $filtered     = [];
                    $seen         = [];

                    foreach ( $preload_paths as $entry ) {
                        $path   = '';
                        $method = 'GET';

                        if ( is_array( $entry ) ) {
                            $path   = isset( $entry[0] ) ? (string) $entry[0] : '';
                            $method = isset( $entry[1] ) ? (string) $entry[1] : 'GET';
                        } elseif ( is_string( $entry ) ) {
                            $path = $entry;
                        }

                        $path = trim( $path );
                        if ( '' === $path ) {
                            continue;
                        }

                        $skip = false;
                        foreach ( $skip_needles as $needle ) {
                            if ( false !== strpos( $path, $needle ) ) {
                                $skip = true;
                                break;
                            }
                        }

                        if ( $skip ) {
                            continue;
                        }

                        $dedupe_key = md5( $method . '|' . $path );
                        if ( isset( $seen[ $dedupe_key ] ) ) {
                            continue;
                        }

                        $seen[ $dedupe_key ] = true;
                        $filtered[]          = $entry;
                    }

                    $preload_limit = (int) apply_filters( 'qs_editor_preload_limit', 0, $filtered, $preload_paths );
                    if ( $preload_limit > 0 && count( $filtered ) > $preload_limit ) {
                        $filtered = array_slice( $filtered, 0, $preload_limit );
                    }

                    return $filtered;
                },
                10
            );
        }

        if ( ! empty( $settings['hide_login_error_details'] ) ) {
            add_filter(
                'login_errors',
                function( $error ) {
                    $error = (string) $error;

                    if ( false !== strpos( $error, '启灵安全拦截' ) ) {
                        return $error;
                    }

                    return '<strong>错误</strong>：用户名或密码错误，请重试。';
                },
                999
            );
        }

        if ( ! empty( $settings['limit_login_attempts'] ) ) {
            $rate_limit = self::get_login_rate_limit_config( $settings );

            add_filter(
                'authenticate',
                function( $user, $username, $password ) use ( $rate_limit ) {
                    if ( empty( $username ) || empty( $password ) ) {
                        return $user;
                    }

                    $ip = QS_Audit::get_real_ip();
                    if ( ! $ip || '0.0.0.0' === $ip ) {
                        return $user;
                    }

                    if ( QS_Audit::is_ip_whitelisted( $ip ) ) {
                        return $user;
                    }

                    if ( QS_DB::is_ip_banned( $ip ) ) {
                        return new WP_Error(
                            'too_many_retries',
                            sprintf(
                                '<strong>启灵安全拦截</strong>：当前来源 IP 已因连续输错密码被临时锁定，请在 %d 小时后再试。',
                                $rate_limit['lockout_hours']
                            )
                        );
                    }

                    return $user;
                },
                30,
                3
            );

            add_action(
                'wp_login_failed',
                function( $username ) use ( $rate_limit ) {
                    $ip = QS_Audit::get_real_ip();
                    if ( ! $ip || '0.0.0.0' === $ip || QS_Audit::is_ip_whitelisted( $ip ) ) {
                        return;
                    }

                    $ban_username   = sanitize_user( (string) $username, true );
                    $ban_username   = '' !== $ban_username ? $ban_username : 'unknown';
                    $transient_name = 'qs_login_fails_' . md5( $ip );
                    $attempts       = (int) get_transient( $transient_name );
                    $attempts++;
                    set_transient( $transient_name, $attempts, HOUR_IN_SECONDS * 24 );

                    if ( $attempts < $rate_limit['max_attempts'] ) {
                        return;
                    }

                    if ( ! QS_DB::is_ip_banned( $ip ) ) {
                        QS_DB::ban_ip( $ip, "密码连续猜测爆破用户: {$ban_username}", $rate_limit['lockout_hours'] );

                        QS_Alert_Center::trigger_event(
                            'login_lockout',
                            '登录爆破触发封禁',
                            [
                                sprintf(
                                    '来源 IP [%s] 因连续猜测账号 [%s] 超过阈值 %d 次，已被封禁 %d 小时。',
                                    $ip,
                                    $ban_username,
                                    $rate_limit['max_attempts'],
                                    $rate_limit['lockout_hours']
                                ),
                            ],
                            [
                                'ip'          => $ip,
                                'username'    => $ban_username,
                                'fingerprint' => 'login-lockout|' . $ip,
                            ]
                        );
                    }
                }
            );

            add_action(
                'wp_login',
                function() {
                    $ip = QS_Audit::get_real_ip();
                    if ( $ip && '0.0.0.0' !== $ip ) {
                        $transient_name = 'qs_login_fails_' . md5( $ip );
                        delete_transient( $transient_name );
                    }
                },
                10,
                2
            );
        }

        if ( self::get_max_concurrent_sessions( $settings ) > 0 ) {
            $max_sessions = self::get_max_concurrent_sessions( $settings );

            add_action(
                'wp_login',
                function( $user_login, $user ) use ( $max_sessions ) {
                    $user_id = isset( $user->ID ) ? absint( $user->ID ) : 0;

                    if ( ! $user_id ) {
                        return;
                    }

                    $removed = QS_Session_Manager::enforce_max_sessions( $user_id, $max_sessions, true );

                    if ( $removed <= 0 ) {
                        return;
                    }

                    $safe_login = sanitize_user( (string) $user_login, true );
                    $safe_login = '' !== $safe_login ? $safe_login : ( isset( $user->user_login ) ? sanitize_user( (string) $user->user_login, true ) : 'unknown' );

                    QS_Audit::record_event(
                        '会话并发限制触发',
                        sprintf( '用户 [%s] 登录后超过并发设备上限 %d，已自动下线 %d 个较早会话。', $safe_login, $max_sessions, $removed ),
                        [
                            'user_id'  => $user_id,
                            'username' => $safe_login,
                        ]
                    );

                    QS_Alert_Center::trigger_event(
                        'session_limit',
                        '会话并发限制触发',
                        [
                            sprintf( '用户 [%s] 登录后超过并发设备上限 %d，已自动下线 %d 个较早会话。', $safe_login, $max_sessions, $removed ),
                        ],
                        [
                            'username'    => $safe_login,
                            'fingerprint' => 'session-limit|' . $user_id,
                        ]
                    );
                },
                30,
                2
            );
        }

        if ( ! empty( $settings['custom_login_url'] ) ) {
            $secret_key = self::sanitize_custom_login_key( $settings['custom_login_url'] );

            if ( $secret_key ) {
                add_action(
                    'init',
                    function() use ( $secret_key ) {
                        self::protect_custom_login_url( $secret_key );
                    },
                    0
                );

                add_filter(
                    'login_url',
                    function( $url ) use ( $secret_key ) {
                        return self::append_secret_to_url( $url, $secret_key );
                    },
                    10,
                    3
                );

                add_filter(
                    'lostpassword_url',
                    function( $url ) use ( $secret_key ) {
                        return self::append_secret_to_url( $url, $secret_key );
                    },
                    10,
                    2
                );

                add_filter(
                    'logout_url',
                    function( $url ) use ( $secret_key ) {
                        return self::append_secret_to_url( $url, $secret_key );
                    },
                    10,
                    2
                );

                add_filter(
                    'register_url',
                    function( $url ) use ( $secret_key ) {
                        return self::append_secret_to_url( $url, $secret_key );
                    },
                    10,
                    1
                );

                add_filter(
                    'site_url',
                    function( $url, $path ) use ( $secret_key ) {
                        if ( 0 === strpos( ltrim( (string) $path, '/' ), 'wp-login.php' ) ) {
                            return self::append_secret_to_url( $url, $secret_key );
                        }

                        return $url;
                    },
                    10,
                    4
                );

                add_filter(
                    'network_site_url',
                    function( $url, $path ) use ( $secret_key ) {
                        if ( 0 === strpos( ltrim( (string) $path, '/' ), 'wp-login.php' ) ) {
                            return self::append_secret_to_url( $url, $secret_key );
                        }

                        return $url;
                    },
                    10,
                    3
                );
            }
        }
    }
}
