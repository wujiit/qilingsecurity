<?php
/**
 * 启灵安全防护 - 本地化与白标模式优化
 *
 * @package QilingSecurity
 */

if ( ! defined( 'ABSPATH' ) ) {
    exit;
}

class QS_Localization_Mode {

public static function is_localization_mode_enabled( $settings = null ) {
        $settings = is_array( $settings ) ? $settings : QS_Protection_Settings::get_settings();

        return ! empty( $settings['enable_localization_mode'] );
    }

public static function get_localization_brand_label( $settings = null ) {
        $settings = is_array( $settings ) ? $settings : QS_Protection_Settings::get_settings();
        $label    = '启灵管理平台';
        $filtered = sanitize_text_field( (string) apply_filters( 'qs_localization_brand_label', $label, $settings ) );

        return '' !== $filtered ? $filtered : $label;
    }

public static function strip_wordpress_brand_text( $text ) {
        $text = (string) $text;
        $text = preg_replace( '/\s*(?:-|—|&mdash;|&#8212;)\s*WordPress\s*$/iu', '', $text );
        $text = str_ireplace(
            [
                ' &#8212; WordPress',
                ' &mdash; WordPress',
                ' — WordPress',
                ' - WordPress',
                'WordPress',
            ],
            '',
            $text
        );

        return trim( (string) $text );
    }

public static function get_empty_core_update_transient( $pre = null ) {
        global $wp_version;

        $transient                  = new stdClass();
        $transient->last_checked    = time();
        $transient->version_checked = isset( $wp_version ) ? (string) $wp_version : '';
        $transient->updates         = [];

        return $transient;
    }

public static function get_empty_plugin_update_transient( $pre = null ) {
        $transient               = new stdClass();
        $transient->last_checked = time();
        $transient->checked      = [];
        $transient->response     = [];
        $transient->no_update    = [];
        $transient->translations = [];

        if ( function_exists( 'get_plugins' ) ) {
            foreach ( get_plugins() as $plugin_file => $plugin_data ) {
                $transient->checked[ $plugin_file ] = isset( $plugin_data['Version'] ) ? (string) $plugin_data['Version'] : '';
            }
        }

        return $transient;
    }

public static function get_empty_theme_update_transient( $pre = null ) {
        $transient               = new stdClass();
        $transient->last_checked = time();
        $transient->checked      = [];
        $transient->response     = [];
        $transient->no_update    = [];
        $transient->translations = [];

        if ( function_exists( 'wp_get_themes' ) ) {
            foreach ( wp_get_themes() as $stylesheet => $theme ) {
                $transient->checked[ $stylesheet ] = is_object( $theme ) && method_exists( $theme, 'get' ) ? (string) $theme->get( 'Version' ) : '';
            }
        }

        return $transient;
    }

public static function is_wp_official_url( $url ) {
        $host = wp_parse_url( (string) $url, PHP_URL_HOST );

        if ( ! is_string( $host ) || '' === $host ) {
            return false;
        }

        $host          = strtolower( trim( $host, ". \t\n\r\0\x0B" ) );
        $blocked_roots = [
            'wordpress.org',
            'w.org',
        ];

        foreach ( $blocked_roots as $root ) {
            if ( $host === $root ) {
                return true;
            }

            $suffix = '.' . $root;
            if ( substr( $host, -strlen( $suffix ) ) === $suffix ) {
                return true;
            }
        }

        return false;
    }

public static function maybe_block_wp_official_http_request( $preempt, $args, $url ) {
        if ( false !== $preempt ) {
            return $preempt;
        }

        if ( ! self::is_wp_official_url( $url ) ) {
            return false;
        }

        return new WP_Error(
            'qs_official_remote_request_blocked',
            '启灵本地化模式已阻断官方远程请求。',
            [
                'url' => esc_url_raw( (string) $url ),
            ]
        );
    }

public static function remove_wp_update_hooks() {
        remove_action( 'wp_version_check', 'wp_version_check' );
        remove_action( 'wp_update_plugins', 'wp_update_plugins' );
        remove_action( 'wp_update_themes', 'wp_update_themes' );
        remove_action( 'wp_maybe_auto_update', 'wp_maybe_auto_update' );
        remove_action( 'init', 'wp_schedule_update_checks' );
        remove_action( 'admin_init', '_maybe_update_core' );
        remove_action( 'admin_init', 'wp_maybe_auto_update' );
        remove_action( 'load-plugins.php', 'wp_update_plugins' );
        remove_action( 'load-update.php', 'wp_update_plugins' );
        remove_action( 'load-update-core.php', 'wp_update_plugins' );
        remove_action( 'load-themes.php', 'wp_update_themes' );
        remove_action( 'load-update.php', 'wp_update_themes' );
        remove_action( 'load-update-core.php', 'wp_update_themes' );
        remove_action( 'admin_notices', 'update_nag', 3 );
        remove_action( 'network_admin_notices', 'update_nag', 3 );
    }

public static function apply_localization_mode( $settings ) {
        $brand_label = self::get_localization_brand_label( $settings );

        add_action( 'admin_bar_menu', [ __CLASS__, 'remove_localization_admin_bar_nodes' ], 999 );
        add_action( 'admin_head', [ __CLASS__, 'print_localization_admin_css' ], 20 );
        add_action( 'admin_init', [ __CLASS__, 'remove_localization_admin_notices' ], 20 );
        add_action( 'wp_dashboard_setup', [ __CLASS__, 'remove_localization_dashboard_widgets' ], 999 );

        add_filter(
            'admin_title',
            static function( $admin_title ) {
                return self::strip_wordpress_brand_text( $admin_title );
            },
            999
        );

        add_filter(
            'admin_footer_text',
            static function() use ( $brand_label ) {
                return esc_html( '感谢使用' . $brand_label . '。' );
            },
            999
        );
        add_filter( 'update_footer', '__return_empty_string', 999 );

        add_action(
            'login_enqueue_scripts',
            static function() use ( $brand_label ) {
                self::print_localization_login_css( $brand_label );
            },
            20
        );
        add_filter(
            'login_headerurl',
            static function() {
                return home_url( '/' );
            },
            999
        );
        add_filter(
            'login_headertext',
            static function() use ( $brand_label ) {
                return $brand_label;
            },
            999
        );
        add_filter(
            'login_headertitle',
            static function() use ( $brand_label ) {
                return $brand_label;
            },
            999
        );
        add_filter(
            'login_title',
            static function( $login_title, $title ) use ( $brand_label ) {
                $title = trim( wp_strip_all_tags( (string) $title ) );

                return '' !== $title ? $title . ' ‹ ' . $brand_label : $brand_label;
            },
            999,
            2
        );

        self::remove_wp_update_hooks();
        add_action( 'init', [ __CLASS__, 'remove_wp_update_hooks' ], 20 );
        add_action( 'admin_init', [ __CLASS__, 'remove_wp_update_hooks' ], 20 );

        add_filter( 'automatic_updater_disabled', '__return_true', 999 );
        add_filter( 'auto_update_core', '__return_false', 999 );
        add_filter( 'allow_major_auto_core_updates', '__return_false', 999 );
        add_filter( 'allow_minor_auto_core_updates', '__return_false', 999 );
        add_filter( 'allow_dev_auto_core_updates', '__return_false', 999 );
        add_filter( 'auto_update_plugin', '__return_false', 999 );
        add_filter( 'auto_update_theme', '__return_false', 999 );
        add_filter( 'auto_update_translation', '__return_false', 999 );
        add_filter( 'auto_core_update_send_email', '__return_false', 999 );
        add_filter( 'send_core_update_notification_email', '__return_false', 999 );
        add_filter( 'auto_plugin_update_send_email', '__return_false', 999 );
        add_filter( 'auto_theme_update_send_email', '__return_false', 999 );
        add_filter( 'pre_site_transient_update_core', [ __CLASS__, 'get_empty_core_update_transient' ], 999 );
        add_filter( 'pre_site_transient_update_plugins', [ __CLASS__, 'get_empty_plugin_update_transient' ], 999 );
        add_filter( 'pre_site_transient_update_themes', [ __CLASS__, 'get_empty_theme_update_transient' ], 999 );
        add_filter( 'plugins_api', [ __CLASS__, 'block_localization_directory_api' ], 999, 3 );
        add_filter( 'themes_api', [ __CLASS__, 'block_localization_directory_api' ], 999, 3 );
        add_filter( 'translations_api', [ __CLASS__, 'block_localization_directory_api' ], 999, 3 );
        add_filter( 'pre_http_request', [ __CLASS__, 'maybe_block_wp_official_http_request' ], 10, 3 );
    }

public static function remove_localization_admin_bar_nodes( $wp_admin_bar ) {
        if ( is_object( $wp_admin_bar ) && method_exists( $wp_admin_bar, 'remove_node' ) ) {
            $wp_admin_bar->remove_node( 'wp-logo' );
        }
    }

public static function print_localization_admin_css() {
        echo '<style id="qs-localization-admin-css">#wp-admin-bar-wp-logo{display:none!important;}</style>';
    }

public static function remove_localization_admin_notices() {
        remove_action( 'welcome_panel', 'wp_welcome_panel' );
        remove_action( 'admin_notices', 'update_nag', 3 );
        remove_action( 'network_admin_notices', 'update_nag', 3 );
    }

public static function remove_localization_dashboard_widgets() {
        $normal_boxes = [
            'dashboard_site_health',
            'dashboard_right_now',
            'dashboard_activity',
            'dashboard_recent_comments',
            'dashboard_incoming_links',
            'dashboard_plugins',
        ];
        $side_boxes   = [
            'dashboard_quick_press',
            'dashboard_primary',
            'dashboard_secondary',
        ];

        foreach ( $normal_boxes as $box_id ) {
            remove_meta_box( $box_id, 'dashboard', 'normal' );
        }

        foreach ( $side_boxes as $box_id ) {
            remove_meta_box( $box_id, 'dashboard', 'side' );
        }
    }

public static function print_localization_login_css( $brand_label ) {
        $brand_json = wp_json_encode( (string) $brand_label, JSON_UNESCAPED_UNICODE );
        if ( ! is_string( $brand_json ) || '' === $brand_json ) {
            $brand_json = '"启灵管理平台"';
        }
        ?>
        <style id="qs-localization-login-css">
            .login h1 a {
                background-image: none !important;
                color: #111827;
                display: inline-flex;
                align-items: center;
                justify-content: center;
                font-size: 0;
                font-weight: 700;
                height: auto;
                line-height: 1.35;
                margin: 0 auto 18px;
                min-height: 48px;
                outline: none;
                text-decoration: none;
                text-indent: 0;
                width: auto;
            }

            .login h1 a::before {
                content: <?php echo $brand_json; // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped ?>;
                border-bottom: 2px solid #2563eb;
                display: inline-block;
                font-size: 24px;
                padding: 0 4px 8px;
            }

            .login h1 a:focus {
                box-shadow: none;
            }
        </style>
        <?php
    }

public static function block_localization_directory_api( $result = null, $action = '', $args = null ) {
        return new WP_Error( 'qs_directory_api_blocked', '启灵本地化模式已关闭官方目录接口。' );
    }
}
