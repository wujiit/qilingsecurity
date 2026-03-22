<?php
/**
 * 安全防护插件 - 扫描规则包管理
 */
if ( ! defined( 'ABSPATH' ) ) {
    exit;
}

class QS_Rules {

    const PACKAGE_ID             = 'qilingsecurity-rules';
    const BUILTIN_VERSION        = '2026.03.11';
    const OPTION_ACTIVE_PACKAGE  = 'qs_rule_package_active';
    const OPTION_PREV_PACKAGE    = 'qs_rule_package_previous';
    const MAX_PACKAGE_FILE_BYTES = 5242880; // 5MB
    const OFFICIAL_SIGNER_ID     = 'qiling-official-v1';
    const OFFICIAL_SIGNER_PUBLIC_KEY = "-----BEGIN PUBLIC KEY-----\nMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAoGkHUbwD0C0/Cd5dpqq5\nlX2DttEzVEIps+hqun5pBJS/Vn2RilGJFfZwRKmNL2a+ajquevzn8v2nhcI5jhf3\nNoQTVydzqykhJFldlapVdtfBU/V+WwTdrhqnKiSgyC0eb/EYyaidYCwRAckrwFwX\nQ4a+NFbXQPXBkzPRFtA9bAUHJ8VDHWD8yNYLsrQ8aSGV1/yJUPNlpAkjJ72F97r+\nNrJBnkUSzfGsE4snMot4tcEhzSrgvbfPSdexx4W6jV8O+RhY/ggp6aNPaxoPwx9B\nEuVRJFgtzCloYw9vZVK4z/OXJ/jR99cifOVoZKG7AXMpjT+xg/XtwgEqKGBSKwjk\ncwIDAQAB\n-----END PUBLIC KEY-----";

    private static $effective_rules_cache = null;
    private static $active_package_cache  = null;
    private static $previous_package_cache = null;

    public static function get_rule( $rule_key, $fallback = null ) {
        $rules = self::get_effective_rules();

        if ( array_key_exists( $rule_key, $rules ) ) {
            return $rules[ $rule_key ];
        }

        return $fallback;
    }

    public static function get_effective_rules() {
        if ( is_array( self::$effective_rules_cache ) ) {
            return self::$effective_rules_cache;
        }

        $rules   = self::get_builtin_rules();
        $package = self::get_active_custom_package();

        if ( ! empty( $package['rules'] ) && is_array( $package['rules'] ) ) {
            foreach ( $package['rules'] as $rule_key => $rule_value ) {
                if ( ! array_key_exists( $rule_key, $rules ) ) {
                    $rules[ $rule_key ] = $rule_value;
                    continue;
                }

                $rules[ $rule_key ] = self::merge_rule_value( $rules[ $rule_key ], $rule_value );
            }
        }

        self::$effective_rules_cache = $rules;

        return self::$effective_rules_cache;
    }

    public static function get_package_status() {
        $active   = self::get_active_custom_package();
        $previous = self::get_previous_custom_package();
        $source   = ! empty( $active ) ? 'custom' : 'builtin';
        $version  = ! empty( $active['version'] ) ? $active['version'] : self::BUILTIN_VERSION;

        return [
            'source'             => $source,
            'version'            => $version,
            'source_label'       => 'custom' === $source ? '官方规则包' : '内置规则',
            'builtin_version'    => self::BUILTIN_VERSION,
            'signer'             => ! empty( $active['signer'] ) ? $active['signer'] : self::OFFICIAL_SIGNER_ID,
            'updated_at'         => ! empty( $active['uploaded_at'] ) ? $active['uploaded_at'] : '',
            'uploaded_by'        => ! empty( $active['uploaded_by'] ) ? absint( $active['uploaded_by'] ) : 0,
            'hash'               => ! empty( $active['rules_sha256'] ) ? $active['rules_sha256'] : '',
            'has_previous'       => ! empty( $previous ),
            'previous_version'   => ! empty( $previous['version'] ) ? $previous['version'] : '',
            'previous_updated_at' => ! empty( $previous['uploaded_at'] ) ? $previous['uploaded_at'] : '',
            'supported_rule_keys' => array_keys( self::get_builtin_rules() ),
        ];
    }

    public static function import_package_from_upload( $file ) {
        $file = is_array( $file ) ? $file : [];

        if ( empty( $file['name'] ) || empty( $file['tmp_name'] ) ) {
            return [
                'success' => false,
                'message' => '未接收到规则包文件。',
            ];
        }

        if ( ! empty( $file['error'] ) ) {
            return [
                'success' => false,
                'message' => self::get_upload_error_message( (int) $file['error'] ),
            ];
        }

        $filename = sanitize_file_name( (string) $file['name'] );
        $tmp_name = (string) $file['tmp_name'];
        $size     = isset( $file['size'] ) ? absint( $file['size'] ) : 0;
        $ext      = strtolower( pathinfo( $filename, PATHINFO_EXTENSION ) );

        if ( 'json' !== $ext ) {
            return [
                'success' => false,
                'message' => '规则包仅支持 .json 文件。',
            ];
        }

        if ( $size > self::MAX_PACKAGE_FILE_BYTES ) {
            return [
                'success' => false,
                'message' => sprintf( '规则包大小无效或超过 %s 限制。', self::get_package_size_limit_label() ),
            ];
        }

        if ( ! is_readable( $tmp_name ) ) {
            return [
                'success' => false,
                'message' => '规则包临时文件不可读。',
            ];
        }

        if ( function_exists( 'is_uploaded_file' ) && ! is_uploaded_file( $tmp_name ) ) {
            return [
                'success' => false,
                'message' => '上传来源无效，请重新选择文件。',
            ];
        }

        $raw = @file_get_contents( $tmp_name );

        if ( ! is_string( $raw ) || '' === $raw ) {
            return [
                'success' => false,
                'message' => '规则包文件读取失败。',
            ];
        }

        if ( strlen( $raw ) > self::MAX_PACKAGE_FILE_BYTES ) {
            return [
                'success' => false,
                'message' => sprintf( '规则包大小超过 %s 限制。', self::get_package_size_limit_label() ),
            ];
        }

        $payload = json_decode( $raw, true );

        if ( ! is_array( $payload ) ) {
            return [
                'success' => false,
                'message' => '规则包 JSON 格式错误。',
            ];
        }

        $normalized = self::normalize_import_payload( $payload, $filename );

        if ( ! empty( $normalized['error'] ) ) {
            return [
                'success' => false,
                'message' => $normalized['error'],
            ];
        }

        $current_package = self::get_active_custom_package();

        if ( ! empty( $current_package ) ) {
            update_option( self::OPTION_PREV_PACKAGE, $current_package, false );
        } else {
            delete_option( self::OPTION_PREV_PACKAGE );
        }

        update_option( self::OPTION_ACTIVE_PACKAGE, $normalized['package'], false );
        self::clear_runtime_cache();

        return [
            'success' => true,
            'message' => sprintf( '规则包导入成功，当前生效版本：%s。', $normalized['package']['version'] ),
            'package' => $normalized['package'],
            'status'  => self::get_package_status(),
        ];
    }

    public static function rollback_to_previous_package() {
        $previous = self::get_previous_custom_package();

        if ( empty( $previous ) ) {
            return [
                'success' => false,
                'message' => '没有可回滚的上一版规则包。',
            ];
        }

        $current = self::get_active_custom_package();

        update_option( self::OPTION_ACTIVE_PACKAGE, $previous, false );

        if ( ! empty( $current ) ) {
            update_option( self::OPTION_PREV_PACKAGE, $current, false );
        } else {
            delete_option( self::OPTION_PREV_PACKAGE );
        }

        self::clear_runtime_cache();

        return [
            'success' => true,
            'message' => sprintf( '已回滚到规则包版本：%s。', $previous['version'] ),
            'status'  => self::get_package_status(),
        ];
    }

    private static function get_builtin_package_meta() {
        return [
            'package_id'   => self::PACKAGE_ID,
            'version'      => self::BUILTIN_VERSION,
            'source'       => 'builtin',
            'uploaded_at'  => '',
            'uploaded_by'  => 0,
            'rules_sha256' => self::build_rules_hash( self::get_builtin_rules() ),
        ];
    }

    private static function get_builtin_rules() {
        return [
            'code_vulnerability_patterns'        => [
                'RCE'   => '/\b(system|exec|shell_exec|passthru|proc_open|popen)\s*\(/i',
                'SSRF'  => '/\b(curl_exec|wp_remote_get|fsockopen)\s*\(.*(\$_GET|\$_POST|\$_REQUEST)/i',
                'WRITE' => '/\b(file_put_contents|fwrite)\s*\(.*(\$_GET|\$_POST|\$_REQUEST)/i',
            ],
            'component_vulnerability_feed'      => [],
            'scan_api_endpoints'                => [
                '/wp-json/wp/v2/users' => '用户枚举 (User Enumeration)',
                '/xmlrpc.php'          => 'XML-RPC (容易被滥用发起 DDoS 或爆破密码)',
                '/wp-sitemap-users-1.xml' => '用户站点地图枚举 (User Sitemap Enumeration)',
            ],
            'dark_link_patterns'                => [
                'display:[[:space:]]*none',
                'position:[[:space:]]*absolute',
                'base64_decode',
                '<iframe',
            ],
            'upload_image_extensions'           => [ 'jpg', 'jpeg', 'jpe', 'png', 'gif', 'webp', 'bmp', 'avif', 'heic', 'heif' ],
            'upload_svg_script_regex'           => '/<(script|foreignObject)\b|onload\s*=|onerror\s*=|javascript:/i',
            'upload_active_script_regex'        => '/(eval\s*\(|document\.write|String\.fromCharCode|base64_decode|<script\b)/i',
            'persistence_safe_high_frequency_hooks' => [ 'action_scheduler_run_queue', 'as_async_request_queue_runner' ],
            'persistence_suspicious_keywords'   => [ 'base64', 'eval', 'shell', 'payload', 'backdoor', 'malware', 'inject', 'cmd', 'remote' ],
            'persistence_suspicious_hook_regex' => '/(?:[a-f0-9]{24,}|base64|eval|shell|gzinflate|cmd|payload|backdoor)/i',
            'persistence_file_exec_regex'       => '/\b(base64_decode|gzinflate|str_rot13|assert|eval|shell_exec|system|passthru|proc_open)\s*\(/i',
            'db_suspicious_option_name_patterns' => [ 'payload', 'backdoor', 'malware', 'shell', 'inject', 'spam', 'eval', 'base64', 'hidden_link', 'seo_spam' ],
            'db_suspicious_option_value_patterns' => [ '<script', '<iframe', 'base64_decode', 'gzinflate', 'document.write', 'fromcharcode', 'data:text/html', 'onerror=', 'onload=', 'shell_exec', 'eval(', 'assert(', 'javascript:' ],
            'db_critical_option_keywords'       => [ '<script', '<iframe', 'base64_decode', 'gzinflate', 'document.write', 'fromcharcode', 'shell_exec', 'eval(', 'assert(', 'javascript:' ],
        ];
    }

    private static function get_active_custom_package() {
        if ( null !== self::$active_package_cache ) {
            return self::$active_package_cache;
        }

        self::$active_package_cache = self::normalize_stored_package( get_option( self::OPTION_ACTIVE_PACKAGE, [] ) );

        return self::$active_package_cache;
    }

    private static function get_previous_custom_package() {
        if ( null !== self::$previous_package_cache ) {
            return self::$previous_package_cache;
        }

        self::$previous_package_cache = self::normalize_stored_package( get_option( self::OPTION_PREV_PACKAGE, [] ) );

        return self::$previous_package_cache;
    }

    private static function normalize_import_payload( $payload, $filename ) {
        $payload    = is_array( $payload ) ? $payload : [];
        $package_id = self::sanitize_plain_text( isset( $payload['package_id'] ) ? $payload['package_id'] : '' );
        $version    = self::sanitize_version( isset( $payload['version'] ) ? $payload['version'] : '' );
        $rules      = isset( $payload['rules'] ) && is_array( $payload['rules'] ) ? $payload['rules'] : [];
        $signer     = sanitize_key( isset( $payload['signer'] ) ? (string) $payload['signer'] : '' );
        $signature  = preg_replace( '/\s+/', '', (string) ( isset( $payload['rules_signature'] ) ? $payload['rules_signature'] : '' ) );

        if ( self::PACKAGE_ID !== $package_id ) {
            return [ 'error' => '规则包 package_id 不匹配。' ];
        }

        if ( '' === $version ) {
            return [ 'error' => '规则包 version 不能为空。' ];
        }

        $min_plugin_version = self::sanitize_version( isset( $payload['min_plugin_version'] ) ? $payload['min_plugin_version'] : '' );

        if ( '' !== $min_plugin_version && version_compare( QS_VERSION, $min_plugin_version, '<' ) ) {
            return [ 'error' => sprintf( '规则包要求插件版本 >= %s，当前插件版本为 %s。', $min_plugin_version, QS_VERSION ) ];
        }

        $sanitized_rules = self::sanitize_rule_overrides( $rules );

        if ( empty( $sanitized_rules ) ) {
            return [ 'error' => '规则包中没有可用的规则项，或全部规则校验失败。' ];
        }

        $expected_hash = strtolower( preg_replace( '/[^a-f0-9]/i', '', (string) ( isset( $payload['rules_sha256'] ) ? $payload['rules_sha256'] : '' ) ) );

        if ( '' === $expected_hash ) {
            return [ 'error' => '规则包缺少 rules_sha256，禁止导入未签名规则包。' ];
        }

        if ( 64 !== strlen( $expected_hash ) ) {
            return [ 'error' => 'rules_sha256 格式无效，必须是 64 位 SHA256 十六进制字符串。' ];
        }

        $actual_hash   = self::build_rules_hash( $sanitized_rules );

        if ( $expected_hash !== $actual_hash ) {
            return [ 'error' => '规则包哈希校验失败，请确认文件未损坏或被篡改。' ];
        }

        if ( '' === $signer || '' === $signature ) {
            return [ 'error' => '规则包缺少官方签名信息（signer / rules_signature）。' ];
        }

        $signature_check = self::validate_package_signature( $package_id, $version, $min_plugin_version, $expected_hash, $signer, $signature );

        if ( empty( $signature_check['ok'] ) ) {
            return [ 'error' => ! empty( $signature_check['message'] ) ? $signature_check['message'] : '规则包签名校验失败。' ];
        }

        $label = self::sanitize_plain_text( isset( $payload['label'] ) ? $payload['label'] : '' );
        if ( '' === $label ) {
            $label = $filename ? $filename : 'custom-package';
        }

        return [
            'package' => [
                'package_id'        => self::PACKAGE_ID,
                'version'           => $version,
                'label'             => self::truncate_text( $label, 120 ),
                'source'            => 'manual_upload',
                'min_plugin_version' => $min_plugin_version,
                'uploaded_at'       => current_time( 'mysql' ),
                'uploaded_by'       => get_current_user_id(),
                'filename'          => self::truncate_text( sanitize_file_name( (string) $filename ), 180 ),
                'signer'            => $signer,
                'rules_signature'   => self::truncate_text( (string) $signature, 4096 ),
                'rules_sha256'      => $actual_hash,
                'rules'             => $sanitized_rules,
            ],
        ];
    }

    private static function normalize_stored_package( $payload ) {
        $payload = is_array( $payload ) ? $payload : [];

        if ( empty( $payload ) ) {
            return [];
        }

        $package_id = self::sanitize_plain_text( isset( $payload['package_id'] ) ? $payload['package_id'] : '' );
        $version    = self::sanitize_version( isset( $payload['version'] ) ? $payload['version'] : '' );
        $signer     = sanitize_key( isset( $payload['signer'] ) ? (string) $payload['signer'] : '' );
        $signature  = preg_replace( '/\s+/', '', (string) ( isset( $payload['rules_signature'] ) ? $payload['rules_signature'] : '' ) );
        $rules      = isset( $payload['rules'] ) && is_array( $payload['rules'] ) ? $payload['rules'] : [];
        $rules      = self::sanitize_rule_overrides( $rules );

        if ( self::PACKAGE_ID !== $package_id || '' === $version || '' === $signer || '' === $signature || empty( $rules ) ) {
            return [];
        }

        $min_plugin_version = self::sanitize_version( isset( $payload['min_plugin_version'] ) ? $payload['min_plugin_version'] : '' );
        $rules_hash         = self::build_rules_hash( $rules );
        $signature_check    = self::validate_package_signature( $package_id, $version, $min_plugin_version, $rules_hash, $signer, $signature );

        if ( empty( $signature_check['ok'] ) ) {
            return [];
        }

        return [
            'package_id'         => self::PACKAGE_ID,
            'version'            => $version,
            'label'              => self::truncate_text( self::sanitize_plain_text( isset( $payload['label'] ) ? $payload['label'] : '' ), 120 ),
            'source'             => self::sanitize_plain_text( isset( $payload['source'] ) ? $payload['source'] : 'manual_upload' ),
            'min_plugin_version' => $min_plugin_version,
            'uploaded_at'        => self::truncate_text( self::sanitize_plain_text( isset( $payload['uploaded_at'] ) ? $payload['uploaded_at'] : '' ), 40 ),
            'uploaded_by'        => isset( $payload['uploaded_by'] ) ? absint( $payload['uploaded_by'] ) : 0,
            'filename'           => self::truncate_text( sanitize_file_name( (string) ( isset( $payload['filename'] ) ? $payload['filename'] : '' ) ), 180 ),
            'signer'             => $signer,
            'rules_signature'    => self::truncate_text( (string) $signature, 4096 ),
            'rules_sha256'       => $rules_hash,
            'rules'              => $rules,
        ];
    }

    private static function sanitize_rule_overrides( $rules ) {
        $rules    = is_array( $rules ) ? $rules : [];
        $defaults = self::get_builtin_rules();
        $cleaned  = [];

        foreach ( $defaults as $rule_key => $default_value ) {
            if ( ! array_key_exists( $rule_key, $rules ) ) {
                continue;
            }

            $candidate = $rules[ $rule_key ];

            if ( is_array( $default_value ) ) {
                if ( self::is_associative_array( $default_value ) ) {
                    $candidate = self::sanitize_rule_map( $rule_key, $candidate );
                } else {
                    $candidate = self::sanitize_rule_list( $rule_key, $candidate );
                }
            } elseif ( is_string( $default_value ) ) {
                $candidate = self::sanitize_rule_scalar( $rule_key, $candidate );
            } else {
                continue;
            }

            if ( null === $candidate || ( is_array( $candidate ) && empty( $candidate ) ) ) {
                continue;
            }

            $cleaned[ $rule_key ] = $candidate;
        }

        return $cleaned;
    }

    private static function sanitize_rule_map( $rule_key, $value ) {
        if ( ! is_array( $value ) ) {
            return null;
        }

        $cleaned = [];

        foreach ( $value as $map_key => $map_value ) {
            if ( 'code_vulnerability_patterns' === $rule_key ) {
                $key = strtoupper( preg_replace( '/[^a-zA-Z0-9_\-]/', '', (string) $map_key ) );
                $val = trim( (string) $map_value );

                if ( '' === $key || '' === $val || ! self::is_valid_regex( $val ) ) {
                    continue;
                }

                $cleaned[ $key ] = self::truncate_text( $val, 500 );
                continue;
            }

            if ( 'scan_api_endpoints' === $rule_key ) {
                $path = '/' . ltrim( self::sanitize_plain_text( $map_key ), '/' );
                $path = preg_replace( '#/+#', '/', $path );
                $label = self::sanitize_plain_text( $map_value );

                if ( '' === trim( $path, '/' ) || '' === $label ) {
                    continue;
                }

                $cleaned[ self::truncate_text( $path, 180 ) ] = self::truncate_text( $label, 180 );
                continue;
            }

            $key = self::sanitize_plain_text( $map_key );
            $val = self::sanitize_plain_text( $map_value );

            if ( '' === $key || '' === $val ) {
                continue;
            }

            $cleaned[ self::truncate_text( $key, 120 ) ] = self::truncate_text( $val, 500 );
        }

        return $cleaned;
    }

    private static function sanitize_rule_list( $rule_key, $value ) {
        if ( ! is_array( $value ) ) {
            return null;
        }

        if ( 'component_vulnerability_feed' === $rule_key ) {
            return self::sanitize_component_vulnerability_feed( $value );
        }

        $cleaned = [];

        foreach ( $value as $item ) {
            $item = self::sanitize_plain_text( $item );

            if ( '' === $item ) {
                continue;
            }

            if ( 'upload_image_extensions' === $rule_key ) {
                $item = ltrim( strtolower( $item ), '.' );
            }

            $cleaned[] = self::truncate_text( $item, 240 );
        }

        $cleaned = array_values( array_unique( array_filter( $cleaned ) ) );

        return array_slice( $cleaned, 0, 400 );
    }

    private static function sanitize_component_vulnerability_feed( $value ) {
        $cleaned = [];

        foreach ( $value as $item ) {
            if ( ! is_array( $item ) ) {
                continue;
            }

            $component_type = sanitize_key( isset( $item['component_type'] ) ? (string) $item['component_type'] : '' );
            $slug           = strtolower( preg_replace( '/[^a-z0-9._-]/', '', (string) ( isset( $item['slug'] ) ? $item['slug'] : '' ) ) );
            $title          = self::truncate_text( self::sanitize_plain_text( isset( $item['title'] ) ? $item['title'] : '' ), 180 );
            $affected       = self::truncate_text( self::sanitize_plain_text( isset( $item['affected_versions'] ) ? $item['affected_versions'] : '' ), 120 );

            if ( ! in_array( $component_type, [ 'plugin', 'theme' ], true ) || '' === $slug || '' === $title || '' === $affected ) {
                continue;
            }

            $cleaned[] = [
                'id'                => self::truncate_text(
                    self::sanitize_plain_text(
                        isset( $item['id'] ) ? $item['id'] : strtoupper( $component_type . ':' . $slug . ':' . $title )
                    ),
                    120
                ),
                'component_type'    => $component_type,
                'slug'              => $slug,
                'title'             => $title,
                'severity'          => self::sanitize_issue_severity( isset( $item['severity'] ) ? $item['severity'] : 'warning' ),
                'affected_versions' => $affected,
                'fixed_in'          => self::sanitize_version( isset( $item['fixed_in'] ) ? $item['fixed_in'] : '' ),
                'reference'         => self::truncate_text( esc_url_raw( (string) ( isset( $item['reference'] ) ? $item['reference'] : '' ) ), 500 ),
                'source'            => self::truncate_text( self::sanitize_plain_text( isset( $item['source'] ) ? $item['source'] : '' ), 80 ),
                'cve'               => self::truncate_text( self::sanitize_plain_text( isset( $item['cve'] ) ? $item['cve'] : '' ), 80 ),
            ];
        }

        return array_slice( array_values( array_unique( $cleaned, SORT_REGULAR ) ), 0, 5000 );
    }

    private static function sanitize_rule_scalar( $rule_key, $value ) {
        $value = trim( (string) $value );

        if ( '' === $value ) {
            return null;
        }

        if ( in_array( $rule_key, [ 'upload_svg_script_regex', 'upload_active_script_regex', 'persistence_suspicious_hook_regex', 'persistence_file_exec_regex' ], true ) ) {
            if ( ! self::is_valid_regex( $value ) ) {
                return null;
            }

            return self::truncate_text( $value, 500 );
        }

        return self::truncate_text( self::sanitize_plain_text( $value ), 500 );
    }

    private static function build_rules_hash( $rules ) {
        $rules = self::normalize_for_hash( is_array( $rules ) ? $rules : [] );
        $json  = wp_json_encode( $rules, JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES );

        return hash( 'sha256', is_string( $json ) ? $json : '' );
    }

    private static function validate_package_signature( $package_id, $version, $min_plugin_version, $rules_hash, $signer, $signature ) {
        $package_id         = (string) $package_id;
        $version            = (string) $version;
        $min_plugin_version = (string) $min_plugin_version;
        $rules_hash         = strtolower( (string) $rules_hash );
        $signer             = sanitize_key( (string) $signer );
        $signature          = preg_replace( '/\s+/', '', (string) $signature );
        $keys               = self::get_official_signing_keys();

        if ( '' === $signer || ! isset( $keys[ $signer ] ) ) {
            return [
                'ok'      => false,
                'message' => '签名方不是官方受信任签名者，已拒绝导入。',
            ];
        }

        if ( ! function_exists( 'openssl_verify' ) || ! function_exists( 'openssl_pkey_get_public' ) ) {
            return [
                'ok'      => false,
                'message' => '服务器缺少 OpenSSL 扩展，无法校验官方规则包签名。',
            ];
        }

        $binary_signature = base64_decode( $signature, true );

        if ( false === $binary_signature || '' === $binary_signature ) {
            return [
                'ok'      => false,
                'message' => 'rules_signature 不是有效的 Base64 签名。',
            ];
        }

        $payload = self::build_signature_payload( $package_id, $version, $min_plugin_version, $rules_hash );

        if ( '' === $payload ) {
            return [
                'ok'      => false,
                'message' => '规则包签名载荷构建失败。',
            ];
        }

        $public_key = openssl_pkey_get_public( $keys[ $signer ] );

        if ( false === $public_key ) {
            return [
                'ok'      => false,
                'message' => '官方公钥加载失败，请检查插件签名配置。',
            ];
        }

        $verify_result = openssl_verify( $payload, $binary_signature, $public_key, OPENSSL_ALGO_SHA256 );

        if ( 1 !== $verify_result ) {
            return [
                'ok'      => false,
                'message' => '规则包签名校验失败，非官方签名或文件被篡改。',
            ];
        }

        return [ 'ok' => true ];
    }

    private static function build_signature_payload( $package_id, $version, $min_plugin_version, $rules_hash ) {
        $payload = [
            'package_id'         => (string) $package_id,
            'version'            => (string) $version,
            'min_plugin_version' => (string) $min_plugin_version,
            'rules_sha256'       => strtolower( (string) $rules_hash ),
        ];

        $json = wp_json_encode( $payload, JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES );

        return is_string( $json ) ? $json : '';
    }

    private static function normalize_for_hash( $value ) {
        if ( ! is_array( $value ) ) {
            return $value;
        }

        if ( self::is_associative_array( $value ) ) {
            ksort( $value );
        }

        foreach ( $value as $key => $child ) {
            $value[ $key ] = self::normalize_for_hash( $child );
        }

        return $value;
    }

    private static function merge_rule_value( $base, $override ) {
        if ( is_array( $base ) && is_array( $override ) ) {
            if ( self::is_associative_array( $base ) || self::is_associative_array( $override ) ) {
                foreach ( $override as $key => $value ) {
                    $base[ $key ] = $value;
                }

                return $base;
            }

            return array_values( array_unique( array_merge( $base, $override ), SORT_REGULAR ) );
        }

        return $override;
    }

    private static function get_official_signing_keys() {
        return [
            self::OFFICIAL_SIGNER_ID => self::OFFICIAL_SIGNER_PUBLIC_KEY,
        ];
    }

    private static function is_associative_array( $array ) {
        if ( ! is_array( $array ) || [] === $array ) {
            return false;
        }

        return array_keys( $array ) !== range( 0, count( $array ) - 1 );
    }

    private static function sanitize_plain_text( $value ) {
        $value = wp_check_invalid_utf8( (string) $value, true );
        $value = str_replace( [ "\0", "\r", "\n", "\t" ], ' ', $value );
        $value = preg_replace( '/\s+/u', ' ', $value );

        return trim( (string) $value );
    }

    private static function sanitize_version( $value ) {
        $value = self::sanitize_plain_text( $value );
        $value = preg_replace( '/[^a-zA-Z0-9._-]/', '', $value );

        return self::truncate_text( (string) $value, 40 );
    }

    private static function truncate_text( $value, $max_length ) {
        $value      = (string) $value;
        $max_length = max( 1, absint( $max_length ) );

        if ( function_exists( 'mb_strlen' ) && function_exists( 'mb_substr' ) ) {
            if ( mb_strlen( $value ) <= $max_length ) {
                return $value;
            }

            return mb_substr( $value, 0, $max_length );
        }

        return strlen( $value ) <= $max_length ? $value : substr( $value, 0, $max_length );
    }

    private static function is_valid_regex( $regex ) {
        $regex = (string) $regex;

        if ( '' === $regex ) {
            return false;
        }

        $result = @preg_match( $regex, 'qiling-security-rule-test' );

        return false !== $result;
    }

    private static function sanitize_issue_severity( $value ) {
        $value = sanitize_key( (string) $value );

        if ( in_array( $value, [ 'critical', 'warning', 'info' ], true ) ) {
            return $value;
        }

        if ( in_array( $value, [ 'high', 'medium', 'moderate', 'low' ], true ) ) {
            if ( 'high' === $value ) {
                return 'critical';
            }

            if ( in_array( $value, [ 'medium', 'moderate' ], true ) ) {
                return 'warning';
            }

            return 'info';
        }

        return 'warning';
    }

    private static function get_upload_error_message( $error_code ) {
        switch ( (int) $error_code ) {
            case UPLOAD_ERR_INI_SIZE:
            case UPLOAD_ERR_FORM_SIZE:
                return '上传文件过大，已超过服务器限制。';
            case UPLOAD_ERR_PARTIAL:
                return '文件上传不完整，请重试。';
            case UPLOAD_ERR_NO_FILE:
                return '未选择上传文件。';
            case UPLOAD_ERR_NO_TMP_DIR:
                return '服务器缺少临时目录，无法接收上传。';
            case UPLOAD_ERR_CANT_WRITE:
                return '服务器无法写入临时文件。';
            case UPLOAD_ERR_EXTENSION:
                return '上传被服务器扩展中断。';
            default:
                return '文件上传失败（未知错误）。';
        }
    }

    private static function get_package_size_limit_label() {
        $bytes = (int) self::MAX_PACKAGE_FILE_BYTES;

        if ( $bytes >= 1048576 ) {
            return rtrim( rtrim( number_format( $bytes / 1048576, 2, '.', '' ), '0' ), '.' ) . 'MB';
        }

        if ( $bytes >= 1024 ) {
            return rtrim( rtrim( number_format( $bytes / 1024, 2, '.', '' ), '0' ), '.' ) . 'KB';
        }

        return $bytes . 'B';
    }

    private static function clear_runtime_cache() {
        self::$effective_rules_cache  = null;
        self::$active_package_cache   = null;
        self::$previous_package_cache = null;
    }
}
