#!/usr/bin/env php
<?php
/**
 * Qiling Security rules package signer.
 *
 * Usage:
 * php sign-package.php --in package-template.json --out package-signed.json --private-key /secure/path/private.pem --signer qiling-official-v1
 */

if ( PHP_SAPI !== 'cli' ) {
    fwrite( STDERR, "This script must run in CLI.\n" );
    exit( 1 );
}

if ( ! function_exists( 'openssl_sign' ) ) {
    fwrite( STDERR, "OpenSSL extension is required.\n" );
    exit( 1 );
}

$options = getopt( '', [ 'in:', 'out:', 'private-key:', 'signer::' ] );
$inPath  = isset( $options['in'] ) ? (string) $options['in'] : '';
$outPath = isset( $options['out'] ) ? (string) $options['out'] : '';
$keyPath = isset( $options['private-key'] ) ? (string) $options['private-key'] : '';
$signer  = isset( $options['signer'] ) ? (string) $options['signer'] : 'qiling-official-v1';

if ( '' === $inPath || '' === $outPath || '' === $keyPath ) {
    fwrite( STDERR, "Missing required arguments.\n" );
    fwrite( STDERR, "Required: --in --out --private-key\n" );
    exit( 1 );
}

if ( ! is_file( $inPath ) || ! is_readable( $inPath ) ) {
    fwrite( STDERR, "Input file is not readable: {$inPath}\n" );
    exit( 1 );
}

if ( ! is_file( $keyPath ) || ! is_readable( $keyPath ) ) {
    fwrite( STDERR, "Private key is not readable: {$keyPath}\n" );
    exit( 1 );
}

$json = file_get_contents( $inPath );

if ( ! is_string( $json ) || '' === $json ) {
    fwrite( STDERR, "Failed to read input file.\n" );
    exit( 1 );
}

$payload = json_decode( $json, true );

if ( ! is_array( $payload ) ) {
    fwrite( STDERR, "Input is not a valid JSON object.\n" );
    exit( 1 );
}

$packageId = isset( $payload['package_id'] ) ? trim( (string) $payload['package_id'] ) : '';
$version   = isset( $payload['version'] ) ? trim( (string) $payload['version'] ) : '';
$minPlugin = isset( $payload['min_plugin_version'] ) ? trim( (string) $payload['min_plugin_version'] ) : '';
$rulesRaw  = isset( $payload['rules'] ) && is_array( $payload['rules'] ) ? $payload['rules'] : null;

if ( 'qilingsecurity-rules' !== $packageId ) {
    fwrite( STDERR, "package_id must be qilingsecurity-rules.\n" );
    exit( 1 );
}

if ( '' === $version ) {
    fwrite( STDERR, "version is required.\n" );
    exit( 1 );
}

if ( null === $rulesRaw ) {
    fwrite( STDERR, "rules must be an object.\n" );
    exit( 1 );
}

$rules = sanitize_rule_overrides( $rulesRaw );

if ( [] === $rules ) {
    fwrite( STDERR, "No valid rules after sanitization.\n" );
    exit( 1 );
}

$rulesJson = json_encode( normalize_for_hash( $rules ), JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES );

if ( ! is_string( $rulesJson ) || '' === $rulesJson ) {
    fwrite( STDERR, "Failed to serialize rules for hashing.\n" );
    exit( 1 );
}

$rulesHash = hash( 'sha256', $rulesJson );

$signaturePayload = json_encode(
    [
        'package_id'         => $packageId,
        'version'            => $version,
        'min_plugin_version' => $minPlugin,
        'rules_sha256'       => strtolower( $rulesHash ),
    ],
    JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES
);

if ( ! is_string( $signaturePayload ) || '' === $signaturePayload ) {
    fwrite( STDERR, "Failed to build signature payload.\n" );
    exit( 1 );
}

$privateKeyText = file_get_contents( $keyPath );
$privateKey     = openssl_pkey_get_private( $privateKeyText );

if ( false === $privateKey ) {
    fwrite( STDERR, "Failed to load private key.\n" );
    exit( 1 );
}

$binarySignature = '';
$signed          = openssl_sign( $signaturePayload, $binarySignature, $privateKey, OPENSSL_ALGO_SHA256 );

if ( ! $signed || '' === $binarySignature ) {
    fwrite( STDERR, "Failed to sign package.\n" );
    exit( 1 );
}

$payload['rules_sha256']    = strtolower( $rulesHash );
$payload['signer']          = trim( $signer );
$payload['rules_signature'] = base64_encode( $binarySignature );
$payload['rules']           = $rules;

$output = json_encode( $payload, JSON_PRETTY_PRINT | JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES );

if ( ! is_string( $output ) || '' === $output ) {
    fwrite( STDERR, "Failed to serialize signed package.\n" );
    exit( 1 );
}

$written = file_put_contents( $outPath, $output . PHP_EOL );

if ( false === $written ) {
    fwrite( STDERR, "Failed to write output file: {$outPath}\n" );
    exit( 1 );
}

fwrite( STDOUT, "Signed package written to {$outPath}\n" );
fwrite( STDOUT, "rules_sha256: {$payload['rules_sha256']}\n" );

exit( 0 );

function normalize_for_hash( $value ) {
    if ( ! is_array( $value ) ) {
        return $value;
    }

    if ( is_associative_array( $value ) ) {
        ksort( $value );
    }

    foreach ( $value as $key => $child ) {
        $value[ $key ] = normalize_for_hash( $child );
    }

    return $value;
}

function is_associative_array( $array ) {
    if ( ! is_array( $array ) || [] === $array ) {
        return false;
    }

    return array_keys( $array ) !== range( 0, count( $array ) - 1 );
}

function sanitize_rule_overrides( $rules ) {
    $rules    = is_array( $rules ) ? $rules : [];
    $defaults = get_builtin_rule_defaults();
    $cleaned  = [];

    foreach ( $defaults as $ruleKey => $defaultValue ) {
        if ( ! array_key_exists( $ruleKey, $rules ) ) {
            continue;
        }

        $candidate = $rules[ $ruleKey ];

        if ( is_array( $defaultValue ) ) {
            if ( is_associative_array( $defaultValue ) ) {
                $candidate = sanitize_rule_map( $ruleKey, $candidate );
            } else {
                $candidate = sanitize_rule_list( $ruleKey, $candidate );
            }
        } elseif ( is_string( $defaultValue ) ) {
            $candidate = sanitize_rule_scalar( $ruleKey, $candidate );
        } else {
            continue;
        }

        if ( null === $candidate || ( is_array( $candidate ) && [] === $candidate ) ) {
            continue;
        }

        $cleaned[ $ruleKey ] = $candidate;
    }

    return $cleaned;
}

function sanitize_rule_map( $ruleKey, $value ) {
    if ( ! is_array( $value ) ) {
        return null;
    }

    $cleaned = [];

    foreach ( $value as $mapKey => $mapValue ) {
        if ( 'code_vulnerability_patterns' === $ruleKey ) {
            $key = strtoupper( preg_replace( '/[^a-zA-Z0-9_\-]/', '', (string) $mapKey ) );
            $val = trim( (string) $mapValue );

            if ( '' === $key || '' === $val || ! is_valid_regex( $val ) ) {
                continue;
            }

            $cleaned[ $key ] = truncate_text( $val, 500 );
            continue;
        }

        if ( 'scan_api_endpoints' === $ruleKey ) {
            $path  = '/' . ltrim( sanitize_plain_text( $mapKey ), '/' );
            $path  = preg_replace( '#/+#', '/', $path );
            $label = sanitize_plain_text( $mapValue );

            if ( '' === trim( $path, '/' ) || '' === $label ) {
                continue;
            }

            $cleaned[ truncate_text( $path, 180 ) ] = truncate_text( $label, 180 );
            continue;
        }

        $key = sanitize_plain_text( $mapKey );
        $val = sanitize_plain_text( $mapValue );

        if ( '' === $key || '' === $val ) {
            continue;
        }

        $cleaned[ truncate_text( $key, 120 ) ] = truncate_text( $val, 500 );
    }

    return $cleaned;
}

function sanitize_rule_list( $ruleKey, $value ) {
    if ( ! is_array( $value ) ) {
        return null;
    }

    if ( 'component_vulnerability_feed' === $ruleKey ) {
        return sanitize_component_vulnerability_feed( $value );
    }

    $cleaned = [];

    foreach ( $value as $item ) {
        $item = sanitize_plain_text( $item );

        if ( '' === $item ) {
            continue;
        }

        if ( 'upload_image_extensions' === $ruleKey ) {
            $item = ltrim( strtolower( $item ), '.' );
        }

        $cleaned[] = truncate_text( $item, 240 );
    }

    $cleaned = array_values( array_unique( array_filter( $cleaned ) ) );

    return array_slice( $cleaned, 0, 400 );
}

function sanitize_component_vulnerability_feed( $value ) {
    $cleaned = [];

    foreach ( $value as $item ) {
        if ( ! is_array( $item ) ) {
            continue;
        }

        $componentType = sanitize_key( isset( $item['component_type'] ) ? (string) $item['component_type'] : '' );
        $slug          = strtolower( preg_replace( '/[^a-z0-9._-]/', '', (string) ( isset( $item['slug'] ) ? $item['slug'] : '' ) ) );
        $title         = truncate_text( sanitize_plain_text( isset( $item['title'] ) ? $item['title'] : '' ), 180 );
        $affected      = truncate_text( sanitize_plain_text( isset( $item['affected_versions'] ) ? $item['affected_versions'] : '' ), 120 );

        if ( ! in_array( $componentType, [ 'plugin', 'theme' ], true ) || '' === $slug || '' === $title || '' === $affected ) {
            continue;
        }

        $cleaned[] = [
            'id'                => truncate_text( sanitize_plain_text( isset( $item['id'] ) ? $item['id'] : strtoupper( $componentType . ':' . $slug . ':' . $title ) ), 120 ),
            'component_type'    => $componentType,
            'slug'              => $slug,
            'title'             => $title,
            'severity'          => sanitize_issue_severity( isset( $item['severity'] ) ? $item['severity'] : 'warning' ),
            'affected_versions' => $affected,
            'fixed_in'          => sanitize_version( isset( $item['fixed_in'] ) ? $item['fixed_in'] : '' ),
            'reference'         => truncate_text( esc_url_raw( (string) ( isset( $item['reference'] ) ? $item['reference'] : '' ) ), 500 ),
            'source'            => truncate_text( sanitize_plain_text( isset( $item['source'] ) ? $item['source'] : '' ), 80 ),
            'cve'               => truncate_text( sanitize_plain_text( isset( $item['cve'] ) ? $item['cve'] : '' ), 80 ),
        ];
    }

    return array_slice( array_values( array_unique( $cleaned, SORT_REGULAR ) ), 0, 5000 );
}

function sanitize_rule_scalar( $ruleKey, $value ) {
    $value = trim( (string) $value );

    if ( '' === $value ) {
        return null;
    }

    if ( in_array( $ruleKey, [ 'upload_svg_script_regex', 'upload_active_script_regex', 'persistence_suspicious_hook_regex', 'persistence_file_exec_regex' ], true ) ) {
        if ( ! is_valid_regex( $value ) ) {
            return null;
        }

        return truncate_text( $value, 500 );
    }

    return truncate_text( sanitize_plain_text( $value ), 500 );
}

function is_valid_regex( $regex ) {
    $result = @preg_match( (string) $regex, 'qiling-security-rule-test' );
    return false !== $result;
}

function sanitize_plain_text( $value ) {
    $value = (string) $value;
    $value = str_replace( [ "\0", "\r", "\n", "\t" ], ' ', $value );
    $value = preg_replace( '/\s+/u', ' ', $value );
    return trim( (string) $value );
}

function sanitize_version( $value ) {
    $value = sanitize_plain_text( $value );
    $value = preg_replace( '/[^a-zA-Z0-9._-]/', '', $value );

    return truncate_text( (string) $value, 40 );
}

function sanitize_issue_severity( $value ) {
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

function truncate_text( $value, $maxLength ) {
    $value     = (string) $value;
    $maxLength = max( 1, (int) $maxLength );

    if ( function_exists( 'mb_strlen' ) && function_exists( 'mb_substr' ) ) {
        return mb_strlen( $value ) <= $maxLength ? $value : mb_substr( $value, 0, $maxLength );
    }

    return strlen( $value ) <= $maxLength ? $value : substr( $value, 0, $maxLength );
}

function get_builtin_rule_defaults() {
    return [
        'code_vulnerability_patterns'          => [
            'RCE'   => '/\b(system|exec|shell_exec|passthru|proc_open|popen)\s*\(/i',
            'SSRF'  => '/\b(curl_exec|wp_remote_get|fsockopen)\s*\(.*(\$_GET|\$_POST|\$_REQUEST)/i',
            'WRITE' => '/\b(file_put_contents|fwrite)\s*\(.*(\$_GET|\$_POST|\$_REQUEST)/i',
        ],
        'component_vulnerability_feed'        => [],
        'scan_api_endpoints'                  => [
            '/wp-json/wp/v2/users' => '用户枚举 (User Enumeration)',
            '/xmlrpc.php'          => 'XML-RPC (容易被滥用发起 DDoS 或爆破密码)',
        ],
        'dark_link_patterns'                  => [
            'display:[[:space:]]*none',
            'position:[[:space:]]*absolute',
            'base64_decode',
            '<iframe',
        ],
        'upload_image_extensions'             => [ 'jpg', 'jpeg', 'jpe', 'png', 'gif', 'webp', 'bmp', 'avif', 'heic', 'heif' ],
        'upload_svg_script_regex'             => '/<(script|foreignObject)\b|onload\s*=|onerror\s*=|javascript:/i',
        'upload_active_script_regex'          => '/(eval\s*\(|document\.write|String\.fromCharCode|base64_decode|<script\b)/i',
        'persistence_safe_high_frequency_hooks' => [ 'action_scheduler_run_queue', 'as_async_request_queue_runner' ],
        'persistence_suspicious_keywords'     => [ 'base64', 'eval', 'shell', 'payload', 'backdoor', 'malware', 'inject', 'cmd', 'remote' ],
        'persistence_suspicious_hook_regex'   => '/(?:[a-f0-9]{24,}|base64|eval|shell|gzinflate|cmd|payload|backdoor)/i',
        'persistence_file_exec_regex'         => '/\b(base64_decode|gzinflate|str_rot13|assert|eval|shell_exec|system|passthru|proc_open)\s*\(/i',
        'db_suspicious_option_name_patterns'  => [ 'payload', 'backdoor', 'malware', 'shell', 'inject', 'spam', 'eval', 'base64', 'hidden_link', 'seo_spam' ],
        'db_suspicious_option_value_patterns' => [ '<script', '<iframe', 'base64_decode', 'gzinflate', 'document.write', 'fromcharcode', 'data:text/html', 'onerror=', 'onload=', 'shell_exec', 'eval(', 'assert(', 'javascript:' ],
        'db_critical_option_keywords'         => [ '<script', '<iframe', 'base64_decode', 'gzinflate', 'document.write', 'fromcharcode', 'shell_exec', 'eval(', 'assert(', 'javascript:' ],
    ];
}
