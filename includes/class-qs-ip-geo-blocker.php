<?php
/**
 * 启灵安全防护 - 独立地区限制
 */
if ( ! defined( 'ABSPATH' ) ) {
    exit;
}

class QS_IP_Geo_Blocker {

    private static $runtime_cache = [];

    public static function maybe_block_current_request( $settings = null ) {
        if ( ! class_exists( 'QS_Protection' ) || ! class_exists( 'QS_DB' ) || ! class_exists( 'QS_Audit' ) ) {
            return;
        }

        $settings = is_array( $settings ) ? $settings : QS_Protection::get_settings();

        if ( ! QS_Protection::is_geo_block_enabled( $settings ) ) {
            return;
        }

        $denied_countries = QS_Protection::get_geo_block_denied_countries( $settings );
        if ( empty( $denied_countries ) ) {
            return;
        }

        if ( QS_Audit::is_current_request_trusted( $settings ) ) {
            return;
        }

        $ip_address = self::normalize_ip_address( QS_Audit::get_real_ip( $settings ) );
        if ( '' === $ip_address || ! self::is_public_ip( $ip_address ) ) {
            return;
        }

        $provider = QS_Protection::get_geo_block_provider( $settings );
        $geo      = self::get_geo_for_ip( $ip_address, $provider, $settings );
        $status   = isset( $geo['query_status'] ) ? sanitize_key( (string) $geo['query_status'] ) : 'unknown';

        if ( 'ready' !== $status ) {
            if ( 'block' === QS_Protection::get_geo_block_failure_policy( $settings ) ) {
                self::handle_blocked_request( $ip_address, $settings, $geo, 'lookup_failed' );
            }

            return;
        }

        $country_code = self::normalize_country_code( isset( $geo['country_code'] ) ? $geo['country_code'] : '' );
        if ( '' === $country_code || ! in_array( $country_code, $denied_countries, true ) ) {
            return;
        }

        self::handle_blocked_request( $ip_address, $settings, $geo, 'country_denied' );
    }

    private static function get_geo_for_ip( $ip_address, $provider, $settings ) {
        $ip_address = self::normalize_ip_address( $ip_address );
        $provider   = sanitize_key( str_replace( '-', '_', (string) $provider ) );

        if ( '' === $ip_address || '' === $provider ) {
            return [
                'query_status'  => 'failed',
                'error_message' => 'invalid_ip_or_provider',
            ];
        }

        $cache_key = $provider . '|' . $ip_address;
        if ( isset( self::$runtime_cache[ $cache_key ] ) ) {
            return self::$runtime_cache[ $cache_key ];
        }

        $cached = QS_DB::get_ip_geo_cache( $ip_address, $provider );
        if ( self::is_cache_fresh( $cached, QS_Protection::get_geo_block_cache_ttl_seconds( $settings ) ) ) {
            QS_DB::touch_ip_geo_cache( $ip_address, $provider );
            self::$runtime_cache[ $cache_key ] = $cached;

            return $cached;
        }

        $geo = self::query_provider( $provider, $ip_address, $settings );
        $geo = self::normalize_geo_result( $provider, $geo );

        QS_DB::upsert_ip_geo_cache( $ip_address, $provider, $geo );

        $stored = QS_DB::get_ip_geo_cache( $ip_address, $provider );
        if ( ! empty( $stored ) ) {
            $geo = $stored;
        }

        self::$runtime_cache[ $cache_key ] = $geo;

        return $geo;
    }

    private static function query_provider( $provider, $ip_address, $settings ) {
        switch ( $provider ) {
            case 'ipdata':
                return self::query_ipdata( $ip_address, $settings );
            case 'ipinfo':
                return self::query_ipinfo( $ip_address, $settings );
            case 'ip_api':
            default:
                return self::query_ip_api( $ip_address, $settings );
        }
    }

    private static function query_ipdata( $ip_address, $settings ) {
        $credentials = QS_Protection::get_ip_risk_provider_credentials( $settings );
        $api_key     = isset( $credentials['ipdata_key'] ) ? trim( (string) $credentials['ipdata_key'] ) : '';

        if ( '' === $api_key ) {
            return self::build_failed_result( 'ipdata', 'missing_api_key' );
        }

        $url      = 'https://api.ipdata.co/' . rawurlencode( $ip_address ) . '?api-key=' . rawurlencode( $api_key ) . '&fields=ip,country_name,country_code';
        $response = self::http_get_json( $url, $settings );

        return self::build_result_from_response( 'ipdata', $response );
    }

    private static function query_ip_api( $ip_address, $settings ) {
        $fields   = 'status,message,country,countryCode,regionName,city,timezone,isp,org';
        $url      = 'http://ip-api.com/json/' . rawurlencode( $ip_address ) . '?fields=' . rawurlencode( $fields );
        $response = self::http_get_json( $url, $settings );

        if ( ! empty( $response['ok'] ) && isset( $response['data']['status'] ) && 'success' !== (string) $response['data']['status'] ) {
            return self::build_failed_result( 'ip_api', isset( $response['data']['message'] ) ? (string) $response['data']['message'] : 'query_failed' );
        }

        return self::build_result_from_response( 'ip_api', $response );
    }

    private static function query_ipinfo( $ip_address, $settings ) {
        $credentials = QS_Protection::get_ip_risk_provider_credentials( $settings );
        $token       = isset( $credentials['ipinfo_token'] ) ? trim( (string) $credentials['ipinfo_token'] ) : '';
        $url         = 'https://ipinfo.io/' . rawurlencode( $ip_address ) . '/json';

        if ( '' !== $token ) {
            $url .= '?token=' . rawurlencode( $token );
        }

        $response = self::http_get_json( $url, $settings );

        return self::build_result_from_response( 'ipinfo', $response );
    }

    private static function build_result_from_response( $provider, $response ) {
        $provider = sanitize_key( (string) $provider );

        if ( empty( $response['ok'] ) ) {
            return self::build_failed_result( $provider, isset( $response['error'] ) ? $response['error'] : 'query_failed' );
        }

        $data    = isset( $response['data'] ) && is_array( $response['data'] ) ? $response['data'] : [];
        $country = self::extract_country_from_provider_data( $provider, $data );

        if ( empty( $country['country_code'] ) ) {
            return self::build_failed_result( $provider, 'country_not_found' );
        }

        return [
            'provider'      => $provider,
            'country_code'  => $country['country_code'],
            'country_name'  => $country['country_name'],
            'query_status'  => 'ready',
            'error_message' => '',
        ];
    }

    private static function build_failed_result( $provider, $error_message ) {
        return [
            'provider'      => sanitize_key( (string) $provider ),
            'country_code'  => '',
            'country_name'  => '',
            'query_status'  => 'failed',
            'error_message' => sanitize_text_field( (string) $error_message ),
        ];
    }

    private static function normalize_geo_result( $provider, $geo ) {
        $geo = is_array( $geo ) ? $geo : [];

        return [
            'provider'      => sanitize_key( isset( $geo['provider'] ) ? (string) $geo['provider'] : (string) $provider ),
            'country_code'  => self::normalize_country_code( isset( $geo['country_code'] ) ? $geo['country_code'] : '' ),
            'country_name'  => substr( sanitize_text_field( (string) ( isset( $geo['country_name'] ) ? $geo['country_name'] : '' ) ), 0, 100 ),
            'query_status'  => sanitize_key( isset( $geo['query_status'] ) ? (string) $geo['query_status'] : 'failed' ),
            'error_message' => substr( sanitize_text_field( (string) ( isset( $geo['error_message'] ) ? $geo['error_message'] : '' ) ), 0, 255 ),
        ];
    }

    private static function extract_country_from_provider_data( $provider, $data ) {
        $provider = sanitize_key( (string) $provider );
        $data     = is_array( $data ) ? $data : [];
        $code     = '';
        $name     = '';

        switch ( $provider ) {
            case 'ipdata':
                $code = isset( $data['country_code'] ) ? $data['country_code'] : '';
                $name = isset( $data['country_name'] ) ? $data['country_name'] : '';
                break;
            case 'ip_api':
                $code = isset( $data['countryCode'] ) ? $data['countryCode'] : '';
                $name = isset( $data['country'] ) ? $data['country'] : '';
                break;
            case 'ipinfo':
                $code = isset( $data['country_code'] ) ? $data['country_code'] : ( isset( $data['country'] ) ? $data['country'] : '' );
                $name = isset( $data['country_name'] ) ? $data['country_name'] : '';
                break;
        }

        if ( '' === $code ) {
            $code = isset( $data['country_code'] ) ? $data['country_code'] : ( isset( $data['countryCode'] ) ? $data['countryCode'] : '' );
        }

        return [
            'country_code' => self::normalize_country_code( $code ),
            'country_name' => substr( sanitize_text_field( (string) $name ), 0, 100 ),
        ];
    }

    private static function http_get_json( $url, $settings, $args = [] ) {
        $headers = isset( $args['headers'] ) && is_array( $args['headers'] ) ? $args['headers'] : [];
        $timeout = 1.5;

        if ( class_exists( 'QS_Protection' ) && method_exists( 'QS_Protection', 'get_ip_risk_provider_timeout_seconds' ) ) {
            $timeout = min( 2.0, max( 0.5, QS_Protection::get_ip_risk_provider_timeout_seconds( $settings ) ) );
        }

        $request = [
            'timeout'     => $timeout,
            'redirection' => 2,
            'sslverify'   => isset( $args['sslverify'] ) ? (bool) $args['sslverify'] : true,
            'headers'     => $headers,
            'user-agent'  => isset( $args['user-agent'] ) ? (string) $args['user-agent'] : 'QilingSecurity/' . ( defined( 'QS_VERSION' ) ? QS_VERSION : '1.0.0' ),
        ];

        $response = wp_safe_remote_get( $url, $request );
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
            return [
                'ok'    => false,
                'error' => 'invalid_json',
            ];
        }

        if ( $code < 200 || $code >= 300 ) {
            $detail = ! empty( $json['message'] ) ? (string) $json['message'] : 'http_' . $code;

            return [
                'ok'    => false,
                'error' => $detail,
                'data'  => $json,
            ];
        }

        return [
            'ok'   => true,
            'data' => $json,
        ];
    }

    private static function handle_blocked_request( $ip_address, $settings, $geo, $reason ) {
        $geo           = is_array( $geo ) ? $geo : [];
        $country_code  = self::normalize_country_code( isset( $geo['country_code'] ) ? $geo['country_code'] : '' );
        $country_name  = isset( $geo['country_name'] ) ? sanitize_text_field( (string) $geo['country_name'] ) : '';
        $provider      = isset( $geo['provider'] ) ? sanitize_key( (string) $geo['provider'] ) : QS_Protection::get_geo_block_provider( $settings );
        $action        = QS_Protection::get_geo_block_action( $settings );
        $redirect_url  = QS_Protection::get_geo_block_redirect_url( $settings );
        $request_path  = QS_Audit::get_request_path();
        $reason        = sanitize_key( (string) $reason );

        if ( 'redirect' !== $action || '' === $redirect_url || self::is_non_page_request() ) {
            $action = 'forbidden';
        }

        self::record_block_event(
            $ip_address,
            $country_code,
            $country_name,
            $provider,
            $action,
            $reason,
            $request_path
        );

        if ( 'redirect' === $action ) {
            wp_redirect( $redirect_url, 302, 'Qiling Security Geo Blocker' );
            exit;
        }

        status_header( 403 );
        nocache_headers();

        wp_die(
            '<h1>403 Forbidden</h1><p>Access denied. Your region is not allowed to access this site.</p>',
            'Forbidden',
            [ 'response' => 403 ]
        );
    }

    private static function record_block_event( $ip_address, $country_code, $country_name, $provider, $action, $reason, $request_path ) {
        if ( '' !== $country_name && '' !== $country_code ) {
            $country_label = $country_name . ' (' . $country_code . ')';
        } elseif ( '' !== $country_name ) {
            $country_label = $country_name;
        } else {
            $country_label = $country_code;
        }
        $detail        = sprintf(
            'IP=%s，地区=%s，来源=%s，动作=%s，原因=%s，路径=%s',
            $ip_address,
            '' !== $country_label ? $country_label : 'unknown',
            $provider,
            $action,
            $reason,
            $request_path
        );

        if ( class_exists( 'QS_DB' ) && method_exists( 'QS_DB', 'record_geo_block_log' ) ) {
            QS_DB::record_geo_block_log(
                [
                    'ip_address'     => $ip_address,
                    'country_code'   => $country_code,
                    'country_name'   => $country_name,
                    'provider'       => $provider,
                    'action'         => $action,
                    'reason'         => $reason,
                    'request_path'   => $request_path,
                    'request_method' => isset( $_SERVER['REQUEST_METHOD'] ) ? wp_unslash( $_SERVER['REQUEST_METHOD'] ) : '',
                    'user_agent'     => isset( $_SERVER['HTTP_USER_AGENT'] ) ? wp_unslash( $_SERVER['HTTP_USER_AGENT'] ) : '',
                    'referer'        => isset( $_SERVER['HTTP_REFERER'] ) ? wp_unslash( $_SERVER['HTTP_REFERER'] ) : '',
                ]
            );
        }

        QS_Audit::record_event(
            '地区限制',
            $detail,
            [
                'ip' => $ip_address,
            ]
        );

        if ( class_exists( 'QS_Alert_Center' ) ) {
            QS_Alert_Center::trigger_event(
                'geo_block',
                '地区限制',
                [ $detail ],
                [
                    'ip'           => $ip_address,
                    'country_code' => $country_code,
                    'provider'     => $provider,
                    'action'       => $action,
                    'fingerprint'  => 'geo-block|' . $country_code . '|' . $provider . '|' . $action,
                ]
            );
        }
    }

    private static function is_cache_fresh( $cache, $ttl_seconds ) {
        if ( empty( $cache ) || ! is_array( $cache ) ) {
            return false;
        }

        $updated_at = isset( $cache['updated_at'] ) ? (string) $cache['updated_at'] : '';
        $updated_ts = strtotime( $updated_at );

        if ( ! $updated_ts ) {
            return false;
        }

        $status        = isset( $cache['query_status'] ) ? sanitize_key( (string) $cache['query_status'] ) : 'unknown';
        $effective_ttl = max( HOUR_IN_SECONDS, (int) $ttl_seconds );

        if ( 'ready' !== $status ) {
            $effective_ttl = min( $effective_ttl, 10 * MINUTE_IN_SECONDS );
        }

        return ( time() - $updated_ts ) <= $effective_ttl;
    }

    private static function is_public_ip( $ip_address ) {
        return (bool) filter_var( $ip_address, FILTER_VALIDATE_IP, FILTER_FLAG_NO_PRIV_RANGE | FILTER_FLAG_NO_RES_RANGE );
    }

    private static function normalize_ip_address( $ip_address ) {
        $ip_address = filter_var( trim( (string) $ip_address ), FILTER_VALIDATE_IP );

        return $ip_address ? $ip_address : '';
    }

    private static function normalize_country_code( $value ) {
        $code = strtoupper( preg_replace( '/[^A-Za-z]/', '', (string) $value ) );

        return 2 === strlen( $code ) ? $code : '';
    }

    private static function is_non_page_request() {
        $path = class_exists( 'QS_Audit' ) ? QS_Audit::get_request_path() : '';

        if ( function_exists( 'wp_doing_ajax' ) && wp_doing_ajax() ) {
            return true;
        }

        if ( function_exists( 'wp_doing_cron' ) && wp_doing_cron() ) {
            return true;
        }

        if ( defined( 'REST_REQUEST' ) && REST_REQUEST ) {
            return true;
        }

        if ( defined( 'XMLRPC_REQUEST' ) && XMLRPC_REQUEST ) {
            return true;
        }

        foreach ( [ '/wp-json', '/wp-admin', '/wp-login.php', '/xmlrpc.php' ] as $prefix ) {
            if ( 0 === strpos( $path, $prefix ) ) {
                return true;
            }
        }

        return false;
    }
}
