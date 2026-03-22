<?php
/**
 * 启灵安全防护 - 本地手机号归属地查询
 */
if ( ! defined( 'ABSPATH' ) ) {
    exit;
}

class QS_Phone_Location {

    const PHONE_SEGMENT_LENGTH = 7;
    const PREFIX_BLOCK_SIZE    = 20000; // 10000 * 2 bytes.
    const PREFIX_RECORD_SIZE   = 5;     // 1 byte prefix + 4 bytes offset.
    const LOW_BITS_MASK        = 31;    // value & 31 => ISP index.

    private static $dataset = null;

    private static $request_cache = [];

    public static function init() {
        // 预留：后续可在此注册统计任务或后台分析入口。
    }

    public static function is_enabled( $settings = null ) {
        if ( class_exists( 'QS_Protection' ) && method_exists( 'QS_Protection', 'is_phone_location_lookup_enabled' ) ) {
            return QS_Protection::is_phone_location_lookup_enabled( $settings );
        }

        return false;
    }

    public static function lookup( $phone, $args = [] ) {
        $normalized = self::normalize_phone( $phone );
        if ( '' === $normalized ) {
            return [];
        }

        if ( ! self::is_enabled() ) {
            return [];
        }

        $segment = substr( $normalized, 0, self::PHONE_SEGMENT_LENGTH );
        $context = isset( $args['context'] ) ? sanitize_key( (string) $args['context'] ) : 'default';

        do_action( 'qs_phone_location_lookup_attempt', $normalized, $segment, $context, $args );

        if ( isset( self::$request_cache[ $segment ] ) ) {
            $cached_result               = self::$request_cache[ $segment ];
            $cached_result['cache_hit']  = true;
            $cached_result['cache_type'] = 'request';

            return apply_filters( 'qs_phone_location_lookup_result', $cached_result, $normalized, $segment, $context, $args );
        }

        $cached = QS_DB::get_phone_location_cache( $segment );
        if ( is_array( $cached ) && ! empty( $cached['phone_segment'] ) ) {
            QS_DB::touch_phone_location_cache( $segment );

            $cached['cache_hit']  = true;
            $cached['cache_type'] = 'db';
            $cached['source']     = ! empty( $cached['source'] ) ? (string) $cached['source'] : 'db';

            self::$request_cache[ $segment ] = $cached;

            do_action( 'qs_phone_location_cache_hit', $normalized, $segment, $cached, $context, $args );
            do_action( 'qs_phone_location_resolved', $normalized, $cached, $context, $args );

            return apply_filters( 'qs_phone_location_lookup_result', $cached, $normalized, $segment, $context, $args );
        }

        $resolved = self::lookup_by_segment_from_dat( $segment );
        if ( empty( $resolved ) ) {
            do_action( 'qs_phone_location_lookup_miss', $normalized, $segment, $context, $args );
            return [];
        }

        $resolved['cache_hit']  = false;
        $resolved['cache_type'] = 'dat';
        $resolved['source']     = 'dat';

        QS_DB::upsert_phone_location_cache( $segment, $resolved );
        do_action( 'qs_phone_location_cache_saved', $segment, $resolved, $context, $args );

        self::$request_cache[ $segment ] = $resolved;

        do_action( 'qs_phone_location_resolved', $normalized, $resolved, $context, $args );

        return apply_filters( 'qs_phone_location_lookup_result', $resolved, $normalized, $segment, $context, $args );
    }

    private static function lookup_by_segment_from_dat( $segment ) {
        $dataset = self::load_dataset();
        if ( empty( $dataset ) || empty( $dataset['binary'] ) || empty( $dataset['prefix_map'] ) ) {
            return [];
        }

        $prefix = (string) absint( substr( $segment, 0, 3 ) );
        $suffix = absint( substr( $segment, 3, 4 ) );

        if ( ! isset( $dataset['prefix_map'][ $prefix ] ) ) {
            return [];
        }

        $base_offset  = (int) $dataset['prefix_map'][ $prefix ];
        $value_offset = $base_offset + ( $suffix * 2 );

        if ( $value_offset < 0 || ( $value_offset + 2 ) > $dataset['size'] ) {
            return [];
        }

        $packed = substr( $dataset['binary'], $value_offset, 2 );
        if ( strlen( $packed ) < 2 ) {
            return [];
        }

        $value = unpack( 'v', $packed );
        $value = isset( $value[1] ) ? (int) $value[1] : 0;

        if ( $value <= 0 ) {
            return [];
        }

        $location_index = $value >> 5;
        $isp_index      = $value & self::LOW_BITS_MASK;

        $location_raw = isset( $dataset['location_entries'][ $location_index ] ) ? trim( (string) $dataset['location_entries'][ $location_index ] ) : '';
        if ( '' === $location_raw ) {
            return [];
        }

        $location_parts = array_map( 'trim', explode( '|', $location_raw ) );

        // 第一项通常是“省份|城市|邮编|区号|行政区划代码”标题行，不作为有效归属地。
        if ( ! empty( $location_parts[0] ) && in_array( $location_parts[0], [ '省份', '城市' ], true ) ) {
            return [];
        }

        $province    = isset( $location_parts[0] ) ? sanitize_text_field( $location_parts[0] ) : '';
        $city        = isset( $location_parts[1] ) ? sanitize_text_field( $location_parts[1] ) : '';
        $tel_code    = isset( $location_parts[2] ) ? sanitize_text_field( $location_parts[2] ) : '';
        $postal_code = isset( $location_parts[3] ) ? sanitize_text_field( $location_parts[3] ) : '';
        $area_code   = isset( $location_parts[4] ) ? sanitize_text_field( $location_parts[4] ) : '';

        $isp = '';
        if ( $isp_index > 0 ) {
            $isp_pos = $isp_index - 1;
            if ( isset( $dataset['isp_entries'][ $isp_pos ] ) ) {
                $isp = sanitize_text_field( trim( (string) $dataset['isp_entries'][ $isp_pos ] ) );
            }
        }

        $parts_for_text = array_values(
            array_filter(
                [ $province, $city, $isp ],
                static function( $part ) {
                    return '' !== trim( (string) $part );
                }
            )
        );

        return [
            'phone_segment' => $segment,
            'prefix'        => substr( $segment, 0, 3 ),
            'province'      => $province,
            'city'          => $city,
            'isp'           => $isp,
            'tel_code'      => $tel_code,
            'postal_code'   => $postal_code,
            'area_code'     => $area_code,
            'location_text' => implode( ' · ', $parts_for_text ),
            'dat_version'   => isset( $dataset['dat_version'] ) ? (string) $dataset['dat_version'] : '',
            'source'        => 'dat',
            'raw_value'     => $value,
        ];
    }

    private static function load_dataset() {
        if ( is_array( self::$dataset ) ) {
            return self::$dataset;
        }

        $path = self::get_dat_path();
        if ( '' === $path || ! is_readable( $path ) ) {
            self::$dataset = [];
            return self::$dataset;
        }

        $binary = @file_get_contents( $path );
        if ( false === $binary || '' === $binary ) {
            self::$dataset = [];
            return self::$dataset;
        }

        $size = strlen( $binary );
        if ( $size < 32 ) {
            self::$dataset = [];
            return self::$dataset;
        }

        $header = unpack( 'Vprefix_count/Vsegment_count/Vheader_three/Vheader_four', substr( $binary, 0, 16 ) );
        if ( ! is_array( $header ) ) {
            self::$dataset = [];
            return self::$dataset;
        }

        $prefix_count = isset( $header['prefix_count'] ) ? (int) $header['prefix_count'] : 0;
        if ( $prefix_count <= 0 || $prefix_count > 255 ) {
            self::$dataset = [];
            return self::$dataset;
        }

        $prefix_bundle_size = $prefix_count * ( self::PREFIX_RECORD_SIZE + self::PREFIX_BLOCK_SIZE );
        $prefix_table_offset = $size - $prefix_bundle_size;

        if ( $prefix_table_offset <= 20 ) {
            self::$dataset = [];
            return self::$dataset;
        }

        $dat_version = unpack( 'V', substr( $binary, 16, 4 ) );
        $dat_version = isset( $dat_version[1] ) ? (string) absint( $dat_version[1] ) : '';

        $text_blob = substr( $binary, 20, $prefix_table_offset - 20 );
        if ( '' === $text_blob ) {
            self::$dataset = [];
            return self::$dataset;
        }

        $marker     = '运营商&';
        $marker_pos = strpos( $text_blob, $marker );
        if ( false === $marker_pos ) {
            self::$dataset = [];
            return self::$dataset;
        }

        $location_blob = substr( $text_blob, 0, $marker_pos );
        $isp_blob      = substr( $text_blob, $marker_pos + strlen( $marker ) );

        $location_entries = array_values(
            array_filter(
                array_map(
                    static function( $entry ) {
                        return trim( (string) $entry );
                    },
                    explode( '&', $location_blob )
                ),
                static function( $entry ) {
                    return '' !== $entry;
                }
            )
        );

        $isp_entries = array_values(
            array_filter(
                array_map(
                    static function( $entry ) {
                        return trim( (string) $entry );
                    },
                    explode( '&', $isp_blob )
                ),
                static function( $entry ) {
                    return '' !== $entry;
                }
            )
        );

        $prefix_map = [];
        for ( $i = 0; $i < $prefix_count; $i++ ) {
            $offset = $prefix_table_offset + ( $i * self::PREFIX_RECORD_SIZE );
            $record = substr( $binary, $offset, self::PREFIX_RECORD_SIZE );
            if ( strlen( $record ) < self::PREFIX_RECORD_SIZE ) {
                continue;
            }

            $prefix_value = ord( $record[0] );
            $block_info   = unpack( 'Vblock_offset', substr( $record, 1, 4 ) );
            $block_offset = isset( $block_info['block_offset'] ) ? (int) $block_info['block_offset'] : 0;

            if ( $prefix_value < 100 || $prefix_value > 199 ) {
                continue;
            }

            if ( $block_offset < 0 || ( $block_offset + self::PREFIX_BLOCK_SIZE ) > $size ) {
                continue;
            }

            $prefix_map[ (string) $prefix_value ] = $block_offset;
        }

        self::$dataset = [
            'binary'           => $binary,
            'size'             => $size,
            'dat_version'      => $dat_version,
            'prefix_count'     => $prefix_count,
            'segment_count'    => isset( $header['segment_count'] ) ? (int) $header['segment_count'] : 0,
            'header_three'     => isset( $header['header_three'] ) ? (int) $header['header_three'] : 0,
            'header_four'      => isset( $header['header_four'] ) ? (int) $header['header_four'] : 0,
            'prefix_table_pos' => $prefix_table_offset,
            'prefix_map'       => $prefix_map,
            'location_entries' => $location_entries,
            'isp_entries'      => $isp_entries,
        ];

        do_action( 'qs_phone_location_dataset_loaded', self::$dataset, $path );

        return self::$dataset;
    }

    private static function get_dat_path() {
        $path = trailingslashit( QS_PLUGIN_DIR ) . 'phone/qiphone.dat';
        $path = apply_filters( 'qs_phone_location_dat_path', $path );
        $path = is_string( $path ) ? trim( $path ) : '';

        if ( '' === $path ) {
            return '';
        }

        return wp_normalize_path( $path );
    }

    public static function normalize_phone( $phone ) {
        $phone = preg_replace( '/[^0-9]/', '', (string) $phone );

        if ( 13 === strlen( $phone ) && 0 === strpos( $phone, '86' ) ) {
            $phone = substr( $phone, 2 );
        }

        if ( 11 !== strlen( $phone ) || ! preg_match( '/^1[3-9][0-9]{9}$/', $phone ) ) {
            return '';
        }

        return $phone;
    }
}

if ( ! function_exists( 'qilingsecurity_phone_location_lookup_enabled' ) ) {
    function qilingsecurity_phone_location_lookup_enabled() {
        if ( ! class_exists( 'QS_Phone_Location' ) ) {
            return false;
        }

        return QS_Phone_Location::is_enabled();
    }
}

if ( ! function_exists( 'qilingsecurity_lookup_phone_location' ) ) {
    function qilingsecurity_lookup_phone_location( $phone, $args = [] ) {
        if ( ! class_exists( 'QS_Phone_Location' ) ) {
            return [];
        }

        return QS_Phone_Location::lookup( $phone, $args );
    }
}
