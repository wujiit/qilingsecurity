<?php
/**
 * 安全防护插件 - 数据库管理表初始化
 */
if ( ! defined( 'ABSPATH' ) ) {
    exit;
}

class QS_DB {

    const SCHEMA_VERSION = '1.4.0';

    private static $schema_checked = false;

    private static $table_exists_cache = [];

    private static function get_tables() {
        return [
            'scans'          => 'qilingsecurity_scans',
            'results'        => 'qilingsecurity_results',
            'audit'          => 'qilingsecurity_audit',
            'ban_ips'        => 'qilingsecurity_ban_ips',
            'baseline_files' => 'qilingsecurity_baseline_files',
            'phone_location_cache' => 'qilingsecurity_phone_location_cache',
            'ip_risk_profiles' => 'qilingsecurity_ip_risk_profiles',
            'ip_risk_events'   => 'qilingsecurity_ip_risk_events',
        ];
    }

    private static function get_table_name( $key ) {
        global $wpdb;

        $tables = self::get_tables();

        if ( ! isset( $tables[ $key ] ) ) {
            return '';
        }

        return $wpdb->prefix . $tables[ $key ];
    }

    private static function table_exists_raw( $table_name ) {
        global $wpdb;

        if ( '' === $table_name ) {
            return false;
        }

        $found_table = $wpdb->get_var(
            $wpdb->prepare( 'SHOW TABLES LIKE %s', $wpdb->esc_like( $table_name ) )
        );

        return $found_table === $table_name;
    }

    private static function refresh_table_cache() {
        self::$table_exists_cache = [];

        foreach ( array_keys( self::get_tables() ) as $key ) {
            self::$table_exists_cache[ $key ] = self::table_exists_raw( self::get_table_name( $key ) );
        }
    }

    private static function table_exists( $key ) {
        self::maybe_install();

        if ( isset( self::$table_exists_cache[ $key ] ) ) {
            return self::$table_exists_cache[ $key ];
        }

        self::$table_exists_cache[ $key ] = self::table_exists_raw( self::get_table_name( $key ) );

        return self::$table_exists_cache[ $key ];
    }

    public static function maybe_install() {
        if ( self::$schema_checked ) {
            return;
        }

        self::$schema_checked = true;
        self::refresh_table_cache();

        if ( self::SCHEMA_VERSION !== get_option( 'qs_db_schema_version' ) || in_array( false, self::$table_exists_cache, true ) ) {
            self::install();
        }
    }

    public static function install() {
        global $wpdb;

        $charset_collate = $wpdb->get_charset_collate();

        require_once ABSPATH . 'wp-admin/includes/upgrade.php';

        $table_scans = self::get_table_name( 'scans' );
        $sql_scans   = "CREATE TABLE $table_scans (
            id bigint(20) NOT NULL AUTO_INCREMENT,
            status varchar(20) NOT NULL DEFAULT 'running',
            start_time datetime DEFAULT CURRENT_TIMESTAMP NOT NULL,
            end_time datetime DEFAULT NULL,
            total_issues int(11) DEFAULT 0,
            PRIMARY KEY  (id)
        ) $charset_collate;";
        dbDelta( $sql_scans );

        $table_results = self::get_table_name( 'results' );
        $sql_results   = "CREATE TABLE $table_results (
            id bigint(20) NOT NULL AUTO_INCREMENT,
            scan_id bigint(20) NOT NULL,
            issue_type varchar(50) NOT NULL,
            file_path text NOT NULL,
            severity varchar(20) NOT NULL DEFAULT 'warning',
            detail text NOT NULL,
            advice text NOT NULL,
            status varchar(20) NOT NULL DEFAULT 'open',
            PRIMARY KEY  (id),
            KEY scan_id (scan_id)
        ) $charset_collate;";
        dbDelta( $sql_results );

        $table_audit = self::get_table_name( 'audit' );
        $sql_audit   = "CREATE TABLE $table_audit (
            id bigint(20) NOT NULL AUTO_INCREMENT,
            time datetime DEFAULT CURRENT_TIMESTAMP NOT NULL,
            user_id bigint(20) NOT NULL,
            username varchar(60) NOT NULL,
            action_type varchar(50) NOT NULL,
            action_detail text NOT NULL,
            ip_address varchar(45) NOT NULL,
            PRIMARY KEY  (id),
            KEY user_id (user_id),
            KEY ip_address (ip_address)
        ) $charset_collate;";
        dbDelta( $sql_audit );

        $table_ban_ips = self::get_table_name( 'ban_ips' );
        $sql_ban_ips   = "CREATE TABLE $table_ban_ips (
            id bigint(20) NOT NULL AUTO_INCREMENT,
            ip_address varchar(45) NOT NULL,
            reason varchar(100) NOT NULL,
            ban_time datetime DEFAULT CURRENT_TIMESTAMP NOT NULL,
            expire_time datetime NOT NULL,
            PRIMARY KEY  (id),
            UNIQUE KEY ip_address (ip_address)
        ) $charset_collate;";
        dbDelta( $sql_ban_ips );

        $table_baseline = self::get_table_name( 'baseline_files' );
        $sql_baseline   = "CREATE TABLE $table_baseline (
            id bigint(20) NOT NULL AUTO_INCREMENT,
            file_path text NOT NULL,
            path_hash char(32) NOT NULL,
            file_hash char(64) NOT NULL,
            file_size bigint(20) NOT NULL DEFAULT 0,
            file_mtime bigint(20) NOT NULL DEFAULT 0,
            scope varchar(50) NOT NULL DEFAULT 'custom',
            updated_at datetime DEFAULT CURRENT_TIMESTAMP NOT NULL,
            PRIMARY KEY  (id),
            UNIQUE KEY path_hash (path_hash)
        ) $charset_collate;";
        dbDelta( $sql_baseline );

        $table_phone_cache = self::get_table_name( 'phone_location_cache' );
        $sql_phone_cache   = "CREATE TABLE $table_phone_cache (
            id bigint(20) NOT NULL AUTO_INCREMENT,
            phone_segment char(7) NOT NULL,
            prefix char(3) NOT NULL,
            province varchar(45) DEFAULT '' NOT NULL,
            city varchar(45) DEFAULT '' NOT NULL,
            isp varchar(45) DEFAULT '' NOT NULL,
            tel_code varchar(20) DEFAULT '' NOT NULL,
            postal_code varchar(20) DEFAULT '' NOT NULL,
            area_code varchar(20) DEFAULT '' NOT NULL,
            location_text varchar(191) DEFAULT '' NOT NULL,
            dat_version varchar(20) DEFAULT '' NOT NULL,
            source varchar(20) DEFAULT 'dat' NOT NULL,
            hit_count bigint(20) unsigned DEFAULT 1 NOT NULL,
            first_seen datetime DEFAULT CURRENT_TIMESTAMP NOT NULL,
            last_seen datetime DEFAULT CURRENT_TIMESTAMP NOT NULL,
            PRIMARY KEY  (id),
            UNIQUE KEY phone_segment (phone_segment),
            KEY prefix (prefix),
            KEY province (province),
            KEY city (city),
            KEY isp (isp),
            KEY last_seen (last_seen)
        ) $charset_collate;";
        dbDelta( $sql_phone_cache );

        $table_ip_risk_profiles = self::get_table_name( 'ip_risk_profiles' );
        $sql_ip_risk_profiles   = "CREATE TABLE $table_ip_risk_profiles (
            id bigint(20) NOT NULL AUTO_INCREMENT,
            ip_address varchar(45) NOT NULL,
            ip_version tinyint(3) unsigned NOT NULL DEFAULT 4,
            risk_score smallint(5) unsigned NOT NULL DEFAULT 0,
            risk_level varchar(20) NOT NULL DEFAULT 'unknown',
            provider_count smallint(5) unsigned NOT NULL DEFAULT 0,
            query_status varchar(20) NOT NULL DEFAULT 'unknown',
            providers_json longtext DEFAULT NULL,
            summary_json longtext DEFAULT NULL,
            source varchar(50) NOT NULL DEFAULT 'ip_risk',
            last_event_type varchar(30) NOT NULL DEFAULT '',
            hit_count bigint(20) unsigned NOT NULL DEFAULT 1,
            first_seen datetime DEFAULT CURRENT_TIMESTAMP NOT NULL,
            last_seen datetime DEFAULT CURRENT_TIMESTAMP NOT NULL,
            updated_at datetime DEFAULT CURRENT_TIMESTAMP NOT NULL,
            PRIMARY KEY  (id),
            UNIQUE KEY ip_address (ip_address),
            KEY risk_level (risk_level),
            KEY query_status (query_status),
            KEY updated_at (updated_at),
            KEY last_seen (last_seen)
        ) $charset_collate;";
        dbDelta( $sql_ip_risk_profiles );

        $table_ip_risk_events = self::get_table_name( 'ip_risk_events' );
        $sql_ip_risk_events   = "CREATE TABLE $table_ip_risk_events (
            id bigint(20) NOT NULL AUTO_INCREMENT,
            event_time datetime DEFAULT CURRENT_TIMESTAMP NOT NULL,
            event_type varchar(30) NOT NULL DEFAULT '',
            ip_address varchar(45) NOT NULL,
            user_id bigint(20) NOT NULL DEFAULT 0,
            username varchar(60) NOT NULL DEFAULT '',
            risk_score smallint(5) unsigned NOT NULL DEFAULT 0,
            risk_level varchar(20) NOT NULL DEFAULT 'unknown',
            profile_status varchar(20) NOT NULL DEFAULT 'unknown',
            provider_count smallint(5) unsigned NOT NULL DEFAULT 0,
            action varchar(20) NOT NULL DEFAULT 'observe',
            profile_id bigint(20) unsigned NOT NULL DEFAULT 0,
            context_json longtext DEFAULT NULL,
            PRIMARY KEY  (id),
            KEY event_time (event_time),
            KEY event_type (event_type),
            KEY ip_address (ip_address),
            KEY user_id (user_id),
            KEY risk_level (risk_level)
        ) $charset_collate;";
        dbDelta( $sql_ip_risk_events );

        self::refresh_table_cache();

        if ( in_array( false, self::$table_exists_cache, true ) ) {
            delete_option( 'qs_db_schema_version' );
        } else {
            update_option( 'qs_db_schema_version', self::SCHEMA_VERSION );
        }
    }

    public static function create_scan() {
        global $wpdb;

        if ( ! self::table_exists( 'scans' ) ) {
            return 0;
        }

        $table = self::get_table_name( 'scans' );
        $wpdb->insert(
            $table,
            [
                'status'     => 'running',
                'start_time' => current_time( 'mysql' ),
            ]
        );

        return (int) $wpdb->insert_id;
    }

    public static function finish_scan( $scan_id ) {
        global $wpdb;

        if ( ! self::table_exists( 'results' ) || ! self::table_exists( 'scans' ) ) {
            return;
        }

        $table_results = self::get_table_name( 'results' );
        $count         = $wpdb->get_var( $wpdb->prepare( "SELECT COUNT(*) FROM $table_results WHERE scan_id = %d AND severity IN ('critical', 'warning')", $scan_id ) );
        $table_scans   = self::get_table_name( 'scans' );

        $wpdb->update(
            $table_scans,
            [
                'status'       => 'completed',
                'end_time'     => current_time( 'mysql' ),
                'total_issues' => $count,
            ],
            [ 'id' => $scan_id ]
        );
    }

    public static function insert_result( $scan_id, $type, $path, $severity, $detail = '', $advice = '' ) {
        global $wpdb;

        if ( ! self::table_exists( 'results' ) ) {
            return false;
        }

        $table = self::get_table_name( 'results' );

        return $wpdb->insert(
            $table,
            [
                'scan_id'    => $scan_id,
                'issue_type' => $type,
                'file_path'  => $path,
                'severity'   => $severity,
                'detail'     => $detail,
                'advice'     => $advice,
            ]
        );
    }

    public static function get_last_scan() {
        global $wpdb;

        if ( ! self::table_exists( 'scans' ) ) {
            return null;
        }

        $table = self::get_table_name( 'scans' );

        return $wpdb->get_row( "SELECT * FROM $table ORDER BY id DESC LIMIT 1" );
    }

    public static function get_results( $scan_id ) {
        global $wpdb;

        if ( ! self::table_exists( 'results' ) ) {
            return [];
        }

        $table = self::get_table_name( 'results' );

        return $wpdb->get_results(
            $wpdb->prepare(
                "SELECT * FROM $table WHERE scan_id = %d ORDER BY CASE status WHEN 'open' THEN 0 WHEN 'resolved' THEN 1 ELSE 2 END, id ASC",
                $scan_id
            )
        );
    }

    public static function update_result_status( $result_id, $status ) {
        global $wpdb;

        if ( ! self::table_exists( 'results' ) ) {
            return false;
        }

        if ( ! in_array( $status, [ 'open', 'resolved', 'ignored' ], true ) ) {
            return false;
        }

        $table = self::get_table_name( 'results' );

        return false !== $wpdb->update(
            $table,
            [ 'status' => $status ],
            [ 'id' => absint( $result_id ) ],
            [ '%s' ],
            [ '%d' ]
        );
    }

    public static function insert_audit_log( $user_id, $username, $action_type, $action_detail, $ip_address ) {
        global $wpdb;

        if ( ! self::table_exists( 'audit' ) ) {
            return false;
        }

        $table = self::get_table_name( 'audit' );

        return $wpdb->insert(
            $table,
            [
                'user_id'       => $user_id,
                'username'      => $username,
                'action_type'   => $action_type,
                'action_detail' => $action_detail,
                'ip_address'    => $ip_address,
                'time'          => current_time( 'mysql' ),
            ]
        );
    }

    public static function ban_ip( $ip_address, $reason, $duration_hours = 24 ) {
        global $wpdb;

        if ( empty( $ip_address ) || ! self::table_exists( 'ban_ips' ) ) {
            return false;
        }

        if ( class_exists( 'QS_Audit' ) && QS_Audit::is_ip_whitelisted( $ip_address ) ) {
            return false;
        }

        $table       = self::get_table_name( 'ban_ips' );
        $expire_time = date( 'Y-m-d H:i:s', current_time( 'timestamp' ) + ( $duration_hours * HOUR_IN_SECONDS ) );

        return $wpdb->replace(
            $table,
            [
                'ip_address'  => $ip_address,
                'reason'      => $reason,
                'ban_time'    => current_time( 'mysql' ),
                'expire_time' => $expire_time,
            ]
        );
    }

    public static function is_ip_banned( $ip_address ) {
        global $wpdb;

        if ( empty( $ip_address ) || ! self::table_exists( 'ban_ips' ) ) {
            return false;
        }

        if ( class_exists( 'QS_Audit' ) && QS_Audit::is_ip_whitelisted( $ip_address ) ) {
            return false;
        }

        $table        = self::get_table_name( 'ban_ips' );
        $current_time = current_time( 'mysql' );
        $sql          = $wpdb->prepare( "SELECT id FROM $table WHERE ip_address = %s AND expire_time > %s", $ip_address, $current_time );

        return (bool) $wpdb->get_var( $sql );
    }

    public static function unban_ip( $ip_address ) {
        global $wpdb;

        if ( empty( $ip_address ) || ! self::table_exists( 'ban_ips' ) ) {
            return false;
        }

        $table = self::get_table_name( 'ban_ips' );

        return $wpdb->delete( $table, [ 'ip_address' => $ip_address ] );
    }

    public static function get_audit_logs( $limit = 50, $offset = 0 ) {
        global $wpdb;

        if ( ! self::table_exists( 'audit' ) ) {
            return [];
        }

        $table = self::get_table_name( 'audit' );

        return $wpdb->get_results( $wpdb->prepare( "SELECT * FROM $table ORDER BY id DESC LIMIT %d OFFSET %d", $limit, $offset ) );
    }

    public static function clear_audit_logs() {
        global $wpdb;

        if ( ! self::table_exists( 'audit' ) ) {
            return 0;
        }

        $table   = self::get_table_name( 'audit' );
        $deleted = $wpdb->query( "DELETE FROM $table" );

        return false === $deleted ? 0 : (int) $deleted;
    }

    public static function get_banned_ips( $limit = 50, $offset = 0 ) {
        global $wpdb;

        if ( ! self::table_exists( 'ban_ips' ) ) {
            return [];
        }

        $table        = self::get_table_name( 'ban_ips' );
        $current_time = current_time( 'mysql' );

        return $wpdb->get_results( $wpdb->prepare( "SELECT * FROM $table WHERE expire_time > %s ORDER BY id DESC LIMIT %d OFFSET %d", $current_time, $limit, $offset ) );
    }

    public static function get_storage_summary() {
        global $wpdb;

        $summary = [
            'scans'          => 0,
            'results'        => 0,
            'audit_logs'     => 0,
            'active_bans'    => 0,
            'expired_bans'   => 0,
            'baseline_files' => 0,
            'phone_cache'    => 0,
            'ip_risk_profiles' => 0,
            'ip_risk_events'   => 0,
        ];

        if ( self::table_exists( 'scans' ) ) {
            $summary['scans'] = (int) $wpdb->get_var( 'SELECT COUNT(*) FROM ' . self::get_table_name( 'scans' ) );
        }

        if ( self::table_exists( 'results' ) ) {
            $summary['results'] = (int) $wpdb->get_var( 'SELECT COUNT(*) FROM ' . self::get_table_name( 'results' ) );
        }

        if ( self::table_exists( 'audit' ) ) {
            $summary['audit_logs'] = (int) $wpdb->get_var( 'SELECT COUNT(*) FROM ' . self::get_table_name( 'audit' ) );
        }

        if ( self::table_exists( 'ban_ips' ) ) {
            $table        = self::get_table_name( 'ban_ips' );
            $current_time = current_time( 'mysql' );

            $summary['active_bans']  = (int) $wpdb->get_var( $wpdb->prepare( "SELECT COUNT(*) FROM $table WHERE expire_time > %s", $current_time ) );
            $summary['expired_bans'] = (int) $wpdb->get_var( $wpdb->prepare( "SELECT COUNT(*) FROM $table WHERE expire_time <= %s", $current_time ) );
        }

        if ( self::table_exists( 'baseline_files' ) ) {
            $summary['baseline_files'] = (int) $wpdb->get_var( 'SELECT COUNT(*) FROM ' . self::get_table_name( 'baseline_files' ) );
        }

        if ( self::table_exists( 'phone_location_cache' ) ) {
            $summary['phone_cache'] = (int) $wpdb->get_var( 'SELECT COUNT(*) FROM ' . self::get_table_name( 'phone_location_cache' ) );
        }

        if ( self::table_exists( 'ip_risk_profiles' ) ) {
            $summary['ip_risk_profiles'] = (int) $wpdb->get_var( 'SELECT COUNT(*) FROM ' . self::get_table_name( 'ip_risk_profiles' ) );
        }

        if ( self::table_exists( 'ip_risk_events' ) ) {
            $summary['ip_risk_events'] = (int) $wpdb->get_var( 'SELECT COUNT(*) FROM ' . self::get_table_name( 'ip_risk_events' ) );
        }

        return $summary;
    }

    public static function get_file_baseline_count() {
        global $wpdb;

        if ( ! self::table_exists( 'baseline_files' ) ) {
            return 0;
        }

        return (int) $wpdb->get_var( 'SELECT COUNT(*) FROM ' . self::get_table_name( 'baseline_files' ) );
    }

    public static function get_file_baseline_map() {
        global $wpdb;

        if ( ! self::table_exists( 'baseline_files' ) ) {
            return [];
        }

        $table = self::get_table_name( 'baseline_files' );
        $rows  = $wpdb->get_results( "SELECT file_path, file_hash, file_size, file_mtime, scope FROM $table", ARRAY_A );
        $map   = [];

        foreach ( (array) $rows as $row ) {
            if ( empty( $row['file_path'] ) ) {
                continue;
            }

            $map[ $row['file_path'] ] = [
                'hash'  => isset( $row['file_hash'] ) ? (string) $row['file_hash'] : '',
                'size'  => isset( $row['file_size'] ) ? (int) $row['file_size'] : 0,
                'mtime' => isset( $row['file_mtime'] ) ? (int) $row['file_mtime'] : 0,
                'scope' => isset( $row['scope'] ) ? (string) $row['scope'] : 'custom',
            ];
        }

        return $map;
    }

    public static function replace_file_baseline_snapshot( $records ) {
        global $wpdb;

        if ( ! self::table_exists( 'baseline_files' ) ) {
            return 0;
        }

        $table   = self::get_table_name( 'baseline_files' );
        $records = is_array( $records ) ? $records : [];

        $wpdb->query( "DELETE FROM $table" );

        $inserted = 0;

        foreach ( $records as $record ) {
            $file_path = isset( $record['file_path'] ) ? sanitize_text_field( (string) $record['file_path'] ) : '';
            $file_hash = isset( $record['file_hash'] ) ? preg_replace( '/[^a-f0-9]/i', '', (string) $record['file_hash'] ) : '';
            $file_size = isset( $record['file_size'] ) ? (int) $record['file_size'] : 0;
            $file_mtime = isset( $record['file_mtime'] ) ? (int) $record['file_mtime'] : 0;
            $scope     = isset( $record['scope'] ) ? sanitize_key( (string) $record['scope'] ) : 'custom';

            if ( '' === $file_path || '' === $file_hash ) {
                continue;
            }

            $result = $wpdb->insert(
                $table,
                [
                    'file_path'  => $file_path,
                    'path_hash'  => md5( $file_path ),
                    'file_hash'  => $file_hash,
                    'file_size'  => $file_size,
                    'file_mtime' => $file_mtime,
                    'scope'      => $scope,
                    'updated_at' => current_time( 'mysql' ),
                ],
                [ '%s', '%s', '%s', '%d', '%d', '%s', '%s' ]
            );

            if ( false !== $result ) {
                $inserted++;
            }
        }

        return $inserted;
    }

    public static function clear_file_baseline() {
        global $wpdb;

        if ( ! self::table_exists( 'baseline_files' ) ) {
            return 0;
        }

        $table   = self::get_table_name( 'baseline_files' );
        $deleted = $wpdb->query( "DELETE FROM $table" );

        return false === $deleted ? 0 : (int) $deleted;
    }

    public static function get_phone_location_cache( $phone_segment ) {
        global $wpdb;

        if ( ! self::table_exists( 'phone_location_cache' ) ) {
            return [];
        }

        $phone_segment = preg_replace( '/[^0-9]/', '', (string) $phone_segment );
        if ( strlen( $phone_segment ) !== 7 ) {
            return [];
        }

        $table = self::get_table_name( 'phone_location_cache' );
        $row   = $wpdb->get_row(
            $wpdb->prepare(
                "SELECT phone_segment, prefix, province, city, isp, tel_code, postal_code, area_code, location_text, dat_version, source, hit_count, first_seen, last_seen FROM $table WHERE phone_segment = %s LIMIT 1",
                $phone_segment
            ),
            ARRAY_A
        );

        if ( ! is_array( $row ) ) {
            return [];
        }

        return [
            'phone_segment' => isset( $row['phone_segment'] ) ? (string) $row['phone_segment'] : '',
            'prefix'        => isset( $row['prefix'] ) ? (string) $row['prefix'] : '',
            'province'      => isset( $row['province'] ) ? (string) $row['province'] : '',
            'city'          => isset( $row['city'] ) ? (string) $row['city'] : '',
            'isp'           => isset( $row['isp'] ) ? (string) $row['isp'] : '',
            'tel_code'      => isset( $row['tel_code'] ) ? (string) $row['tel_code'] : '',
            'postal_code'   => isset( $row['postal_code'] ) ? (string) $row['postal_code'] : '',
            'area_code'     => isset( $row['area_code'] ) ? (string) $row['area_code'] : '',
            'location_text' => isset( $row['location_text'] ) ? (string) $row['location_text'] : '',
            'dat_version'   => isset( $row['dat_version'] ) ? (string) $row['dat_version'] : '',
            'source'        => isset( $row['source'] ) ? (string) $row['source'] : 'db',
            'hit_count'     => isset( $row['hit_count'] ) ? (int) $row['hit_count'] : 0,
            'first_seen'    => isset( $row['first_seen'] ) ? (string) $row['first_seen'] : '',
            'last_seen'     => isset( $row['last_seen'] ) ? (string) $row['last_seen'] : '',
        ];
    }

    public static function touch_phone_location_cache( $phone_segment ) {
        global $wpdb;

        if ( ! self::table_exists( 'phone_location_cache' ) ) {
            return false;
        }

        $phone_segment = preg_replace( '/[^0-9]/', '', (string) $phone_segment );
        if ( strlen( $phone_segment ) !== 7 ) {
            return false;
        }

        $table = self::get_table_name( 'phone_location_cache' );

        return false !== $wpdb->query(
            $wpdb->prepare(
                "UPDATE $table SET hit_count = hit_count + 1, last_seen = %s WHERE phone_segment = %s",
                current_time( 'mysql' ),
                $phone_segment
            )
        );
    }

    public static function upsert_phone_location_cache( $phone_segment, $payload ) {
        global $wpdb;

        if ( ! self::table_exists( 'phone_location_cache' ) ) {
            return false;
        }

        $phone_segment = preg_replace( '/[^0-9]/', '', (string) $phone_segment );
        if ( strlen( $phone_segment ) !== 7 ) {
            return false;
        }

        $payload = is_array( $payload ) ? $payload : [];
        $prefix  = substr( $phone_segment, 0, 3 );
        $now     = current_time( 'mysql' );
        $table   = self::get_table_name( 'phone_location_cache' );

        $province      = sanitize_text_field( isset( $payload['province'] ) ? (string) $payload['province'] : '' );
        $city          = sanitize_text_field( isset( $payload['city'] ) ? (string) $payload['city'] : '' );
        $isp           = sanitize_text_field( isset( $payload['isp'] ) ? (string) $payload['isp'] : '' );
        $tel_code      = sanitize_text_field( isset( $payload['tel_code'] ) ? (string) $payload['tel_code'] : '' );
        $postal_code   = sanitize_text_field( isset( $payload['postal_code'] ) ? (string) $payload['postal_code'] : '' );
        $area_code     = sanitize_text_field( isset( $payload['area_code'] ) ? (string) $payload['area_code'] : '' );
        $location_text = sanitize_text_field( isset( $payload['location_text'] ) ? (string) $payload['location_text'] : '' );
        $dat_version   = sanitize_text_field( isset( $payload['dat_version'] ) ? (string) $payload['dat_version'] : '' );
        $source        = sanitize_key( isset( $payload['source'] ) ? (string) $payload['source'] : 'dat' );
        if ( '' === $source ) {
            $source = 'dat';
        }

        $sql = "
            INSERT INTO $table
                (phone_segment, prefix, province, city, isp, tel_code, postal_code, area_code, location_text, dat_version, source, hit_count, first_seen, last_seen)
            VALUES
                (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, 1, %s, %s)
            ON DUPLICATE KEY UPDATE
                prefix = VALUES(prefix),
                province = VALUES(province),
                city = VALUES(city),
                isp = VALUES(isp),
                tel_code = VALUES(tel_code),
                postal_code = VALUES(postal_code),
                area_code = VALUES(area_code),
                location_text = VALUES(location_text),
                dat_version = VALUES(dat_version),
                source = VALUES(source),
                hit_count = hit_count + 1,
                last_seen = VALUES(last_seen)
        ";

        return false !== $wpdb->query(
            $wpdb->prepare(
                $sql,
                $phone_segment,
                $prefix,
                $province,
                $city,
                $isp,
                $tel_code,
                $postal_code,
                $area_code,
                $location_text,
                $dat_version,
                $source,
                $now,
                $now
            )
        );
    }

    public static function get_ip_risk_profile( $ip_address ) {
        global $wpdb;

        if ( ! self::table_exists( 'ip_risk_profiles' ) ) {
            return [];
        }

        $ip_address = self::normalize_ip_address( $ip_address );
        if ( '' === $ip_address ) {
            return [];
        }

        $table = self::get_table_name( 'ip_risk_profiles' );
        $row   = $wpdb->get_row(
            $wpdb->prepare(
                "SELECT id, ip_address, ip_version, risk_score, risk_level, provider_count, query_status, providers_json, summary_json, source, last_event_type, hit_count, first_seen, last_seen, updated_at FROM $table WHERE ip_address = %s LIMIT 1",
                $ip_address
            ),
            ARRAY_A
        );

        if ( ! is_array( $row ) ) {
            return [];
        }

        $providers = [];
        if ( ! empty( $row['providers_json'] ) ) {
            $decoded = json_decode( (string) $row['providers_json'], true );
            if ( is_array( $decoded ) ) {
                $providers = $decoded;
            }
        }

        $summary = [];
        if ( ! empty( $row['summary_json'] ) ) {
            $decoded = json_decode( (string) $row['summary_json'], true );
            if ( is_array( $decoded ) ) {
                $summary = $decoded;
            }
        }

        return [
            'id'             => isset( $row['id'] ) ? (int) $row['id'] : 0,
            'ip_address'     => isset( $row['ip_address'] ) ? (string) $row['ip_address'] : '',
            'ip_version'     => isset( $row['ip_version'] ) ? (int) $row['ip_version'] : 4,
            'risk_score'     => isset( $row['risk_score'] ) ? (int) $row['risk_score'] : 0,
            'risk_level'     => self::normalize_ip_risk_level(
                isset( $row['risk_level'] ) ? (string) $row['risk_level'] : 'unknown',
                isset( $row['risk_score'] ) ? (int) $row['risk_score'] : 0,
                isset( $row['provider_count'] ) ? (int) $row['provider_count'] : 0
            ),
            'provider_count' => isset( $row['provider_count'] ) ? (int) $row['provider_count'] : 0,
            'query_status'   => isset( $row['query_status'] ) ? (string) $row['query_status'] : 'unknown',
            'providers'      => $providers,
            'summary'        => $summary,
            'source'         => isset( $row['source'] ) ? (string) $row['source'] : 'ip_risk',
            'last_event_type' => isset( $row['last_event_type'] ) ? (string) $row['last_event_type'] : '',
            'hit_count'      => isset( $row['hit_count'] ) ? (int) $row['hit_count'] : 0,
            'first_seen'     => isset( $row['first_seen'] ) ? (string) $row['first_seen'] : '',
            'last_seen'      => isset( $row['last_seen'] ) ? (string) $row['last_seen'] : '',
            'updated_at'     => isset( $row['updated_at'] ) ? (string) $row['updated_at'] : '',
        ];
    }

    public static function touch_ip_risk_profile( $ip_address, $event_type = '' ) {
        global $wpdb;

        if ( ! self::table_exists( 'ip_risk_profiles' ) ) {
            return false;
        }

        $ip_address = self::normalize_ip_address( $ip_address );
        if ( '' === $ip_address ) {
            return false;
        }

        $event_type = sanitize_key( (string) $event_type );
        $table      = self::get_table_name( 'ip_risk_profiles' );

        if ( '' !== $event_type ) {
            return false !== $wpdb->query(
                $wpdb->prepare(
                    "UPDATE $table SET hit_count = hit_count + 1, last_seen = %s, last_event_type = %s WHERE ip_address = %s",
                    current_time( 'mysql' ),
                    $event_type,
                    $ip_address
                )
            );
        }

        return false !== $wpdb->query(
            $wpdb->prepare(
                "UPDATE $table SET hit_count = hit_count + 1, last_seen = %s WHERE ip_address = %s",
                current_time( 'mysql' ),
                $ip_address
            )
        );
    }

    public static function upsert_ip_risk_profile( $ip_address, $payload ) {
        global $wpdb;

        if ( ! self::table_exists( 'ip_risk_profiles' ) ) {
            return false;
        }

        $ip_address = self::normalize_ip_address( $ip_address );
        if ( '' === $ip_address ) {
            return false;
        }

        $payload        = is_array( $payload ) ? $payload : [];
        $ip_version     = false !== strpos( $ip_address, ':' ) ? 6 : 4;
        $risk_score     = max( 0, min( 100, (int) ( isset( $payload['risk_score'] ) ? $payload['risk_score'] : 0 ) ) );
        $provider_count = max( 0, (int) ( isset( $payload['provider_count'] ) ? $payload['provider_count'] : 0 ) );
        $risk_level     = self::normalize_ip_risk_level(
            isset( $payload['risk_level'] ) ? (string) $payload['risk_level'] : 'unknown',
            $risk_score,
            $provider_count
        );
        $query_status   = sanitize_key( isset( $payload['query_status'] ) ? (string) $payload['query_status'] : 'unknown' );
        $source         = sanitize_key( isset( $payload['source'] ) ? (string) $payload['source'] : 'ip_risk' );
        $event_type     = sanitize_key( isset( $payload['last_event_type'] ) ? (string) $payload['last_event_type'] : '' );
        $providers_json = wp_json_encode( isset( $payload['providers'] ) && is_array( $payload['providers'] ) ? $payload['providers'] : [] );
        $summary_json   = wp_json_encode( isset( $payload['summary'] ) && is_array( $payload['summary'] ) ? $payload['summary'] : [] );
        $providers_json = is_string( $providers_json ) ? $providers_json : '{}';
        $summary_json   = is_string( $summary_json ) ? $summary_json : '{}';
        $now            = current_time( 'mysql' );
        $table          = self::get_table_name( 'ip_risk_profiles' );

        $sql = "
            INSERT INTO $table
                (ip_address, ip_version, risk_score, risk_level, provider_count, query_status, providers_json, summary_json, source, last_event_type, hit_count, first_seen, last_seen, updated_at)
            VALUES
                (%s, %d, %d, %s, %d, %s, %s, %s, %s, %s, 1, %s, %s, %s)
            ON DUPLICATE KEY UPDATE
                ip_version = VALUES(ip_version),
                risk_score = VALUES(risk_score),
                risk_level = VALUES(risk_level),
                provider_count = VALUES(provider_count),
                query_status = VALUES(query_status),
                providers_json = VALUES(providers_json),
                summary_json = VALUES(summary_json),
                source = VALUES(source),
                last_event_type = VALUES(last_event_type),
                hit_count = hit_count + 1,
                last_seen = VALUES(last_seen),
                updated_at = VALUES(updated_at)
        ";

        return false !== $wpdb->query(
            $wpdb->prepare(
                $sql,
                $ip_address,
                $ip_version,
                $risk_score,
                $risk_level,
                $provider_count,
                $query_status,
                $providers_json,
                $summary_json,
                $source,
                $event_type,
                $now,
                $now,
                $now
            )
        );
    }

    public static function insert_ip_risk_event( $payload ) {
        global $wpdb;

        if ( ! self::table_exists( 'ip_risk_events' ) ) {
            return 0;
        }

        $payload    = is_array( $payload ) ? $payload : [];
        $ip_address = self::normalize_ip_address( isset( $payload['ip_address'] ) ? $payload['ip_address'] : '' );
        if ( '' === $ip_address ) {
            return 0;
        }

        $table        = self::get_table_name( 'ip_risk_events' );
        $context_json = wp_json_encode( isset( $payload['context'] ) && is_array( $payload['context'] ) ? $payload['context'] : [] );
        $context_json = is_string( $context_json ) ? $context_json : '{}';
        $risk_score   = max( 0, min( 100, (int) ( isset( $payload['risk_score'] ) ? $payload['risk_score'] : 0 ) ) );
        $provider_count = max( 0, (int) ( isset( $payload['provider_count'] ) ? $payload['provider_count'] : 0 ) );
        $risk_level   = self::normalize_ip_risk_level(
            isset( $payload['risk_level'] ) ? (string) $payload['risk_level'] : 'unknown',
            $risk_score,
            $provider_count
        );

        $data = [
            'event_time'    => current_time( 'mysql' ),
            'event_type'    => sanitize_key( isset( $payload['event_type'] ) ? (string) $payload['event_type'] : '' ),
            'ip_address'    => $ip_address,
            'user_id'       => absint( isset( $payload['user_id'] ) ? $payload['user_id'] : 0 ),
            'username'      => substr( sanitize_text_field( (string) ( isset( $payload['username'] ) ? $payload['username'] : '' ) ), 0, 60 ),
            'risk_score'    => $risk_score,
            'risk_level'    => $risk_level,
            'profile_status' => sanitize_key( (string) ( isset( $payload['profile_status'] ) ? $payload['profile_status'] : 'unknown' ) ),
            'provider_count' => $provider_count,
            'action'        => sanitize_key( (string) ( isset( $payload['action'] ) ? $payload['action'] : 'observe' ) ),
            'profile_id'    => absint( isset( $payload['profile_id'] ) ? $payload['profile_id'] : 0 ),
            'context_json'  => $context_json,
        ];

        $inserted = $wpdb->insert(
            $table,
            $data,
            [ '%s', '%s', '%s', '%d', '%s', '%d', '%s', '%s', '%d', '%s', '%d', '%s' ]
        );

        if ( false === $inserted ) {
            return 0;
        }

        return (int) $wpdb->insert_id;
    }

    public static function refresh_pending_ip_risk_events( $ip_address, $profile ) {
        global $wpdb;

        if ( ! self::table_exists( 'ip_risk_events' ) ) {
            return 0;
        }

        $ip_address = self::normalize_ip_address( $ip_address );
        if ( '' === $ip_address ) {
            return 0;
        }

        $profile        = is_array( $profile ) ? $profile : [];
        $risk_score     = max( 0, min( 100, (int) ( isset( $profile['risk_score'] ) ? $profile['risk_score'] : 0 ) ) );
        $provider_count = max( 0, (int) ( isset( $profile['provider_count'] ) ? $profile['provider_count'] : 0 ) );
        $risk_level     = self::normalize_ip_risk_level(
            isset( $profile['risk_level'] ) ? (string) $profile['risk_level'] : 'unknown',
            $risk_score,
            $provider_count
        );
        $status         = sanitize_key( (string) ( isset( $profile['query_status'] ) ? $profile['query_status'] : 'unknown' ) );

        if ( in_array( $status, [ 'pending', 'pending_async', 'pending_external' ], true ) ) {
            return 0;
        }

        $table = self::get_table_name( 'ip_risk_events' );
        $sql   = "
            UPDATE $table
            SET risk_score = %d,
                risk_level = %s,
                provider_count = %d,
                profile_status = %s
            WHERE ip_address = %s
              AND profile_status IN ('pending', 'pending_async', 'pending_external', 'missing')
            ORDER BY id DESC
            LIMIT 200
        ";

        $updated = $wpdb->query(
            $wpdb->prepare(
                $sql,
                $risk_score,
                $risk_level,
                $provider_count,
                $status,
                $ip_address
            )
        );

        return false === $updated ? 0 : (int) $updated;
    }

    public static function get_pending_ip_risk_addresses( $limit = 30 ) {
        global $wpdb;

        $limit = max( 1, min( 500, absint( $limit ) ) );
        $ips   = [];

        if ( self::table_exists( 'ip_risk_profiles' ) ) {
            $profiles_table = self::get_table_name( 'ip_risk_profiles' );
            $rows           = $wpdb->get_col(
                $wpdb->prepare(
                    "SELECT ip_address
                    FROM $profiles_table
                    WHERE query_status IN ('pending', 'pending_async', 'pending_external', 'missing')
                    ORDER BY updated_at ASC
                    LIMIT %d",
                    $limit
                )
            );

            foreach ( (array) $rows as $row_ip ) {
                $ip = self::normalize_ip_address( $row_ip );
                if ( '' !== $ip ) {
                    $ips[ $ip ] = true;
                }
            }
        }

        if ( count( $ips ) < $limit && self::table_exists( 'ip_risk_events' ) ) {
            $events_table = self::get_table_name( 'ip_risk_events' );
            $rows         = $wpdb->get_col(
                $wpdb->prepare(
                    "SELECT ip_address
                    FROM $events_table
                    WHERE profile_status IN ('pending', 'pending_async', 'pending_external', 'missing')
                    ORDER BY id DESC
                    LIMIT %d",
                    $limit * 3
                )
            );

            foreach ( (array) $rows as $row_ip ) {
                $ip = self::normalize_ip_address( $row_ip );
                if ( '' !== $ip ) {
                    $ips[ $ip ] = true;
                }

                if ( count( $ips ) >= $limit ) {
                    break;
                }
            }
        }

        return array_slice( array_keys( $ips ), 0, $limit );
    }

    public static function get_ip_risk_analytics( $days = 7, $recent_limit = 80 ) {
        global $wpdb;

        $days          = max( 1, min( 30, absint( $days ) ) );
        $recent_limit  = max( 20, min( 300, absint( $recent_limit ) ) );
        $current_ts    = current_time( 'timestamp' );
        $window_24h    = date( 'Y-m-d H:i:s', $current_ts - DAY_IN_SECONDS );
        $window_period = date( 'Y-m-d H:i:s', $current_ts - ( $days * DAY_IN_SECONDS ) );
        $analytics     = [
            'summary'       => [
                'profiles_total'      => 0,
                'profiles_ready'      => 0,
                'profiles_high_risk'  => 0,
                'profiles_unknown'    => 0,
                'events_24h'          => 0,
                'high_events_24h'     => 0,
                'failed_events_24h'   => 0,
                'success_events_24h'  => 0,
            ],
            'risk_levels'   => [],
            'actions'       => [],
            'top_ips'       => [],
            'top_signals'   => [],
            'recent_events' => [],
        ];

        if ( self::table_exists( 'ip_risk_profiles' ) ) {
            $profiles_table = self::get_table_name( 'ip_risk_profiles' );

            $analytics['summary']['profiles_total'] = (int) $wpdb->get_var( "SELECT COUNT(*) FROM $profiles_table" );
            $analytics['summary']['profiles_ready'] = (int) $wpdb->get_var( "SELECT COUNT(*) FROM $profiles_table WHERE query_status = 'ready'" );
            $analytics['summary']['profiles_high_risk'] = (int) $wpdb->get_var( "SELECT COUNT(*) FROM $profiles_table WHERE risk_level IN ('high', 'critical')" );
            $analytics['summary']['profiles_unknown'] = (int) $wpdb->get_var( "SELECT COUNT(*) FROM $profiles_table WHERE risk_level = 'unknown'" );

            $risk_rows = $wpdb->get_results(
                "SELECT risk_level, COUNT(*) AS total FROM $profiles_table GROUP BY risk_level ORDER BY total DESC",
                ARRAY_A
            );

            foreach ( (array) $risk_rows as $risk_row ) {
                $level = self::normalize_ip_risk_level(
                    isset( $risk_row['risk_level'] ) ? $risk_row['risk_level'] : '',
                    0
                );
                $total = isset( $risk_row['total'] ) ? (int) $risk_row['total'] : 0;

                if ( $total <= 0 ) {
                    continue;
                }

                $analytics['risk_levels'][] = [
                    'label' => $level,
                    'count' => $total,
                ];
            }

            $signal_rows = $wpdb->get_col( "SELECT summary_json FROM $profiles_table WHERE summary_json IS NOT NULL AND summary_json <> '' ORDER BY updated_at DESC LIMIT 500" );
            $signal_map  = [];

            foreach ( (array) $signal_rows as $summary_json ) {
                if ( ! is_string( $summary_json ) || '' === $summary_json ) {
                    continue;
                }

                $decoded = json_decode( $summary_json, true );
                if ( ! is_array( $decoded ) || empty( $decoded['signals'] ) || ! is_array( $decoded['signals'] ) ) {
                    continue;
                }

                foreach ( $decoded['signals'] as $signal ) {
                    $signal = sanitize_key( (string) $signal );
                    if ( '' === $signal ) {
                        continue;
                    }

                    if ( ! isset( $signal_map[ $signal ] ) ) {
                        $signal_map[ $signal ] = 0;
                    }

                    $signal_map[ $signal ]++;
                }
            }

            $analytics['top_signals'] = self::format_top_counts( $signal_map, 12 );
        }

        if ( self::table_exists( 'ip_risk_events' ) ) {
            $events_table = self::get_table_name( 'ip_risk_events' );

            $analytics['summary']['events_24h'] = (int) $wpdb->get_var(
                $wpdb->prepare(
                    "SELECT COUNT(*) FROM $events_table WHERE event_time >= %s",
                    $window_24h
                )
            );
            $analytics['summary']['high_events_24h'] = (int) $wpdb->get_var(
                $wpdb->prepare(
                    "SELECT COUNT(*) FROM $events_table WHERE event_time >= %s AND risk_level IN ('high', 'critical')",
                    $window_24h
                )
            );
            $analytics['summary']['failed_events_24h'] = (int) $wpdb->get_var(
                $wpdb->prepare(
                    "SELECT COUNT(*) FROM $events_table WHERE event_time >= %s AND event_type = 'login_failed'",
                    $window_24h
                )
            );
            $analytics['summary']['success_events_24h'] = (int) $wpdb->get_var(
                $wpdb->prepare(
                    "SELECT COUNT(*) FROM $events_table WHERE event_time >= %s AND event_type = 'login_success'",
                    $window_24h
                )
            );

            $action_rows = $wpdb->get_results(
                $wpdb->prepare(
                    "SELECT action, COUNT(*) AS total FROM $events_table WHERE event_time >= %s GROUP BY action ORDER BY total DESC",
                    $window_period
                ),
                ARRAY_A
            );

            foreach ( (array) $action_rows as $action_row ) {
                $action = sanitize_key( isset( $action_row['action'] ) ? (string) $action_row['action'] : '' );
                $total  = isset( $action_row['total'] ) ? (int) $action_row['total'] : 0;

                if ( '' === $action || $total <= 0 ) {
                    continue;
                }

                $analytics['actions'][] = [
                    'label' => $action,
                    'count' => $total,
                ];
            }

            $top_ip_rows = $wpdb->get_results(
                $wpdb->prepare(
                    "SELECT ip_address, COUNT(*) AS hit_count, MAX(risk_score) AS max_score, MAX(provider_count) AS max_providers, MAX(event_time) AS last_seen
                    FROM $events_table
                    WHERE event_time >= %s
                    GROUP BY ip_address
                    ORDER BY hit_count DESC, max_score DESC, last_seen DESC
                    LIMIT %d",
                    $window_period,
                    8
                ),
                ARRAY_A
            );

            foreach ( (array) $top_ip_rows as $ip_row ) {
                $ip_address = isset( $ip_row['ip_address'] ) ? self::normalize_ip_address( $ip_row['ip_address'] ) : '';
                if ( '' === $ip_address ) {
                    continue;
                }

                $max_score     = isset( $ip_row['max_score'] ) ? (int) $ip_row['max_score'] : 0;
                $max_providers = isset( $ip_row['max_providers'] ) ? (int) $ip_row['max_providers'] : 0;
                $analytics['top_ips'][] = [
                    'ip'         => $ip_address,
                    'count'      => isset( $ip_row['hit_count'] ) ? (int) $ip_row['hit_count'] : 0,
                    'max_score'  => max( 0, min( 100, $max_score ) ),
                    'risk_level' => self::normalize_ip_risk_level( '', $max_score, $max_providers ),
                    'last_seen'  => isset( $ip_row['last_seen'] ) ? (string) $ip_row['last_seen'] : '',
                ];
            }

            $event_rows = $wpdb->get_results(
                $wpdb->prepare(
                    "SELECT id, event_time, event_type, ip_address, user_id, username, risk_score, risk_level, profile_status, provider_count, action, context_json
                    FROM $events_table
                    ORDER BY id DESC
                    LIMIT %d",
                    $recent_limit
                ),
                ARRAY_A
            );
            $profile_cache  = [];
            $profile_synced = [];

            foreach ( (array) $event_rows as $event_row ) {
                $context = [];
                if ( ! empty( $event_row['context_json'] ) && is_string( $event_row['context_json'] ) ) {
                    $decoded = json_decode( $event_row['context_json'], true );
                    if ( is_array( $decoded ) ) {
                        $context = $decoded;
                    }
                }

                $ip_address      = isset( $event_row['ip_address'] ) ? self::normalize_ip_address( $event_row['ip_address'] ) : '';
                $risk_score      = isset( $event_row['risk_score'] ) ? (int) $event_row['risk_score'] : 0;
                $provider_count  = isset( $event_row['provider_count'] ) ? max( 0, (int) $event_row['provider_count'] ) : 0;
                $profile_status  = sanitize_key( isset( $event_row['profile_status'] ) ? (string) $event_row['profile_status'] : 'unknown' );
                $risk_level_hint = isset( $event_row['risk_level'] ) ? (string) $event_row['risk_level'] : '';

                if ( self::is_pending_ip_risk_status( $profile_status ) && '' !== $ip_address ) {
                    if ( ! array_key_exists( $ip_address, $profile_cache ) ) {
                        $profile_cache[ $ip_address ] = self::get_ip_risk_profile( $ip_address );
                    }

                    $latest_profile = is_array( $profile_cache[ $ip_address ] ) ? $profile_cache[ $ip_address ] : [];
                    $latest_status  = sanitize_key( isset( $latest_profile['query_status'] ) ? (string) $latest_profile['query_status'] : '' );

                    if ( '' !== $latest_status && ! self::is_pending_ip_risk_status( $latest_status ) ) {
                        $profile_status = $latest_status;
                        $risk_score     = isset( $latest_profile['risk_score'] ) ? (int) $latest_profile['risk_score'] : $risk_score;
                        $provider_count = max( $provider_count, isset( $latest_profile['provider_count'] ) ? (int) $latest_profile['provider_count'] : 0 );
                        $risk_level_hint = isset( $latest_profile['risk_level'] ) ? (string) $latest_profile['risk_level'] : $risk_level_hint;

                        if ( empty( $profile_synced[ $ip_address ] ) ) {
                            self::refresh_pending_ip_risk_events( $ip_address, $latest_profile );
                            $profile_synced[ $ip_address ] = true;
                        }
                    }
                }

                $analytics['recent_events'][] = [
                    'time'          => isset( $event_row['event_time'] ) ? (string) $event_row['event_time'] : '',
                    'event_type'    => sanitize_key( isset( $event_row['event_type'] ) ? (string) $event_row['event_type'] : '' ),
                    'ip_address'    => '' !== $ip_address ? $ip_address : ( isset( $event_row['ip_address'] ) ? (string) $event_row['ip_address'] : '' ),
                    'user_id'       => isset( $event_row['user_id'] ) ? (int) $event_row['user_id'] : 0,
                    'username'      => isset( $event_row['username'] ) ? (string) $event_row['username'] : '',
                    'risk_score'    => max( 0, min( 100, $risk_score ) ),
                    'risk_level'    => self::normalize_ip_risk_level(
                        $risk_level_hint,
                        $risk_score,
                        $provider_count
                    ),
                    'profile_status' => $profile_status,
                    'provider_count' => $provider_count,
                    'action'        => sanitize_key( isset( $event_row['action'] ) ? (string) $event_row['action'] : 'observe' ),
                    'query_mode'    => isset( $context['query_mode'] ) ? sanitize_key( (string) $context['query_mode'] ) : '',
                    'scope'         => isset( $context['scope'] ) ? sanitize_key( (string) $context['scope'] ) : '',
                ];
            }
        }

        return $analytics;
    }

    public static function get_ip_risk_events_by_ip( $ip_address, $limit = 20 ) {
        global $wpdb;

        if ( ! self::table_exists( 'ip_risk_events' ) ) {
            return [];
        }

        $ip_address = self::normalize_ip_address( $ip_address );
        if ( '' === $ip_address ) {
            return [];
        }

        $limit = max( 1, min( 100, absint( $limit ) ) );
        $table = self::get_table_name( 'ip_risk_events' );
        $rows  = $wpdb->get_results(
            $wpdb->prepare(
                "SELECT event_time, event_type, ip_address, user_id, username, risk_score, risk_level, profile_status, provider_count, action, context_json
                FROM $table
                WHERE ip_address = %s
                ORDER BY id DESC
                LIMIT %d",
                $ip_address,
                $limit
            ),
            ARRAY_A
        );

        $events = [];

        foreach ( (array) $rows as $row ) {
            $context = [];
            if ( ! empty( $row['context_json'] ) && is_string( $row['context_json'] ) ) {
                $decoded = json_decode( $row['context_json'], true );
                if ( is_array( $decoded ) ) {
                    $context = $decoded;
                }
            }

            $events[] = [
                'time'           => isset( $row['event_time'] ) ? (string) $row['event_time'] : '',
                'event_type'     => sanitize_key( isset( $row['event_type'] ) ? (string) $row['event_type'] : '' ),
                'ip_address'     => isset( $row['ip_address'] ) ? (string) $row['ip_address'] : $ip_address,
                'user_id'        => isset( $row['user_id'] ) ? absint( $row['user_id'] ) : 0,
                'username'       => isset( $row['username'] ) ? (string) $row['username'] : '',
                'risk_score'     => max( 0, min( 100, isset( $row['risk_score'] ) ? (int) $row['risk_score'] : 0 ) ),
                'risk_level'     => self::normalize_ip_risk_level(
                    isset( $row['risk_level'] ) ? (string) $row['risk_level'] : 'unknown',
                    isset( $row['risk_score'] ) ? (int) $row['risk_score'] : 0,
                    isset( $row['provider_count'] ) ? (int) $row['provider_count'] : 0
                ),
                'profile_status' => sanitize_key( isset( $row['profile_status'] ) ? (string) $row['profile_status'] : 'unknown' ),
                'provider_count' => max( 0, isset( $row['provider_count'] ) ? (int) $row['provider_count'] : 0 ),
                'action'         => sanitize_key( isset( $row['action'] ) ? (string) $row['action'] : 'observe' ),
                'query_mode'     => isset( $context['query_mode'] ) ? sanitize_key( (string) $context['query_mode'] ) : '',
                'scope'          => isset( $context['scope'] ) ? sanitize_key( (string) $context['scope'] ) : '',
            ];
        }

        return $events;
    }

    public static function delete_ip_risk_profile( $ip_address, $delete_events = true ) {
        global $wpdb;

        $summary = [
            'profiles' => 0,
            'events'   => 0,
        ];

        $ip_address = self::normalize_ip_address( $ip_address );
        if ( '' === $ip_address ) {
            return $summary;
        }

        if ( self::table_exists( 'ip_risk_profiles' ) ) {
            $table                 = self::get_table_name( 'ip_risk_profiles' );
            $deleted               = $wpdb->delete( $table, [ 'ip_address' => $ip_address ], [ '%s' ] );
            $summary['profiles']   = false === $deleted ? 0 : (int) $deleted;
        }

        if ( $delete_events && self::table_exists( 'ip_risk_events' ) ) {
            $table               = self::get_table_name( 'ip_risk_events' );
            $deleted             = $wpdb->delete( $table, [ 'ip_address' => $ip_address ], [ '%s' ] );
            $summary['events']   = false === $deleted ? 0 : (int) $deleted;
        }

        return $summary;
    }

    public static function clear_ip_risk_data( $target = 'all' ) {
        global $wpdb;

        $target  = sanitize_key( (string) $target );
        $summary = [
            'profiles' => 0,
            'events'   => 0,
        ];

        if ( in_array( $target, [ 'profiles', 'all' ], true ) && self::table_exists( 'ip_risk_profiles' ) ) {
            $table               = self::get_table_name( 'ip_risk_profiles' );
            $deleted             = $wpdb->query( "DELETE FROM $table" );
            $summary['profiles'] = false === $deleted ? 0 : (int) $deleted;
        }

        if ( in_array( $target, [ 'events', 'all' ], true ) && self::table_exists( 'ip_risk_events' ) ) {
            $table             = self::get_table_name( 'ip_risk_events' );
            $deleted           = $wpdb->query( "DELETE FROM $table" );
            $summary['events'] = false === $deleted ? 0 : (int) $deleted;
        }

        return $summary;
    }

    public static function cleanup_expired_ip_risk_data( $days = 30 ) {
        global $wpdb;

        $days      = max( 7, absint( $days ) );
        $threshold = date( 'Y-m-d H:i:s', current_time( 'timestamp' ) - ( $days * DAY_IN_SECONDS ) );
        $summary   = [
            'profiles' => 0,
            'events'   => 0,
        ];

        if ( self::table_exists( 'ip_risk_profiles' ) ) {
            $table               = self::get_table_name( 'ip_risk_profiles' );
            $deleted             = $wpdb->query( $wpdb->prepare( "DELETE FROM $table WHERE updated_at < %s", $threshold ) );
            $summary['profiles'] = false === $deleted ? 0 : (int) $deleted;
        }

        if ( self::table_exists( 'ip_risk_events' ) ) {
            $table             = self::get_table_name( 'ip_risk_events' );
            $deleted           = $wpdb->query( $wpdb->prepare( "DELETE FROM $table WHERE event_time < %s", $threshold ) );
            $summary['events'] = false === $deleted ? 0 : (int) $deleted;
        }

        return $summary;
    }

    private static function normalize_ip_risk_level( $level, $score = 0, $provider_count = 0 ) {
        $level = sanitize_key( (string) $level );
        if ( in_array( $level, [ 'safe', 'low', 'medium', 'high', 'critical' ], true ) ) {
            return $level;
        }

        $provider_count = max( 0, (int) $provider_count );
        $score = max( 0, min( 100, (int) $score ) );

        if ( 'unknown' === $level ) {
            if ( $score > 0 ) {
                $level = '';
            } elseif ( $provider_count > 0 ) {
                return 'safe';
            } else {
                return 'unknown';
            }
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

        if ( $provider_count > 0 ) {
            return 'safe';
        }

        return 0 === $score ? 'unknown' : 'safe';
    }

    private static function is_pending_ip_risk_status( $status ) {
        $status = sanitize_key( (string) $status );
        return in_array( $status, [ 'pending', 'pending_async', 'pending_external', 'missing' ], true );
    }

    private static function normalize_ip_address( $ip_address ) {
        $ip_address = trim( (string) $ip_address );
        $ip_address = filter_var( $ip_address, FILTER_VALIDATE_IP );

        return $ip_address ? $ip_address : '';
    }

    public static function get_security_analytics( $days = 7 ) {
        global $wpdb;

        $days              = max( 1, min( 30, absint( $days ) ) );
        $current_timestamp = current_time( 'timestamp' );
        $window_24h        = date( 'Y-m-d H:i:s', $current_timestamp - DAY_IN_SECONDS );
        $window_days       = date( 'Y-m-d H:i:s', $current_timestamp - ( $days * DAY_IN_SECONDS ) );
        $max_logs          = 5000;
        $max_bans          = 1000;
        $analytics         = [
            'summary'       => [
                'login_failures_24h' => 0,
                'rate_limits_24h'    => 0,
                'active_bans'        => 0,
                'critical_open'      => 0,
            ],
            'top_ips'       => [],
            'top_paths'     => [],
            'top_usernames' => [],
            'ban_reasons'   => [],
            'trends'        => [],
            'has_audit'     => self::table_exists( 'audit' ),
        ];
        $ip_counts         = [];
        $path_counts       = [];
        $username_counts   = [];

        $trend_days = [];
        for ( $offset = $days - 1; $offset >= 0; $offset-- ) {
            $day = date( 'Y-m-d', $current_timestamp - ( $offset * DAY_IN_SECONDS ) );

            $trend_days[ $day ] = [
                'day'            => $day,
                'label'          => substr( $day, 5 ),
                'login_failures' => 0,
                'rate_limits'    => 0,
                'bans'           => 0,
            ];
        }

        if ( self::table_exists( 'audit' ) ) {
            $table = self::get_table_name( 'audit' );
            $logs  = $wpdb->get_results(
                $wpdb->prepare(
                    "SELECT time, username, action_type, action_detail, ip_address FROM $table WHERE time >= %s ORDER BY time DESC LIMIT %d",
                    $window_days,
                    $max_logs
                )
            );

            foreach ( (array) $logs as $log ) {
                $action_type = isset( $log->action_type ) ? (string) $log->action_type : '';
                $detail      = isset( $log->action_detail ) ? (string) $log->action_detail : '';
                $ip          = isset( $log->ip_address ) ? (string) $log->ip_address : '';
                $time        = isset( $log->time ) ? (string) $log->time : '';
                $day         = strlen( $time ) >= 10 ? substr( $time, 0, 10 ) : '';
                $is_last_24h = ! empty( $time ) && strtotime( $time ) >= strtotime( $window_24h );

                if ( isset( $trend_days[ $day ] ) ) {
                    if ( '登录失败' === $action_type ) {
                        $trend_days[ $day ]['login_failures']++;
                    } elseif ( '行为限速触发' === $action_type ) {
                        $trend_days[ $day ]['rate_limits']++;
                    }
                }

                if ( ! $is_last_24h ) {
                    continue;
                }

                if ( '登录失败' === $action_type ) {
                    $analytics['summary']['login_failures_24h']++;

                    if ( '' !== $ip ) {
                        if ( ! isset( $ip_counts[ $ip ] ) ) {
                            $ip_counts[ $ip ] = 0;
                        }

                        $ip_counts[ $ip ]++;
                    }

                    $username = self::extract_attack_username_from_detail( $action_type, $detail );
                    if ( '' !== $username ) {
                        if ( ! isset( $username_counts[ $username ] ) ) {
                            $username_counts[ $username ] = 0;
                        }

                        $username_counts[ $username ]++;
                    }
                } elseif ( '行为限速触发' === $action_type ) {
                    $analytics['summary']['rate_limits_24h']++;

                    if ( '' !== $ip ) {
                        if ( ! isset( $ip_counts[ $ip ] ) ) {
                            $ip_counts[ $ip ] = 0;
                        }

                        $ip_counts[ $ip ]++;
                    }
                }

                $path = self::extract_attack_path_from_detail( $action_type, $detail );
                if ( '' !== $path ) {
                    if ( ! isset( $path_counts[ $path ] ) ) {
                        $path_counts[ $path ] = 0;
                    }

                    $path_counts[ $path ]++;
                }
            }
        }

        if ( self::table_exists( 'ban_ips' ) ) {
            $table        = self::get_table_name( 'ban_ips' );
            $current_time = current_time( 'mysql' );
            $ban_rows     = $wpdb->get_results(
                $wpdb->prepare(
                    "SELECT ip_address, reason, ban_time, expire_time FROM $table WHERE ban_time >= %s ORDER BY ban_time DESC LIMIT %d",
                    $window_days,
                    $max_bans
                )
            );

            $analytics['summary']['active_bans'] = (int) $wpdb->get_var(
                $wpdb->prepare(
                    "SELECT COUNT(*) FROM $table WHERE expire_time > %s",
                    $current_time
                )
            );

            $ban_reason_counts = [];

            foreach ( (array) $ban_rows as $ban_row ) {
                $ban_time = isset( $ban_row->ban_time ) ? (string) $ban_row->ban_time : '';
                $ban_day  = strlen( $ban_time ) >= 10 ? substr( $ban_time, 0, 10 ) : '';
                $reason   = isset( $ban_row->reason ) ? (string) $ban_row->reason : '未注明原因';
                $ip       = isset( $ban_row->ip_address ) ? (string) $ban_row->ip_address : '';

                if ( isset( $trend_days[ $ban_day ] ) ) {
                    $trend_days[ $ban_day ]['bans']++;
                }

                if ( ! empty( $ban_time ) && strtotime( $ban_time ) >= strtotime( $window_24h ) && '' !== $ip ) {
                    if ( ! isset( $ip_counts[ $ip ] ) ) {
                        $ip_counts[ $ip ] = 0;
                    }

                    $ip_counts[ $ip ]++;
                }

                if ( ! isset( $ban_reason_counts[ $reason ] ) ) {
                    $ban_reason_counts[ $reason ] = 0;
                }

                $ban_reason_counts[ $reason ]++;
            }

            $analytics['ban_reasons'] = self::format_top_counts( $ban_reason_counts, 6 );
        }

        if ( self::table_exists( 'results' ) ) {
            $table = self::get_table_name( 'results' );

            $analytics['summary']['critical_open'] = (int) $wpdb->get_var(
                "SELECT COUNT(*) FROM $table WHERE severity = 'critical' AND status = 'open'"
            );
        }

        $analytics['top_ips']       = self::format_top_counts( $ip_counts );
        $analytics['top_paths']     = self::format_top_counts( $path_counts );
        $analytics['top_usernames'] = self::format_top_counts( $username_counts );

        $analytics['trends'] = array_values( $trend_days );

        return $analytics;
    }

    public static function cleanup_history( $settings = [] ) {
        global $wpdb;

        $settings = is_array( $settings ) ? $settings : [];
        $summary  = [
            'scans'   => 0,
            'results' => 0,
            'audit'   => 0,
            'bans'    => 0,
            'ip_risk_events'   => 0,
            'ip_risk_profiles' => 0,
        ];

        if ( self::table_exists( 'scans' ) && self::table_exists( 'results' ) ) {
            $scan_retention_days = isset( $settings['scan_retention_days'] ) ? absint( $settings['scan_retention_days'] ) : 0;

            if ( $scan_retention_days > 0 ) {
                $table_scans = self::get_table_name( 'scans' );
                $cutoff      = date( 'Y-m-d H:i:s', current_time( 'timestamp' ) - ( $scan_retention_days * DAY_IN_SECONDS ) );
                $scan_ids    = $wpdb->get_col( $wpdb->prepare( "SELECT id FROM $table_scans WHERE end_time IS NOT NULL AND end_time < %s", $cutoff ) );
                $scan_ids    = array_filter( array_map( 'absint', (array) $scan_ids ) );

                if ( ! empty( $scan_ids ) ) {
                    $summary['results'] = self::delete_results_by_scan_ids( $scan_ids );
                    $summary['scans']   = self::delete_rows_by_ids( self::get_table_name( 'scans' ), $scan_ids );
                }
            }
        }

        if ( self::table_exists( 'audit' ) ) {
            $audit_retention_days = isset( $settings['audit_retention_days'] ) ? absint( $settings['audit_retention_days'] ) : 0;

            if ( $audit_retention_days > 0 ) {
                $table   = self::get_table_name( 'audit' );
                $cutoff  = date( 'Y-m-d H:i:s', current_time( 'timestamp' ) - ( $audit_retention_days * DAY_IN_SECONDS ) );
                $query   = $wpdb->prepare( "DELETE FROM $table WHERE time < %s", $cutoff );
                $deleted = $wpdb->query( $query );

                $summary['audit'] = false === $deleted ? 0 : (int) $deleted;
            }
        }

        if ( self::table_exists( 'ban_ips' ) ) {
            $table        = self::get_table_name( 'ban_ips' );
            $current_time = current_time( 'mysql' );
            $query        = $wpdb->prepare( "DELETE FROM $table WHERE expire_time <= %s", $current_time );
            $deleted      = $wpdb->query( $query );

            $summary['bans'] = false === $deleted ? 0 : (int) $deleted;
        }

        $ip_risk_retention_days = isset( $settings['ip_risk_retention_days'] ) ? absint( $settings['ip_risk_retention_days'] ) : 0;

        if ( $ip_risk_retention_days > 0 && self::table_exists( 'ip_risk_events' ) ) {
            $table   = self::get_table_name( 'ip_risk_events' );
            $cutoff  = date( 'Y-m-d H:i:s', current_time( 'timestamp' ) - ( $ip_risk_retention_days * DAY_IN_SECONDS ) );
            $query   = $wpdb->prepare( "DELETE FROM $table WHERE event_time < %s", $cutoff );
            $deleted = $wpdb->query( $query );

            $summary['ip_risk_events'] = false === $deleted ? 0 : (int) $deleted;
        }

        if ( $ip_risk_retention_days > 0 && self::table_exists( 'ip_risk_profiles' ) ) {
            $table   = self::get_table_name( 'ip_risk_profiles' );
            $cutoff  = date( 'Y-m-d H:i:s', current_time( 'timestamp' ) - ( $ip_risk_retention_days * DAY_IN_SECONDS ) );
            $query   = $wpdb->prepare( "DELETE FROM $table WHERE last_seen < %s", $cutoff );
            $deleted = $wpdb->query( $query );

            $summary['ip_risk_profiles'] = false === $deleted ? 0 : (int) $deleted;
        }

        return $summary;
    }

    public static function clear_all_history() {
        global $wpdb;

        $summary = [
            'scans'    => 0,
            'results'  => 0,
            'audit'    => 0,
            'bans'     => 0,
            'baseline' => 0,
            'phone_cache' => 0,
            'ip_risk_profiles' => 0,
            'ip_risk_events'   => 0,
        ];

        if ( self::table_exists( 'results' ) ) {
            $table              = self::get_table_name( 'results' );
            $deleted            = $wpdb->query( "DELETE FROM $table" );
            $summary['results'] = false === $deleted ? 0 : (int) $deleted;
        }

        if ( self::table_exists( 'scans' ) ) {
            $table            = self::get_table_name( 'scans' );
            $deleted          = $wpdb->query( "DELETE FROM $table" );
            $summary['scans'] = false === $deleted ? 0 : (int) $deleted;
        }

        if ( self::table_exists( 'audit' ) ) {
            $table            = self::get_table_name( 'audit' );
            $deleted          = $wpdb->query( "DELETE FROM $table" );
            $summary['audit'] = false === $deleted ? 0 : (int) $deleted;
        }

        if ( self::table_exists( 'ban_ips' ) ) {
            $table           = self::get_table_name( 'ban_ips' );
            $deleted         = $wpdb->query( "DELETE FROM $table" );
            $summary['bans'] = false === $deleted ? 0 : (int) $deleted;
        }

        if ( self::table_exists( 'baseline_files' ) ) {
            $table               = self::get_table_name( 'baseline_files' );
            $deleted             = $wpdb->query( "DELETE FROM $table" );
            $summary['baseline'] = false === $deleted ? 0 : (int) $deleted;
        }

        if ( self::table_exists( 'phone_location_cache' ) ) {
            $table                  = self::get_table_name( 'phone_location_cache' );
            $deleted                = $wpdb->query( "DELETE FROM $table" );
            $summary['phone_cache'] = false === $deleted ? 0 : (int) $deleted;
        }

        if ( self::table_exists( 'ip_risk_profiles' ) ) {
            $table                         = self::get_table_name( 'ip_risk_profiles' );
            $deleted                       = $wpdb->query( "DELETE FROM $table" );
            $summary['ip_risk_profiles']   = false === $deleted ? 0 : (int) $deleted;
        }

        if ( self::table_exists( 'ip_risk_events' ) ) {
            $table                       = self::get_table_name( 'ip_risk_events' );
            $deleted                     = $wpdb->query( "DELETE FROM $table" );
            $summary['ip_risk_events']   = false === $deleted ? 0 : (int) $deleted;
        }

        return $summary;
    }

    public static function delete_all_data() {
        global $wpdb;

        foreach ( self::get_tables() as $table_name ) {
            $wpdb->query( 'DROP TABLE IF EXISTS ' . $wpdb->prefix . $table_name );
        }

        delete_option( 'qs_db_schema_version' );
        delete_option( 'qs_protection_settings' );
        delete_option( 'qs_rule_package_active' );
        delete_option( 'qs_rule_package_previous' );
    }

    private static function delete_results_by_scan_ids( $scan_ids ) {
        return self::delete_rows_by_ids( self::get_table_name( 'results' ), $scan_ids, 'scan_id' );
    }

    private static function delete_rows_by_ids( $table, $ids, $column = 'id' ) {
        global $wpdb;

        $ids = array_filter( array_map( 'absint', (array) $ids ) );

        if ( empty( $ids ) || '' === $table ) {
            return 0;
        }

        $placeholders = implode( ',', array_fill( 0, count( $ids ), '%d' ) );
        $query        = $wpdb->prepare( "DELETE FROM $table WHERE $column IN ($placeholders)", $ids );
        $deleted      = $wpdb->query( $query );

        return false === $deleted ? 0 : (int) $deleted;
    }

    private static function extract_attack_path_from_detail( $action_type, $detail ) {
        $action_type = (string) $action_type;
        $detail      = (string) $detail;

        if ( '' === $detail ) {
            return '';
        }

        if ( '登录失败' === $action_type && preg_match( '/入口 \[([^\]]+)\]/u', $detail, $matches ) ) {
            return self::normalize_attack_label( $matches[1] );
        }

        if ( '行为限速触发' === $action_type && preg_match( '/请求 [A-Z]+ ([^；]+)/u', $detail, $matches ) ) {
            return self::normalize_attack_label( $matches[1] );
        }

        return '';
    }

    private static function extract_attack_username_from_detail( $action_type, $detail ) {
        $action_type = (string) $action_type;
        $detail      = (string) $detail;

        if ( '登录失败' !== $action_type || '' === $detail ) {
            return '';
        }

        if ( preg_match( '/身份验证失败 \[([^\]]+)\]/u', $detail, $matches ) ) {
            return self::normalize_attack_label( $matches[1] );
        }

        return '';
    }

    private static function normalize_attack_label( $value ) {
        $value = trim( sanitize_text_field( (string) $value ) );

        if ( '' === $value ) {
            return '';
        }

        if ( function_exists( 'mb_substr' ) ) {
            return mb_substr( $value, 0, 120 );
        }

        return substr( $value, 0, 120 );
    }

    private static function format_top_counts( $counts, $limit = 8 ) {
        $counts = is_array( $counts ) ? $counts : [];
        $limit  = max( 1, absint( $limit ) );

        arsort( $counts );
        $counts = array_slice( $counts, 0, $limit, true );
        $items  = [];

        foreach ( $counts as $label => $count ) {
            $items[] = [
                'label' => (string) $label,
                'count' => (int) $count,
            ];
        }

        return $items;
    }
}
