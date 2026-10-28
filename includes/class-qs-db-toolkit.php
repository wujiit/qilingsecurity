<?php
/**
 * 启灵安全防护 - 数据库优化与管理独立工具箱
 *
 * 专注于数据库健康分析、Autoload 性能体检、垃圾数据清理、碎片整理以及序列化安全的通用数据库替换。
 * 独立文件、独立数据表，与安全主引擎解耦，方便后期单独维护与功能拓展。
 *
 * @package QilingSecurity
 */

if ( ! defined( 'ABSPATH' ) ) {
    exit;
}

class QS_DB_Toolkit {

    const SCHEMA_VERSION        = '1.0.0';
    const OPTION_SCHEMA_VERSION = 'qs_db_toolkit_schema_version';
    const LOG_TABLE_KEY         = 'qilingsecurity_db_toolkit_logs';

    /**
     * 初始化工具箱
     */
    public static function init() {
        self::maybe_install();

        // 注册专用 AJAX 钩子
        add_action( 'wp_ajax_qs_db_toolkit_analyze', [ __CLASS__, 'ajax_analyze' ] );
        add_action( 'wp_ajax_qs_db_toolkit_cleanup', [ __CLASS__, 'ajax_cleanup' ] );
        add_action( 'wp_ajax_qs_db_toolkit_optimize_tables', [ __CLASS__, 'ajax_optimize_tables' ] );
        add_action( 'wp_ajax_qs_db_toolkit_toggle_autoload', [ __CLASS__, 'ajax_toggle_autoload' ] );
        add_action( 'wp_ajax_qs_db_toolkit_search_replace_batch', [ __CLASS__, 'ajax_search_replace_batch' ] );
        add_action( 'wp_ajax_qs_db_toolkit_get_logs', [ __CLASS__, 'ajax_get_logs' ] );
        add_action( 'wp_ajax_qs_db_toolkit_clear_logs', [ __CLASS__, 'ajax_clear_logs' ] );
        add_action( 'wp_ajax_qs_db_toolkit_get_index_status', [ __CLASS__, 'ajax_get_index_status' ] );
        add_action( 'wp_ajax_qs_db_toolkit_toggle_index', [ __CLASS__, 'ajax_toggle_index' ] );
    }

    /**
     * 获取日志表完整名称
     */
    public static function get_log_table_name() {
        global $wpdb;
        return $wpdb->prefix . self::LOG_TABLE_KEY;
    }

    /**
     * 自动安装 / 升级独立数据表
     */
    public static function maybe_install() {
        $installed_ver = get_option( self::OPTION_SCHEMA_VERSION, '' );
        if ( version_compare( $installed_ver, self::SCHEMA_VERSION, '<' ) ) {
            self::install();
        }
    }

    /**
     * 执行建表
     */
    public static function install() {
        global $wpdb;

        $table_name      = self::get_log_table_name();
        $charset_collate = $wpdb->get_charset_collate();

        $sql = "CREATE TABLE {$table_name} (
            id bigint(20) unsigned NOT NULL AUTO_INCREMENT,
            action_type varchar(50) NOT NULL DEFAULT '',
            target_scope varchar(255) NOT NULL DEFAULT '',
            affected_rows bigint(20) NOT NULL DEFAULT 0,
            is_dry_run tinyint(1) NOT NULL DEFAULT 0,
            status varchar(20) NOT NULL DEFAULT 'success',
            details longtext,
            user_id bigint(20) unsigned NOT NULL DEFAULT 0,
            duration_ms int(11) NOT NULL DEFAULT 0,
            created_at datetime NOT NULL DEFAULT CURRENT_TIMESTAMP,
            PRIMARY KEY  (id),
            KEY action_type (action_type),
            KEY created_at (created_at)
        ) {$charset_collate};";

        require_once ABSPATH . 'wp-admin/includes/upgrade.php';
        dbDelta( $sql );

        update_option( self::OPTION_SCHEMA_VERSION, self::SCHEMA_VERSION );
    }

    /**
     * 记录运维操作日志
     */
    public static function log_action( $action_type, $target_scope, $affected_rows, $is_dry_run = false, $details = [], $duration_ms = 0, $status = 'success' ) {
        global $wpdb;

        $table_name = self::get_log_table_name();
        $user_id    = get_current_user_id();

        $wpdb->insert(
            $table_name,
            [
                'action_type'   => sanitize_key( (string) $action_type ),
                'target_scope'  => sanitize_text_field( (string) $target_scope ),
                'affected_rows' => (int) $affected_rows,
                'is_dry_run'    => $is_dry_run ? 1 : 0,
                'status'        => sanitize_key( (string) $status ),
                'details'       => ! empty( $details ) ? wp_json_encode( $details ) : '',
                'user_id'       => absint( $user_id ),
                'duration_ms'   => absint( $duration_ms ),
                'created_at'    => current_time( 'mysql' ),
            ],
            [ '%s', '%s', '%d', '%d', '%s', '%s', '%d', '%d', '%s' ]
        );
    }

    /**
     * 字节大小人性化格式转换
     */
    public static function format_bytes( $bytes, $precision = 2 ) {
        $bytes = (float) $bytes;
        if ( $bytes <= 0 ) {
            return '0 B';
        }
        $units = [ 'B', 'KB', 'MB', 'GB', 'TB' ];
        $pow   = floor( log( $bytes ) / log( 1024 ) );
        $pow   = min( $pow, count( $units ) - 1 );
        $bytes /= pow( 1024, $pow );
        return round( $bytes, $precision ) . ' ' . $units[ $pow ];
    }

    /**
     * 安全转义 SQL 标识符（表名/字段名）
     */
    public static function esc_identifier( $identifier ) {
        return '`' . preg_replace( '/[^a-zA-Z0-9_]/', '', (string) $identifier ) . '`';
    }

    // =========================================================================
    // 1. 数据库分析引擎
    // =========================================================================

    /**
     * 获取全站数据表状态及概览
     */
    public static function get_database_overview() {
        global $wpdb;

        $tables_raw = $wpdb->get_results( 'SHOW TABLE STATUS', ARRAY_A );
        if ( ! is_array( $tables_raw ) ) {
            $tables_raw = [];
        }

        $summary = [
            'total_tables'     => count( $tables_raw ),
            'total_rows'       => 0,
            'total_data_bytes' => 0,
            'total_idx_bytes'  => 0,
            'total_free_bytes' => 0,
            'total_size_bytes' => 0,
            'wp_tables_count'  => 0,
            'other_tables_cnt' => 0,
            'tables'           => [],
        ];

        $prefix = $wpdb->prefix;

        foreach ( $tables_raw as $table ) {
            $name        = isset( $table['Name'] ) ? $table['Name'] : '';
            $engine      = isset( $table['Engine'] ) ? $table['Engine'] : 'Unknown';
            $rows        = isset( $table['Rows'] ) ? (int) $table['Rows'] : 0;
            $data_len    = isset( $table['Data_length'] ) ? (float) $table['Data_length'] : 0;
            $idx_len     = isset( $table['Index_length'] ) ? (float) $table['Index_length'] : 0;
            $data_free   = isset( $table['Data_free'] ) ? (float) $table['Data_free'] : 0;
            $table_total = $data_len + $idx_len;
            $is_wp       = ( 0 === strpos( $name, $prefix ) );

            $summary['total_rows']       += $rows;
            $summary['total_data_bytes'] += $data_len;
            $summary['total_idx_bytes']  += $idx_len;
            $summary['total_free_bytes'] += $data_free;
            $summary['total_size_bytes'] += $table_total;

            if ( $is_wp ) {
                $summary['wp_tables_count']++;
            } else {
                $summary['other_tables_cnt']++;
            }

            $summary['tables'][] = [
                'name'            => $name,
                'engine'          => $engine,
                'rows'            => $rows,
                'data_size'       => self::format_bytes( $data_len ),
                'index_size'      => self::format_bytes( $idx_len ),
                'free_size'       => self::format_bytes( $data_free ),
                'total_size'      => self::format_bytes( $table_total ),
                'total_bytes'     => $table_total,
                'free_bytes'      => $data_free,
                'is_wp'           => $is_wp,
                'has_fragment'    => ( $data_free > 0 ),
            ];
        }

        // 按体积降序排列
        usort( $summary['tables'], function( $a, $b ) {
            return $b['total_bytes'] <=> $a['total_bytes'];
        } );

        $summary['total_data_size_fmt'] = self::format_bytes( $summary['total_data_bytes'] );
        $summary['total_idx_size_fmt']  = self::format_bytes( $summary['total_idx_bytes'] );
        $summary['total_free_size_fmt'] = self::format_bytes( $summary['total_free_bytes'] );
        $summary['total_size_fmt']      = self::format_bytes( $summary['total_size_bytes'] );

        return $summary;
    }

    /**
     * Autoload 选项深度分析 (WordPress 性能核心瓶颈)
     */
    public static function get_autoload_analysis() {
        global $wpdb;

        $table_options = $wpdb->options;

        // 统计总 Autoload 大小与条目数
        $stats = $wpdb->get_row( "SELECT COUNT(*) as total_count, SUM(LENGTH(option_value)) as total_bytes FROM {$table_options} WHERE autoload = 'yes' OR autoload = 'on'", ARRAY_A );
        $total_bytes = isset( $stats['total_bytes'] ) ? (float) $stats['total_bytes'] : 0;
        $total_count = isset( $stats['total_count'] ) ? (int) $stats['total_count'] : 0;

        // 获取占用最大的 TOP 20 Autoload 选项
        $top_options_raw = $wpdb->get_results(
            "SELECT option_name, LENGTH(option_value) as val_bytes, autoload FROM {$table_options} WHERE autoload = 'yes' OR autoload = 'on' ORDER BY val_bytes DESC LIMIT 20",
            ARRAY_A
        );

        $top_options = [];
        if ( is_array( $top_options_raw ) ) {
            foreach ( $top_options_raw as $opt ) {
                $b = (float) $opt['val_bytes'];
                $top_options[] = [
                    'name'       => $opt['option_name'],
                    'size_bytes' => $b,
                    'size_fmt'   => self::format_bytes( $b ),
                    'autoload'   => $opt['autoload'],
                    'is_huge'    => ( $b >= 102400 ), // 单项超过 100KB 标记为过大
                ];
            }
        }

        // 评估健康级别
        $health_level = 'good'; // good, warning, danger
        $health_tip   = 'Autoload 选项体积处于健康范围 (< 500 KB)。';

        if ( $total_bytes > 1572864 ) { // > 1.5MB
            $health_level = 'danger';
            $health_tip   = 'Autoload 体积严重超标（> 1.5 MB），每次页面请求均会全量载入内存，严重拖慢 TTFB 响应！建议排查大项并将其关闭 autoload。';
        } elseif ( $total_bytes > 819200 ) { // > 800KB
            $health_level = 'warning';
            $health_tip   = 'Autoload 体积偏大（> 800 KB），可能包含废弃插件遗留的庞大配置缓存，建议适当收敛。';
        }

        return [
            'total_bytes'     => $total_bytes,
            'total_size_fmt'  => self::format_bytes( $total_bytes ),
            'total_count'     => $total_count,
            'health_level'    => $health_level,
            'health_tip'      => $health_tip,
            'top_options'     => $top_options,
        ];
    }

    /**
     * 探测可清理垃圾数据量
     */
    public static function get_cleanable_stats() {
        global $wpdb;

        $stats = [
            'revisions'          => 0,
            'auto_drafts'        => 0,
            'trashed_posts'      => 0,
            'spam_comments'      => 0,
            'trashed_comments'   => 0,
            'expired_transients' => 0,
            'orphan_postmeta'    => 0,
            'orphan_termmeta'    => 0,
            'orphan_usermeta'    => 0,
            'total_cleanable'    => 0,
        ];

        // 1. 文章修订版
        $stats['revisions'] = (int) $wpdb->get_var( "SELECT COUNT(*) FROM {$wpdb->posts} WHERE post_type = 'revision'" );

        // 2. 自动草稿
        $stats['auto_drafts'] = (int) $wpdb->get_var( "SELECT COUNT(*) FROM {$wpdb->posts} WHERE post_status = 'auto-draft'" );

        // 3. 回收站文章/页面
        $stats['trashed_posts'] = (int) $wpdb->get_var( "SELECT COUNT(*) FROM {$wpdb->posts} WHERE post_status = 'trash'" );

        // 4. 垃圾评论
        $stats['spam_comments'] = (int) $wpdb->get_var( "SELECT COUNT(*) FROM {$wpdb->comments} WHERE comment_approved = 'spam'" );

        // 5. 回收站评论
        $stats['trashed_comments'] = (int) $wpdb->get_var( "SELECT COUNT(*) FROM {$wpdb->comments} WHERE comment_approved = 'trash'" );

        // 6. 过期 Transients
        $now = time();
        $stats['expired_transients'] = (int) $wpdb->get_var( $wpdb->prepare(
            "SELECT COUNT(*) FROM {$wpdb->options} WHERE (option_name LIKE %s OR option_name LIKE %s) AND option_value < %d",
            '_transient_timeout_%',
            '_site_transient_timeout_%',
            $now
        ) );

        // 7. 孤立 postmeta
        $stats['orphan_postmeta'] = (int) $wpdb->get_var(
            "SELECT COUNT(*) FROM {$wpdb->postmeta} pm LEFT JOIN {$wpdb->posts} p ON pm.post_id = p.ID WHERE p.ID IS NULL"
        );

        // 8. 孤立 termmeta
        if ( isset( $wpdb->termmeta ) && ! empty( $wpdb->termmeta ) ) {
            $stats['orphan_termmeta'] = (int) $wpdb->get_var(
                "SELECT COUNT(*) FROM {$wpdb->termmeta} tm LEFT JOIN {$wpdb->terms} t ON tm.term_id = t.term_id WHERE t.term_id IS NULL"
            );
        }

        // 9. 孤立 usermeta
        $stats['orphan_usermeta'] = (int) $wpdb->get_var(
            "SELECT COUNT(*) FROM {$wpdb->usermeta} um LEFT JOIN {$wpdb->users} u ON um.user_id = u.ID WHERE u.ID IS NULL"
        );

        $stats['total_cleanable'] = array_sum( $stats );

        return $stats;
    }

    // =========================================================================
    // 2. 数据库垃圾清理与优化执行器
    // =========================================================================

    /**
     * 执行指定垃圾项清理
     *
     * @param array $targets 要清理的项
     * @param int   $keep_revisions 保留每个 post 最近 N 个修订版 (0 为全部清除)
     * @param bool  $dry_run 是否为预演测试
     * @return array
     */
    public static function execute_cleanup( $targets = [], $keep_revisions = 0, $dry_run = false ) {
        global $wpdb;

        $targets        = is_array( $targets ) ? $targets : [];
        $keep_revisions = max( 0, (int) $keep_revisions );
        $dry_run        = (bool) $dry_run;

        $results = [
            'dry_run'       => $dry_run,
            'total_deleted' => 0,
            'items'         => [],
        ];

        $start_time = microtime( true );

        // 1. 文章历史修订版本
        if ( in_array( 'revisions', $targets, true ) ) {
            $deleted = 0;
            if ( $keep_revisions > 0 ) {
                // 保留最近 N 个版本
                $parents = $wpdb->get_col( "SELECT DISTINCT post_parent FROM {$wpdb->posts} WHERE post_type = 'revision' AND post_parent > 0" );
                foreach ( $parents as $parent_id ) {
                    $keep_ids = $wpdb->get_col( $wpdb->prepare(
                        "SELECT ID FROM {$wpdb->posts} WHERE post_type = 'revision' AND post_parent = %d ORDER BY ID DESC LIMIT %d",
                        $parent_id,
                        $keep_revisions
                    ) );
                    if ( ! empty( $keep_ids ) ) {
                        $keep_in = implode( ',', array_map( 'absint', $keep_ids ) );
                        $del_ids = $wpdb->get_col( $wpdb->prepare(
                            "SELECT ID FROM {$wpdb->posts} WHERE post_type = 'revision' AND post_parent = %d AND ID NOT IN ({$keep_in})",
                            $parent_id
                        ) );
                    } else {
                        $del_ids = $wpdb->get_col( $wpdb->prepare( "SELECT ID FROM {$wpdb->posts} WHERE post_type = 'revision' AND post_parent = %d", $parent_id ) );
                    }

                    if ( ! empty( $del_ids ) ) {
                        $del_count = count( $del_ids );
                        $deleted  += $del_count;
                        if ( ! $dry_run ) {
                            $in_ids = implode( ',', array_map( 'absint', $del_ids ) );
                            $wpdb->query( "DELETE FROM {$wpdb->posts} WHERE ID IN ({$in_ids})" );
                            $wpdb->query( "DELETE FROM {$wpdb->postmeta} WHERE post_id IN ({$in_ids})" );
                        }
                    }
                }
            } else {
                $count = (int) $wpdb->get_var( "SELECT COUNT(*) FROM {$wpdb->posts} WHERE post_type = 'revision'" );
                $deleted = $count;
                if ( ! $dry_run && $count > 0 ) {
                    $wpdb->query( "DELETE FROM {$wpdb->postmeta} WHERE post_id IN (SELECT ID FROM {$wpdb->posts} WHERE post_type = 'revision')" );
                    $wpdb->query( "DELETE FROM {$wpdb->posts} WHERE post_type = 'revision'" );
                }
            }
            $results['items']['revisions'] = $deleted;
            $results['total_deleted']     += $deleted;
        }

        // 2. 自动草稿
        if ( in_array( 'auto_drafts', $targets, true ) ) {
            $count = (int) $wpdb->get_var( "SELECT COUNT(*) FROM {$wpdb->posts} WHERE post_status = 'auto-draft'" );
            if ( ! $dry_run && $count > 0 ) {
                $wpdb->query( "DELETE FROM {$wpdb->postmeta} WHERE post_id IN (SELECT ID FROM {$wpdb->posts} WHERE post_status = 'auto-draft')" );
                $wpdb->query( "DELETE FROM {$wpdb->posts} WHERE post_status = 'auto-draft'" );
            }
            $results['items']['auto_drafts'] = $count;
            $results['total_deleted']        += $count;
        }

        // 3. 回收站文章/页面
        if ( in_array( 'trashed_posts', $targets, true ) ) {
            $count = (int) $wpdb->get_var( "SELECT COUNT(*) FROM {$wpdb->posts} WHERE post_status = 'trash'" );
            if ( ! $dry_run && $count > 0 ) {
                $wpdb->query( "DELETE FROM {$wpdb->postmeta} WHERE post_id IN (SELECT ID FROM {$wpdb->posts} WHERE post_status = 'trash')" );
                $wpdb->query( "DELETE FROM {$wpdb->posts} WHERE post_status = 'trash'" );
            }
            $results['items']['trashed_posts'] = $count;
            $results['total_deleted']          += $count;
        }

        // 4. 垃圾评论
        if ( in_array( 'spam_comments', $targets, true ) ) {
            $count = (int) $wpdb->get_var( "SELECT COUNT(*) FROM {$wpdb->comments} WHERE comment_approved = 'spam'" );
            if ( ! $dry_run && $count > 0 ) {
                $wpdb->query( "DELETE FROM {$wpdb->commentmeta} WHERE comment_id IN (SELECT comment_ID FROM {$wpdb->comments} WHERE comment_approved = 'spam')" );
                $wpdb->query( "DELETE FROM {$wpdb->comments} WHERE comment_approved = 'spam'" );
            }
            $results['items']['spam_comments'] = $count;
            $results['total_deleted']          += $count;
        }

        // 5. 回收站评论
        if ( in_array( 'trashed_comments', $targets, true ) ) {
            $count = (int) $wpdb->get_var( "SELECT COUNT(*) FROM {$wpdb->comments} WHERE comment_approved = 'trash'" );
            if ( ! $dry_run && $count > 0 ) {
                $wpdb->query( "DELETE FROM {$wpdb->commentmeta} WHERE comment_id IN (SELECT comment_ID FROM {$wpdb->comments} WHERE comment_approved = 'trash')" );
                $wpdb->query( "DELETE FROM {$wpdb->comments} WHERE comment_approved = 'trash'" );
            }
            $results['items']['trashed_comments'] = $count;
            $results['total_deleted']            += $count;
        }

        // 6. 过期 Transients 缓存
        if ( in_array( 'expired_transients', $targets, true ) ) {
            $now = time();
            $timeout_keys = $wpdb->get_col( $wpdb->prepare(
                "SELECT option_name FROM {$wpdb->options} WHERE (option_name LIKE %s OR option_name LIKE %s) AND option_value < %d",
                '_transient_timeout_%',
                '_site_transient_timeout_%',
                $now
            ) );

            $del_count = 0;
            if ( ! empty( $timeout_keys ) ) {
                $value_keys = [];
                foreach ( $timeout_keys as $t_key ) {
                    if ( 0 === strpos( $t_key, '_transient_timeout_' ) ) {
                        $value_keys[] = '_transient_' . substr( $t_key, 19 );
                    } elseif ( 0 === strpos( $t_key, '_site_transient_timeout_' ) ) {
                        $value_keys[] = '_site_transient_' . substr( $t_key, 24 );
                    }
                }
                $all_keys = array_merge( $timeout_keys, $value_keys );
                $del_count = count( $all_keys );

                if ( ! $dry_run ) {
                    $in_keys = "'" . implode( "','", array_map( 'esc_sql', $all_keys ) ) . "'";
                    $wpdb->query( "DELETE FROM {$wpdb->options} WHERE option_name IN ({$in_keys})" );
                }
            }
            $results['items']['expired_transients'] = $del_count;
            $results['total_deleted']               += $del_count;
        }

        // 7. 孤立 postmeta
        if ( in_array( 'orphan_postmeta', $targets, true ) ) {
            $count = (int) $wpdb->get_var( "SELECT COUNT(*) FROM {$wpdb->postmeta} pm LEFT JOIN {$wpdb->posts} p ON pm.post_id = p.ID WHERE p.ID IS NULL" );
            if ( ! $dry_run && $count > 0 ) {
                $wpdb->query( "DELETE pm FROM {$wpdb->postmeta} pm LEFT JOIN {$wpdb->posts} p ON pm.post_id = p.ID WHERE p.ID IS NULL" );
            }
            $results['items']['orphan_postmeta'] = $count;
            $results['total_deleted']            += $count;
        }

        // 8. 孤立 termmeta
        if ( in_array( 'orphan_termmeta', $targets, true ) && isset( $wpdb->termmeta ) && ! empty( $wpdb->termmeta ) ) {
            $count = (int) $wpdb->get_var( "SELECT COUNT(*) FROM {$wpdb->termmeta} tm LEFT JOIN {$wpdb->terms} t ON tm.term_id = t.term_id WHERE t.term_id IS NULL" );
            if ( ! $dry_run && $count > 0 ) {
                $wpdb->query( "DELETE tm FROM {$wpdb->termmeta} tm LEFT JOIN {$wpdb->terms} t ON tm.term_id = t.term_id WHERE t.term_id IS NULL" );
            }
            $results['items']['orphan_termmeta'] = $count;
            $results['total_deleted']            += $count;
        }

        // 9. 孤立 usermeta
        if ( in_array( 'orphan_usermeta', $targets, true ) ) {
            $count = (int) $wpdb->get_var( "SELECT COUNT(*) FROM {$wpdb->usermeta} um LEFT JOIN {$wpdb->users} u ON um.user_id = u.ID WHERE u.ID IS NULL" );
            if ( ! $dry_run && $count > 0 ) {
                $wpdb->query( "DELETE um FROM {$wpdb->usermeta} um LEFT JOIN {$wpdb->users} u ON um.user_id = u.ID WHERE u.ID IS NULL" );
            }
            $results['items']['orphan_usermeta'] = $count;
            $results['total_deleted']            += $count;
        }

        $duration_ms = (int) round( ( microtime( true ) - $start_time ) * 1000 );
        $results['duration_ms'] = $duration_ms;

        // 写入独立日志表
        self::log_action(
            'db_cleanup',
            implode( ', ', $targets ),
            $results['total_deleted'],
            $dry_run,
            $results['items'],
            $duration_ms
        );

        return $results;
    }

    /**
     * 执行数据表优化碎片整理 (OPTIMIZE TABLE)
     */
    public static function execute_optimize_tables( $tables = [], $dry_run = false ) {
        global $wpdb;

        $tables  = is_array( $tables ) ? $tables : [];
        $dry_run = (bool) $dry_run;

        // 获取全部现有合法数据表
        $all_db_tables = $wpdb->get_col( 'SHOW TABLES' );
        if ( ! is_array( $all_db_tables ) ) {
            $all_db_tables = [];
        }

        // 过滤合法表名，若未传特定表，则筛选出所有有碎片 (Data_free > 0) 的表
        if ( empty( $tables ) ) {
            $status_list = $wpdb->get_results( 'SHOW TABLE STATUS', ARRAY_A );
            if ( is_array( $status_list ) ) {
                foreach ( $status_list as $st ) {
                    if ( isset( $st['Data_free'] ) && (float) $st['Data_free'] > 0 && isset( $st['Name'] ) ) {
                        $tables[] = $st['Name'];
                    }
                }
            }
        }

        $valid_tables = array_values( array_intersect( $tables, $all_db_tables ) );
        $start_time   = microtime( true );
        $details      = [];
        $total_freed  = 0;

        foreach ( $valid_tables as $tbl ) {
            $esc_tbl = self::esc_identifier( $tbl );
            if ( $dry_run ) {
                $st = $wpdb->get_row( "SHOW TABLE STATUS LIKE '{$tbl}'", ARRAY_A );
                $free = isset( $st['Data_free'] ) ? (float) $st['Data_free'] : 0;
                $details[] = [
                    'table'    => $tbl,
                    'status'   => 'dry_run_ready',
                    'freed'    => self::format_bytes( $free ),
                    'raw_free' => $free,
                ];
                $total_freed += $free;
            } else {
                // 执行真实优化
                $opt_res = $wpdb->get_results( "OPTIMIZE TABLE {$esc_tbl}", ARRAY_A );
                $msg_txt = 'Table is already up to date / Optimized';
                if ( ! empty( $opt_res ) && isset( $opt_res[0]['Msg_text'] ) ) {
                    $msg_txt = $opt_res[0]['Msg_text'];
                }
                $details[] = [
                    'table'   => $tbl,
                    'status'  => $msg_txt,
                ];
            }
        }

        $duration_ms = (int) round( ( microtime( true ) - $start_time ) * 1000 );

        self::log_action(
            'optimize_tables',
            sprintf( '%d 个数据表', count( $valid_tables ) ),
            count( $valid_tables ),
            $dry_run,
            [
                'tables'      => $valid_tables,
                'total_freed' => self::format_bytes( $total_freed ),
                'details'     => $details,
            ],
            $duration_ms
        );

        return [
            'dry_run'        => $dry_run,
            'table_count'    => count( $valid_tables ),
            'total_freed'    => self::format_bytes( $total_freed ),
            'details'        => $details,
            'duration_ms'    => $duration_ms,
        ];
    }

    /**
     * 切换选项 autoload 状态 ('yes' <-> 'no')
     */
    public static function toggle_autoload( $option_name, $target_state = 'no' ) {
        global $wpdb;

        $option_name  = sanitize_text_field( (string) $option_name );
        $target_state = ( 'yes' === $target_state ) ? 'yes' : 'no';

        if ( '' === $option_name ) {
            return false;
        }

        $updated = $wpdb->update(
            $wpdb->options,
            [ 'autoload' => $target_state ],
            [ 'option_name' => $option_name ],
            [ '%s' ],
            [ '%s' ]
        );

        if ( false !== $updated ) {
            self::log_action(
                'toggle_autoload',
                $option_name,
                $updated,
                false,
                [ 'new_state' => $target_state ]
            );
            return true;
        }

        return false;
    }

    // =========================================================================
    // 3. 通用全量数据库安全替换 (含反序列化与 JSON 递归修正)
    // =========================================================================

    /**
     * 获取数据库可替换表列表及字段信息
     */
    /**
     * 获取支持替换的 WordPress 核心数据表范围（严格限定 WP 核心标准表）
     */
    public static function get_replaceable_tables() {
        global $wpdb;

        $core_defs = [
            'options' => [
                'table'   => $wpdb->options,
                'label'   => '站点设置与配置 (wp_options)',
                'desc'    => '包含 siteurl、home、主题与核心选项值',
                'default' => true,
            ],
            'posts' => [
                'table'   => $wpdb->posts,
                'label'   => '文章、页面与附件 (wp_posts)',
                'desc'    => '包含 post_content 正文、post_excerpt 摘要、guid 附件地址',
                'default' => true,
            ],
            'postmeta' => [
                'table'   => $wpdb->postmeta,
                'label'   => '文章与媒体元数据 (wp_postmeta)',
                'desc'    => '包含媒体图片路径 _wp_attached_file、序列化元数据、自定义字段',
                'default' => true,
            ],
            'comments' => [
                'table'   => $wpdb->comments,
                'label'   => '评论内容与作者网址 (wp_comments)',
                'desc'    => '包含评论内容 comment_content 与访客网址 comment_author_url',
                'default' => true,
            ],
            'commentmeta' => [
                'table'   => isset( $wpdb->commentmeta ) ? $wpdb->commentmeta : $wpdb->prefix . 'commentmeta',
                'label'   => '评论元数据 (wp_commentmeta)',
                'desc'    => '包含评论扩展属性 meta_value',
                'default' => false,
            ],
            'users' => [
                'table'   => $wpdb->users,
                'label'   => '用户账号网址 (wp_users)',
                'desc'    => '包含用户主页 user_url',
                'default' => false,
            ],
            'usermeta' => [
                'table'   => $wpdb->usermeta,
                'label'   => '用户元数据 (wp_usermeta)',
                'desc'    => '包含用户个人资料与偏好 meta_value',
                'default' => true,
            ],
            'terms' => [
                'table'   => $wpdb->terms,
                'label'   => '分类与标签名称 (wp_terms)',
                'desc'    => '包含分类名称 name 与别名 slug',
                'default' => false,
            ],
            'termmeta' => [
                'table'   => isset( $wpdb->termmeta ) ? $wpdb->termmeta : $wpdb->prefix . 'termmeta',
                'label'   => '分类标签元数据 (wp_termmeta)',
                'desc'    => '包含分类封面及扩展属性 meta_value',
                'default' => true,
            ],
        ];

        $items = [];
        foreach ( $core_defs as $key => $def ) {
            $table_name = $def['table'];
            $exists     = $wpdb->get_var( $wpdb->prepare( 'SHOW TABLES LIKE %s', $wpdb->esc_like( $table_name ) ) );
            if ( $exists === $table_name ) {
                $items[] = [
                    'key'     => $key,
                    'table'   => $table_name,
                    'label'   => $def['label'],
                    'desc'    => $def['desc'],
                    'default' => $def['default'],
                    'is_core' => true,
                ];
            }
        }

        return $items;
    }

    /**
     * 获取单表的主键字段和文本列
     */
    public static function get_table_schema_info( $table_name ) {
        global $wpdb;

        $esc_table = self::esc_identifier( $table_name );
        $columns   = $wpdb->get_results( "SHOW COLUMNS FROM {$esc_table}", ARRAY_A );

        if ( empty( $columns ) || ! is_array( $columns ) ) {
            return null;
        }

        $primary_key = '';
        $text_cols   = [];

        foreach ( $columns as $col ) {
            $field = isset( $col['Field'] ) ? $col['Field'] : '';
            $key   = isset( $col['Key'] ) ? $col['Key'] : '';
            $type  = isset( $col['Type'] ) ? strtolower( (string) $col['Type'] ) : '';

            if ( 'PRI' === $key && '' === $primary_key ) {
                $primary_key = $field;
            }

            // 仅对文本、字符、blob 类可能存有字符串的字段进行处理
            if ( preg_match( '/(char|text|blob|json)/i', $type ) ) {
                $text_cols[] = $field;
            }
        }

        return [
            'primary_key'  => $primary_key,
            'text_columns' => $text_cols,
        ];
    }

    /**
     * 单批次安全替换执行 (支持 Dry-Run 预演)
     */
    public static function search_replace_batch( $table_name, $search, $replace, $last_id = 0, $limit = 500, $dry_run = true ) {
        global $wpdb;

        $search  = (string) $search;
        $replace = (string) $replace;
        $last_id = absint( $last_id );
        $limit   = max( 10, min( 1000, absint( $limit ) ) );
        $dry_run = (bool) $dry_run;

        if ( '' === $search ) {
            return [ 'error' => '搜索关键字不能为空。' ];
        }

        $schema = self::get_table_schema_info( $table_name );
        if ( empty( $schema ) || empty( $schema['text_columns'] ) ) {
            return [
                'done'         => true,
                'scanned'      => 0,
                'updated'      => 0,
                'replacements' => 0,
                'next_id'      => $last_id,
            ];
        }

        $primary   = $schema['primary_key'];
        $columns   = $schema['text_columns'];
        $esc_table = self::esc_identifier( $table_name );

        // 构造带主键或 Offset 的分页查询
        if ( '' !== $primary ) {
            $esc_primary = self::esc_identifier( $primary );
            $cols_sql    = implode( ', ', array_map( [ __CLASS__, 'esc_identifier' ], array_merge( [ $primary ], $columns ) ) );
            $query       = $wpdb->prepare(
                "SELECT {$cols_sql} FROM {$esc_table} WHERE {$esc_primary} > %d ORDER BY {$esc_primary} ASC LIMIT %d",
                $last_id,
                $limit
            );
        } else {
            // 无主键表降级走 OFFSET
            $cols_sql = implode( ', ', array_map( [ __CLASS__, 'esc_identifier' ], $columns ) );
            $query    = $wpdb->prepare(
                "SELECT {$cols_sql} FROM {$esc_table} LIMIT %d OFFSET %d",
                $limit,
                $last_id
            );
        }

        $rows = $wpdb->get_results( $query, ARRAY_A );
        if ( ! is_array( $rows ) ) {
            $rows = [];
        }

        $scanned      = count( $rows );
        $updated_rows = 0;
        $replace_hits = 0;
        $max_id_seen  = $last_id;

        foreach ( $rows as $idx => $row ) {
            $row_id = ( '' !== $primary && isset( $row[ $primary ] ) ) ? (int) $row[ $primary ] : ( $last_id + $idx + 1 );
            if ( $row_id > $max_id_seen ) {
                $max_id_seen = $row_id;
            }

            $update_fields = [];
            $update_format = [];

            foreach ( $columns as $col ) {
                $val = isset( $row[ $col ] ) ? $row[ $col ] : '';
                if ( ! is_string( $val ) || '' === $val ) {
                    continue;
                }

                $changed       = false;
                $hits          = 0;
                $updated_value = self::safe_replace_value( $val, $search, $replace, $changed, $hits );

                if ( $changed ) {
                    $replace_hits           += $hits;
                    $update_fields[ $col ]   = $updated_value;
                    $update_format[]         = '%s';
                }
            }

            if ( ! empty( $update_fields ) ) {
                $updated_rows++;
                if ( ! $dry_run && '' !== $primary ) {
                    $wpdb->update(
                        $table_name,
                        $update_fields,
                        [ $primary => $row[ $primary ] ],
                        $update_format,
                        [ '%d' ]
                    );
                }
            }
        }

        $is_done = ( $scanned < $limit );

        return [
            'done'         => $is_done,
            'scanned'      => $scanned,
            'updated'      => $updated_rows,
            'replacements' => $replace_hits,
            'next_id'      => $max_id_seen,
        ];
    }

    /**
     * 智能数据清洗与递归替换 (支持 JSON / PHP 序列化 / 普通字符串)
     */
    public static function safe_replace_value( $value, $search, $replace, &$changed, &$hits ) {
        $changed = false;
        $hits    = 0;

        if ( ! is_string( $value ) || '' === $value ) {
            return $value;
        }

        // 1. 判断是否为 PHP 序列化字符串
        if ( function_exists( 'is_serialized' ) && is_serialized( $value ) ) {
            $unserialized = @unserialize( $value, [ 'allowed_classes' => false ] );
            if ( false !== $unserialized || 'b:0;' === $value ) {
                $new_data = self::recursive_replace( $unserialized, $search, $replace, $changed, $hits );
                if ( $changed ) {
                    return serialize( $new_data );
                }
                return $value;
            }
        }

        // 2. 判断是否为 JSON 字符串
        if ( ( 0 === strpos( $value, '{' ) || 0 === strpos( $value, '[' ) ) ) {
            $json = json_decode( $value, true );
            if ( json_last_error() === JSON_ERROR_NONE && ( is_array( $json ) || is_object( $json ) ) ) {
                $new_data = self::recursive_replace( $json, $search, $replace, $changed, $hits );
                if ( $changed ) {
                    return wp_json_encode( $new_data, JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES );
                }
                return $value;
            }
        }

        // 3. 普通文本直接替换
        if ( false !== strpos( $value, $search ) ) {
            $count   = 0;
            $new_val = str_replace( $search, $replace, $value, $count );
            if ( $count > 0 ) {
                $changed = true;
                $hits    = $count;
                return $new_val;
            }
        }

        return $value;
    }

    /**
     * 递归替换数组与对象
     */
    private static function recursive_replace( $data, $search, $replace, &$changed, &$hits ) {
        if ( is_array( $data ) ) {
            $result = [];
            foreach ( $data as $k => $v ) {
                $k_changed = false;
                $k_hits    = 0;
                $new_k     = is_string( $k ) ? self::safe_replace_value( $k, $search, $replace, $k_changed, $k_hits ) : $k;
                if ( $k_changed ) {
                    $changed = true;
                    $hits   += $k_hits;
                }

                $v_changed = false;
                $v_hits    = 0;
                $new_v     = self::recursive_replace( $v, $search, $replace, $v_changed, $v_hits );
                if ( $v_changed ) {
                    $changed = true;
                    $hits   += $v_hits;
                }

                $result[ $new_k ] = $new_v;
            }
            return $result;
        } elseif ( is_string( $data ) ) {
            if ( false !== strpos( $data, $search ) ) {
                $count   = 0;
                $new_str = str_replace( $search, $replace, $data, $count );
                if ( $count > 0 ) {
                    $changed = true;
                    $hits   += $count;
                    return $new_str;
                }
            }
            return $data;
        }

        return $data;
    }

    // =========================================================================
    // 4. AJAX 响应处理端点 (权限 + Nonce 全链路加固)
    // =========================================================================

    private static function verify_ajax_access() {
        check_ajax_referer( 'qs_ajax_nonce', 'nonce' );
        if ( ! current_user_can( 'manage_options' ) ) {
            wp_send_json_error( [ 'message' => '权限不足，拒绝访问。' ] );
        }
    }

    /**
     * 获取 Post Type 空间占用透视与膨胀诊断
     */
    public static function get_post_type_distribution() {
        global $wpdb;

        $results = $wpdb->get_results(
            "SELECT post_type, post_status, COUNT(*) as cnt
             FROM {$wpdb->posts}
             GROUP BY post_type, post_status
             ORDER BY cnt DESC",
            ARRAY_A
        );

        $total_posts = 0;
        $by_type     = [];

        $type_labels = [
            'post'                => '标准文章',
            'page'                => '静态页面',
            'attachment'          => '媒体附件',
            'revision'            => '历史修订版本',
            'nav_menu_item'       => '导航菜单项',
            'custom_css'          => '自定义 CSS',
            'customize_changeset' => '自定义器草稿',
            'oembed_cache'        => '内嵌缓存',
            'user_request'        => '隐私申请',
            'wp_block'            => '同步区块 / 模板',
            'wp_template'         => '全站模板',
            'wp_template_part'    => '模板部件',
            'wp_global_styles'    => '全局样式',
            'wp_navigation'       => '导航区块',
            'shop_order'          => '商城订单',
            'shop_order_refund'   => '订单退款',
            'shop_coupon'         => '优惠券',
            'product'             => '商品',
            'product_variation'   => '商品规格',
            'qiling_shop_order'   => '启灵商城订单',
        ];

        if ( ! empty( $results ) ) {
            foreach ( $results as $row ) {
                $type   = (string) $row['post_type'];
                $status = (string) $row['post_status'];
                $count  = (int) $row['cnt'];

                $total_posts += $count;

                if ( ! isset( $by_type[ $type ] ) ) {
                    $by_type[ $type ] = [
                        'type'     => $type,
                        'label'    => isset( $type_labels[ $type ] ) ? $type_labels[ $type ] : $type,
                        'count'    => 0,
                        'statuses' => [],
                    ];
                }

                $by_type[ $type ]['count'] += $count;
                $by_type[ $type ]['statuses'][ $status ] = $count;
            }
        }

        $items = array_values( $by_type );
        usort( $items, function( $a, $b ) {
            return $b['count'] - $a['count'];
        } );

        $suggestions = [];
        foreach ( $items as &$item ) {
            $item['pct'] = $total_posts > 0 ? round( ( $item['count'] / $total_posts ) * 100, 1 ) : 0;
            if ( 'revision' === $item['type'] && $item['pct'] > 25 ) {
                $suggestions[] = sprintf( '历史修订版本（revision）占比高达 %s%%（%s 条），严重拖慢 post 表查询速度，建议使用「一键优化与垃圾清理」释放空间！', $item['pct'], number_format_i18n( $item['count'] ) );
            }
            if ( isset( $item['statuses']['auto-draft'] ) && $item['statuses']['auto-draft'] > 50 ) {
                $suggestions[] = sprintf( '检测到 %s 条自动草稿（auto-draft）残留，建议使用工具箱定期清理。', number_format_i18n( $item['statuses']['auto-draft'] ) );
            }
        }
        unset( $item );

        return [
            'total_posts' => $total_posts,
            'items'       => $items,
            'suggestions' => $suggestions,
        ];
    }

    /**
     * 定义高性能核心复合索引列表
     */
    public static function get_index_definitions() {
        global $wpdb;

        return [
            'idx_postmeta' => [
                'name'        => 'qs_idx_postmeta_key_val',
                'table'       => $wpdb->postmeta,
                'table_key'   => 'postmeta',
                'title'       => 'Postmeta 键值联合索引',
                'columns'     => '(meta_key(191), meta_value(100))',
                'description' => '加速按自定义字段（meta_query）组合筛选与比较查询，消除多属性关联时的全表扫描。',
                'benefit'     => '自定义字段筛选查询提速 5~30 倍',
            ],
            'idx_options'  => [
                'name'        => 'qs_idx_options_autoload',
                'table'       => $wpdb->options,
                'table_key'   => 'options',
                'title'       => 'Options 自动加载复合索引',
                'columns'     => '(autoload, option_name(191))',
                'description' => '加速每次页面加载最先执行的全局配置读取（WHERE autoload = "yes"），有效降低 TTFB 延迟。',
                'benefit'     => '全局配置加载提速 3~10 倍',
            ],
            'idx_posts'    => [
                'name'        => 'qs_idx_posts_type_status_date',
                'table'       => $wpdb->posts,
                'table_key'   => 'posts',
                'title'       => 'Posts 类型/状态/日期覆盖索引',
                'columns'     => '(post_type, post_status, post_date, ID)',
                'description' => '高频文章列表（按发布时间倒序）直接命中复合覆盖索引，避免大表 filesort 排序瓶颈。',
                'benefit'     => '文章列表排序与翻页提速 3~10 倍',
            ],
        ];
    }

    /**
     * 检查数据表索引是否存在
     */
    public static function check_index_exists( $table_name, $index_name ) {
        global $wpdb;
        $table_name = sanitize_key( $table_name );
        $indexes    = $wpdb->get_results( "SHOW INDEX FROM `{$table_name}` WHERE Key_name = '{$index_name}'", ARRAY_A );
        return ! empty( $indexes );
    }

    /**
     * 获取全部复合索引当前状态
     */
    public static function get_index_status() {
        global $wpdb;
        $definitions = self::get_index_definitions();
        $status_list = [];

        foreach ( $definitions as $key => $def ) {
            $exists    = self::check_index_exists( $def['table'], $def['name'] );
            $row_count = (int) $wpdb->get_var( "SELECT COUNT(*) FROM `{$def['table']}`" );

            $status_list[ $key ] = array_merge( $def, [
                'exists'    => $exists,
                'row_count' => $row_count,
            ] );
        }

        return $status_list;
    }

    /**
     * 切换（添加或移除）指定复合索引
     */
    public static function toggle_index( $index_key, $action = 'add' ) {
        global $wpdb;

        $definitions = self::get_index_definitions();
        if ( ! isset( $definitions[ $index_key ] ) ) {
            return new WP_Error( 'invalid_index', '未知的索引定义标识。' );
        }

        $def        = $definitions[ $index_key ];
        $table_name = $def['table'];
        $index_name = $def['name'];
        $columns    = $def['columns'];
        $start_time = microtime( true );

        $exists = self::check_index_exists( $table_name, $index_name );

        if ( 'add' === $action ) {
            if ( $exists ) {
                return [ 'message' => "索引 {$index_name} 已存在，无需重复创建。", 'exists' => true ];
            }

            $row_count = (int) $wpdb->get_var( "SELECT COUNT(*) FROM `{$table_name}`" );
            $sql       = "ALTER TABLE `{$table_name}` ADD INDEX `{$index_name}` {$columns}";
            $result    = $wpdb->query( $sql );

            if ( false === $result ) {
                return new WP_Error( 'sql_error', '创建索引失败: ' . $wpdb->last_error );
            }

            $duration_ms = (int) round( ( microtime( true ) - $start_time ) * 1000 );
            self::log_action(
                'index_add',
                "{$table_name}.{$index_name}",
                $row_count,
                false,
                [ 'sql' => $sql, 'duration' => "{$duration_ms}ms" ],
                $duration_ms
            );

            return [
                'message'     => "索引 {$index_name} 创建成功，已正式生效！",
                'exists'      => true,
                'duration_ms' => $duration_ms,
            ];
        } elseif ( 'drop' === $action ) {
            if ( ! $exists ) {
                return [ 'message' => "索引 {$index_name} 不存在，无需移除。", 'exists' => false ];
            }

            $sql    = "ALTER TABLE `{$table_name}` DROP INDEX `{$index_name}`";
            $result = $wpdb->query( $sql );

            if ( false === $result ) {
                return new WP_Error( 'sql_error', '移除索引失败: ' . $wpdb->last_error );
            }

            $duration_ms = (int) round( ( microtime( true ) - $start_time ) * 1000 );
            self::log_action(
                'index_drop',
                "{$table_name}.{$index_name}",
                0,
                false,
                [ 'sql' => $sql, 'duration' => "{$duration_ms}ms" ],
                $duration_ms
            );

            return [
                'message'     => "索引 {$index_name} 已安全移除，已恢复出厂默认状态。",
                'exists'      => false,
                'duration_ms' => $duration_ms,
            ];
        }

        return new WP_Error( 'invalid_action', '非法的操作类型。' );
    }

    public static function ajax_get_index_status() {
        self::verify_ajax_access();
        wp_send_json_success( [
            'indexes' => self::get_index_status(),
        ] );
    }

    public static function ajax_toggle_index() {
        self::verify_ajax_access();

        $index_key = isset( $_POST['index_key'] ) ? sanitize_key( wp_unslash( $_POST['index_key'] ) ) : '';
        $action    = isset( $_POST['index_action'] ) ? sanitize_key( wp_unslash( $_POST['index_action'] ) ) : 'add';

        if ( 'all' === $index_key ) {
            $definitions = self::get_index_definitions();
            $results     = [];
            $errors      = [];

            foreach ( array_keys( $definitions ) as $key ) {
                $res = self::toggle_index( $key, $action );
                if ( is_wp_error( $res ) ) {
                    $errors[] = $res->get_error_message();
                } else {
                    $results[ $key ] = $res;
                }
            }

            if ( ! empty( $errors ) ) {
                wp_send_json_error( [ 'message' => implode( '; ', $errors ), 'results' => $results ] );
            }

            wp_send_json_success( [
                'message' => 'add' === $action ? '所有核心优化复合索引已全部创建生效！' : '所有优化复合索引已全部安全移除，恢复出厂默认。',
                'indexes' => self::get_index_status(),
            ] );
        }

        $res = self::toggle_index( $index_key, $action );
        if ( is_wp_error( $res ) ) {
            wp_send_json_error( [ 'message' => $res->get_error_message() ] );
        }

        wp_send_json_success( [
            'message' => $res['message'],
            'indexes' => self::get_index_status(),
        ] );
    }

    public static function ajax_analyze() {
        self::verify_ajax_access();

        $overview   = self::get_database_overview();
        $autoload   = self::get_autoload_analysis();
        $cleanable  = self::get_cleanable_stats();
        $post_types = self::get_post_type_distribution();

        wp_send_json_success( [
            'overview'   => $overview,
            'autoload'   => $autoload,
            'cleanable'  => $cleanable,
            'post_types' => $post_types,
        ] );
    }

    public static function ajax_cleanup() {
        self::verify_ajax_access();

        $targets        = isset( $_POST['targets'] ) ? (array) wp_unslash( $_POST['targets'] ) : [];
        $keep_revisions = isset( $_POST['keep_revisions'] ) ? absint( $_POST['keep_revisions'] ) : 0;
        $dry_run        = ! empty( $_POST['dry_run'] ) && '0' !== (string) wp_unslash( $_POST['dry_run'] );

        $targets = array_map( 'sanitize_key', $targets );
        $targets = array_filter( $targets );

        if ( empty( $targets ) ) {
            wp_send_json_error( [ 'message' => '请至少勾选一项需要清理的垃圾类型。' ] );
        }

        $res = self::execute_cleanup( $targets, $keep_revisions, $dry_run );
        wp_send_json_success( $res );
    }

    public static function ajax_optimize_tables() {
        self::verify_ajax_access();

        $tables  = isset( $_POST['tables'] ) ? (array) wp_unslash( $_POST['tables'] ) : [];
        $dry_run = ! empty( $_POST['dry_run'] ) && '0' !== (string) wp_unslash( $_POST['dry_run'] );

        $tables = array_map( 'sanitize_text_field', $tables );
        $tables = array_filter( $tables );

        $res = self::execute_optimize_tables( $tables, $dry_run );
        wp_send_json_success( $res );
    }

    public static function ajax_toggle_autoload() {
        self::verify_ajax_access();

        $option_name  = isset( $_POST['option_name'] ) ? sanitize_text_field( wp_unslash( $_POST['option_name'] ) ) : '';
        $target_state = isset( $_POST['target_state'] ) ? sanitize_key( wp_unslash( $_POST['target_state'] ) ) : 'no';

        if ( '' === $option_name ) {
            wp_send_json_error( [ 'message' => '选项名称不能为空。' ] );
        }

        $ok = self::toggle_autoload( $option_name, $target_state );
        if ( $ok ) {
            wp_send_json_success( [ 'message' => sprintf( '选项 [%s] 的 autoload 状态已更新为 [%s]。', $option_name, $target_state ) ] );
        } else {
            wp_send_json_error( [ 'message' => '更新失败，可能该选项值未发生变更或数据库写入受阻。' ] );
        }
    }

    public static function ajax_search_replace_batch() {
        self::verify_ajax_access();

        $table_name = isset( $_POST['table_name'] ) ? sanitize_text_field( wp_unslash( $_POST['table_name'] ) ) : '';
        $search     = isset( $_POST['search'] ) ? (string) wp_unslash( $_POST['search'] ) : '';
        $replace    = isset( $_POST['replace'] ) ? (string) wp_unslash( $_POST['replace'] ) : '';
        $last_id    = isset( $_POST['last_id'] ) ? absint( $_POST['last_id'] ) : 0;
        $limit      = isset( $_POST['limit'] ) ? absint( $_POST['limit'] ) : 500;
        $dry_run    = ! empty( $_POST['dry_run'] ) && '0' !== (string) wp_unslash( $_POST['dry_run'] );

        if ( '' === $table_name || '' === $search ) {
            wp_send_json_error( [ 'message' => '目标表名与搜索内容不能为空。' ] );
        }

        $res = self::search_replace_batch( $table_name, $search, $replace, $last_id, $limit, $dry_run );

        if ( isset( $res['error'] ) ) {
            wp_send_json_error( [ 'message' => $res['error'] ] );
        }

        // 若当前表已全部跑完，记录一次统计日志
        if ( ! empty( $res['done'] ) && ( $res['updated'] > 0 || $res['replacements'] > 0 ) ) {
            self::log_action(
                'search_replace',
                $table_name,
                $res['updated'],
                $dry_run,
                [
                    'search'       => $search,
                    'replace'      => $replace,
                    'replacements' => $res['replacements'],
                ]
            );
        }

        wp_send_json_success( $res );
    }

    public static function ajax_get_logs() {
        self::verify_ajax_access();
        global $wpdb;

        $table_name = self::get_log_table_name();
        $logs       = $wpdb->get_results( "SELECT * FROM {$table_name} ORDER BY id DESC LIMIT 50", ARRAY_A );

        if ( ! is_array( $logs ) ) {
            $logs = [];
        }

        wp_send_json_success( [ 'logs' => $logs ] );
    }

    public static function ajax_clear_logs() {
        self::verify_ajax_access();
        global $wpdb;

        $table_name = self::get_log_table_name();
        $wpdb->query( "TRUNCATE TABLE {$table_name}" );

        wp_send_json_success( [ 'message' => '运维日志已成功清空。' ] );
    }

    // =========================================================================
    // 5. 后台 UI 渲染
    // =========================================================================

    /**
     * 渲染完整独立的数据库管理控制面板
     */
    public static function render_panel() {
        $replaceable_tables = self::get_replaceable_tables();
        ?>
        <div class="qs-panel qs-db-toolkit-wrap">
            <style>
                .qs-subtab-nav {
                    display: flex;
                    flex-wrap: wrap;
                    gap: 8px;
                    border-bottom: 1px solid #e2e8f0;
                    padding-bottom: 14px;
                    margin-bottom: 22px;
                }
                .qs-subtab-btn {
                    height: 32px !important;
                    line-height: 30px !important;
                    padding: 0 16px !important;
                    font-size: 13px !important;
                    font-weight: 500 !important;
                    border-radius: 4px !important;
                    cursor: pointer;
                    text-align: center;
                }
            </style>
            <h2>
                <span class="dashicons dashicons-database" style="vertical-align:middle; margin-right:4px;"></span> 数据库优化与管理工具箱
            </h2>

            <div class="qs-inline-notice" style="margin-bottom: 20px;">
                <span class="dashicons dashicons-info" style="vertical-align: middle; margin-right: 4px;"></span>
                <strong>安全声明：</strong>本工具箱完全独立于核心防护引擎。数据库的直接写入与清理属于<strong>高危操作</strong>，在执行任何正式优化或全量替换前，<strong>请务必先通过主机控制面板或备份插件做好数据库完整备份！</strong>建议优先使用「预演模式（Dry-Run）」预览受影响条目。
            </div>

            <!-- 子模块导航栏 -->
            <div class="qs-subtab-nav">
                <button type="button" class="button button-primary qs-subtab-btn" data-target="analytics">数据库体检与分析</button>
                <button type="button" class="button button-secondary qs-subtab-btn" data-target="cleanup">一键优化与垃圾清理</button>
                <button type="button" class="button button-secondary qs-subtab-btn" data-target="indexes">高性能复合索引</button>
                <button type="button" class="button button-secondary qs-subtab-btn" data-target="replace">通用安全替换</button>
                <button type="button" class="button button-secondary qs-subtab-btn" data-target="logs">运维操作日志</button>
            </div>

            <!-- ===================== 子面板 1: 数据库体检与分析 ===================== -->
            <div class="qs-subtab-content" id="qs-subtab-analytics">
                <div class="qs-toolbar-row">
                    <div class="qs-toolbar-meta">
                        点击「开始全库分析」扫描所有数据表体积、碎片及 Autoload 负载。
                    </div>
                    <div class="qs-toolbar-actions">
                        <button type="button" class="button button-primary" id="qs-btn-run-analysis" style="height:32px; line-height:30px; padding:0 16px;">
                            开始全库深度分析
                        </button>
                    </div>
                </div>

                <div id="qs-analytics-loading" style="display:none; text-align:center; padding:40px 0;">
                    <span class="dashicons dashicons-update qs-tab-lazy-icon is-loading" style="font-size:32px; width:32px; height:32px; color:#2563eb;"></span>
                    <p style="color:#64748b; font-size:14px; margin-top:10px;">正在深度扫描数据表结构、索引体积及 Autoload 项，请稍候...</p>
                </div>

                <div id="qs-analytics-result" style="display:none;">
                    <!-- 顶层汇总卡片 -->
                    <div style="display:grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap:15px; margin-bottom:20px;">
                        <div style="background:#f8fafc; border:1px solid #e2e8f0; border-radius:6px; padding:15px;">
                            <div style="color:#64748b; font-size:12px; margin-bottom:4px;">总数据表数量</div>
                            <div style="font-size:22px; font-weight:700; color:#1e293b;" id="qs-stat-table-count">0</div>
                            <div style="font-size:11px; color:#94a3b8; margin-top:4px;" id="qs-stat-table-split">WP核心: 0 / 扩展: 0</div>
                        </div>
                        <div style="background:#f8fafc; border:1px solid #e2e8f0; border-radius:6px; padding:15px;">
                            <div style="color:#64748b; font-size:12px; margin-bottom:4px;">总记录条数</div>
                            <div style="font-size:22px; font-weight:700; color:#1e293b;" id="qs-stat-row-count">0</div>
                            <div style="font-size:11px; color:#94a3b8; margin-top:4px;">全库物理记录行目</div>
                        </div>
                        <div style="background:#f8fafc; border:1px solid #e2e8f0; border-radius:6px; padding:15px;">
                            <div style="color:#64748b; font-size:12px; margin-bottom:4px;">全库物理占用体积</div>
                            <div style="font-size:22px; font-weight:700; color:#2563eb;" id="qs-stat-total-size">0 MB</div>
                            <div style="font-size:11px; color:#94a3b8; margin-top:4px;" id="qs-stat-size-split">数据: 0 / 索引: 0</div>
                        </div>
                        <div style="background:#f8fafc; border:1px solid #e2e8f0; border-radius:6px; padding:15px;">
                            <div style="color:#64748b; font-size:12px; margin-bottom:4px;">可回收碎片空间</div>
                            <div style="font-size:22px; font-weight:700; color:#e11d48;" id="qs-stat-free-size">0 MB</div>
                            <div style="font-size:11px; color:#94a3b8; margin-top:4px;">可通过表碎片优化清理</div>
                        </div>
                    </div>

                    <!-- Autoload 诊断卡片 -->
                    <div style="background:#fff; border:1px solid #e2e8f0; border-radius:6px; padding:18px; margin-bottom:25px; box-shadow:0 1px 2px rgba(0,0,0,0.03);">
                        <div style="display:flex; justify-content:space-between; align-items:center; margin-bottom:12px;">
                            <h3 style="margin:0; font-size:15px; color:#1e293b; display:flex; align-items:center; gap:6px;">
                                <span class="dashicons dashicons-performance" style="color:#f59e0b;"></span> Autoload 性能核心体检 (wp_options)
                            </h3>
                            <span id="qs-autoload-badge" class="qs-badge" style="padding:4px 10px; border-radius:12px; font-size:12px; font-weight:600;"></span>
                        </div>
                        <p id="qs-autoload-tip" style="font-size:13px; margin:0 0 15px 0; color:#475569; line-height:1.6;"></p>
                        
                        <div style="font-size:13px; color:#334155; margin-bottom:10px;">
                            <strong>TOP 20 占用最大的自动加载选项：</strong>
                        </div>
                        <div style="max-height:260px; overflow-y:auto; border:1px solid #f1f5f9; border-radius:4px;">
                            <table class="widefat striped" style="border:none;">
                                <thead>
                                    <tr>
                                        <th style="width:50%;">Option 名称</th>
                                        <th style="width:25%;">占用大小</th>
                                        <th style="width:25%; text-align:right;">操作</th>
                                    </tr>
                                </thead>
                                <tbody id="qs-autoload-table-body"></tbody>
                            </table>
                        </div>
                    </div>

                    <!-- Post 空间透视分析（wp_posts 膨胀诊断） -->
                    <div style="background:#fff; border:1px solid #e2e8f0; border-radius:6px; padding:18px; margin-bottom:20px;">
                        <div style="display:flex; justify-content:space-between; align-items:center; margin-bottom:12px; flex-wrap:wrap; gap:10px;">
                            <h3 style="margin:0; font-size:15px; color:#1e293b;">
                                Post 空间透视分析（wp_posts 膨胀诊断）
                            </h3>
                            <span id="qs-post-type-total-badge" style="background:#f1f5f9; color:#475569; padding:4px 10px; border-radius:12px; font-size:12px; font-weight:600;"></span>
                        </div>

                        <div id="qs-post-type-alerts" style="display:none; margin-bottom:14px;"></div>

                        <div style="max-height:360px; overflow-y:auto; border:1px solid #f1f5f9; border-radius:4px;">
                            <table class="widefat striped" style="border:none;">
                                <thead>
                                    <tr>
                                        <th style="width:200px;">Post 类型</th>
                                        <th style="width:100px;">记录数</th>
                                        <th style="width:240px;">占全表比例</th>
                                        <th>状态分布明细</th>
                                        <th style="width:140px; text-align:right;">健康建议</th>
                                    </tr>
                                </thead>
                                <tbody id="qs-post-types-table-body"></tbody>
                            </table>
                        </div>
                    </div>

                    <!-- 数据表详细清单 -->
                    <div style="background:#fff; border:1px solid #e2e8f0; border-radius:6px; padding:18px;">
                        <h3 style="margin:0 0 12px 0; font-size:15px; color:#1e293b;">全库数据表体积与碎片分布</h3>
                        <div style="max-height:400px; overflow-y:auto; border:1px solid #f1f5f9; border-radius:4px;">
                            <table class="widefat striped" style="border:none;">
                                <thead>
                                    <tr>
                                        <th>数据表名称</th>
                                        <th>存储引擎</th>
                                        <th>行数</th>
                                        <th>数据体积</th>
                                        <th>索引体积</th>
                                        <th>碎片空间</th>
                                        <th>总占用</th>
                                    </tr>
                                </thead>
                                <tbody id="qs-tables-list-body"></tbody>
                            </table>
                        </div>
                    </div>
                </div>
            </div>

            <!-- ===================== 子面板 2: 数据库一键清理与优化 ===================== -->
            <div class="qs-subtab-content" id="qs-subtab-cleanup" style="display:none;">
                <div class="qs-inline-notice" style="background:#f8fafc; border-left-color:#64748b; color:#334155; margin-bottom:20px;">
                    定期清理废弃的修订版本、临时草稿与过期缓存，能够显著减小数据库物理体积，加快索引查询速度。
                </div>

                <div style="display:grid; grid-template-columns: 1.2fr 1fr; gap:20px;">
                    <!-- 左列：垃圾清理选项 -->
                    <div style="background:#fff; border:1px solid #e2e8f0; border-radius:6px; padding:20px;">
                        <h3 style="margin-top:0; font-size:16px; border-bottom:1px solid #f1f5f9; padding-bottom:10px;">
                            <span class="dashicons dashicons-trash"></span> 垃圾数据清理项
                        </h3>

                        <div style="margin-bottom:15px;">
                            <label style="display:flex; align-items:flex-start; gap:8px; margin-bottom:12px; cursor:pointer;">
                                <input type="checkbox" class="qs-cleanup-cb" value="revisions" checked>
                                <div>
                                    <strong style="color:#1e293b;">文章历史修订版本 (Post Revisions)</strong>
                                    <div style="font-size:12px; color:#64748b;">每次保存文章时 WordPress 产生的历史快照。</div>
                                    <div style="margin-top:4px; font-size:12px; color:#475569;">
                                        保留策略：每个 Post 保留最近 
                                        <input type="number" id="qs-cleanup-keep-revisions" value="3" min="0" max="50" style="width:55px; height:26px; padding:2px 6px;"> 
                                        个版本（填 0 为全清）
                                    </div>
                                </div>
                            </label>

                            <label style="display:flex; align-items:flex-start; gap:8px; margin-bottom:12px; cursor:pointer;">
                                <input type="checkbox" class="qs-cleanup-cb" value="auto_drafts" checked>
                                <div>
                                    <strong style="color:#1e293b;">自动草稿 (Auto Drafts)</strong>
                                    <div style="font-size:12px; color:#64748b;">新建文章未保存时产生的空草稿条目。</div>
                                </div>
                            </label>

                            <label style="display:flex; align-items:flex-start; gap:8px; margin-bottom:12px; cursor:pointer;">
                                <input type="checkbox" class="qs-cleanup-cb" value="trashed_posts" checked>
                                <div>
                                    <strong style="color:#1e293b;">回收站文章与页面 (Trash Posts)</strong>
                                    <div style="font-size:12px; color:#64748b;">已移入回收站但未永久删除的文章内容。</div>
                                </div>
                            </label>

                            <label style="display:flex; align-items:flex-start; gap:8px; margin-bottom:12px; cursor:pointer;">
                                <input type="checkbox" class="qs-cleanup-cb" value="spam_comments" checked>
                                <div>
                                    <strong style="color:#1e293b;">垃圾评论 (Spam Comments)</strong>
                                    <div style="font-size:12px; color:#64748b;">被系统标记为垃圾评论的内容。</div>
                                </div>
                            </label>

                            <label style="display:flex; align-items:flex-start; gap:8px; margin-bottom:12px; cursor:pointer;">
                                <input type="checkbox" class="qs-cleanup-cb" value="trashed_comments" checked>
                                <div>
                                    <strong style="color:#1e293b;">回收站评论 (Trash Comments)</strong>
                                    <div style="font-size:12px; color:#64748b;">已删除在回收站中积压的评论。</div>
                                </div>
                            </label>

                            <label style="display:flex; align-items:flex-start; gap:8px; margin-bottom:12px; cursor:pointer;">
                                <input type="checkbox" class="qs-cleanup-cb" value="expired_transients" checked>
                                <div>
                                    <strong style="color:#1e293b;">过期 Transients 缓存 (wp_options)</strong>
                                    <div style="font-size:12px; color:#64748b;">已过期的瞬态临时缓存键值与超时标记。</div>
                                </div>
                            </label>

                            <label style="display:flex; align-items:flex-start; gap:8px; margin-bottom:12px; cursor:pointer;">
                                <input type="checkbox" class="qs-cleanup-cb" value="orphan_postmeta" checked>
                                <div>
                                    <strong style="color:#1e293b;">孤立文章元数据 (Orphan Postmeta)</strong>
                                    <div style="font-size:12px; color:#64748b;">对应文章已被物理删除，但残留未删的 postmeta。</div>
                                </div>
                            </label>

                            <label style="display:flex; align-items:flex-start; gap:8px; margin-bottom:12px; cursor:pointer;">
                                <input type="checkbox" class="qs-cleanup-cb" value="orphan_termmeta">
                                <div>
                                    <strong style="color:#1e293b;">孤立分类标签元数据 (Orphan Termmeta)</strong>
                                    <div style="font-size:12px; color:#64748b;">对应分类/标签已删除后残留的元数据。</div>
                                </div>
                            </label>

                            <label style="display:flex; align-items:flex-start; gap:8px; margin-bottom:12px; cursor:pointer;">
                                <input type="checkbox" class="qs-cleanup-cb" value="orphan_usermeta">
                                <div>
                                    <strong style="color:#1e293b;">孤立用户元数据 (Orphan Usermeta)</strong>
                                    <div style="font-size:12px; color:#64748b;">对应用户已删除后残留的元数据。</div>
                                </div>
                            </label>
                        </div>

                        <div style="padding-top:15px; border-top:1px solid #f1f5f9; display:flex; gap:10px; align-items:center;">
                            <button type="button" class="button button-secondary" id="qs-btn-cleanup-dryrun" style="height:32px; line-height:30px; padding:0 16px;">
                                仅预演测试 (Dry-Run)
                            </button>
                            <button type="button" class="button button-primary" id="qs-btn-cleanup-run" style="background:#dc2626; border-color:#b91c1c; height:32px; line-height:30px; padding:0 16px;">
                                立即执行清理
                            </button>
                        </div>
                    </div>

                    <!-- 右列：数据表碎片整理优化 -->
                    <div style="background:#fff; border:1px solid #e2e8f0; border-radius:6px; padding:20px; height:fit-content;">
                        <h3 style="margin-top:0; font-size:16px; border-bottom:1px solid #f1f5f9; padding-bottom:10px;">
                            数据表碎片整理 (OPTIMIZE)
                        </h3>
                        <p style="font-size:13px; color:#475569; line-height:1.6;">
                            频繁进行文章增删、更新评论和写入缓存后，InnoDB / MyISAM 数据表内部会产生空间空洞（碎片）。对表执行 <code>OPTIMIZE TABLE</code> 可回收碎片磁盘空间并重建表索引。
                        </p>

                        <div style="margin:20px 0;">
                            <button type="button" class="button button-primary" id="qs-btn-run-table-optimize" style="height:32px; line-height:30px; padding:0 16px;">
                                一键优化全库有碎片的数据表
                            </button>
                        </div>

                        <div id="qs-cleanup-log-box" style="display:none; margin-top:20px; background:#f8fafc; border:1px solid #e2e8f0; border-radius:4px; padding:12px; font-size:13px;">
                            <strong>执行结果：</strong>
                            <div id="qs-cleanup-log-msg" style="margin-top:6px; color:#334155; line-height:1.6;"></div>
                        </div>
                    </div>
                </div>
            </div>

            <!-- ===================== 子面板 3: 高性能复合索引 ===================== -->
            <div class="qs-subtab-content" id="qs-subtab-indexes" style="display:none;">
                <div class="qs-toolbar-row" style="margin-bottom:18px;">
                    <div class="qs-toolbar-meta">
                        为 WordPress 核心高频数据表建立定制复合索引，解决自定义字段过滤、全局配置载入与文章排序全表扫描痛点。
                    </div>
                    <div class="qs-toolbar-actions">
                        <button type="button" class="button button-primary" id="qs-btn-apply-all-indexes" style="height:32px; line-height:30px; padding:0 16px;">
                            一键启用全部加速索引
                        </button>
                        <button type="button" class="button button-secondary" id="qs-btn-drop-all-indexes" style="height:32px; line-height:30px; padding:0 16px;">
                            一键移除恢复出厂
                        </button>
                    </div>
                </div>

                <div class="qs-inline-notice" style="background:#f0fdf4; border-left-color:#22c55e; color:#15803d; margin-bottom:20px;">
                    <strong>安全保障声明：</strong>
                    本加速索引均使用独立专属前缀（<code>qs_idx_*</code>），与 WordPress 核心升级机制（<code>dbDelta</code>）互不冲突。在现代 MySQL/MariaDB InnoDB 引擎上支持在线无锁构建（Online DDL），不锁表、不影响站点正常访问，且 <strong>100% 支持随时一键移除并还原默认</strong>。
                </div>

                <div id="qs-indexes-loading" style="display:none; text-align:center; padding:30px 0;">
                    <span class="dashicons dashicons-update qs-tab-lazy-icon is-loading" style="font-size:28px; width:28px; height:28px; color:#2563eb;"></span>
                    <p style="color:#64748b; font-size:13px; margin-top:8px;">正在读取数据表索引现状与行数统计...</p>
                </div>

                <div id="qs-indexes-table-box" style="background:#fff; border:1px solid #e2e8f0; border-radius:6px; padding:18px;">
                    <table class="widefat fixed striped" style="border:none;">
                        <thead>
                            <tr>
                                <th style="width:230px;">优化索引名称 / 目标表</th>
                                <th style="width:230px;">索引结构与字段</th>
                                <th>解决的痛点与加速场景</th>
                                <th style="width:110px;">当前状态</th>
                                <th style="width:130px; text-align:right;">操作</th>
                            </tr>
                        </thead>
                        <tbody id="qs-indexes-table-body">
                            <!-- 由 JS 动态渲染 -->
                        </tbody>
                    </table>
                </div>

                <div id="qs-index-action-feedback" style="margin-top:14px; font-weight:600; display:none;"></div>
            </div>

            <!-- ===================== 子面板 4: 通用全量安全替换 ===================== -->
            <div class="qs-subtab-content" id="qs-subtab-replace" style="display:none;">
                <div class="qs-inline-notice" style="margin-bottom:20px;">
                    <span class="dashicons dashicons-shield"></span>
                    <strong>深度安全保障：</strong>本功能支持在任意选定数据表中搜索替换文本或网址。核心算法<strong>递归解析并正确修正 PHP 序列化字符串长度与 JSON 结构</strong>，杜绝因单纯字符串替换破坏序列化结构导致网站白屏的事故！
                </div>

                <div style="background:#fff; border:1px solid #e2e8f0; border-radius:6px; padding:20px; max-width:850px;">
                    <table class="form-table" role="presentation">
                        <tr>
                            <th scope="row"><label for="qs-rep-search">搜索目标字符串 / 原域名</label></th>
                            <td>
                                <input type="text" id="qs-rep-search" class="regular-text" style="width:100%;" placeholder="例如：http://old-domain.com 或 旧关键词">
                                <div style="margin-top:6px;">
                                    <button type="button" class="button button-small" id="qs-btn-fill-home-url">
                                        自动填入当前站点地址 (<code><?php echo esc_html( home_url() ); ?></code>)
                                    </button>
                                </div>
                                <p class="description">区分大小写。将精确匹配并替换该字符串或域名。</p>
                            </td>
                        </tr>
                        <tr>
                            <th scope="row"><label for="qs-rep-replace">替换为新字符串 / 新域名</label></th>
                            <td>
                                <input type="text" id="qs-rep-replace" class="regular-text" style="width:100%;" placeholder="例如：https://new-domain.com 或 新关键词">
                                <p class="description">支持替换为新域名或新文本，留空表示将其剔除/清空。</p>
                            </td>
                        </tr>
                        <tr>
                            <th scope="row">目标数据表范围 (WordPress 核心)</th>
                            <td>
                                <div style="margin-bottom:10px;">
                                    <button type="button" class="button button-small" id="qs-btn-select-all-tables">全选核心表</button>
                                    <button type="button" class="button button-small" id="qs-btn-select-default-tables">恢复推荐默认</button>
                                    <button type="button" class="button button-small" id="qs-btn-unselect-tables">全部取消</button>
                                </div>
                                <div style="max-height:240px; overflow-y:auto; border:1px solid #cbd5e1; border-radius:4px; padding:10px 14px; background:#f8fafc;">
                                    <?php foreach ( $replaceable_tables as $tb ) : ?>
                                        <label style="display:flex; align-items:flex-start; gap:8px; margin-bottom:10px; cursor:pointer;" data-default="<?php echo $tb['default'] ? '1' : '0'; ?>">
                                            <input type="checkbox" class="qs-rep-table-cb" value="<?php echo esc_attr( $tb['table'] ); ?>" <?php echo $tb['default'] ? 'checked' : ''; ?> style="margin-top:2px;">
                                            <div>
                                                <strong style="color:#1e293b;"><?php echo esc_html( $tb['label'] ); ?></strong>
                                                <div style="font-size:12px; color:#64748b;"><?php echo esc_html( $tb['desc'] ); ?></div>
                                            </div>
                                        </label>
                                    <?php endforeach; ?>
                                </div>
                            </td>
                        </tr>
                        <tr>
                            <th scope="row">运行模式</th>
                            <td>
                                <label style="display:flex; align-items:center; gap:8px; cursor:pointer;">
                                    <input type="checkbox" id="qs-rep-dryrun" checked>
                                    <strong style="color:#2563eb;">预演测试模式 (Dry-Run，仅统计命中数，不写入数据库)</strong>
                                </label>
                                <p class="description">强烈建议先勾选预演测试，确认命中条数无误后，再取消勾选执行正式替换。</p>
                            </td>
                        </tr>
                    </table>

                    <div style="margin-top:20px; padding-top:15px; border-top:1px solid #f1f5f9;">
                        <button type="button" class="button button-primary" id="qs-btn-start-replace" style="padding:4px 20px; height:34px;">
                            开始执行替换
                        </button>
                    </div>

                    <!-- 进度与日志输出条 -->
                    <div id="qs-rep-progress-box" style="display:none; margin-top:20px; background:#f8fafc; border:1px solid #e2e8f0; border-radius:6px; padding:16px;">
                        <div style="display:flex; justify-content:space-between; margin-bottom:8px;">
                            <strong id="qs-rep-status-title" style="color:#1e293b;">正在处理...</strong>
                            <span id="qs-rep-progress-pct" style="font-weight:700; color:#2563eb;">0%</span>
                        </div>
                        <div style="width:100%; height:8px; background:#e2e8f0; border-radius:4px; overflow:hidden; margin-bottom:12px;">
                            <div id="qs-rep-progress-bar" style="width:0%; height:100%; background:#2563eb; transition: width 0.3s;"></div>
                        </div>
                        <div id="qs-rep-log-lines" style="max-height:160px; overflow-y:auto; font-family:monospace; font-size:12px; color:#334155; line-height:1.6; background:#fff; border:1px solid #cbd5e1; border-radius:4px; padding:8px 10px;"></div>
                    </div>
                </div>
            </div>

            <!-- ===================== 子面板 4: 运维操作日志 ===================== -->
            <div class="qs-subtab-content" id="qs-subtab-logs" style="display:none;">
                <div class="qs-toolbar-row">
                    <div class="qs-toolbar-meta">
                        记录最近 50 次在数据库工具箱中执行的清理、优化与替换动作（独立存储于 <code><?php echo esc_html( self::get_log_table_name() ); ?></code>）。
                    </div>
                    <div class="qs-toolbar-actions">
                        <button type="button" class="button button-secondary" id="qs-btn-refresh-logs">刷新日志</button>
                        <button type="button" class="button button-secondary" id="qs-btn-clear-logs" style="color:#dc2626;">清空日志记录</button>
                    </div>
                </div>

                <table class="widefat striped">
                    <thead>
                        <tr>
                            <th style="width:160px;">操作时间</th>
                            <th style="width:120px;">任务类型</th>
                            <th style="width:160px;">目标范围</th>
                            <th style="width:100px;">影响条目</th>
                            <th style="width:90px;">模式</th>
                            <th style="width:90px;">耗时</th>
                            <th>详情</th>
                        </tr>
                    </thead>
                    <tbody id="qs-logs-table-body">
                        <tr><td colspan="7" style="text-align:center; color:#94a3b8; padding:20px;">点击下方按钮载入运维历史记录</td></tr>
                    </tbody>
                </table>
            </div>
        </div>

        <script>
        jQuery(function($) {
            var ajaxurl = qsData.ajaxurl;
            var nonce   = qsData.nonce;

            // 1. 子选项卡切换
            $('.qs-subtab-btn').on('click', function() {
                var target = $(this).data('target');
                $('.qs-subtab-btn').removeClass('button-primary').addClass('button-secondary');
                $(this).removeClass('button-secondary').addClass('button-primary');
                $('.qs-subtab-content').hide();
                $('#qs-subtab-' + target).fadeIn(150);

                if (target === 'logs') {
                    loadLogs();
                } else if (target === 'indexes') {
                    loadIndexes();
                }
            });

            // 2. 数据库分析
            $('#qs-btn-run-analysis').on('click', function() {
                var $btn = $(this);
                $btn.prop('disabled', true);
                $('#qs-analytics-result').hide();
                $('#qs-analytics-loading').show();

                $.post(ajaxurl, {
                    action: 'qs_db_toolkit_analyze',
                    nonce: nonce
                }, function(res) {
                    $btn.prop('disabled', false);
                    $('#qs-analytics-loading').hide();

                    if (!res.success) {
                        alert(res.data && res.data.message ? res.data.message : '分析失败');
                        return;
                    }

                    var data = res.data;
                    var ov = data.overview;
                    var al = data.autoload;

                    // 填充汇总
                    $('#qs-stat-table-count').text(ov.total_tables);
                    $('#qs-stat-table-split').text('WP核心: ' + ov.wp_tables_count + ' / 第三方: ' + ov.other_tables_cnt);
                    $('#qs-stat-row-count').text(Number(ov.total_rows).toLocaleString());
                    $('#qs-stat-total-size').text(ov.total_size_fmt);
                    $('#qs-stat-size-split').text('数据: ' + ov.total_data_size_fmt + ' / 索引: ' + ov.total_idx_size_fmt);
                    $('#qs-stat-free-size').text(ov.total_free_size_fmt);

                    // 填充 Autoload
                    var badgeStyle = 'background:#dcfce7; color:#15803d;';
                    var badgeText  = '状态优秀 (' + al.total_size_fmt + ')';
                    if (al.health_level === 'danger') {
                        badgeStyle = 'background:#fee2e2; color:#b91c1c;';
                        badgeText  = '严重超标 (' + al.total_size_fmt + ')';
                    } else if (al.health_level === 'warning') {
                        badgeStyle = 'background:#fef3c7; color:#b45309;';
                        badgeText  = '体积偏大 (' + al.total_size_fmt + ')';
                    }
                    $('#qs-autoload-badge').attr('style', badgeStyle + ' padding:4px 10px; border-radius:12px; font-size:12px; font-weight:600;').text(badgeText);
                    $('#qs-autoload-tip').text(al.health_tip + '（总计 ' + al.total_count + ' 个选项随站点初始化自动载入）');

                    var alHtml = '';
                    $.each(al.top_options, function(i, opt) {
                        alHtml += '<tr>';
                        alHtml += '<td><code>' + $('<div>').text(opt.name).html() + '</code></td>';
                        alHtml += '<td><span ' + (opt.is_huge ? 'style="color:#dc2626; font-weight:600;"' : '') + '>' + opt.size_fmt + '</span></td>';
                        alHtml += '<td style="text-align:right;"><button type="button" class="button button-small qs-btn-disable-autoload" data-option="' + $('<div>').text(opt.name).html() + '">转为不自动加载 (no)</button></td>';
                        alHtml += '</tr>';
                    });
                    $('#qs-autoload-table-body').html(alHtml);

                    // 填充 Post Type 透视分析
                    if (data.post_types) {
                        var pt = data.post_types;
                        $('#qs-post-type-total-badge').text('wp_posts 总记录: ' + Number(pt.total_posts).toLocaleString() + ' 行');

                        if (pt.suggestions && pt.suggestions.length > 0) {
                            var alertHtml = '';
                            $.each(pt.suggestions, function(i, sug) {
                                alertHtml += '<div style="background:#fef3c7; border-left:4px solid #f59e0b; color:#92400e; padding:8px 12px; border-radius:4px; font-size:13px; margin-bottom:6px;">' + sug + '</div>';
                            });
                            $('#qs-post-type-alerts').html(alertHtml).show();
                        } else {
                            $('#qs-post-type-alerts').hide();
                        }

                        var ptHtml = '';
                        $.each(pt.items, function(i, item) {
                            var barColor = '#3b82f6';
                            if (item.type === 'revision') barColor = '#f59e0b';
                            else if (item.type === 'auto-draft') barColor = '#ef4444';
                            else if (item.type === 'attachment') barColor = '#8b5cf6';

                            var statusDetails = [];
                            $.each(item.statuses, function(st, cnt) {
                                statusDetails.push(st + ': ' + Number(cnt).toLocaleString());
                            });

                            var actionTip = '<span style="color:#64748b; font-size:12px;">正常</span>';
                            if (item.type === 'revision' && item.pct > 25) {
                                actionTip = '<span style="color:#d97706; font-size:12px; font-weight:600;">建议清理修订</span>';
                            } else if (item.type === 'auto-draft' && item.count > 50) {
                                actionTip = '<span style="color:#dc2626; font-size:12px; font-weight:600;">建议清理草稿</span>';
                            }

                            ptHtml += '<tr>';
                            ptHtml += '<td><strong>' + item.label + '</strong> <code style="font-size:11px; color:#64748b;">(' + item.type + ')</code></td>';
                            ptHtml += '<td>' + Number(item.count).toLocaleString() + '</td>';
                            ptHtml += '<td><div style="display:flex; align-items:center; gap:8px;"><div style="flex:1; background:#f1f5f9; height:8px; border-radius:4px; overflow:hidden;"><div style="width:' + item.pct + '%; background:' + barColor + '; height:100%;"></div></div><span style="font-size:12px; width:45px; text-align:right;">' + item.pct + '%</span></div></td>';
                            ptHtml += '<td><span style="font-size:12px; color:#475569;">' + statusDetails.join(' | ') + '</span></td>';
                            ptHtml += '<td style="text-align:right;">' + actionTip + '</td>';
                            ptHtml += '</tr>';
                        });
                        $('#qs-post-types-table-body').html(ptHtml);
                    }

                    // 填充表清单
                    var tbHtml = '';
                    $.each(ov.tables, function(i, tb) {
                        tbHtml += '<tr>';
                        tbHtml += '<td><code>' + $('<div>').text(tb.name).html() + '</code></td>';
                        tbHtml += '<td>' + tb.engine + '</td>';
                        tbHtml += '<td>' + Number(tb.rows).toLocaleString() + '</td>';
                        tbHtml += '<td>' + tb.data_size + '</td>';
                        tbHtml += '<td>' + tb.index_size + '</td>';
                        tbHtml += '<td>' + (tb.has_fragment ? '<span style="color:#e11d48; font-weight:600;">' + tb.free_size + '</span>' : '0 B') + '</td>';
                        tbHtml += '<td><strong>' + tb.total_size + '</strong></td>';
                        tbHtml += '</tr>';
                    });
                    $('#qs-tables-list-body').html(tbHtml);

                    $('#qs-analytics-result').fadeIn(200);
                });
            });

            // 禁用单个 Autoload
            $(document).on('click', '.qs-btn-disable-autoload', function() {
                var $btn = $(this);
                var optName = $btn.data('option');
                if (!confirm('确定要将选项 [' + optName + '] 设为不自动加载吗？\n这将释放前台常驻内存，但在极少数插件中若强依赖该选项可能需要其自行按需读取。')) {
                    return;
                }
                $btn.prop('disabled', true).text('修改中...');
                $.post(ajaxurl, {
                    action: 'qs_db_toolkit_toggle_autoload',
                    nonce: nonce,
                    option_name: optName,
                    target_state: 'no'
                }, function(res) {
                    if (res.success) {
                        $btn.replaceWith('<span style="color:#16a34a; font-size:12px;">已转为 no</span>');
                    } else {
                        alert(res.data && res.data.message ? res.data.message : '修改失败');
                        $btn.prop('disabled', false).text('转为不自动加载 (no)');
                    }
                });
            });

            // 3. 垃圾数据清理 (Dry-run / Real)
            function runCleanup(isDryRun) {
                var targets = [];
                $('.qs-cleanup-cb:checked').each(function() {
                    targets.push($(this).val());
                });

                if (targets.length === 0) {
                    alert('请至少勾选一个清理项！');
                    return;
                }

                if (!isDryRun && !confirm('警告：您当前选择的是【正式清理】模式，匹配的垃圾数据将被永久物理删除且无法撤销！\n请确认您已完成数据库备份。确定继续吗？')) {
                    return;
                }

                var keepRevisions = $('#qs-cleanup-keep-revisions').val();
                var $box = $('#qs-cleanup-log-box');
                var $msg = $('#qs-cleanup-log-msg');

                $box.show();
                $msg.html('<span class="dashicons dashicons-update qs-tab-lazy-icon is-loading"></span> 正在' + (isDryRun ? '预演分析' : '执行物理清理') + '中...');

                $.post(ajaxurl, {
                    action: 'qs_db_toolkit_cleanup',
                    nonce: nonce,
                    targets: targets,
                    keep_revisions: keepRevisions,
                    dry_run: isDryRun ? 1 : 0
                }, function(res) {
                    if (!res.success) {
                        $msg.html('<span style="color:#dc2626;">失败：' + (res.data && res.data.message ? res.data.message : '请求异常') + '</span>');
                        return;
                    }

                    var d = res.data;
                    var html = '<div style="font-weight:600; color:' + (isDryRun ? '#2563eb' : '#16a34a') + ';">' + (isDryRun ? '【预演测试完成】预计可清理条目总数：' : '【清理成功】实际物理清除条目总数：') + d.total_deleted + ' 条（耗时 ' + d.duration_ms + 'ms）</div><ul style="margin:6px 0 0 16px; list-style:disc;">';
                    $.each(d.items, function(k, v) {
                        html += '<li>' + k + ': ' + v + ' 条</li>';
                    });
                    html += '</ul>';
                    $msg.html(html);
                });
            }

            $('#qs-btn-cleanup-dryrun').on('click', function() { runCleanup(true); });
            $('#qs-btn-cleanup-run').on('click', function() { runCleanup(false); });

            // 4. 数据表优化 (OPTIMIZE TABLE)
            $('#qs-btn-run-table-optimize').on('click', function() {
                if (!confirm('确定要对全库产生碎片的数据表执行 OPTIMIZE TABLE 整理吗？')) {
                    return;
                }
                var $btn = $(this);
                var $box = $('#qs-cleanup-log-box');
                var $msg = $('#qs-cleanup-log-msg');

                $btn.prop('disabled', true);
                $box.show();
                $msg.html('<span class="dashicons dashicons-update qs-tab-lazy-icon is-loading"></span> 正在优化数据表碎片，请稍候...');

                $.post(ajaxurl, {
                    action: 'qs_db_toolkit_optimize_tables',
                    nonce: nonce,
                    dry_run: 0
                }, function(res) {
                    $btn.prop('disabled', false);
                    if (!res.success) {
                        $msg.html('<span style="color:#dc2626;">优化失败</span>');
                        return;
                    }
                    var d = res.data;
                    var html = '<div style="font-weight:600; color:#16a34a;">优化完成！共优化 ' + d.table_count + ' 个数据表，耗时 ' + d.duration_ms + 'ms。</div>';
                    html += '<ul style="margin:6px 0 0 16px; list-style:disc;">';
                    $.each(d.details, function(i, item) {
                        html += '<li><code>' + item.table + '</code>: ' + item.status + '</li>';
                    });
                    html += '</ul>';
                    $msg.html(html);
                });
            });

            // 5. 替换模块快捷键
            $('#qs-btn-fill-home-url').on('click', function(e) {
                e.preventDefault();
                $('#qs-rep-search').val('<?php echo esc_js( home_url() ); ?>');
            });
            $('#qs-btn-select-all-tables').on('click', function() { $('.qs-rep-table-cb').prop('checked', true); });
            $('#qs-btn-select-default-tables').on('click', function() {
                $('.qs-rep-table-cb').each(function() {
                    var isDef = $(this).closest('label').data('default') == 1;
                    $(this).prop('checked', isDef);
                });
            });
            $('#qs-btn-unselect-tables').on('click', function() { $('.qs-rep-table-cb').prop('checked', false); });

            // 6. 执行全量批量替换
            $('#qs-btn-start-replace').on('click', function() {
                var searchStr  = $('#qs-rep-search').val();
                var replaceStr = $('#qs-rep-replace').val();
                var isDryRun   = $('#qs-rep-dryrun').is(':checked');

                if (!searchStr) {
                    alert('请输入要搜索的源字符串！');
                    return;
                }

                var tables = [];
                $('.qs-rep-table-cb:checked').each(function() {
                    tables.push($(this).val());
                });

                if (tables.length === 0) {
                    alert('请至少勾选一个目标数据表！');
                    return;
                }

                if (!isDryRun && !confirm('【极度严重警告】\n您当前取消了预演测试，即将进行【真实全库替换】！\n替换将永久改写数据库中的所有匹配记录且无法撤销！\n请再次确认您已完成数据库备份。\n\n确定要立即开始写入替换吗？')) {
                    return;
                }

                var $btn = $(this);
                $btn.prop('disabled', true);

                $('#qs-rep-progress-box').show();
                $('#qs-rep-log-lines').empty();
                $('#qs-rep-status-title').text(isDryRun ? '正在预演搜索中...' : '正在执行替换写入中...');
                $('#qs-rep-progress-pct').text('0%');
                $('#qs-rep-progress-bar').css('width', '0%');

                var totalTables = tables.length;
                var currentTableIndex = 0;
                var globalUpdated = 0;
                var globalHits = 0;

                function appendLog(text) {
                    var $lines = $('#qs-rep-log-lines');
                    $lines.append('<div>' + text + '</div>');
                    $lines.scrollTop($lines[0].scrollHeight);
                }

                function processBatch(tbl, lastId) {
                    $.post(ajaxurl, {
                        action: 'qs_db_toolkit_search_replace_batch',
                        nonce: nonce,
                        table_name: tbl,
                        search: searchStr,
                        replace: replaceStr,
                        last_id: lastId,
                        limit: 500,
                        dry_run: isDryRun ? 1 : 0
                    }, function(res) {
                        if (!res.success) {
                            appendLog('<span style="color:#dc2626;">[错误] 表 ' + tbl + ' 处理失败: ' + (res.data && res.data.message ? res.data.message : '未知错误') + '</span>');
                            currentTableIndex++;
                            processNextTable();
                            return;
                        }

                        var d = res.data;
                        globalUpdated += d.updated;
                        globalHits    += d.replacements;

                        if (d.updated > 0) {
                            appendLog('表 ' + tbl + ' 批次扫描 ID>' + lastId + ': 匹配 ' + d.updated + ' 行, 命中 ' + d.replacements + ' 处');
                        }

                        if (!d.done) {
                            processBatch(tbl, d.next_id);
                        } else {
                            currentTableIndex++;
                            var pct = Math.round((currentTableIndex / totalTables) * 100);
                            $('#qs-rep-progress-pct').text(pct + '%');
                            $('#qs-rep-progress-bar').css('width', pct + '%');
                            processNextTable();
                        }
                    }).fail(function() {
                        appendLog('<span style="color:#dc2626;">[超时/错误] 表 ' + tbl + ' 请求无响应，跳过继续下个表...</span>');
                        currentTableIndex++;
                        processNextTable();
                    });
                }

                function processNextTable() {
                    if (currentTableIndex >= totalTables) {
                        $btn.prop('disabled', false);
                        $('#qs-rep-status-title').html('<span style="color:#16a34a;">' + (isDryRun ? '预演统计完成！' : '替换全部完成！') + '</span>');
                        appendLog('----------------------------------------------------');
                        appendLog('<strong>' + (isDryRun ? '【预演总结】' : '【执行总结】') + '共检查 ' + totalTables + ' 个表，共计匹配 ' + globalUpdated + ' 行记录，发现 ' + globalHits + ' 处替换点。</strong>');
                        return;
                    }

                    var tbl = tables[currentTableIndex];
                    appendLog('正在扫描表 [' + (currentTableIndex + 1) + '/' + totalTables + ']: ' + tbl + ' ...');
                    processBatch(tbl, 0);
                }

                processNextTable();
            });

            // 7. 日志载入与清空
            function loadLogs() {
                $('#qs-logs-table-body').html('<tr><td colspan="7" style="text-align:center; padding:20px;"><span class="dashicons dashicons-update qs-tab-lazy-icon is-loading"></span> 正在读取日志...</td></tr>');
                $.post(ajaxurl, {
                    action: 'qs_db_toolkit_get_logs',
                    nonce: nonce
                }, function(res) {
                    if (!res.success || !res.data.logs || res.data.logs.length === 0) {
                        $('#qs-logs-table-body').html('<tr><td colspan="7" style="text-align:center; color:#94a3b8; padding:20px;">暂无运维操作日志</td></tr>');
                        return;
                    }

                    var html = '';
                    $.each(res.data.logs, function(i, log) {
                        var modeLabel = (log.is_dry_run == 1) ? '<span style="color:#2563eb;">预演模式</span>' : '<span style="color:#16a34a;">实际执行</span>';
                        html += '<tr>';
                        html += '<td><span style="font-size:12px; color:#64748b;">' + log.created_at + '</span></td>';
                        html += '<td><code>' + log.action_type + '</code></td>';
                        html += '<td>' + log.target_scope + '</td>';
                        html += '<td><strong>' + log.affected_rows + '</strong></td>';
                        html += '<td>' + modeLabel + '</td>';
                        html += '<td>' + log.duration_ms + 'ms</td>';
                        html += '<td><span style="font-size:11px; color:#475569; word-break:break-all;">' + $('<div>').text(log.details || '-').html() + '</span></td>';
                        html += '</tr>';
                    });
                    $('#qs-logs-table-body').html(html);
                });
            }

            $('#qs-btn-refresh-logs').on('click', loadLogs);
            $('#qs-btn-clear-logs').on('click', function() {
                if (!confirm('确定要清空全部数据库工具箱日志吗？')) {
                    return;
                }
                $.post(ajaxurl, {
                    action: 'qs_db_toolkit_clear_logs',
                    nonce: nonce
                }, function(res) {
                    if (res.success) {
                        loadLogs();
                    }
                });
            });

            // 8. 复合索引异步管理与加载
            function loadIndexes() {
                $('#qs-indexes-loading').show();
                $('#qs-indexes-table-box').hide();
                $('#qs-index-action-feedback').hide();

                $.post(ajaxurl, {
                    action: 'qs_db_toolkit_get_index_status',
                    nonce: nonce
                }, function(res) {
                    $('#qs-indexes-loading').hide();
                    if (!res.success || !res.data.indexes) {
                        return;
                    }
                    renderIndexList(res.data.indexes);
                    $('#qs-indexes-table-box').fadeIn(150);
                });
            }

            function renderIndexList(indexes) {
                var html = '';
                $.each(indexes, function(key, idx) {
                    var statusBadge = idx.exists 
                        ? '<span style="background:#dcfce7; color:#15803d; padding:3px 8px; border-radius:12px; font-size:12px; font-weight:600;">已生效加速</span>'
                        : '<span style="background:#f1f5f9; color:#64748b; padding:3px 8px; border-radius:12px; font-size:12px; font-weight:600;">未启用</span>';

                    var btnHtml = idx.exists
                        ? '<button type="button" class="button button-secondary qs-btn-toggle-idx" data-key="' + key + '" data-action="drop" style="font-size:12px;">一键移除还原</button>'
                        : '<button type="button" class="button button-primary qs-btn-toggle-idx" data-key="' + key + '" data-action="add" style="font-size:12px;">创建加速索引</button>';

                    html += '<tr>';
                    html += '<td><div style="font-weight:600; color:#1e293b;">' + idx.title + '</div><code style="font-size:11px; color:#2563eb;">' + idx.name + '</code><div style="font-size:11px; color:#64748b; margin-top:2px;">目标表: ' + idx.table + ' (' + Number(idx.row_count).toLocaleString() + ' 行)</div></td>';
                    html += '<td><code>' + idx.columns + '</code></td>';
                    html += '<td><div style="color:#334155; font-size:13px;">' + idx.description + '</div><div style="color:#16a34a; font-size:12px; font-weight:600; margin-top:3px;">预期效果：' + idx.benefit + '</div></td>';
                    html += '<td>' + statusBadge + '</td>';
                    html += '<td style="text-align:right;">' + btnHtml + '</td>';
                    html += '</tr>';
                });
                $('#qs-indexes-table-body').html(html);
            }

            $(document).on('click', '.qs-btn-toggle-idx', function() {
                var $btn = $(this);
                var key = $btn.data('key');
                var act = $btn.data('action');

                if (act === 'drop' && !confirm('确定要移除该优化索引并恢复默认结构吗？\n移除后多条件查询速度可能会下降。')) {
                    return;
                }

                $btn.prop('disabled', true).text(act === 'add' ? '创建中...' : '移除中...');
                $('#qs-index-action-feedback').hide();

                $.post(ajaxurl, {
                    action: 'qs_db_toolkit_toggle_index',
                    nonce: nonce,
                    index_key: key,
                    index_action: act
                }, function(res) {
                    if (res.success) {
                        $('#qs-index-action-feedback').css('color', '#16a34a').text(res.data.message).show();
                        renderIndexList(res.data.indexes);
                    } else {
                        $('#qs-index-action-feedback').css('color', '#dc2626').text('操作失败: ' + (res.data && res.data.message ? res.data.message : '未知错误')).show();
                        loadIndexes();
                    }
                }).fail(function() {
                    alert('网络超时或数据库异常，请检查权限。');
                    loadIndexes();
                });
            });

            $('#qs-btn-apply-all-indexes').on('click', function() {
                if (!confirm('确定要一键启用全部 3 项核心复合索引吗？\n系统将自动在线安全构建索引，加速自定义字段、配置和列表查询。')) {
                    return;
                }
                var $btn = $(this);
                $btn.prop('disabled', true).text('正在构建索引...');
                $('#qs-index-action-feedback').hide();

                $.post(ajaxurl, {
                    action: 'qs_db_toolkit_toggle_index',
                    nonce: nonce,
                    index_key: 'all',
                    index_action: 'add'
                }, function(res) {
                    $btn.prop('disabled', false).text('一键启用全部加速索引');
                    if (res.success) {
                        $('#qs-index-action-feedback').css('color', '#16a34a').text(res.data.message).show();
                        renderIndexList(res.data.indexes);
                    } else {
                        $('#qs-index-action-feedback').css('color', '#dc2626').text('部分或全部失败: ' + (res.data && res.data.message ? res.data.message : '未知错误')).show();
                        loadIndexes();
                    }
                });
            });

            $('#qs-btn-drop-all-indexes').on('click', function() {
                if (!confirm('确定要一键移除所有优化索引并恢复出厂默认吗？')) {
                    return;
                }
                var $btn = $(this);
                $btn.prop('disabled', true).text('正在移除索引...');
                $('#qs-index-action-feedback').hide();

                $.post(ajaxurl, {
                    action: 'qs_db_toolkit_toggle_index',
                    nonce: nonce,
                    index_key: 'all',
                    index_action: 'drop'
                }, function(res) {
                    $btn.prop('disabled', false).text('一键移除恢复出厂');
                    if (res.success) {
                        $('#qs-index-action-feedback').css('color', '#16a34a').text(res.data.message).show();
                        renderIndexList(res.data.indexes);
                    } else {
                        $('#qs-index-action-feedback').css('color', '#dc2626').text('部分或全部失败: ' + (res.data && res.data.message ? res.data.message : '未知错误')).show();
                        loadIndexes();
                    }
                });
            });
        });
        </script>
        <?php
    }
}
