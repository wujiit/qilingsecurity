<?php
/**
 * 启灵安全防护 - Redis 对象缓存管理模块
 */
if ( ! defined( 'ABSPATH' ) ) {
    exit;
}

class QS_Redis_Cache {

    const DROPIN_FILENAME = 'object-cache.php';
    const DROPIN_TEMPLATE = 'dropins/object-cache.php.stub';
    const DROPIN_SIGNATURE = 'Qiling Security Redis Object Cache Drop-In';
    const RUNTIME_OPTION = 'qs_redis_cache_runtime';

    public static function get_setting_keys() {
        return [
            'redis_object_cache_enabled',
            'redis_object_cache_host',
            'redis_object_cache_username',
            'redis_object_cache_port',
            'redis_object_cache_password',
            'redis_object_cache_database',
            'redis_object_cache_prefix',
        ];
    }

    public static function get_settings( $settings = null ) {
        $settings = is_array( $settings ) ? $settings : QS_Protection::get_settings();
        $config   = [];

        foreach ( self::get_setting_keys() as $key ) {
            $config[ $key ] = isset( $settings[ $key ] ) ? $settings[ $key ] : '';
        }

        $config['redis_object_cache_enabled']  = ! empty( $config['redis_object_cache_enabled'] );
        $config['redis_object_cache_host']     = isset( $config['redis_object_cache_host'] ) ? trim( (string) $config['redis_object_cache_host'] ) : '127.0.0.1';
        $config['redis_object_cache_username'] = isset( $config['redis_object_cache_username'] ) ? trim( (string) $config['redis_object_cache_username'] ) : '';
        $config['redis_object_cache_port']     = max( 0, absint( $config['redis_object_cache_port'] ) );
        $config['redis_object_cache_database'] = max( 0, absint( $config['redis_object_cache_database'] ) );
        $config['redis_object_cache_password'] = isset( $config['redis_object_cache_password'] ) ? (string) $config['redis_object_cache_password'] : '';
        $config['redis_object_cache_prefix']   = isset( $config['redis_object_cache_prefix'] ) ? trim( (string) $config['redis_object_cache_prefix'] ) : '';

        if ( '' === $config['redis_object_cache_host'] ) {
            $config['redis_object_cache_host'] = '127.0.0.1';
        }

        if ( 0 === $config['redis_object_cache_port'] && 0 !== strpos( $config['redis_object_cache_host'], '/' ) ) {
            $config['redis_object_cache_port'] = 6379;
        }

        return $config;
    }

    public static function get_dropin_path() {
        $content_dir = defined( 'WP_CONTENT_DIR' ) ? WP_CONTENT_DIR : ABSPATH . 'wp-content';

        return rtrim( (string) $content_dir, "/\\" ) . '/' . self::DROPIN_FILENAME;
    }

    public static function get_dropin_template_path() {
        return QS_PLUGIN_DIR . self::DROPIN_TEMPLATE;
    }

    public static function get_display_prefix( $settings = null ) {
        $config = self::get_settings( $settings );

        if ( '' !== $config['redis_object_cache_prefix'] ) {
            return $config['redis_object_cache_prefix'];
        }

        global $table_prefix;

        $db_name      = defined( 'DB_NAME' ) ? (string) DB_NAME : 'wpdb';
        $table_prefix = is_string( $table_prefix ) ? $table_prefix : '';

        return 'qsredis:' . md5( $db_name . '|' . $table_prefix ) . ':';
    }

    public static function is_dropin_installed() {
        return file_exists( self::get_dropin_path() );
    }

    public static function is_managed_dropin() {
        $path = self::get_dropin_path();
        if ( ! file_exists( $path ) || ! is_readable( $path ) ) {
            return false;
        }

        $contents = file_get_contents( $path );
        if ( false === $contents ) {
            return false;
        }

        return false !== strpos( $contents, self::DROPIN_SIGNATURE );
    }

    public static function can_manage_dropin() {
        $path = self::get_dropin_path();

        if ( file_exists( $path ) ) {
            return is_writable( $path );
        }

        return is_dir( dirname( $path ) ) && is_writable( dirname( $path ) );
    }

    public static function sync_dropin( $settings = null ) {
        $config = self::get_settings( $settings );

        if ( ! $config['redis_object_cache_enabled'] ) {
            $managed_dropin = self::is_managed_dropin();

            if ( $managed_dropin && ! self::remove_dropin() ) {
                $message = 'Redis 已关闭，但未能移除现有 object-cache.php，请检查 wp-content 目录权限。';
                self::record_runtime_event(
                    'sync',
                    [
                        'status'  => 'error',
                        'message' => $message,
                    ]
                );

                return new WP_Error( 'qs_redis_dropin_remove_failed', $message );
            }

            $message = $managed_dropin ? 'Redis 对象缓存已关闭，并移除了插件托管的 object-cache.php。' : 'Redis 对象缓存当前处于关闭状态。';
            self::record_runtime_event(
                'sync',
                [
                    'status'  => 'success',
                    'message' => $message,
                ]
            );

            return [
                'changed' => $managed_dropin,
                'message' => $managed_dropin ? $message : '',
            ];
        }

        if ( self::is_dropin_installed() && ! self::is_managed_dropin() ) {
            $message = '检测到现有 object-cache.php 不是启灵安全防护托管的。为避免覆盖其他缓存方案，请先手动备份或移除现有 drop-in 后再开启。';
            self::record_runtime_event(
                'sync',
                [
                    'status'  => 'error',
                    'message' => $message,
                ]
            );

            return new WP_Error( 'qs_redis_dropin_conflict', $message );
        }

        $written = self::write_dropin( $config );
        if ( is_wp_error( $written ) ) {
            self::record_runtime_event(
                'sync',
                [
                    'status'  => 'error',
                    'message' => $written->get_error_message(),
                ]
            );

            return $written;
        }

        $message = 'Redis 对象缓存 drop-in 已同步到 wp-content/object-cache.php。';
        self::purge_settings_option_object_cache( $config );
        self::record_runtime_event(
            'sync',
            [
                'status'  => 'success',
                'message' => $message,
            ]
        );

        return [
            'changed' => true,
            'message' => $message,
        ];
    }

    public static function maybe_upgrade_managed_dropin( $settings = null ) {
        if ( ! self::is_managed_dropin() || ! self::can_manage_dropin() ) {
            return false;
        }

        $dropin_path = self::get_dropin_path();
        $contents    = file_get_contents( $dropin_path );
        if ( false === $contents ) {
            return false;
        }

        // 如果现有 drop-in 依然包含旧版导致 OOM 的 array_chunk 特征，或缺少新的流式刷新方法，则自动重写升级
        $is_outdated = false !== strpos( $contents, 'array_chunk( $keys, 500 )' )
            || false === strpos( $contents, 'flush_by_prefix' );

        if ( $is_outdated ) {
            $config = self::get_settings( $settings );
            return self::write_dropin( $config );
        }

        return false;
    }

    public static function get_status( $settings = null ) {
        $config         = self::get_settings( $settings );
        $dropin_path    = self::get_dropin_path();
        $dropin_exists  = file_exists( $dropin_path );
        $managed_dropin = self::is_managed_dropin();
        $using_ext      = function_exists( 'wp_using_ext_object_cache' ) ? wp_using_ext_object_cache() : $dropin_exists;
        $status         = [
            'enabled'             => ! empty( $config['redis_object_cache_enabled'] ),
            'dropin_exists'       => $dropin_exists,
            'dropin_managed'      => $managed_dropin,
            'dropin_path'         => $dropin_path,
            'can_manage_dropin'   => self::can_manage_dropin(),
            'using_ext_object_cache' => $using_ext,
            'redis_extension'     => class_exists( 'Redis' ),
            'prefix'              => self::get_display_prefix( $config ),
            'config'              => [
                'host'     => $config['redis_object_cache_host'],
                'port'     => (int) $config['redis_object_cache_port'],
                'database' => (int) $config['redis_object_cache_database'],
            ],
            'connection_ok'       => false,
            'connection_latency_ms' => '',
            'connection_message'  => '',
            'supports'            => self::get_support_matrix(),
            'runtime'             => self::get_runtime_state(),
            'ecosystem_targets'   => self::get_ecosystem_refresh_targets(),
            'stats'               => [
                'keys'            => 0,
                'prefix_keys'     => 0,
                'prefix_keys_truncated' => false,
                'used_memory'     => '',
                'maxmemory'       => '',
                'hits'            => 0,
                'misses'          => 0,
                'hit_rate'        => '',
                'uptime_days'     => '',
                'connected_clients' => 0,
                'evicted_keys'    => 0,
                'redis_version'   => '',
                'redis_mode'      => '',
            ],
        ];

        if ( ! class_exists( 'Redis' ) ) {
            $status['connection_message'] = '当前 PHP 未加载 Redis 扩展，保存设置后也无法建立持久对象缓存。';

            return $status;
        }

        $connection = self::connect( $config );
        if ( is_wp_error( $connection ) ) {
            $status['connection_message'] = $connection->get_error_message();

            return $status;
        }

        $redis                     = $connection['redis'];
        $status['connection_ok']   = true;
        $status['connection_latency_ms'] = isset( $connection['latency_ms'] ) ? (string) $connection['latency_ms'] : '';
        $status['connection_message'] = 'Redis 连接正常，可用于 WordPress 持久对象缓存。';
        $status['stats']           = self::collect_stats( $redis, $status['prefix'] );

        if ( $status['enabled'] && ! $status['using_ext_object_cache'] ) {
            $status['connection_message'] = 'Redis 连接正常，但当前 WordPress 尚未启用外部对象缓存，请确认 object-cache.php 已生效。';
        }

        self::close_connection( $redis );

        return $status;
    }

    public static function flush_cache( $settings = null ) {
        $settings = self::get_settings( $settings );

        $managed_dropin = self::is_managed_dropin();
        if ( $managed_dropin ) {
            self::maybe_upgrade_managed_dropin( $settings );
        }

        global $wp_object_cache;
        $in_memory_dropin_outdated = $managed_dropin
            && is_object( $wp_object_cache )
            && ! method_exists( $wp_object_cache, 'flush_by_prefix' );

        if ( ! $in_memory_dropin_outdated && function_exists( 'wp_using_ext_object_cache' ) && wp_using_ext_object_cache() && function_exists( 'wp_cache_flush' ) ) {
            $result = wp_cache_flush();
            if ( false === $result ) {
                return new WP_Error( 'qs_redis_flush_failed', 'WordPress 对象缓存刷新失败，请检查 Redis 连接与 object-cache.php 配置。' );
            }
        } else {
            $connection = self::connect( $settings );
            if ( is_wp_error( $connection ) ) {
                return $connection;
            }

            $redis  = $connection['redis'];
            $prefix = self::get_display_prefix( $settings );
            $result = self::flush_prefix_keys( $redis, $prefix );

            self::close_connection( $redis );

            if ( false === $result ) {
                return new WP_Error( 'qs_redis_flush_failed', 'Redis 对象缓存刷新失败，请检查当前 Redis 库权限或连接状态。' );
            }

            if ( is_object( $wp_object_cache ) && method_exists( $wp_object_cache, 'flush_runtime' ) ) {
                $wp_object_cache->flush_runtime();
            }
        }

        $refreshed = self::refresh_qiling_ecosystem_cache_versions();
        $message   = 'Redis 对象缓存已刷新，启灵生态缓存兼容层已同步处理。';
        self::record_runtime_event(
            'flush',
            [
                'status'  => 'success',
                'message' => $message,
                'targets' => $refreshed,
            ]
        );

        return [
            'message'   => $message,
            'refreshed' => $refreshed,
        ];
    }

    public static function run_probe( $settings = null ) {
        $config = self::get_settings( $settings );
        $steps  = [];

        if ( ! $config['redis_object_cache_enabled'] ) {
            return self::finalize_probe_result( false, '当前尚未启用启灵 Redis 对象缓存，无法执行缓存自检。', $steps );
        }

        if ( self::is_dropin_installed() && ! self::is_managed_dropin() ) {
            return self::finalize_probe_result( false, '当前 object-cache.php 不由启灵安全防护托管。为避免误判，本面板不执行启灵 Redis 自检。', $steps );
        }

        if ( ! class_exists( 'Redis' ) ) {
            return self::finalize_probe_result( false, '当前 PHP 未加载 Redis 扩展，无法执行 Redis 持久对象缓存自检。', $steps );
        }

        $connection = self::connect( $config );
        if ( is_wp_error( $connection ) ) {
            return self::finalize_probe_result( false, $connection->get_error_message(), $steps );
        }

        $latency = isset( $connection['latency_ms'] ) ? (string) $connection['latency_ms'] : '';
        $steps[] = [
            'label'   => 'Redis 连接',
            'ok'      => true,
            'message' => '' !== $latency ? sprintf( '连接成功，耗时约 %s ms。', $latency ) : '连接成功。',
        ];

        self::close_connection( $connection['redis'] );

        if ( ! function_exists( 'wp_using_ext_object_cache' ) || ! wp_using_ext_object_cache() ) {
            $steps[] = [
                'label'   => 'WordPress 外部对象缓存',
                'ok'      => false,
                'message' => 'wp_using_ext_object_cache() 当前未返回 true，说明 object-cache.php 还没有真正接管本次请求。',
            ];

            return self::finalize_probe_result( false, 'Redis 连接正常，但 WordPress 当前并未真正启用外部对象缓存。', $steps );
        }

        $steps[] = [
            'label'   => 'WordPress 外部对象缓存',
            'ok'      => true,
            'message' => 'wp_using_ext_object_cache() 已返回 true，当前请求会优先走 object-cache drop-in。',
        ];

        if ( ! function_exists( 'wp_cache_set' ) || ! function_exists( 'wp_cache_get' ) || ! function_exists( 'wp_cache_delete' ) ) {
            $steps[] = [
                'label'   => '对象缓存接口',
                'ok'      => false,
                'message' => 'WordPress 当前缺少必要的 wp_cache_* 接口，无法完成自检。',
            ];

            return self::finalize_probe_result( false, 'WordPress 对象缓存接口不完整，缓存自检无法继续。', $steps );
        }

        $group   = 'qs_redis_probe';
        $key     = 'probe_' . wp_generate_password( 10, false, false );
        $payload = [
            'token' => wp_generate_uuid4(),
            'time'  => time(),
        ];

        $write_ok = (bool) wp_cache_set( $key, $payload, $group, 60 );
        $steps[]  = [
            'label'   => '写入缓存',
            'ok'      => $write_ok,
            'message' => $write_ok ? '测试缓存已写入对象缓存。' : 'wp_cache_set() 写入失败。',
        ];

        if ( ! $write_ok ) {
            return self::finalize_probe_result( false, 'WordPress 对象缓存写入失败，请检查 object-cache.php 与 Redis 配置。', $steps );
        }

        $found   = false;
        $read    = wp_cache_get( $key, $group, true, $found );
        $read_ok = $found && $read === $payload;
        $steps[] = [
            'label'   => '强制回源读取',
            'ok'      => $read_ok,
            'message' => $read_ok ? '缓存已能在绕过运行时缓存后重新读回，说明持久缓存链路正常。' : '未能从持久对象缓存中读回刚写入的数据。',
        ];

        if ( ! $read_ok ) {
            wp_cache_delete( $key, $group );

            return self::finalize_probe_result( false, '写入成功，但未能从持久对象缓存中重新读回数据，当前更像是只命中了运行时缓存。', $steps );
        }

        if ( function_exists( 'wp_cache_add' ) ) {
            $add_key        = 'probe_add_' . wp_generate_password( 8, false, false );
            $add_first_ok   = (bool) wp_cache_add( $add_key, 'first-write', $group, 60 );
            $add_second_ok  = ! wp_cache_add( $add_key, 'second-write', $group, 60 );
            $add_found      = false;
            $add_value      = wp_cache_get( $add_key, $group, true, $add_found );
            $add_probe_ok   = $add_first_ok && $add_second_ok && $add_found && 'first-write' === $add_value;
            $steps[] = [
                'label'   => '原子新增',
                'ok'      => $add_probe_ok,
                'message' => $add_probe_ok ? 'wp_cache_add() 已验证只会写入第一次值。' : 'wp_cache_add() 未能稳定保持首写结果，请检查当前 drop-in 的 add 语义。',
            ];

            wp_cache_delete( $add_key, $group );

            if ( ! $add_probe_ok ) {
                wp_cache_delete( $key, $group );

                return self::finalize_probe_result( false, '对象缓存原子新增探针未通过，当前 drop-in 对 wp_cache_add() 的兼容性不足。', $steps );
            }
        } else {
            $steps[] = [
                'label'   => '原子新增',
                'ok'      => false,
                'message' => 'WordPress 当前缺少 wp_cache_add() 接口，无法确认 Redis 对 add 语义的兼容性。',
            ];

            wp_cache_delete( $key, $group );

            return self::finalize_probe_result( false, 'WordPress 缺少 wp_cache_add() 接口，缓存自检无法完整验证。', $steps );
        }

        $supports_get_multiple = function_exists( 'wp_cache_supports' )
            ? (bool) wp_cache_supports( 'get_multiple' )
            : function_exists( 'wp_cache_get_multiple' );

        if ( $supports_get_multiple && function_exists( 'wp_cache_get_multiple' ) ) {
            $multi_keys = [
                'probe_multi_a_' . wp_generate_password( 6, false, false ) => 'alpha',
                'probe_multi_b_' . wp_generate_password( 6, false, false ) => 'beta',
            ];

            foreach ( $multi_keys as $multi_key => $multi_value ) {
                wp_cache_set( $multi_key, $multi_value, $group, 60 );
            }

            $multi_result = wp_cache_get_multiple( array_keys( $multi_keys ), $group, true );
            $multi_ok     = is_array( $multi_result );

            foreach ( $multi_keys as $multi_key => $multi_value ) {
                if ( ! $multi_ok || ! array_key_exists( $multi_key, $multi_result ) || $multi_result[ $multi_key ] !== $multi_value ) {
                    $multi_ok = false;
                    break;
                }
            }

            $steps[] = [
                'label'   => '批量读取',
                'ok'      => $multi_ok,
                'message' => $multi_ok ? 'wp_cache_get_multiple() 已成功批量回源读取测试数据。' : 'wp_cache_get_multiple() 返回结果异常，当前 drop-in 的批量读取兼容性不足。',
            ];

            if ( function_exists( 'wp_cache_delete_multiple' ) ) {
                wp_cache_delete_multiple( array_keys( $multi_keys ), $group );
            } else {
                foreach ( array_keys( $multi_keys ) as $multi_key ) {
                    wp_cache_delete( $multi_key, $group );
                }
            }

            if ( ! $multi_ok ) {
                wp_cache_delete( $key, $group );

                return self::finalize_probe_result( false, '对象缓存批量读取探针未通过，当前 drop-in 对 wp_cache_get_multiple() 的兼容性不足。', $steps );
            }
        } else {
            $steps[] = [
                'label'   => '批量读取',
                'ok'      => true,
                'message' => '运行环境未提供 get_multiple 探针，已跳过此项。',
            ];
        }

        $delete_ok = (bool) wp_cache_delete( $key, $group );
        $deleted   = false;
        $after     = wp_cache_get( $key, $group, true, $deleted );
        unset( $after );
        $delete_ok = $delete_ok && ! $deleted;
        $steps[]   = [
            'label'   => '删除缓存',
            'ok'      => $delete_ok,
            'message' => $delete_ok ? '测试缓存删除成功。' : '测试缓存删除后仍然可读，请检查 drop-in 行为。',
        ];

        if ( ! $delete_ok ) {
            return self::finalize_probe_result( false, '对象缓存删除探针未通过，请检查当前 drop-in 是否正常响应删除操作。', $steps );
        }

        $supports_flush_group = function_exists( 'wp_cache_supports' )
            ? (bool) wp_cache_supports( 'flush_group' )
            : function_exists( 'wp_cache_flush_group' );

        if ( $supports_flush_group && function_exists( 'wp_cache_flush_group' ) ) {
            $flush_key = 'probe_group_' . wp_generate_password( 8, false, false );
            wp_cache_set( $flush_key, $payload, $group, 60 );
            $group_flush = (bool) wp_cache_flush_group( $group );
            $flushed_found = false;
            wp_cache_get( $flush_key, $group, true, $flushed_found );

            $flush_group_ok = $group_flush && ! $flushed_found;
            $steps[] = [
                'label'   => '分组刷新',
                'ok'      => $flush_group_ok,
                'message' => $flush_group_ok ? 'wp_cache_flush_group() 已正常工作。' : '分组刷新未通过，当前对象缓存不一定支持精准分组刷新。',
            ];
        } else {
            $steps[] = [
                'label'   => '分组刷新',
                'ok'      => true,
                'message' => '运行环境未提供 flush_group 探针，已跳过此项。',
            ];
        }

        return self::finalize_probe_result( true, 'Redis 缓存自检通过，WordPress 已成功验证写入、原子新增、批量读取、删除与分组刷新等关键对象缓存链路。', $steps );
    }

    public static function get_runtime_state() {
        $defaults = self::get_runtime_defaults();
        $state    = get_option( self::RUNTIME_OPTION, [] );

        if ( ! is_array( $state ) ) {
            $state = [];
        }

        return wp_parse_args( $state, $defaults );
    }

    public static function get_ecosystem_refresh_targets() {
        return [
            [
                'id'          => 'qiling_theme',
                'label'       => '启灵主题',
                'description' => '刷新主题 content/settings 版本签名，收敛前台公共缓存与片段缓存。',
                'available'   => function_exists( 'developer_starter_bump_cache_version' ),
            ],
            [
                'id'          => 'qibbs_community',
                'label'       => 'Qibbs 社区',
                'description' => '联动社区 feed/热榜/论坛统计缓存，并刷新 qibbs_cache_version。',
                'available'   => class_exists( 'Qibbs_Cache_Service' ) || self::option_exists( 'qibbs_cache_version' ),
            ],
            [
                'id'          => 'qilingdoc',
                'label'       => '启灵文档',
                'description' => '刷新文档目录树、推荐文档等版本化缓存。',
                'available'   => class_exists( '\\QilingDoc\\Plugin' ) || self::option_exists( 'qilingdoc_cache_version' ),
            ],
            [
                'id'          => 'qilingshop_catalog',
                'label'       => '启灵商城商品/分类',
                'description' => '递增商品与分类版本键，确保商品列表、分类树等立即换新。',
                'available'   => class_exists( 'QLS_Product' ) || class_exists( 'QLS_Category' ) || self::option_exists( 'qls_shop_product_cache_version' ) || self::option_exists( 'qls_shop_category_cache_version' ),
            ],
            [
                'id'          => 'qilingshop_group',
                'label'       => '启灵商城拼团',
                'description' => '刷新拼团商品展示版本，避免前台拼团数据继续复用旧缓存。',
                'available'   => class_exists( 'QLS_Group' ) || self::option_exists( 'qls_group_products_cache_version' ),
            ],
            [
                'id'          => 'qiling_nav',
                'label'       => '启灵导航',
                'description' => '清除导航页 transient，并同步导航前端版本号。',
                'available'   => class_exists( 'XB_Nav_Cache' ) || self::option_exists( 'xb_nav_cache_version' ),
            ],
            [
                'id'          => 'qivoting',
                'label'       => '启灵投票',
                'description' => '清空投票数据缓存并同步投票前端资源版本。',
                'available'   => class_exists( 'Qivot_Cache' ) || self::option_exists( 'qivot_asset_version' ),
            ],
            [
                'id'          => 'qiling_ai_image',
                'label'       => '启灵图片工具',
                'description' => '刷新前台内容缓存版本，并同步前端资源版本号。',
                'available'   => function_exists( 'xb_aicytxgj_bump_frontend_content_cache_version' ) || self::option_exists( 'xb_aicytxgj_frontend_cache_version' ) || self::option_exists( 'xb_aicytxgj_asset_version' ),
            ],
            [
                'id'          => 'qiapp',
                'label'       => '启灵应用库',
                'description' => '清理软件聚合 transient，避免软件下载统计与列表继续复用旧结果。',
                'available'   => class_exists( 'QiApp_Software' ),
            ],
            [
                'id'          => 'qilingcoupon_analytics',
                'label'       => '启灵优惠券统计',
                'description' => '递增优惠券后台统计版本键，确保统计图表尽快重算。',
                'available'   => self::option_exists( 'qilingcp_analytics_cache_ver' ),
            ],
        ];
    }

    private static function write_dropin( $settings ) {
        $template_path = self::get_dropin_template_path();
        if ( ! file_exists( $template_path ) || ! is_readable( $template_path ) ) {
            return new WP_Error( 'qs_redis_dropin_template_missing', 'Redis 对象缓存模板文件不存在，无法生成 object-cache.php。' );
        }

        $template = file_get_contents( $template_path );
        if ( false === $template ) {
            return new WP_Error( 'qs_redis_dropin_template_read_failed', 'Redis 对象缓存模板读取失败。' );
        }

        $path = self::get_dropin_path();
        $dir  = dirname( $path );
        if ( ! is_dir( $dir ) || ! is_writable( $dir ) ) {
            if ( file_exists( $path ) && is_writable( $path ) ) {
                // 现有文件可写，继续覆盖。
            } else {
                return new WP_Error( 'qs_redis_dropin_dir_unwritable', 'wp-content 目录当前不可写，无法安装 object-cache.php。' );
            }
        }

        $contents = strtr(
            $template,
            [
                '__QS_REDIS_SIGNATURE__'    => self::DROPIN_SIGNATURE,
                '__QS_REDIS_GENERATED_AT__' => gmdate( 'c' ),
                '__QS_REDIS_HOST__'         => var_export( (string) $settings['redis_object_cache_host'], true ),
                '__QS_REDIS_USERNAME__'     => var_export( (string) $settings['redis_object_cache_username'], true ),
                '__QS_REDIS_PORT__'         => (string) max( 0, absint( $settings['redis_object_cache_port'] ) ),
                '__QS_REDIS_PASSWORD__'     => var_export( (string) $settings['redis_object_cache_password'], true ),
                '__QS_REDIS_DATABASE__'     => (string) max( 0, absint( $settings['redis_object_cache_database'] ) ),
                '__QS_REDIS_PREFIX__'       => var_export( (string) $settings['redis_object_cache_prefix'], true ),
            ]
        );

        $result = file_put_contents( $path, $contents, LOCK_EX );

        if ( false === $result ) {
            return new WP_Error( 'qs_redis_dropin_write_failed', 'object-cache.php 写入失败，请检查 wp-content 目录权限。' );
        }

        return true;
    }

    private static function remove_dropin() {
        $path = self::get_dropin_path();

        if ( ! file_exists( $path ) ) {
            return true;
        }

        return wp_delete_file( $path );
    }

    private static function connect( $settings ) {
        if ( ! class_exists( 'Redis' ) ) {
            return new WP_Error( 'qs_redis_extension_missing', '当前 PHP 未安装 Redis 扩展。' );
        }

        $host     = isset( $settings['redis_object_cache_host'] ) ? (string) $settings['redis_object_cache_host'] : '127.0.0.1';
        $username = isset( $settings['redis_object_cache_username'] ) ? trim( (string) $settings['redis_object_cache_username'] ) : '';
        $port     = isset( $settings['redis_object_cache_port'] ) ? max( 0, (int) $settings['redis_object_cache_port'] ) : 6379;
        $password = isset( $settings['redis_object_cache_password'] ) ? (string) $settings['redis_object_cache_password'] : '';
        $database = isset( $settings['redis_object_cache_database'] ) ? max( 0, (int) $settings['redis_object_cache_database'] ) : 0;
        $started  = microtime( true );

        try {
            $redis = new Redis();
            $ok    = false;

            if ( 0 === strpos( $host, '/' ) ) {
                $ok = @ $redis->connect( $host );
            } else {
                $ok = @ $redis->connect( $host, $port, 1.5 );
            }

            if ( ! $ok ) {
                return new WP_Error( 'qs_redis_connect_failed', 'Redis 连接失败，请检查主机、端口和服务状态。' );
            }

            if ( defined( 'Redis::OPT_SCAN' ) && defined( 'Redis::SCAN_RETRY' ) && method_exists( $redis, 'setOption' ) ) {
                @ $redis->setOption( Redis::OPT_SCAN, Redis::SCAN_RETRY );
            }

            if ( '' !== $username ) {
                $auth_result = @ $redis->auth( [ $username, $password ] );
            } elseif ( '' !== $password ) {
                $auth_result = @ $redis->auth( $password );
            } else {
                $auth_result = true;
            }

            if ( ! $auth_result ) {
                self::close_connection( $redis );

                return new WP_Error( 'qs_redis_auth_failed', '' !== $username ? 'Redis ACL 验证失败，请检查用户名与密码配置。' : 'Redis 密码验证失败，请检查密码配置。' );
            }

            if ( $database > 0 && ! @ $redis->select( $database ) ) {
                self::close_connection( $redis );

                return new WP_Error( 'qs_redis_select_failed', 'Redis 数据库切换失败，请检查 database 配置。' );
            }

            return [
                'redis'      => $redis,
                'latency_ms' => round( ( microtime( true ) - $started ) * 1000, 1 ),
            ];
        } catch ( Exception $e ) {
            return new WP_Error( 'qs_redis_exception', 'Redis 连接异常：' . $e->getMessage() );
        }
    }

    private static function collect_stats( $redis, $prefix = '' ) {
        $stats = [
            'keys'                 => 0,
            'prefix_keys'          => 0,
            'prefix_keys_truncated' => false,
            'used_memory'          => '',
            'maxmemory'            => '',
            'hits'                 => 0,
            'misses'               => 0,
            'hit_rate'             => '',
            'uptime_days'          => '',
            'connected_clients'    => 0,
            'evicted_keys'         => 0,
            'redis_version'        => '',
            'redis_mode'           => '',
        ];

        try {
            $info = $redis->info();
            if ( is_array( $info ) ) {
                $stats['used_memory']       = ! empty( $info['used_memory_human'] ) ? (string) $info['used_memory_human'] : '';
                $stats['maxmemory']         = ! empty( $info['maxmemory_human'] ) && '0B' !== (string) $info['maxmemory_human'] ? (string) $info['maxmemory_human'] : '';
                $stats['hits']              = isset( $info['keyspace_hits'] ) ? (int) $info['keyspace_hits'] : 0;
                $stats['misses']            = isset( $info['keyspace_misses'] ) ? (int) $info['keyspace_misses'] : 0;
                $stats['connected_clients'] = isset( $info['connected_clients'] ) ? (int) $info['connected_clients'] : 0;
                $stats['evicted_keys']      = isset( $info['evicted_keys'] ) ? (int) $info['evicted_keys'] : 0;
                $stats['redis_version']     = ! empty( $info['redis_version'] ) ? (string) $info['redis_version'] : '';
                $stats['redis_mode']        = ! empty( $info['redis_mode'] ) ? (string) $info['redis_mode'] : '';

                $total = $stats['hits'] + $stats['misses'];
                if ( $total > 0 ) {
                    $stats['hit_rate'] = round( ( $stats['hits'] / $total ) * 100, 1 ) . '%';
                }

                if ( isset( $info['uptime_in_days'] ) ) {
                    $stats['uptime_days'] = (string) $info['uptime_in_days'];
                }
            }

            $stats['keys'] = (int) $redis->dbSize();

            if ( '' !== $prefix ) {
                $prefix_stats = self::count_prefix_keys( $redis, $prefix );
                $stats['prefix_keys'] = isset( $prefix_stats['count'] ) ? (int) $prefix_stats['count'] : 0;
                $stats['prefix_keys_truncated'] = ! empty( $prefix_stats['truncated'] );
            }
        } catch ( Exception $e ) {
            // 统计信息仅作尽力记录。
        }

        return $stats;
    }

    private static function count_prefix_keys( $redis, $prefix, $limit = 3000 ) {
        $cursor    = null;
        $count     = 0;
        $truncated = false;

        try {
            do {
                $batch = $redis->scan( $cursor, $prefix . '*', 300 );
                if ( false === $batch || empty( $batch ) ) {
                    continue;
                }

                foreach ( $batch as $key ) {
                    unset( $key );
                    $count++;

                    if ( $count >= $limit ) {
                        $truncated = true;
                        break 2;
                    }
                }
            } while ( 0 !== (int) $cursor );
        } catch ( Exception $e ) {
            return [
                'count'     => 0,
                'truncated' => false,
            ];
        }

        return [
            'count'     => $count,
            'truncated' => $truncated,
        ];
    }

    private static function get_support_matrix() {
        $supports = [
            'wp_cache_api'   => function_exists( 'wp_cache_get' ) && function_exists( 'wp_cache_set' ) && function_exists( 'wp_cache_delete' ),
            'flush_group'    => false,
            'flush_runtime'  => false,
            'get_multiple'   => false,
            'set_multiple'   => false,
            'delete_multiple' => false,
        ];

        if ( function_exists( 'wp_cache_supports' ) ) {
            $supports['flush_group']   = (bool) wp_cache_supports( 'flush_group' );
            $supports['flush_runtime'] = (bool) wp_cache_supports( 'flush_runtime' );
            $supports['get_multiple']  = (bool) wp_cache_supports( 'get_multiple' );
            $supports['set_multiple']  = (bool) wp_cache_supports( 'set_multiple' );
            $supports['delete_multiple'] = (bool) wp_cache_supports( 'delete_multiple' );
        } else {
            $supports['flush_group']   = function_exists( 'wp_cache_flush_group' );
            $supports['flush_runtime'] = function_exists( 'wp_cache_flush_runtime' );
            $supports['get_multiple']  = function_exists( 'wp_cache_get_multiple' );
            $supports['set_multiple']  = function_exists( 'wp_cache_set_multiple' );
            $supports['delete_multiple'] = function_exists( 'wp_cache_delete_multiple' );
        }

        return $supports;
    }

    private static function get_runtime_defaults() {
        return [
            'last_flush_at'       => 0,
            'last_flush_status'   => '',
            'last_flush_message'  => '',
            'last_flush_targets'  => [],
            'last_probe_at'       => 0,
            'last_probe_status'   => '',
            'last_probe_message'  => '',
            'last_probe_steps'    => [],
            'last_sync_at'        => 0,
            'last_sync_status'    => '',
            'last_sync_message'   => '',
        ];
    }

    private static function purge_settings_option_object_cache( $settings ) {
        $config = self::get_settings( $settings );

        if ( '' === trim( (string) $config['redis_object_cache_host'] ) ) {
            return false;
        }

        $connection = self::connect( $config );
        if ( is_wp_error( $connection ) ) {
            return false;
        }

        $redis        = $connection['redis'];
        $prefix       = self::get_display_prefix( $config );
        $registry_key = $prefix . 'index:groups';
        $deleted_any  = false;
        $targets      = [
            [
                'scope' => self::get_dropin_blog_scope(),
                'group' => 'options',
            ],
            [
                'scope' => 'global',
                'group' => 'site-options',
            ],
        ];

        foreach ( $targets as $target ) {
            $index_key = self::build_dropin_index_key( $prefix, $target['scope'], $target['group'] );
            if ( self::flush_dropin_index_key( $redis, $index_key, $registry_key ) ) {
                $deleted_any = true;
            }

            if ( self::delete_dropin_cache_keys(
                $redis,
                $prefix,
                $target['scope'],
                $target['group'],
                [ 'alloptions', 'notoptions', 'qs_protection_settings', self::RUNTIME_OPTION ]
            ) ) {
                $deleted_any = true;
            }
        }

        self::close_connection( $redis );

        if ( function_exists( 'wp_cache_delete' ) ) {
            wp_cache_delete( 'alloptions', 'options' );
            wp_cache_delete( 'notoptions', 'options' );
            wp_cache_delete( 'qs_protection_settings', 'options' );
            wp_cache_delete( self::RUNTIME_OPTION, 'options' );
            wp_cache_delete( 'alloptions', 'site-options' );
            wp_cache_delete( 'notoptions', 'site-options' );
            wp_cache_delete( 'qs_protection_settings', 'site-options' );
            wp_cache_delete( self::RUNTIME_OPTION, 'site-options' );
        }

        if ( function_exists( 'wp_cache_flush_runtime' ) ) {
            wp_cache_flush_runtime();
        }

        return $deleted_any;
    }

    private static function get_dropin_blog_scope() {
        if ( function_exists( 'is_multisite' ) && is_multisite() && function_exists( 'get_current_blog_id' ) ) {
            return 'blog:' . (int) get_current_blog_id();
        }

        return 'blog:0';
    }

    private static function normalize_dropin_group( $group ) {
        $group = '' === (string) $group ? 'default' : (string) $group;

        return preg_replace( '/[^A-Za-z0-9_.:-]/', '_', $group );
    }

    private static function build_dropin_data_key( $prefix, $scope, $group, $key ) {
        return $prefix . 'data:' . $scope . ':' . self::normalize_dropin_group( $group ) . ':' . md5( (string) $key );
    }

    private static function build_dropin_index_key( $prefix, $scope, $group ) {
        return $prefix . 'index:' . $scope . ':' . self::normalize_dropin_group( $group );
    }

    public static function delete_redis_key_batch( $redis, array $keys ) {
        if ( empty( $keys ) || ! is_object( $redis ) ) {
            return false;
        }

        try {
            if ( method_exists( $redis, 'unlink' ) ) {
                return (bool) call_user_func_array( [ $redis, 'unlink' ], $keys );
            }

            return (bool) call_user_func_array( [ $redis, 'del' ], $keys );
        } catch ( Exception $e ) {
            $any = false;
            foreach ( $keys as $k ) {
                try {
                    if ( $redis->del( $k ) ) {
                        $any = true;
                    }
                } catch ( Exception $ignored ) {
                }
            }
            return $any;
        }
    }

    private static function flush_dropin_index_key( $redis, $index_key, $registry_key = '' ) {
        if ( ! is_object( $redis ) ) {
            return false;
        }

        $deleted = false;

        try {
            // 1. 优先使用 sPop 批量流式消费，防止因集合元素过多导致 PHP 内存溢出 (OOM)
            $can_spop_batch = method_exists( $redis, 'sPop' );
            while ( $can_spop_batch ) {
                $keys = false;
                try {
                    $keys = $redis->sPop( $index_key, 500 );
                } catch ( Exception $e ) {
                    $can_spop_batch = false;
                    break;
                }

                if ( false === $keys || null === $keys || empty( $keys ) ) {
                    break;
                }

                $batch = is_array( $keys ) ? $keys : [ $keys ];
                if ( ! empty( $batch ) ) {
                    self::delete_redis_key_batch( $redis, $batch );
                    $deleted = true;
                }

                if ( count( $batch ) < 500 ) {
                    break;
                }
            }

            // 2. 若 sPop 批量不支持，尝试使用 sScan 游标流式遍历
            if ( ! $can_spop_batch && method_exists( $redis, 'sScan' ) ) {
                $cursor = null;
                do {
                    $keys = $redis->sScan( $index_key, $cursor, null, 500 );
                    if ( false === $keys ) {
                        break;
                    }
                    if ( ! empty( $keys ) && is_array( $keys ) ) {
                        self::delete_redis_key_batch( $redis, (array) $keys );
                        $deleted = true;
                    }
                } while ( 0 !== (int) $cursor );
            }

            if ( $redis->del( $index_key ) ) {
                $deleted = true;
            }

            if ( '' !== $registry_key && method_exists( $redis, 'sRem' ) ) {
                $redis->sRem( $registry_key, $index_key );
            }
        } catch ( Exception $e ) {
            return $deleted;
        }

        return $deleted;
    }

    private static function delete_dropin_cache_keys( $redis, $prefix, $scope, $group, $keys ) {
        if ( ! is_object( $redis ) ) {
            return false;
        }

        $redis_keys = [];
        foreach ( (array) $keys as $key ) {
            $redis_keys[] = self::build_dropin_data_key( $prefix, $scope, $group, $key );
        }

        $redis_keys = array_values( array_unique( array_filter( $redis_keys ) ) );
        if ( empty( $redis_keys ) ) {
            return false;
        }

        return self::delete_redis_key_batch( $redis, $redis_keys );
    }

    private static function record_runtime_event( $type, $payload ) {
        $state = self::get_runtime_state();
        $time  = time();
        $type  = sanitize_key( (string) $type );
        $data  = is_array( $payload ) ? $payload : [];

        switch ( $type ) {
            case 'flush':
                $state['last_flush_at']      = $time;
                $state['last_flush_status']  = ! empty( $data['status'] ) ? sanitize_key( (string) $data['status'] ) : 'success';
                $state['last_flush_message'] = ! empty( $data['message'] ) ? sanitize_text_field( (string) $data['message'] ) : '';
                $state['last_flush_targets'] = ! empty( $data['targets'] ) && is_array( $data['targets'] ) ? self::sanitize_refresh_targets( $data['targets'] ) : [];
                break;

            case 'probe':
                $state['last_probe_at']      = $time;
                $state['last_probe_status']  = ! empty( $data['status'] ) ? sanitize_key( (string) $data['status'] ) : 'success';
                $state['last_probe_message'] = ! empty( $data['message'] ) ? sanitize_text_field( (string) $data['message'] ) : '';
                $state['last_probe_steps']   = ! empty( $data['steps'] ) && is_array( $data['steps'] ) ? self::sanitize_probe_steps( $data['steps'] ) : [];
                break;

            case 'sync':
                $state['last_sync_at']      = $time;
                $state['last_sync_status']  = ! empty( $data['status'] ) ? sanitize_key( (string) $data['status'] ) : 'success';
                $state['last_sync_message'] = ! empty( $data['message'] ) ? sanitize_text_field( (string) $data['message'] ) : '';
                break;
        }

        update_option( self::RUNTIME_OPTION, $state, false );
    }

    private static function sanitize_probe_steps( $steps ) {
        $normalized = [];

        foreach ( (array) $steps as $step ) {
            if ( ! is_array( $step ) ) {
                continue;
            }

            $normalized[] = [
                'label'   => isset( $step['label'] ) ? sanitize_text_field( (string) $step['label'] ) : '',
                'ok'      => ! empty( $step['ok'] ),
                'message' => isset( $step['message'] ) ? sanitize_text_field( (string) $step['message'] ) : '',
            ];
        }

        return $normalized;
    }

    private static function sanitize_refresh_targets( $targets ) {
        $normalized = [];

        foreach ( (array) $targets as $target ) {
            if ( ! is_array( $target ) ) {
                continue;
            }

            $normalized[] = [
                'id'      => isset( $target['id'] ) ? sanitize_key( (string) $target['id'] ) : '',
                'label'   => isset( $target['label'] ) ? sanitize_text_field( (string) $target['label'] ) : '',
                'status'  => isset( $target['status'] ) ? sanitize_key( (string) $target['status'] ) : 'success',
                'message' => isset( $target['message'] ) ? sanitize_text_field( (string) $target['message'] ) : '',
            ];
        }

        return $normalized;
    }

    private static function finalize_probe_result( $ok, $message, $steps ) {
        $steps   = self::sanitize_probe_steps( $steps );
        $message = sanitize_text_field( (string) $message );
        $status  = $ok ? 'success' : 'error';

        self::record_runtime_event(
            'probe',
            [
                'status'  => $status,
                'message' => $message,
                'steps'   => $steps,
            ]
        );

        return [
            'ok'      => (bool) $ok,
            'status'  => $status,
            'message' => $message,
            'steps'   => $steps,
        ];
    }

    private static function flush_prefix_keys( $redis, $prefix ) {
        $cursor = null;
        $keys   = [];

        try {
            do {
                $batch = $redis->scan( $cursor, $prefix . '*' );
                if ( false === $batch || empty( $batch ) ) {
                    continue;
                }

                foreach ( $batch as $key ) {
                    $keys[] = $key;
                    if ( count( $keys ) >= 500 ) {
                        self::delete_redis_key_batch( $redis, $keys );
                        $keys = [];
                    }
                }
            } while ( 0 !== (int) $cursor );

            if ( ! empty( $keys ) ) {
                self::delete_redis_key_batch( $redis, $keys );
            }
        } catch ( Exception $e ) {
            return false;
        }

        return true;
    }

    private static function refresh_qiling_ecosystem_cache_versions() {
        $results       = [];
        $new_version   = sprintf( '%.0f', microtime( true ) * 1000000 ) . '-' . wp_rand( 1000, 9999 );
        $asset_version = (string) time();

        if ( function_exists( 'developer_starter_bump_cache_version' ) ) {
            developer_starter_bump_cache_version( 'content' );
            developer_starter_bump_cache_version( 'settings' );
            $results[] = self::build_refresh_target_result( 'qiling_theme', '启灵主题', 'success', '已刷新 content/settings 两组主题缓存版本。' );
        }

        $qibbs_actions = [];
        if ( class_exists( 'Qibbs_Cache_Service' ) && method_exists( 'Qibbs_Cache_Service', 'invalidate_all' ) ) {
            Qibbs_Cache_Service::invalidate_all();
            $qibbs_actions[] = '社区 feed/热榜/论坛统计缓存已失效';
        }
        if ( self::option_exists( 'qibbs_cache_version' ) ) {
            update_option( 'qibbs_cache_version', $new_version );
            $qibbs_actions[] = 'qibbs_cache_version 已更新';
        }
        if ( ! empty( $qibbs_actions ) ) {
            $results[] = self::build_refresh_target_result( 'qibbs_community', 'Qibbs 社区', 'success', implode( '；', $qibbs_actions ) . '。' );
        }

        if ( class_exists( '\\QilingDoc\\Plugin' ) && method_exists( '\\QilingDoc\\Plugin', 'bump_cache_version' ) ) {
            \QilingDoc\Plugin::bump_cache_version();
            $results[] = self::build_refresh_target_result( 'qilingdoc', '启灵文档', 'success', '已调用文档插件缓存版本刷新入口。' );
        } elseif ( self::option_exists( 'qilingdoc_cache_version' ) ) {
            update_option( 'qilingdoc_cache_version', $asset_version );
            $results[] = self::build_refresh_target_result( 'qilingdoc', '启灵文档', 'success', '已直接更新 qilingdoc_cache_version。' );
        }

        $shop_actions = [];
        if ( class_exists( 'QLS_Product' ) || self::option_exists( 'qls_shop_product_cache_version' ) ) {
            update_option( 'qls_shop_product_cache_version', $new_version );
            $shop_actions[] = '商品缓存版本已刷新';
        }
        if ( class_exists( 'QLS_Category' ) || self::option_exists( 'qls_shop_category_cache_version' ) ) {
            update_option( 'qls_shop_category_cache_version', $new_version );
            $shop_actions[] = '分类缓存版本已刷新';
        }
        if ( ! empty( $shop_actions ) ) {
            $results[] = self::build_refresh_target_result( 'qilingshop_catalog', '启灵商城商品/分类', 'success', implode( '；', $shop_actions ) . '。' );
        }

        if ( class_exists( 'QLS_Group' ) || self::option_exists( 'qls_group_products_cache_version' ) ) {
            $group_version = absint( get_option( 'qls_group_products_cache_version', 1 ) );
            update_option( 'qls_group_products_cache_version', max( 1, $group_version ) + 1, false );
            $results[] = self::build_refresh_target_result( 'qilingshop_group', '启灵商城拼团', 'success', '拼团商品展示版本已递增。' );
        }

        $nav_actions = [];
        if ( class_exists( 'XB_Nav_Cache' ) && method_exists( 'XB_Nav_Cache', 'clear_all' ) ) {
            XB_Nav_Cache::clear_all();
            $nav_actions[] = '导航 transient 已清空';
        }
        if ( class_exists( 'XB_Nav_Cache' ) || self::option_exists( 'xb_nav_cache_version' ) ) {
            $version = defined( 'XB_NAV_VERSION' ) ? XB_NAV_VERSION . '.' . $asset_version : $asset_version;
            update_option( 'xb_nav_cache_version', $version );
            $nav_actions[] = 'xb_nav_cache_version 已更新';
        }
        if ( ! empty( $nav_actions ) ) {
            $results[] = self::build_refresh_target_result( 'qiling_nav', '启灵导航', 'success', implode( '；', $nav_actions ) . '。' );
        }

        $qivot_actions = [];
        if ( class_exists( 'Qivot_Cache' ) && method_exists( 'Qivot_Cache', 'clear_all' ) ) {
            Qivot_Cache::clear_all();
            $qivot_actions[] = '投票数据缓存已清理';
        }
        if ( class_exists( 'Qivot_Cache' ) || self::option_exists( 'qivot_asset_version' ) ) {
            update_option( 'qivot_asset_version', $asset_version );
            $qivot_actions[] = 'qivot_asset_version 已更新';
        }
        if ( ! empty( $qivot_actions ) ) {
            $results[] = self::build_refresh_target_result( 'qivoting', '启灵投票', 'success', implode( '；', $qivot_actions ) . '。' );
        }

        $image_actions = [];
        if ( function_exists( 'xb_aicytxgj_bump_frontend_content_cache_version' ) ) {
            xb_aicytxgj_bump_frontend_content_cache_version();
            $image_actions[] = '前台内容缓存版本已刷新';
        } elseif ( self::option_exists( 'xb_aicytxgj_frontend_cache_version' ) ) {
            update_option( 'xb_aicytxgj_frontend_cache_version', $asset_version );
            $image_actions[] = 'xb_aicytxgj_frontend_cache_version 已更新';
        }
        if ( self::option_exists( 'xb_aicytxgj_asset_version' ) ) {
            update_option( 'xb_aicytxgj_asset_version', $asset_version );
            $image_actions[] = '前端资源版本已更新';
        }
        if ( ! empty( $image_actions ) ) {
            $results[] = self::build_refresh_target_result( 'qiling_ai_image', '启灵图片工具', 'success', implode( '；', $image_actions ) . '。' );
        }

        if ( class_exists( 'QiApp_Software' ) && method_exists( 'QiApp_Software', 'clear_cache' ) ) {
            QiApp_Software::clear_cache( 0, 0, true );
            $results[] = self::build_refresh_target_result( 'qiapp', '启灵应用库', 'success', '软件聚合 transient 已清理。' );
        }

        if ( self::option_exists( 'qilingcp_analytics_cache_ver' ) ) {
            $coupon_version = absint( get_option( 'qilingcp_analytics_cache_ver', 1 ) );
            update_option( 'qilingcp_analytics_cache_ver', max( 1, $coupon_version ) + 1, false );
            $results[] = self::build_refresh_target_result( 'qilingcoupon_analytics', '启灵优惠券统计', 'success', '优惠券统计缓存版本已递增。' );
        }

        return $results;
    }

    private static function option_exists( $option_name ) {
        return null !== get_option( (string) $option_name, null );
    }

    private static function build_refresh_target_result( $id, $label, $status, $message ) {
        return [
            'id'      => sanitize_key( (string) $id ),
            'label'   => sanitize_text_field( (string) $label ),
            'status'  => sanitize_key( (string) $status ),
            'message' => sanitize_text_field( (string) $message ),
        ];
    }

    private static function close_connection( $redis ) {
        if ( ! is_object( $redis ) || ! method_exists( $redis, 'close' ) ) {
            return;
        }

        try {
            $redis->close();
        } catch ( Exception $e ) {
            // 关闭失败不影响主流程。
        }
    }
}
