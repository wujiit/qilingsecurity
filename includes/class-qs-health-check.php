<?php
/**
 * 启灵安全防护 - 插件健康自检中心
 */
if ( ! defined( 'ABSPATH' ) ) {
    exit;
}

class QS_Health_Check {

    const OPTION_LAST_REPORT = 'qs_health_check_last_report';
    const REPORT_TTL         = 900;

    public static function get_report( $settings = null, $force = false ) {
        static $runtime_report = null;

        if ( ! $force && is_array( $runtime_report ) && ! empty( $runtime_report['checks'] ) ) {
            return $runtime_report;
        }

        $stored = get_option( self::OPTION_LAST_REPORT, [] );
        if ( ! $force && self::is_valid_report( $stored ) && self::is_fresh_report( $stored ) ) {
            $runtime_report = $stored;

            return $runtime_report;
        }

        $runtime_report = self::run_checks( $settings );

        return $runtime_report;
    }

    public static function run_checks( $settings = null ) {
        $settings = is_array( $settings ) ? $settings : QS_Protection::get_settings();
        $checks   = [
            self::build_database_check(),
            self::build_php_version_check(),
            self::build_rules_package_check(),
            self::build_private_key_check(),
            self::build_async_task_check( $settings ),
            self::build_ip_risk_transport_check( $settings ),
            self::build_redis_check( $settings ),
        ];

        $summary = [
            'success'  => 0,
            'warning'  => 0,
            'critical' => 0,
            'neutral'  => 0,
            'total'    => count( $checks ),
        ];

        foreach ( $checks as $check ) {
            $status = isset( $check['status'] ) ? sanitize_key( (string) $check['status'] ) : 'neutral';
            if ( isset( $summary[ $status ] ) ) {
                $summary[ $status ]++;
            }
        }

        if ( $summary['critical'] > 0 ) {
            $summary['overall_status'] = 'critical';
            $summary['overall_label']  = '需立即处理';
        } elseif ( $summary['warning'] > 0 ) {
            $summary['overall_status'] = 'warning';
            $summary['overall_label']  = '需留意';
        } else {
            $summary['overall_status'] = 'success';
            $summary['overall_label']  = '状态良好';
        }

        $report = [
            'generated_at' => current_time( 'timestamp' ),
            'summary'      => $summary,
            'checks'       => $checks,
        ];

        update_option( self::OPTION_LAST_REPORT, $report, false );

        return $report;
    }

    private static function build_database_check() {
        $status = QS_DB::get_schema_status();

        if ( ! empty( $status['missing_tables'] ) || empty( $status['schema_current'] ) ) {
            $details = [];

            if ( ! empty( $status['missing_tables'] ) ) {
                $details[] = '缺失数据表：' . implode( '、', array_map( 'sanitize_text_field', $status['missing_tables'] ) );
            }

            if ( empty( $status['schema_current'] ) ) {
                $details[] = '当前 schema version=' . sanitize_text_field( (string) $status['installed_version'] ) . '，期望=' . sanitize_text_field( (string) $status['expected_version'] );
            }

            return self::build_check(
                'database_schema',
                '数据库结构',
                'critical',
                '插件核心数据表或 schema 版本不完整，部分扫描、审计、封禁功能可能无法正常工作。',
                implode( '；', $details )
            );
        }

        return self::build_check(
            'database_schema',
            '数据库结构',
            'success',
            '插件核心数据表结构完整，当前 schema 已处于最新版本。',
            'schema version=' . sanitize_text_field( (string) $status['expected_version'] )
        );
    }

    private static function build_php_version_check() {
        $current_php = PHP_VERSION;
        $baseline    = '8.2.35';

        if ( version_compare( $current_php, $baseline, '<' ) ) {
            return self::build_check(
                'php_version_security',
                'PHP 运行时版本安全基线',
                'warning',
                sprintf( '当前 PHP 版本为 PHP %s，低于安全建议基准（%s）。', $current_php, $baseline ),
                '近期存在 PHP 核心严重远程代码执行漏洞（CVSS 9.8），建议在条件允许时升级至 PHP 8.2.35+ 或 PHP 8.3+ 以确保服务器底层安全。'
            );
        }

        return self::build_check(
            'php_version_security',
            'PHP 运行时版本安全基线',
            'success',
            sprintf( '当前 PHP 版本为 PHP %s，符合安全建议基线要求。', $current_php ),
            '服务器运行环境处于推荐的安全版本范围。'
        );
    }

    private static function build_rules_package_check() {
        $status         = QS_Rules::get_package_status();
        $raw_active     = get_option( QS_Rules::OPTION_ACTIVE_PACKAGE, [] );
        $has_raw_active = is_array( $raw_active ) && ! empty( $raw_active );
        $openssl_ready  = function_exists( 'openssl_verify' ) && function_exists( 'openssl_pkey_get_public' );

        if ( ! $openssl_ready ) {
            return self::build_check(
                'rules_package',
                '规则包签名环境',
                'warning',
                '服务器缺少 OpenSSL 能力，当前无法校验和导入官方签名规则包。',
                '内置规则仍可继续使用，但建议补齐 OpenSSL 扩展。'
            );
        }

        if ( $has_raw_active && 'builtin' === $status['source'] ) {
            return self::build_check(
                'rules_package',
                '规则包签名环境',
                'warning',
                '检测到历史自定义规则包，但当前已回退到内置规则，可能是签名失效、版本不兼容或数据损坏。',
                '当前生效版本：' . sanitize_text_field( (string) $status['version'] )
            );
        }

        $message = 'builtin' === $status['source']
            ? '当前使用插件内置规则，规则签名环境正常。'
            : '当前官方规则包已通过签名校验并处于启用状态。';

        return self::build_check(
            'rules_package',
            '规则包签名环境',
            'success',
            $message,
            '当前规则版本：' . sanitize_text_field( (string) $status['version'] )
        );
    }

    private static function build_private_key_check() {
        $private_key_path = QS_PLUGIN_DIR . 'rules/qiling-official-private.pem';

        if ( file_exists( $private_key_path ) ) {
            return self::build_check(
                'private_key_exposure',
                '规则签名私钥',
                'critical',
                '插件目录中检测到规则签名私钥文件，规则信任链存在高风险。',
                '请立即将私钥移出仓库和发布目录，并重新轮换新的签名密钥对。'
            );
        }

        return self::build_check(
            'private_key_exposure',
            '规则签名私钥',
            'success',
            '插件目录中未发现规则签名私钥文件，发布包侧的私钥泄露风险已解除。'
        );
    }

    private static function build_async_task_check( $settings ) {
        if ( ! QS_Protection::is_ip_risk_profile_enabled( $settings ) ) {
            return self::build_check(
                'async_tasks',
                '异步任务链路',
                'neutral',
                '登录 IP 风险画像当前未启用，异步任务自检已跳过。'
            );
        }

        $query_mode = QS_Protection::get_ip_risk_query_mode( $settings );

        if ( 'external' === $query_mode ) {
            $cron_key = QS_Protection::get_ip_risk_external_cron_key( $settings, true );

            if ( '' === $cron_key ) {
                return self::build_check(
                    'async_tasks',
                    '异步任务链路',
                    'critical',
                    '已开启外部任务模式，但当前没有可用的外部任务密钥。',
                    '请重新保存设置，或手动配置外部任务地址。'
                );
            }

            return self::build_check(
                'async_tasks',
                '异步任务链路',
                'success',
                '登录 IP 风险画像当前使用外部任务模式，不依赖 WP-Cron 执行。',
                '请确保外部任务地址按 1~3 分钟频率持续访问。'
            );
        }

        if ( defined( 'DISABLE_WP_CRON' ) && DISABLE_WP_CRON ) {
            return self::build_check(
                'async_tasks',
                '异步任务链路',
                'warning',
                '站点已禁用 WP-Cron，登录 IP 风险画像的异步刷新和单次任务可能无法按预期触发。',
                '建议切换到 external 模式，或为站点单独配置真实系统 Cron。'
            );
        }

        return self::build_check(
            'async_tasks',
            '异步任务链路',
            'success',
            'WP-Cron 当前可用，登录 IP 风险画像的异步刷新具备执行条件。',
            '当前查询模式：' . sanitize_text_field( (string) $query_mode )
        );
    }

    private static function build_ip_risk_transport_check( $settings ) {
        if ( ! QS_Protection::is_ip_risk_profile_enabled( $settings ) ) {
            return self::build_check(
                'ip_risk_transport',
                '风险画像数据源',
                'neutral',
                '登录 IP 风险画像当前未启用，数据源传输检查已跳过。'
            );
        }

        $providers = QS_Protection::get_ip_risk_provider_list( $settings );

        if ( in_array( 'ip_api', $providers, true ) ) {
            return self::build_check(
                'ip_risk_transport',
                '风险画像数据源',
                'warning',
                '当前启用了 IP-API 公共源，该服务走明文 HTTP 查询，不适合作为唯一风险画像来源。',
                '建议优先使用 ipdata 或 ipinfo 等 HTTPS 数据源。'
            );
        }

        return self::build_check(
            'ip_risk_transport',
            '风险画像数据源',
            'success',
            '当前风险画像提供方未检测到 HTTP-only 公共源，外部请求默认走证书校验。',
            '当前提供方：' . implode( '、', array_map( 'sanitize_text_field', $providers ) )
        );
    }

    private static function build_redis_check( $settings ) {
        $status = QS_Redis_Cache::get_status( $settings );

        if ( empty( $status['enabled'] ) ) {
            return self::build_check(
                'redis_cache',
                'Redis 对象缓存',
                'neutral',
                'Redis 对象缓存当前未启用，此项健康检查已跳过。'
            );
        }

        if ( ! empty( $status['dropin_exists'] ) && empty( $status['dropin_managed'] ) ) {
            return self::build_check(
                'redis_cache',
                'Redis 对象缓存',
                'critical',
                '检测到当前 object-cache.php 不由启灵安全防护托管，Redis 接管状态存在冲突。',
                '请确认现场是否已有其他对象缓存方案。'
            );
        }

        if ( empty( $status['redis_extension'] ) || empty( $status['connection_ok'] ) ) {
            return self::build_check(
                'redis_cache',
                'Redis 对象缓存',
                'critical',
                ! empty( $status['connection_message'] ) ? $status['connection_message'] : 'Redis 当前不可用，持久对象缓存链路未建立。'
            );
        }

        if ( empty( $status['using_ext_object_cache'] ) ) {
            return self::build_check(
                'redis_cache',
                'Redis 对象缓存',
                'warning',
                'Redis 连接正常，但 WordPress 当前尚未真正接管外部对象缓存。',
                '请确认 wp-content/object-cache.php 已生效。'
            );
        }

        return self::build_check(
            'redis_cache',
            'Redis 对象缓存',
            'success',
            'Redis 连接和 WordPress 外部对象缓存接管状态均正常。',
            sanitize_text_field( (string) $status['config']['host'] ) . ':' . absint( $status['config']['port'] ) . ' / DB ' . absint( $status['config']['database'] )
        );
    }

    private static function build_check( $id, $label, $status, $message, $detail = '' ) {
        return [
            'id'      => sanitize_key( (string) $id ),
            'label'   => sanitize_text_field( (string) $label ),
            'status'  => sanitize_key( (string) $status ),
            'message' => sanitize_text_field( (string) $message ),
            'detail'  => sanitize_text_field( (string) $detail ),
        ];
    }

    private static function is_valid_report( $report ) {
        return is_array( $report ) && ! empty( $report['checks'] ) && isset( $report['generated_at'] );
    }

    private static function is_fresh_report( $report ) {
        $generated_at = isset( $report['generated_at'] ) ? absint( $report['generated_at'] ) : 0;

        return $generated_at > 0 && ( time() - $generated_at ) <= self::REPORT_TTL;
    }
}
