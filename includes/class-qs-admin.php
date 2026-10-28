<?php
/**
 * 安全防护插件 - 后台管理界面
 */
if ( ! defined( 'ABSPATH' ) ) exit;

class QS_Admin {

    public static function init() {
        add_action( 'admin_menu', [ __CLASS__, 'add_menu_pages' ] );
        add_action( 'admin_enqueue_scripts', [ __CLASS__, 'enqueue_assets' ] );
        add_action( 'admin_enqueue_scripts', [ __CLASS__, 'enqueue_toolbar_assets' ] );

        if ( function_exists( 'is_user_logged_in' ) && is_user_logged_in() ) {
            add_action( 'wp_enqueue_scripts', [ __CLASS__, 'enqueue_toolbar_assets' ] );
            add_action( 'admin_bar_menu', [ __CLASS__, 'add_admin_bar_items' ], 90 );
        }
    }

    public static function add_menu_pages() {
        add_menu_page(
            '启灵安全防护',
            '启灵安全防护',
            'manage_options',
            'qiling-security',
            [ __CLASS__, 'render_dashboard' ],
            'dashicons-shield',
            80
        );
    }

    public static function enqueue_assets( $hook ) {
        if ( 'toplevel_page_qiling-security' !== $hook ) {
            return;
        }

        self::enqueue_redis_ui_assets();

        $style_path    = QS_PLUGIN_DIR . 'assets/css/admin.css';
        $script_path   = QS_PLUGIN_DIR . 'assets/js/admin.js';
        $style_version = file_exists( $style_path ) ? (string) filemtime( $style_path ) : QS_VERSION;
        $script_version = file_exists( $script_path ) ? (string) filemtime( $script_path ) : QS_VERSION;

        wp_enqueue_style( 'qs-admin-style', QS_PLUGIN_URL . 'assets/css/admin.css', [], $style_version );
        wp_enqueue_script( 'qs-admin-script', QS_PLUGIN_URL . 'assets/js/admin.js', [ 'jquery' ], $script_version, true );

        $scan_steps = array_map(
            static function( $step ) {
                return [
                    'id'   => $step['id'],
                    'name' => $step['name'],
                ];
            },
            QS_Scanner::get_scan_steps()
        );

        wp_localize_script( 'qs-admin-script', 'qsData', [
            'ajaxurl'            => admin_url( 'admin-ajax.php' ),
            'nonce'              => wp_create_nonce( 'qs_ajax_nonce' ),
            'scanSteps'          => array_values( $scan_steps ),
            'lazyTabs'           => self::get_lazy_admin_tab_keys(),
            'proxyPresets'       => QS_Protection::get_proxy_presets_for_js(),
            'defaultProxyHeaders' => QS_Protection::get_default_proxy_headers(),
        ] );
    }

    public static function enqueue_toolbar_assets( $hook = '' ) {
        if ( ! current_user_can( 'manage_options' ) ) {
            return;
        }

        if ( is_admin() ) {
            if ( 'toplevel_page_qiling-security' !== $hook && ! is_admin_bar_showing() ) {
                return;
            }
        } elseif ( ! is_admin_bar_showing() ) {
            return;
        }

        self::enqueue_redis_ui_assets();
    }

    private static function enqueue_redis_ui_assets() {
        if ( wp_script_is( 'qs-redis-ui-script', 'enqueued' ) ) {
            return;
        }

        $style_path     = QS_PLUGIN_DIR . 'assets/css/redis-ui.css';
        $script_path    = QS_PLUGIN_DIR . 'assets/js/redis-ui.js';
        $style_version  = file_exists( $style_path ) ? (string) filemtime( $style_path ) : QS_VERSION;
        $script_version = file_exists( $script_path ) ? (string) filemtime( $script_path ) : QS_VERSION;

        wp_enqueue_style( 'qs-redis-ui-style', QS_PLUGIN_URL . 'assets/css/redis-ui.css', [], $style_version );
        wp_enqueue_script( 'qs-redis-ui-script', QS_PLUGIN_URL . 'assets/js/redis-ui.js', [], $script_version, true );
        wp_localize_script(
            'qs-redis-ui-script',
            'qsRedisUiData',
            [
                'ajaxurl'  => admin_url( 'admin-ajax.php' ),
                'nonce'    => wp_create_nonce( 'qs_ajax_nonce' ),
                'panelUrl' => admin_url( 'admin.php?page=qiling-security#tab-redis-cache' ),
            ]
        );
    }

    public static function add_admin_bar_items( $wp_admin_bar ) {
        if ( ! is_admin_bar_showing() || ! current_user_can( 'manage_options' ) ) {
            return;
        }

        if ( class_exists( 'QS_Redis_Cache' ) && method_exists( 'QS_Redis_Cache', 'maybe_upgrade_managed_dropin' ) ) {
            QS_Redis_Cache::maybe_upgrade_managed_dropin();
        }

        $panel_url = admin_url( 'admin.php?page=qiling-security#tab-redis-cache' );

        $wp_admin_bar->add_node(
            [
                'id'    => 'qs-redis-cache',
                'title' => '启灵缓存',
                'href'  => $panel_url,
                'meta'  => [
                    'title' => '打开启灵 Redis 对象缓存面板',
                ],
            ]
        );

        $wp_admin_bar->add_node(
            [
                'id'     => 'qs-redis-cache-flush',
                'parent' => 'qs-redis-cache',
                'title'  => '刷新 Redis 缓存',
                'href'   => '#',
                'meta'   => [
                    'title' => '刷新 Redis 对象缓存',
                ],
            ]
        );

        $wp_admin_bar->add_node(
            [
                'id'     => 'qs-redis-cache-panel',
                'parent' => 'qs-redis-cache',
                'title'  => '打开 Redis 面板',
                'href'   => $panel_url,
                'meta'   => [
                    'title' => '前往启灵安全防护的 Redis 面板',
                ],
            ]
        );
    }

    private static function get_lazy_admin_tabs() {
        return [
            'insights'          => '安全态势分析',
            'iprisk'            => 'IP 风险与访问管控',
            'security-optimize' => '安全优化',
            'redis-cache'       => 'Redis 对象缓存',
            'self-check'        => '插件自检',
            'alert-center'      => '安全告警中心',
            'protection'        => '主动防护防火墙',
            'route-isolation'   => 'REST 路由隔离',
            'db-toolkit'        => '数据库优化与管理',
            'nginx'             => 'Nginx 安全建议',
            'audit'             => '操作审计日志',
            'bans'              => '动态 IP 封禁',
            'sessions'          => '用户会话管理',
            'help'              => '使用说明',
        ];
    }

    public static function get_lazy_admin_tab_keys() {
        return array_keys( self::get_lazy_admin_tabs() );
    }

    public static function get_admin_tab_markup( $tab_key ) {
        $tab_key = sanitize_key( (string) $tab_key );

        if ( '' === $tab_key || ( 'scanner' !== $tab_key && ! isset( self::get_lazy_admin_tabs()[ $tab_key ] ) ) ) {
            return new WP_Error( 'invalid_tab', '未知的后台页签。' );
        }

        ob_start();
        $rendered = self::render_admin_tab_content( $tab_key );
        $markup   = trim( (string) ob_get_clean() );

        if ( ! $rendered || '' === $markup ) {
            return new WP_Error( 'tab_render_failed', '页签内容渲染失败。' );
        }

        return $markup;
    }

    private static function render_admin_tab_content( $tab_key ) {
        $tab_key = sanitize_key( (string) $tab_key );

        switch ( $tab_key ) {
            case 'scanner':
                self::render_scanner_panel();
                return true;

            case 'insights':
                self::render_security_insights_panel( QS_DB::get_security_analytics( 7 ) );
                return true;

            case 'iprisk':
                self::render_ip_risk_and_access_panel( QS_DB::get_ip_risk_analytics( 7, 80 ), QS_Protection::get_settings(), 'overview' );
                return true;

            case 'security-optimize':
                self::render_security_optimize_panel( QS_Protection::get_settings() );
                return true;

            case 'redis-cache':
                self::render_redis_cache_panel( QS_Protection::get_settings() );
                return true;

            case 'self-check':
                self::render_health_check_panel( QS_Protection::get_settings() );
                return true;

            case 'alert-center':
                self::render_alert_center_panel( QS_Protection::get_settings() );
                return true;

            case 'protection':
                self::render_protection_panel( QS_Protection::get_settings() );
                return true;

            case 'geo-block':
                self::render_ip_risk_and_access_panel( QS_DB::get_ip_risk_analytics( 7, 80 ), QS_Protection::get_settings(), 'geo' );
                return true;

            case 'route-isolation':
                self::render_route_isolation_panel( QS_Protection::get_settings() );
                return true;

            case 'db-toolkit':
                if ( class_exists( 'QS_DB_Toolkit' ) ) {
                    QS_DB_Toolkit::render_panel();
                    return true;
                }
                return false;

            case 'nginx':
                self::render_nginx_panel();
                return true;

            case 'audit':
                self::render_audit_panel();
                return true;

            case 'bans':
                self::render_bans_panel();
                return true;

            case 'sessions':
                $sessions = QS_Session_Manager::get_active_sessions( 200 );
                self::render_session_management_panel( $sessions, QS_Session_Manager::get_active_session_summary( $sessions ) );
                return true;

            case 'help':
                self::render_usage_help_panel();
                return true;
        }

        return false;
    }

    private static function render_lazy_tab_placeholder( $label, $state = 'idle', $message = '' ) {
        $label   = sanitize_text_field( (string) $label );
        $state   = sanitize_key( (string) $state );
        $message = '' !== $message ? sanitize_text_field( (string) $message ) : '';

        if ( '' === $message ) {
            if ( 'error' === $state ) {
                $message = '加载失败，请点击下方按钮重试。';
            } elseif ( 'loading' === $state ) {
                $message = '正在加载「' . $label . '」面板内容...';
            } else {
                $message = '该面板内容按需加载，以降低后台首屏开销。';
            }
        }
        ?>
        <div class="qs-tab-lazy-state is-<?php echo esc_attr( $state ); ?>">
            <div class="qs-tab-lazy-card<?php echo 'error' === $state ? ' is-error' : ''; ?>">
                <span class="dashicons <?php echo 'error' === $state ? 'dashicons-warning' : 'dashicons-update'; ?> qs-tab-lazy-icon<?php echo 'loading' === $state ? ' is-loading' : ''; ?>"></span>
                <strong><?php echo esc_html( $label ); ?></strong>
                <p><?php echo esc_html( $message ); ?></p>
                <?php if ( 'error' === $state ) : ?>
                    <button type="button" class="button button-secondary qs-tab-retry-load">重新加载此页签</button>
                <?php endif; ?>
            </div>
        </div>
        <?php
    }

    public static function render_dashboard() {
        ?>
        <div class="wrap qs-wrap">
            <h1 class="qs-title">
                <span class="dashicons dashicons-shield"></span> 启灵安全防护中心
            </h1>
            
            <?php if ( version_compare( PHP_VERSION, '8.2.35', '<' ) ) : ?>
                <div class="notice notice-warning inline" style="margin: 0 0 20px; padding: 12px 16px; border-left: 4px solid #f59e0b; background: #fffbeb; border-radius: 6px; box-shadow: 0 1px 2px rgba(0,0,0,0.05);">
                    <p style="margin: 0; font-size: 13px; color: #92400e; display: flex; align-items: center; gap: 8px;">
                        <span class="dashicons dashicons-warning" style="color: #f59e0b; font-size: 20px; width: 20px; height: 20px;"></span>
                        <span><strong>PHP 核心安全基线提示：</strong>检测到当前服务器 PHP 版本为 <code><?php echo esc_html( PHP_VERSION ); ?></code>（低于安全建议基准 <code>8.2.35</code>）。近期 PHP 核心存在严重远程代码执行漏洞（CVSS 9.8），建议站长在条件允许时将 PHP 升级至 <strong>PHP 8.2.35+</strong> 或 <strong>PHP 8.3+</strong> 以加固底层防护。</span>
                    </p>
                </div>
            <?php endif; ?>
            
            <div class="nav-tab-wrapper qs-tab-nav" role="tablist" aria-label="启灵安全防护导航">
                <a href="#tab-scanner" class="nav-tab qs-admin-tab nav-tab-active" id="qs-tab-scanner" role="tab" aria-selected="true">全盘安全体检</a>
                <a href="#tab-insights" class="nav-tab qs-admin-tab" id="qs-tab-insights" role="tab" aria-selected="false">安全态势分析</a>
                <a href="#tab-iprisk" class="nav-tab qs-admin-tab" id="qs-tab-iprisk" role="tab" aria-selected="false">IP 风险与访问管控</a>
                <a href="#tab-security-optimize" class="nav-tab qs-admin-tab" id="qs-tab-security-optimize" role="tab" aria-selected="false">安全优化</a>
                <a href="#tab-redis-cache" class="nav-tab qs-admin-tab" id="qs-tab-redis-cache" role="tab" aria-selected="false">Redis 对象缓存</a>
                <a href="#tab-self-check" class="nav-tab qs-admin-tab" id="qs-tab-self-check" role="tab" aria-selected="false">插件自检</a>
                <a href="#tab-alert-center" class="nav-tab qs-admin-tab" id="qs-tab-alert-center" role="tab" aria-selected="false">安全告警中心</a>
                <a href="#tab-protection" class="nav-tab qs-admin-tab" id="qs-tab-protection" role="tab" aria-selected="false">主动防护防火墙</a>
                <a href="#tab-route-isolation" class="nav-tab qs-admin-tab" id="qs-tab-route-isolation" role="tab" aria-selected="false">REST 路由隔离</a>
                <a href="#tab-db-toolkit" class="nav-tab qs-admin-tab" id="qs-tab-db-toolkit" role="tab" aria-selected="false">数据库优化与管理</a>
                <a href="#tab-nginx" class="nav-tab qs-admin-tab" id="qs-tab-nginx" role="tab" aria-selected="false">Nginx 安全建议</a>
                <a href="#tab-audit" class="nav-tab qs-admin-tab" id="qs-tab-audit" role="tab" aria-selected="false">操作审计日志</a>
                <a href="#tab-bans" class="nav-tab qs-admin-tab" id="qs-tab-bans" role="tab" aria-selected="false">动态 IP 封禁</a>
                <a href="#tab-sessions" class="nav-tab qs-admin-tab" id="qs-tab-sessions" role="tab" aria-selected="false">用户会话管理</a>
                <a href="#tab-help" class="nav-tab qs-admin-tab" id="qs-tab-help" role="tab" aria-selected="false">使用说明</a>
            </div>

            <div id="tab-content-scanner" class="qs-tab-content" data-tab-key="scanner" data-tab-loaded="1" role="tabpanel" aria-hidden="false">
                <?php self::render_scanner_panel(); ?>
            </div>

            <?php foreach ( self::get_lazy_admin_tabs() as $tab_key => $tab_label ) : ?>
                <div
                    id="tab-content-<?php echo esc_attr( $tab_key ); ?>"
                    class="qs-tab-content qs-tab-content-lazy"
                    data-tab-key="<?php echo esc_attr( $tab_key ); ?>"
                    data-tab-label="<?php echo esc_attr( $tab_label ); ?>"
                    data-tab-loaded="0"
                    data-tab-loading="0"
                    style="display:none; margin-top:20px;"
                    role="tabpanel"
                    aria-hidden="true"
                >
                    <?php self::render_lazy_tab_placeholder( $tab_label ); ?>
                </div>
            <?php endforeach; ?>
        </div>
        <?php
    }

    private static function render_scanner_panel() {
        $settings         = QS_Protection::get_settings();
        $last_scan        = QS_DB::get_last_scan();
        $latest_results   = ( $last_scan && ! empty( $last_scan->id ) ) ? QS_DB::get_results( $last_scan->id ) : [];
        $baseline_count   = QS_DB::get_file_baseline_count();
        $baseline_paths   = QS_Protection::get_file_integrity_paths( $settings );
        $scan_step_count  = count( QS_Scanner::get_scan_steps() );
        $total_issues     = $last_scan && isset( $last_scan->total_issues ) ? absint( $last_scan->total_issues ) : 0;
        $last_scan_status = $last_scan && ! empty( $last_scan->status ) ? sanitize_key( (string) $last_scan->status ) : '';
        $open_issues      = 0;
        $critical_issues  = 0;
        $warning_issues   = 0;

        foreach ( (array) $latest_results as $result ) {
            $result_status = ! empty( $result->status ) ? sanitize_key( (string) $result->status ) : 'open';
            $severity      = ! empty( $result->severity ) ? sanitize_key( (string) $result->severity ) : '';

            if ( 'open' === $result_status ) {
                $open_issues++;
            }

            if ( 'critical' === $severity ) {
                $critical_issues++;
            } elseif ( 'warning' === $severity ) {
                $warning_issues++;
            }
        }

        if ( 'completed' === $last_scan_status ) {
            $scan_status_text  = '最近一次体检已完成';
            $scan_status_color = '#10b981';
        } elseif ( 'running' === $last_scan_status ) {
            $scan_status_text  = '最近一次体检正在执行中';
            $scan_status_color = '#f59e0b';
        } else {
            $scan_status_text  = '还没有执行过全盘安全体检';
            $scan_status_color = '#64748b';
        }

        if ( $last_scan && ! empty( $last_scan->end_time ) ) {
            $last_scan_time = (string) $last_scan->end_time;
        } elseif ( $last_scan && ! empty( $last_scan->start_time ) ) {
            $last_scan_time = (string) $last_scan->start_time;
        } else {
            $last_scan_time = '尚无记录';
        }
        ?>
        <div class="qs-panel">
            <h2><span class="dashicons dashicons-search"></span> 全盘安全体检</h2>
            <p>用于启动全盘安全体检。扫描任务会按步骤分片执行，并汇总风险、基线、审计和封禁数据。</p>

            <div class="qs-analytics-grid">
                <?php
                self::render_analytics_metric_card( '扫描步骤', $scan_step_count, '当前版本内置的全盘体检步骤数量。', 'info' );
                self::render_analytics_metric_card( '最近风险项', $total_issues, '最近一次体检识别出的风险总数。', $total_issues > 0 ? 'warning' : 'safe' );
                self::render_analytics_metric_card( '待处理项', $open_issues, '最近一次体检里仍处于待处理状态的风险项。', $open_issues > 0 ? 'danger' : 'safe' );
                self::render_analytics_metric_card( '文件基线记录', $baseline_count, '用于比对文件新增、变更与缺失的基线数量。', $baseline_count > 0 ? 'info' : 'safe' );
                ?>
            </div>

            <div class="qs-toolbar-row">
                <div class="qs-toolbar-meta">
                    最近一次体检时间：<strong><?php echo esc_html( $last_scan_time ); ?></strong><br>
                    最近一次状态：<strong id="qs-last-scan-status" style="color:<?php echo esc_attr( $scan_status_color ); ?>;"><?php echo esc_html( $scan_status_text ); ?></strong><br>
                    最近一次结果：高危 <strong><?php echo esc_html( number_format_i18n( $critical_issues ) ); ?></strong> 项，警告 <strong><?php echo esc_html( number_format_i18n( $warning_issues ) ); ?></strong> 项
                </div>
                <div class="qs-toolbar-actions">
                    <button type="button" id="qs-start-scan" class="button button-primary button-hero">开始全盘安全体检</button>
                </div>
            </div>

            <div id="qs-progress-area" style="display:none;">
                <p id="qs-current-task" style="font-weight:600; color:#334155;">正在初始化扫描任务...</p>
                <div class="qs-progress-bar">
                    <div id="qs-progress-fill" class="qs-progress-fill"></div>
                </div>
                <p id="qs-progress-text" style="margin-bottom:0; color:#64748b;">0 / <?php echo esc_html( number_format_i18n( $scan_step_count ) ); ?> 阶段</p>
            </div>
        </div>

        <div class="qs-panel" style="margin-top:20px;">
            <h2><span class="dashicons dashicons-backup"></span> 文件完整性基线</h2>
            <p>文件完整性基线用于保存可信文件快照，后续体检可据此识别新增、变更或缺失文件。</p>

            <?php if ( empty( $settings['enable_file_integrity_baseline'] ) ) : ?>
                <div class="qs-inline-notice qs-inline-notice-warning">
                    文件完整性基线检测未启用。启用后可持续监控主题、插件与上传目录中的文件变化。
                </div>
            <?php else : ?>
                <div class="qs-inline-notice">
                    文件完整性基线检测已启用。
                    <?php if ( ! empty( $settings['auto_initialize_file_baseline'] ) ) : ?>
                        首次基线为空时，扫描将自动初始化。
                    <?php else : ?>
                        首次基线需要手动点击“重建文件基线”建立。
                    <?php endif; ?>
                </div>
            <?php endif; ?>

            <div class="qs-baseline-toolbar">
                <div class="qs-toolbar-meta">
                    当前基线记录数：<strong><?php echo esc_html( number_format_i18n( $baseline_count ) ); ?></strong><br>
                    当前监控目录：
                    <?php if ( empty( $baseline_paths ) ) : ?>
                        <span>未配置</span>
                    <?php else : ?>
                        <span>
                            <?php foreach ( (array) $baseline_paths as $baseline_path ) : ?>
                                <code><?php echo esc_html( (string) $baseline_path ); ?></code>
                            <?php endforeach; ?>
                        </span>
                    <?php endif; ?>
                </div>
                <div class="qs-toolbar-actions">
                    <button type="button" id="qs-rebuild-file-baseline" class="button">重建文件基线</button>
                    <span class="spinner qs-baseline-spinner" style="float:none; margin-top:4px;"></span>
                    <span id="qs-baseline-message" style="font-weight:bold;"></span>
                </div>
            </div>
        </div>

        <div id="qs-results-panel" class="qs-panel" style="margin-top:20px;">
            <h2><span class="dashicons dashicons-clipboard"></span> 最近一次体检结果</h2>
            <p>此处显示最近一次体检结果。体检执行过程中，当前扫描状态会实时写入下方列表。</p>

            <table class="wp-list-table widefat fixed striped">
                <thead>
                    <tr>
                        <th style="width:100px;">风险等级</th>
                        <th style="width:180px;">风险类型</th>
                        <th style="width:120px;">处理状态</th>
                        <th>详情</th>
                        <th style="width:240px;">操作</th>
                    </tr>
                </thead>
                <tbody id="qs-results-body">
                    <?php if ( empty( $latest_results ) ) : ?>
                        <tr>
                            <td colspan="5" style="text-align:center; padding:24px;">
                                还没有历史体检结果。点击上方按钮即可开始第一次全盘安全体检。
                            </td>
                        </tr>
                    <?php else : ?>
                        <?php foreach ( $latest_results as $result ) : ?>
                            <?php self::render_scan_result_row( $result ); ?>
                        <?php endforeach; ?>
                    <?php endif; ?>
                </tbody>
            </table>
        </div>
        <?php
    }

    private static function render_protection_panel( $settings ) {
        $settings = is_array( $settings ) ? $settings : QS_Protection::get_settings();
        ?>
        <div class="qs-panel">
            <h2><span class="dashicons dashicons-shield-alt"></span> 主动防护防火墙</h2>
            <p>此处集中管理启灵安全防护的核心基础设置，包括基础加固、白名单、真实 IP、登录保护、行为限速、WAF、扫描引擎高级参数、手机号归属地和数据生命周期。</p>
            <p class="description" style="margin-bottom:0;">为降低后台首屏负载，`安全优化`、`Redis 对象缓存`、`安全告警中心`、`IP 风险与访问管控`、`REST 路由隔离` 已拆分为独立页签统一管理。</p>

            <?php
            self::render_protection_settings_table(
                $settings,
                [
                    'exclude_sections' => [
                        'security_optimize',
                        'redis_cache',
                        'route_isolation',
                        'geo_block',
                        'alerts',
                        'ip_risk',
                    ],
                ]
            );
            ?>

            <p class="submit">
                <button type="button" id="qs-save-protection" class="button button-primary">保存主动防护设置</button>
                <span class="spinner qs-save-spinner" style="float:none; margin-top: 4px;"></span>
                <span id="qs-save-message" style="margin-left:10px; font-weight:bold; color:#10b981;"></span>
            </p>
        </div>

        <?php self::render_maintenance_panel(); ?>
        <?php self::render_rules_package_panel(); ?>
        <?php
    }

    private static function render_nginx_panel() {
        $nginx_rules = <<<'NGINX'
# 1. 安全响应头
add_header Strict-Transport-Security "max-age=31536000; includeSubDomains" always;
add_header X-Frame-Options "SAMEORIGIN" always;
add_header X-Content-Type-Options "nosniff" always;
add_header Referrer-Policy "strict-origin-when-cross-origin" always;
add_header Permissions-Policy "geolocation=(), microphone=(), camera=()" always;

# 2. 内容安全策略 (CSP) - 通用示例，前后台分离
# 前台使用相对收敛的策略；后台与登录页使用兼容性更高的白名单
# 资源来源未绑定具体域名，使用前请按实际业务补充或收紧来源范围
# CSP 需按站点实际资源来源配置；默认保持注释，仅作为参考策略
# set $csp_policy "default-src https: data: blob:; script-src 'unsafe-inline' https: blob:; style-src 'unsafe-inline' https:; img-src data: https: blob:; font-src data: https:; connect-src https: wss:; media-src https: data: blob:; object-src 'none'; frame-ancestors 'self'; form-action 'self' https:; base-uri 'self'; upgrade-insecure-requests;";

# if ($uri ~* "^/wp-admin(?:/|$)|^/wp-login\.php$") {
#    set $csp_policy "default-src https: data: blob:; script-src 'unsafe-inline' https: blob:; style-src 'unsafe-inline' https:; img-src data: https: blob:; font-src data: https:; connect-src https: wss:; frame-src https: data: blob:; worker-src blob:; media-src https: data: blob:; object-src 'none'; frame-ancestors 'self'; form-action 'self' https:; base-uri 'self'; upgrade-insecure-requests;";
# }

# add_header Content-Security-Policy "$csp_policy" always;

# 3. WordPress 基础接入与限速
# 请按实际部署方式接入 WordPress 重写规则，或自行编写等效的 try_files 规则
# include /path/to/wordpress-rewrite.conf;

# 注意：以下两个 zone 需要先在 nginx 全局 http {} 中定义，再在 server {} 中引用
# limit_conn qs_conn_zone 30;
# limit_req zone=qs_req_zone burst=30 nodelay;

# 4. 请求收口
# 只允许常见方法
if ($request_method !~ ^(GET|POST|HEAD)$) {
    return 444;
}

# 禁止任意 rest_route 参数访问
if ($arg_rest_route != "") {
    return 403;
}

# 5. robots / REST API 收口
location = /robots.txt {
    allow all;
    log_not_found off;
    access_log off;
}

# 禁止直接访问 /wp-json 和 /wp-json/
location = /wp-json {
    return 301 https://$host/;
}

location = /wp-json/ {
    return 301 https://$host/;
}

# 屏蔽高风险 oEmbed
location ~* ^/wp-json/oembed/1\.0(/.*)?$ {
    return 403;
}

# 其他 REST API 仍交给 WordPress
location ~* ^/wp-json(/.*)?$ {
    try_files $uri $uri/ /index.php?$args;
}

# 6. 禁止日志/调试文件与隐藏文件
location ~* \.(log|logs|debug|txt)$ {
    deny all;
    access_log off;
    log_not_found off;
}

location = /wp-content/debug.log {
    deny all;
}

location ~* ^/wp-content/.*\.(log|txt|dat|BIN|debug)$ {
    deny all;
}

location ~ /\.(?!well-known).* {
    deny all;
}

# 7. WordPress 敏感路径保护
location ~* ^/(wp-config\.php|readme\.html|license\.txt)$ {
    deny all;
}

location ~* ^/wp-includes/.*\.php$ {
    deny all;
}

location ~* ^/wp-content/uploads/.*\.php$ {
    deny all;
}

# 8. PHP 处理与静态资源缓存
location ~ [^/]\.php(/|$) {
    fastcgi_pass unix:/path/to/php-fpm.sock;
    # 或使用 TCP 方式，例如：fastcgi_pass 127.0.0.1:9000;
    fastcgi_index index.php;
    include fastcgi.conf;
}

location ~* \.(gif|jpg|jpeg|png|bmp|swf|flv|mp4|ico)$ {
    expires 30d;
    access_log off;
}

location ~* \.(js|css)$ {
    expires 7d;
    access_log off;
}

location ~ /\.ht {
    deny all;
}
NGINX;
        ?>
        <div class="qs-panel">
            <h2><span class="dashicons dashicons-editor-code"></span> Nginx 安全建议</h2>
            <p>以下内容为 WordPress + Nginx 场景的通用安全示例，涵盖响应头、CSP、请求收口、REST API 限制、敏感路径保护和静态缓存等常见段落。</p>

            <div class="qs-inline-notice">
                部署前需按实际环境调整重写规则路径、限速 zone 名称、PHP-FPM 连接方式与缓存策略。若 CDN、WAF 或服务器层已输出同类响应头，请保持单一出口，避免重复注入。
            </div>

            <div class="qs-nginx-toolbar">
                <button type="button" id="qs-copy-nginx-rules" class="button button-secondary">复制示例规则</button>
                <span id="qs-copy-nginx-message"></span>
            </div>

            <pre id="qs-nginx-code" class="qs-nginx-code-block"><code><?php echo esc_html( trim( $nginx_rules ) ); ?></code></pre>
        </div>
        <?php
    }

    private static function render_audit_panel() {
        $summary    = QS_DB::get_storage_summary();
        $audit_logs = QS_DB::get_audit_logs( 100 );
        ?>
        <div class="qs-panel">
            <h2><span class="dashicons dashicons-visibility"></span> 关键操作审计日志</h2>
            <p>记录网站后台关键敏感操作，并包含登录成功、登录失败、来源入口和封禁累积次数，方便排查撞库和爆破。最多展示最近 100 条记录。</p>

            <div class="qs-toolbar-row">
                <div class="qs-toolbar-meta">
                    当前审计日志总数：<strong><?php echo esc_html( number_format_i18n( isset( $summary['audit_logs'] ) ? (int) $summary['audit_logs'] : 0 ) ); ?></strong>
                </div>
                <div class="qs-toolbar-actions">
                    <button type="button" id="qs-clear-audit-logs" class="button">单独清空审计日志</button>
                    <span class="spinner qs-clear-audit-spinner" style="float:none; margin-top: 4px;"></span>
                    <span id="qs-clear-audit-message" style="font-weight:bold;"></span>
                </div>
            </div>

            <table class="wp-list-table widefat fixed striped">
                <thead>
                    <tr>
                        <th style="width:170px;">时间</th>
                        <th style="width:180px;">操作人</th>
                        <th style="width:160px;">动作类型</th>
                        <th>详情</th>
                        <th style="width:140px;">出处 IP</th>
                    </tr>
                </thead>
                <tbody>
                    <?php if ( empty( $audit_logs ) ) : ?>
                        <tr><td colspan="5" style="text-align:center; padding:20px;">当前还没有可展示的审计日志记录。</td></tr>
                    <?php else : ?>
                        <?php foreach ( $audit_logs as $log ) : ?>
                            <tr>
                                <td><?php echo esc_html( ! empty( $log->time ) ? (string) $log->time : '' ); ?></td>
                                <td>
                                    <strong><?php echo esc_html( ! empty( $log->username ) ? (string) $log->username : '系统' ); ?></strong>
                                    <?php if ( isset( $log->user_id ) && absint( $log->user_id ) > 0 ) : ?>
                                        <br><span style="color:#64748b;">用户 ID：<?php echo esc_html( number_format_i18n( absint( $log->user_id ) ) ); ?></span>
                                    <?php endif; ?>
                                </td>
                                <td>
                                    <span class="qs-badge <?php echo esc_attr( self::get_audit_action_badge_class( ! empty( $log->action_type ) ? (string) $log->action_type : '' ) ); ?>">
                                        <?php echo esc_html( ! empty( $log->action_type ) ? (string) $log->action_type : '-' ); ?>
                                    </span>
                                </td>
                                <td><?php echo esc_html( ! empty( $log->action_detail ) ? (string) $log->action_detail : '-' ); ?></td>
                                <td><code><?php echo esc_html( ! empty( $log->ip_address ) ? (string) $log->ip_address : '-' ); ?></code></td>
                            </tr>
                        <?php endforeach; ?>
                    <?php endif; ?>
                </tbody>
            </table>
        </div>
        <?php
    }

    private static function render_bans_panel() {
        $summary     = QS_DB::get_storage_summary();
        $banned_ips  = QS_DB::get_banned_ips( 100 );
        $current_ts  = current_time( 'timestamp' );
        ?>
        <div class="qs-panel">
            <h2><span class="dashicons dashicons-shield"></span> 动态 IP 封禁</h2>
            <p>展示当前仍处于封禁期内的来源 IP，便于核查登录爆破、行为限速或 WAF 拦截带来的封禁记录，并支持手动提前解封。</p>

            <div class="qs-toolbar-row">
                <div class="qs-toolbar-meta">
                    当前活动封禁数：<strong><?php echo esc_html( number_format_i18n( isset( $summary['active_bans'] ) ? (int) $summary['active_bans'] : 0 ) ); ?></strong>
                </div>
            </div>

            <table class="wp-list-table widefat fixed striped">
                <thead>
                    <tr>
                        <th style="width:170px;">来源 IP</th>
                        <th style="width:220px;">封禁原因</th>
                        <th style="width:170px;">封禁时间</th>
                        <th style="width:170px;">到期时间</th>
                        <th style="width:130px;">剩余时长</th>
                        <th style="width:120px;">操作</th>
                    </tr>
                </thead>
                <tbody>
                    <?php if ( empty( $banned_ips ) ) : ?>
                        <tr><td colspan="6" style="text-align:center; padding:20px;">当前没有仍在生效中的封禁 IP。</td></tr>
                    <?php else : ?>
                        <?php foreach ( $banned_ips as $ban ) : ?>
                            <?php
                            $row_id       = 'qs-ban-row-' . absint( $ban->id );
                            $expire_ts    = ! empty( $ban->expire_time ) ? strtotime( (string) $ban->expire_time ) : 0;
                            $remaining    = ( $expire_ts > $current_ts ) ? human_time_diff( $current_ts, $expire_ts ) : '即将到期';
                            ?>
                            <tr id="<?php echo esc_attr( $row_id ); ?>">
                                <td><code><?php echo esc_html( ! empty( $ban->ip_address ) ? (string) $ban->ip_address : '-' ); ?></code></td>
                                <td><?php echo esc_html( ! empty( $ban->reason ) ? (string) $ban->reason : '-' ); ?></td>
                                <td><?php echo esc_html( ! empty( $ban->ban_time ) ? (string) $ban->ban_time : '-' ); ?></td>
                                <td><?php echo esc_html( ! empty( $ban->expire_time ) ? (string) $ban->expire_time : '-' ); ?></td>
                                <td><?php echo esc_html( $remaining ); ?></td>
                                <td>
                                    <button
                                        type="button"
                                        class="button button-small qs-unban-btn"
                                        data-ip="<?php echo esc_attr( ! empty( $ban->ip_address ) ? (string) $ban->ip_address : '' ); ?>"
                                        data-row="<?php echo esc_attr( $row_id ); ?>"
                                    >立即解封</button>
                                </td>
                            </tr>
                        <?php endforeach; ?>
                    <?php endif; ?>
                </tbody>
            </table>
        </div>
        <?php
    }

    public static function get_result_status_label( $status ) {
        $labels = [
            'open'     => '待处理',
            'resolved' => '已处理',
            'ignored'  => '已忽略',
        ];

        return isset( $labels[ $status ] ) ? $labels[ $status ] : '待处理';
    }

    public static function get_result_status_class( $status ) {
        $classes = [
            'open'     => 'warning',
            'resolved' => 'success',
            'ignored'  => 'neutral',
        ];

        return isset( $classes[ $status ] ) ? $classes[ $status ] : 'warning';
    }

    public static function get_audit_action_badge_class( $action_type ) {
        $action_type = (string) $action_type;

        if ( false !== strpos( $action_type, '失败' ) || false !== strpos( $action_type, '封禁' ) ) {
            return 'warning';
        }

        if ( false !== strpos( $action_type, '成功' ) || false !== strpos( $action_type, '解封' ) ) {
            return 'success';
        }

        if ( false !== strpos( $action_type, '登出' ) ) {
            return 'neutral';
        }

        return 'info';
    }

    private static function render_security_insights_panel( $analytics ) {
        $analytics = is_array( $analytics ) ? $analytics : [];
        $summary   = isset( $analytics['summary'] ) && is_array( $analytics['summary'] ) ? $analytics['summary'] : [];
        $settings  = QS_Protection::get_settings();
        ?>
        <div class="qs-panel">
            <h2><span class="dashicons dashicons-chart-area"></span> 最近 24 小时安全态势</h2>
            <p>汇总最近 24 小时的攻击痕迹、最近 7 天的封禁趋势与未处理高危项，用于快速判断站点是否存在撞库、扫描或接口滥用。</p>

            <?php if ( empty( $settings['enable_audit_log'] ) ) : ?>
                <div class="qs-inline-notice qs-inline-notice-warning">
                    “关键操作审计日志”未启用，部分登录失败、限速命中和入口统计可能不完整。
                </div>
            <?php endif; ?>

            <div class="qs-analytics-grid">
                <?php
                self::render_analytics_metric_card( '24h 登录失败', isset( $summary['login_failures_24h'] ) ? $summary['login_failures_24h'] : 0, '用于判断是否存在撞库和密码爆破。', ! empty( $summary['login_failures_24h'] ) ? 'danger' : 'safe' );
                self::render_analytics_metric_card( '24h 限速命中', isset( $summary['rate_limits_24h'] ) ? $summary['rate_limits_24h'] : 0, '包含公开 REST、搜索、评论等行为型限速规则。', ! empty( $summary['rate_limits_24h'] ) ? 'warning' : 'safe' );
                self::render_analytics_metric_card( '当前活动封禁', isset( $summary['active_bans'] ) ? $summary['active_bans'] : 0, '仍在封禁期内的恶意来源 IP。', ! empty( $summary['active_bans'] ) ? 'danger' : 'safe' );
                self::render_analytics_metric_card( '待处理高危项', isset( $summary['critical_open'] ) ? $summary['critical_open'] : 0, '扫描报告里仍未处理的 critical 风险。', ! empty( $summary['critical_open'] ) ? 'danger' : 'safe' );
                ?>
            </div>
        </div>

        <div class="qs-analytics-panels">
            <div class="qs-panel">
                <?php self::render_analytics_top_list( '攻击来源 IP Top', isset( $analytics['top_ips'] ) ? $analytics['top_ips'] : [], '最近 24 小时还没有明显的攻击来源 IP 记录。', true ); ?>
            </div>
            <div class="qs-panel">
                <?php self::render_analytics_top_list( '被打最多的入口', isset( $analytics['top_paths'] ) ? $analytics['top_paths'] : [], '最近 24 小时还没有明显的热点入口。', false ); ?>
            </div>
        </div>

        <div class="qs-analytics-panels">
            <div class="qs-panel">
                <?php self::render_analytics_top_list( '爆破用户名 Top', isset( $analytics['top_usernames'] ) ? $analytics['top_usernames'] : [], '最近 24 小时没有明显的用户名撞库痕迹。', false ); ?>
            </div>
            <div class="qs-panel">
                <?php self::render_analytics_top_list( '最近 7 天封禁原因', isset( $analytics['ban_reasons'] ) ? $analytics['ban_reasons'] : [], '最近 7 天还没有新增封禁记录。', false ); ?>
            </div>
        </div>

        <div class="qs-panel">
            <h2><span class="dashicons dashicons-chart-bar"></span> 最近 7 天攻击趋势</h2>
            <p>按天展示登录失败、行为限速命中和新增封禁数量，用于观察异常波动。</p>
            <?php self::render_analytics_trends( isset( $analytics['trends'] ) ? $analytics['trends'] : [] ); ?>
        </div>
        <?php
    }

    public static function render_ip_risk_and_access_panel( $analytics = null, $settings = null, $initial_subtab = 'overview' ) {
        $settings       = is_array( $settings ) ? $settings : QS_Protection::get_settings();
        $analytics      = is_array( $analytics ) ? $analytics : QS_DB::get_ip_risk_analytics( 7, 80 );
        $active_subtab  = in_array( $initial_subtab, [ 'overview', 'geo', 'settings' ], true ) ? $initial_subtab : 'overview';
        $ip_risk_fields = self::get_setting_field_keys_by_section( 'ip_risk' );
        ?>
        <div class="qs-iprisk-management-container">
            <div class="qs-subtab-nav" style="display:flex; gap:10px; margin-bottom:20px; border-bottom:1px solid #e2e8f0; padding-bottom:12px;">
                <button type="button" class="button <?php echo 'overview' === $active_subtab ? 'button-primary' : ''; ?> qs-subtab-btn" data-subtab="overview">IP 风险画像与事件</button>
                <button type="button" class="button <?php echo 'geo' === $active_subtab ? 'button-primary' : ''; ?> qs-subtab-btn" data-subtab="geo">地区限制与访问策略</button>
                <button type="button" class="button <?php echo 'settings' === $active_subtab ? 'button-primary' : ''; ?> qs-subtab-btn" data-subtab="settings">IP 风险规则设置</button>
            </div>

            <!-- 子页面 1：IP 风险画像与事件 -->
            <div id="qs-iprisk-section-overview" class="qs-iprisk-section" style="<?php echo 'overview' === $active_subtab ? '' : 'display:none;'; ?>">
                <?php self::render_ip_risk_panel( $analytics, $settings ); ?>
            </div>

            <!-- 子页面 2：地区限制与访问策略 -->
            <div id="qs-iprisk-section-geo" class="qs-iprisk-section" style="<?php echo 'geo' === $active_subtab ? '' : 'display:none;'; ?>">
                <?php self::render_geo_block_panel( $settings ); ?>
            </div>

            <!-- 子页面 3：IP 风险规则设置 -->
            <div id="qs-iprisk-section-settings" class="qs-iprisk-section" style="<?php echo 'settings' === $active_subtab ? '' : 'display:none;'; ?>">
                <div class="qs-panel" data-setting-fields="<?php echo esc_attr( implode( ',', $ip_risk_fields ) ); ?>">
                    <h2>IP 风险规则与数据源</h2>
                    <p>配置登录画像的触发范围、查询模式、可用数据源及 API Key。当前聚合支持 IPData、IPinfo 和 IP-API。</p>

                    <?php self::render_protection_settings_table( $settings, [ 'include_sections' => [ 'ip_risk' ] ] ); ?>

                    <p class="submit">
                        <button type="button" id="qs-save-ip-risk" class="button button-primary">保存 IP 风险设置</button>
                        <span class="spinner qs-ip-risk-save-spinner" style="float:none; margin-top: 4px;"></span>
                        <span id="qs-save-ip-risk-message" style="margin-left:10px; font-weight:bold; color:#10b981;"></span>
                    </p>
                </div>
            </div>
        </div>
        <?php
    }

    private static function render_ip_risk_panel( $analytics, $settings ) {
        $analytics        = is_array( $analytics ) ? $analytics : [];
        $summary          = isset( $analytics['summary'] ) && is_array( $analytics['summary'] ) ? $analytics['summary'] : [];
        $risk_levels      = isset( $analytics['risk_levels'] ) && is_array( $analytics['risk_levels'] ) ? $analytics['risk_levels'] : [];
        $actions          = isset( $analytics['actions'] ) && is_array( $analytics['actions'] ) ? $analytics['actions'] : [];
        $top_ips          = isset( $analytics['top_ips'] ) && is_array( $analytics['top_ips'] ) ? $analytics['top_ips'] : [];
        $top_signals      = isset( $analytics['top_signals'] ) && is_array( $analytics['top_signals'] ) ? $analytics['top_signals'] : [];
        $recent_events    = isset( $analytics['recent_events'] ) && is_array( $analytics['recent_events'] ) ? $analytics['recent_events'] : [];
        $settings         = is_array( $settings ) ? $settings : QS_Protection::get_settings();
        $enabled          = QS_Protection::is_ip_risk_profile_enabled( $settings );
        $query_mode       = QS_Protection::get_ip_risk_query_mode( $settings );
        $scope            = QS_Protection::get_ip_risk_scope( $settings );
        $provider_status  = self::get_ip_risk_provider_statuses( $settings );
        $max_provider_num = QS_Protection::get_ip_risk_max_provider_calls( $settings );
        ?>
        <div class="qs-panel">
            <h2><span class="dashicons dashicons-admin-site"></span> 登录链路 IP 风险画像总览</h2>
            <p>本面板仅统计登录成功与登录失败链路的来源 IP，用于识别高风险来源、异常登录模式和风险信号标签。</p>

            <?php if ( ! $enabled ) : ?>
                <div class="qs-inline-notice qs-inline-notice-warning">
                    “登录 IP 风险画像”未启用。启用后可查看来源 IP 风险统计与画像明细。
                </div>
            <?php else : ?>
                <div class="qs-inline-notice">
                    查询模式：<?php echo esc_html( 'external' === $query_mode ? '外部任务' : ( 'async' === $query_mode ? '异步查询（WP-Cron）' : '同步查询' ) ); ?>，
                    触发范围：<?php echo esc_html( self::get_ip_risk_scope_label( $scope ) ); ?>，
                    单次最多查询来源：<?php echo esc_html( number_format_i18n( $max_provider_num ) ); ?>。
                    未配置 API Key 的收费来源会自动回退到可用的公共来源。
                </div>
            <?php endif; ?>

            <div class="qs-analytics-grid qs-iprisk-metrics">
                <?php
                self::render_analytics_metric_card( '画像缓存总数', isset( $summary['profiles_total'] ) ? $summary['profiles_total'] : 0, '当前已缓存的来源 IP 画像数量。', ! empty( $summary['profiles_total'] ) ? 'info' : 'safe' );
                self::render_analytics_metric_card( '高风险画像', isset( $summary['profiles_high_risk'] ) ? $summary['profiles_high_risk'] : 0, '风险等级为 high / critical 的缓存画像。', ! empty( $summary['profiles_high_risk'] ) ? 'danger' : 'safe' );
                self::render_analytics_metric_card( '24h 画像事件', isset( $summary['events_24h'] ) ? $summary['events_24h'] : 0, '最近 24 小时登录链路触发的风险画像事件总数。', ! empty( $summary['events_24h'] ) ? 'warning' : 'safe' );
                self::render_analytics_metric_card( '24h 高风险命中', isset( $summary['high_events_24h'] ) ? $summary['high_events_24h'] : 0, '最近 24 小时 high / critical 命中数。', ! empty( $summary['high_events_24h'] ) ? 'danger' : 'safe' );
                ?>
            </div>

            <div class="qs-toolbar-row qs-iprisk-toolbar">
                <div class="qs-toolbar-meta">
                    数据维护：可清空画像缓存、画像事件或全部记录；单个 IP 可在详情面板内删除。
                </div>
                <div class="qs-toolbar-actions">
                    <button type="button" id="qs-iprisk-clear-profiles" class="button">清空画像缓存</button>
                    <button type="button" id="qs-iprisk-clear-events" class="button">清空画像事件</button>
                    <button type="button" id="qs-iprisk-clear-all" class="button button-secondary">全部清空</button>
                    <span class="spinner qs-iprisk-action-spinner" style="float:none; margin-top:4px;"></span>
                    <span id="qs-iprisk-action-message" style="font-weight:bold;"></span>
                </div>
            </div>

            <div class="qs-notice-box" style="margin-top:20px;">
                <h4>外部任务访问链接</h4>
                <p>如需通过服务器计划任务或外部 URL 监控触发，可将以下链接加入对应任务系统：</p>
                <p>
                    <strong>自动刷新待处理 IP：</strong><br>
                    <code><?php echo esc_url( QS_Protection::get_ip_risk_external_cron_url( $settings ) ); ?></code>
                </p>
                <p>
                    <strong>自动清理过期历史画像（建议每天执行一次）：</strong><br>
                    <code><?php echo esc_url( QS_Protection::get_ip_risk_external_cleanup_url( $settings ) ); ?></code>
                </p>
                <p class="description">
                    * 访问密钥已自动包含在 URL 中，请妥善保管。
                </p>
            </div>
        </div>

        <div class="qs-analytics-panels">
            <div class="qs-panel">
                <h2><span class="dashicons dashicons-admin-generic"></span> 来源状态标签</h2>
                <p>带 Key 的来源可提供更完整的风险字段。未填 Key 时会自动走公共来源，不会中断画像流程。</p>
                <div class="qs-iprisk-tags">
                    <?php foreach ( $provider_status as $provider ) : ?>
                        <?php
                        $classes = [ 'qs-iprisk-tag' ];
                        if ( 'public' === $provider['mode'] ) {
                            $classes[] = 'qs-iprisk-tag-public';
                        } elseif ( 'key_ready' === $provider['mode'] ) {
                            $classes[] = 'qs-iprisk-tag-key';
                        } else {
                            $classes[] = 'qs-iprisk-tag-fallback';
                        }
                        ?>
                        <span class="<?php echo esc_attr( implode( ' ', $classes ) ); ?>">
                            <?php echo esc_html( $provider['label'] ); ?>
                            <small><?php echo esc_html( $provider['tip'] ); ?></small>
                        </span>
                    <?php endforeach; ?>
                </div>
            </div>

            <div class="qs-panel">
                <h2><span class="dashicons dashicons-analytics"></span> 主要风险分布</h2>
                <?php if ( empty( $risk_levels ) ) : ?>
                    <p style="color:#64748b; margin-bottom:0;">暂无风险等级分布数据。</p>
                <?php else : ?>
                    <div class="qs-analytics-list">
                        <?php foreach ( $risk_levels as $row ) : ?>
                            <?php
                            $level = isset( $row['label'] ) ? sanitize_key( (string) $row['label'] ) : 'unknown';
                            $count = isset( $row['count'] ) ? absint( $row['count'] ) : 0;
                            ?>
                            <div class="qs-analytics-list-item">
                                <div class="qs-analytics-list-head">
                                    <span class="qs-analytics-list-label"><?php self::render_ip_risk_level_badge( $level ); ?></span>
                                    <strong><?php echo esc_html( number_format_i18n( $count ) ); ?></strong>
                                </div>
                            </div>
                        <?php endforeach; ?>
                    </div>
                <?php endif; ?>

                <h2 style="margin-top:18px;"><span class="dashicons dashicons-filter"></span> 处置动作分布</h2>
                <?php if ( empty( $actions ) ) : ?>
                    <p style="color:#64748b; margin-bottom:0;">暂无动作分布数据。</p>
                <?php else : ?>
                    <div class="qs-analytics-list">
                        <?php foreach ( $actions as $row ) : ?>
                            <?php
                            $action = isset( $row['label'] ) ? sanitize_key( (string) $row['label'] ) : 'observe';
                            $count  = isset( $row['count'] ) ? absint( $row['count'] ) : 0;
                            ?>
                            <div class="qs-analytics-list-item">
                                <div class="qs-analytics-list-head">
                                    <span class="qs-analytics-list-label"><?php echo esc_html( self::get_ip_risk_action_label( $action ) ); ?></span>
                                    <strong><?php echo esc_html( number_format_i18n( $count ) ); ?></strong>
                                </div>
                            </div>
                        <?php endforeach; ?>
                    </div>
                <?php endif; ?>
            </div>
        </div>

        <div class="qs-analytics-panels">
            <div class="qs-panel">
                <h2><span class="dashicons dashicons-shield-alt"></span> 风险来源 IP Top</h2>
                <?php if ( empty( $top_ips ) ) : ?>
                    <p style="color:#64748b; margin-bottom:0;">最近没有可展示的 IP 风险画像记录。</p>
                <?php else : ?>
                    <div class="qs-analytics-list">
                        <?php foreach ( $top_ips as $item ) : ?>
                            <?php
                            $ip         = isset( $item['ip'] ) ? (string) $item['ip'] : '';
                            $count      = isset( $item['count'] ) ? absint( $item['count'] ) : 0;
                            $max_score  = isset( $item['max_score'] ) ? absint( $item['max_score'] ) : 0;
                            $risk_level = isset( $item['risk_level'] ) ? sanitize_key( (string) $item['risk_level'] ) : 'unknown';
                            ?>
                            <div class="qs-analytics-list-item">
                                <div class="qs-analytics-list-head">
                                    <span class="qs-analytics-list-label">
                                        <code><?php echo esc_html( $ip ); ?></code>
                                    </span>
                                    <strong><?php echo esc_html( number_format_i18n( $count ) ); ?></strong>
                                </div>
                                <div class="qs-iprisk-ip-meta">
                                    <?php self::render_ip_risk_level_badge( $risk_level ); ?>
                                    <button type="button" class="button button-small qs-iprisk-detail-btn" data-ip-address="<?php echo esc_attr( $ip ); ?>">查看详情</button>
                                </div>
                            </div>
                        <?php endforeach; ?>
                    </div>
                <?php endif; ?>
            </div>

            <div class="qs-panel">
                <h2><span class="dashicons dashicons-tag"></span> 风险信号标签</h2>
                <?php if ( empty( $top_signals ) ) : ?>
                    <p style="color:#64748b; margin-bottom:0;">暂无信号标签数据（例如 tor、proxy、abuse_high）。</p>
                <?php else : ?>
                    <div class="qs-iprisk-tags">
                        <?php foreach ( $top_signals as $signal ) : ?>
                            <?php
                            $label = isset( $signal['label'] ) ? sanitize_key( (string) $signal['label'] ) : '';
                            $count = isset( $signal['count'] ) ? absint( $signal['count'] ) : 0;
                            if ( '' === $label ) {
                                continue;
                            }
                            ?>
                            <span class="qs-iprisk-tag qs-iprisk-tag-signal">
                                <?php echo esc_html( $label ); ?>
                                <small><?php echo esc_html( number_format_i18n( $count ) ); ?></small>
                            </span>
                        <?php endforeach; ?>
                    </div>
                <?php endif; ?>
            </div>
        </div>

        <div class="qs-panel">
            <h2><span class="dashicons dashicons-list-view"></span> 最近画像事件明细</h2>
            <p>展示最近登录链路触发的 IP 风险画像事件，用于快速排查异常来源与风险等级变化。</p>
            <div class="qs-iprisk-table-wrap">
                <table class="wp-list-table widefat fixed striped qs-iprisk-table">
                    <thead>
                        <tr>
                            <th style="width:160px;">时间</th>
                            <th style="width:120px;">事件</th>
                            <th style="width:170px;">来源 IP</th>
                            <th style="width:120px;">用户</th>
                            <th style="width:120px;">风险等级</th>
                            <th style="width:100px;">状态</th>
                            <th style="width:120px;">动作</th>
                            <th style="width:100px;">详情</th>
                        </tr>
                    </thead>
                    <tbody>
                        <?php if ( empty( $recent_events ) ) : ?>
                            <tr><td colspan="8" style="text-align:center; padding:20px;">暂无画像事件数据。触发一次登录成功/失败后会自动出现。</td></tr>
                        <?php else : ?>
                            <?php foreach ( $recent_events as $event ) : ?>
                                <?php
                                $level = isset( $event['risk_level'] ) ? sanitize_key( (string) $event['risk_level'] ) : 'unknown';
                                $event_ip = isset( $event['ip_address'] ) ? (string) $event['ip_address'] : '';
                                ?>
                                <tr>
                                    <td><?php echo esc_html( isset( $event['time'] ) ? (string) $event['time'] : '' ); ?></td>
                                    <td><?php echo esc_html( self::get_ip_risk_event_type_label( isset( $event['event_type'] ) ? $event['event_type'] : '' ) ); ?></td>
                                    <td><code><?php echo esc_html( $event_ip ); ?></code></td>
                                    <td><?php echo esc_html( isset( $event['username'] ) ? (string) $event['username'] : '' ); ?></td>
                                    <td><?php self::render_ip_risk_level_badge( $level ); ?></td>
                                    <td><code><?php echo esc_html( self::get_ip_risk_profile_status_label( isset( $event['profile_status'] ) ? $event['profile_status'] : '' ) ); ?></code></td>
                                    <td><?php echo esc_html( self::get_ip_risk_action_label( isset( $event['action'] ) ? $event['action'] : '' ) ); ?></td>
                                    <td>
                                        <?php if ( '' !== $event_ip ) : ?>
                                            <button type="button" class="button button-small qs-iprisk-detail-btn" data-ip-address="<?php echo esc_attr( $event_ip ); ?>">查看详情</button>
                                        <?php else : ?>
                                            -
                                        <?php endif; ?>
                                    </td>
                                </tr>
                            <?php endforeach; ?>
                        <?php endif; ?>
                    </tbody>
                </table>
            </div>

            <div id="qs-iprisk-detail-panel" class="qs-iprisk-detail-panel" style="display:none;">
                <div class="qs-toolbar-row" style="margin-top:0;">
                    <h3 style="margin:0;">IP 详细画像：<code id="qs-iprisk-detail-ip"></code></h3>
                    <div class="qs-toolbar-actions">
                        <button type="button" id="qs-iprisk-delete-current" class="button button-small" data-ip-address="" disabled>删除该 IP 记录</button>
                    </div>
                </div>
                <p id="qs-iprisk-detail-meta" class="qs-iprisk-detail-meta"></p>

                <div class="qs-iprisk-detail-grid">
                    <div>
                        <h4>风险标签</h4>
                        <div id="qs-iprisk-detail-signals" class="qs-iprisk-tags"></div>
                    </div>
                    <div>
                        <h4>来源计划</h4>
                        <div id="qs-iprisk-detail-provider-plan" class="qs-iprisk-tags"></div>
                    </div>
                </div>

                <h4 style="margin-top:16px;">来源查询明细</h4>
                <div id="qs-iprisk-detail-providers" class="qs-iprisk-detail-providers"></div>

                <h4 style="margin-top:16px;">该 IP 最近登录画像事件</h4>
                <div class="qs-iprisk-table-wrap">
                    <table class="wp-list-table widefat fixed striped qs-iprisk-table">
                        <thead>
                            <tr>
                                <th style="width:160px;">时间</th>
                                <th style="width:100px;">事件</th>
                                <th style="width:120px;">用户</th>
                                <th style="width:120px;">风险等级</th>
                                <th style="width:100px;">状态</th>
                                <th style="width:100px;">动作</th>
                            </tr>
                        </thead>
                        <tbody id="qs-iprisk-detail-events-body">
                            <tr><td colspan="6" style="text-align:center; padding:20px;">点击上方“查看详情”加载该 IP 的完整画像数据。</td></tr>
                        </tbody>
                    </table>
                </div>
            </div>
        </div>
        <?php
    }

    private static function get_ip_risk_provider_statuses( $settings ) {
        $settings    = is_array( $settings ) ? $settings : QS_Protection::get_settings();
        $providers   = QS_Protection::get_ip_risk_provider_list( $settings );
        $credentials = QS_Protection::get_ip_risk_provider_credentials( $settings );
        $catalog     = self::get_ip_risk_provider_catalog();
        $statuses    = [];

        foreach ( (array) $providers as $provider_id ) {
            $provider_id = sanitize_key( str_replace( '-', '_', (string) $provider_id ) );
            if ( '' === $provider_id ) {
                continue;
            }

            $provider = isset( $catalog[ $provider_id ] ) ? $catalog[ $provider_id ] : [
                'label'        => $provider_id,
                'requires_key' => false,
                'key_field'    => '',
            ];

            $key_field    = isset( $provider['key_field'] ) ? (string) $provider['key_field'] : '';
            $has_key      = '' !== $key_field && ! empty( $credentials[ $key_field ] );
            $requires_key = ! empty( $provider['requires_key'] );

            if ( $has_key ) {
                $statuses[] = [
                    'id'    => $provider_id,
                    'label' => $provider['label'],
                    'mode'  => 'key_ready',
                    'tip'   => '已配置 Key',
                ];
            } elseif ( $requires_key ) {
                $statuses[] = [
                    'id'    => $provider_id,
                    'label' => $provider['label'],
                    'mode'  => 'fallback',
                    'tip'   => '无 Key，自动回退公共',
                ];
            } else {
                $statuses[] = [
                    'id'    => $provider_id,
                    'label' => $provider['label'],
                    'mode'  => 'public',
                    'tip'   => '' !== $key_field ? '未配置 Key，当前公共查询' : '公共查询',
                ];
            }
        }

        return $statuses;
    }

    private static function get_ip_risk_provider_catalog() {
        return [
            'ipdata' => [ 'label' => 'IPData', 'requires_key' => true, 'key_field' => 'ipdata_key' ],
            'ip_api' => [ 'label' => 'IP-API (延迟高)', 'requires_key' => false, 'key_field' => '' ],
            'ipinfo' => [ 'label' => 'IPinfo', 'requires_key' => false, 'key_field' => 'ipinfo_token' ],
        ];
    }

    private static function render_ip_risk_level_badge( $level ) {
        $level = sanitize_key( (string) $level );
        $map   = [
            'safe'     => [ 'label' => '安全', 'class' => 'success' ],
            'low'      => [ 'label' => '低风险', 'class' => 'info' ],
            'medium'   => [ 'label' => '中风险', 'class' => 'warning' ],
            'high'     => [ 'label' => '高风险', 'class' => 'critical' ],
            'critical' => [ 'label' => '严重', 'class' => 'critical' ],
            'unknown'  => [ 'label' => '未知', 'class' => 'neutral' ],
        ];
        $meta = isset( $map[ $level ] ) ? $map[ $level ] : $map['unknown'];
        ?>
        <span class="qs-badge <?php echo esc_attr( $meta['class'] ); ?>"><?php echo esc_html( $meta['label'] ); ?></span>
        <?php
    }

    private static function get_ip_risk_scope_label( $scope ) {
        $scope = sanitize_key( (string) $scope );
        $map   = [
            'both'         => '登录成功 + 登录失败',
            'attempt_only' => '仅登录失败',
            'success_only' => '仅登录成功',
        ];

        return isset( $map[ $scope ] ) ? $map[ $scope ] : $map['both'];
    }

    private static function get_ip_risk_event_type_label( $event_type ) {
        $event_type = sanitize_key( (string) $event_type );
        $map        = [
            'login_success' => '登录成功',
            'login_failed'  => '登录失败',
        ];

        return isset( $map[ $event_type ] ) ? $map[ $event_type ] : ( '' !== $event_type ? $event_type : '未知事件' );
    }

    private static function get_ip_risk_action_label( $action ) {
        $action = sanitize_key( (string) $action );
        $map    = [
            'observe' => '观察',
            'alert'   => '告警',
            'block'   => '拦截',
        ];

        return isset( $map[ $action ] ) ? $map[ $action ] : ( '' !== $action ? $action : '观察' );
    }

    private static function get_ip_risk_profile_status_label( $status ) {
        $status = sanitize_key( (string) $status );
        $map    = [
            'ready'         => '已完成',
            'stale'         => '缓存过期',
            'failed'        => '查询失败',
            'skipped'       => '已跳过',
            'pending'       => '等待查询',
            'pending_async' => '异步处理中',
            'pending_external' => '等待外部任务',
            'private_ip'    => '内网IP',
            'missing'       => '无画像',
            'unknown'       => '未知',
        ];

        return isset( $map[ $status ] ) ? $map[ $status ] : ( '' !== $status ? $status : '未知' );
    }

    private static function render_analytics_metric_card( $label, $value, $description, $tone = 'info' ) {
        ?>
        <div class="qs-stat-box qs-analytics-card qs-analytics-card-<?php echo esc_attr( $tone ); ?>">
            <strong><?php echo esc_html( $label ); ?></strong>
            <span class="qs-analytics-card-value"><?php echo esc_html( number_format_i18n( (int) $value ) ); ?></span>
            <p><?php echo esc_html( $description ); ?></p>
        </div>
        <?php
    }

    private static function render_analytics_top_list( $title, $items, $empty_message, $use_code_style = false ) {
        $items     = is_array( $items ) ? $items : [];
        $max_count = 0;

        foreach ( $items as $item ) {
            $count = isset( $item['count'] ) ? absint( $item['count'] ) : 0;
            if ( $count > $max_count ) {
                $max_count = $count;
            }
        }
        ?>
        <h2><span class="dashicons dashicons-list-view"></span> <?php echo esc_html( $title ); ?></h2>
        <?php if ( empty( $items ) ) : ?>
            <p style="color:#64748b; margin-bottom:0;"><?php echo esc_html( $empty_message ); ?></p>
        <?php else : ?>
            <div class="qs-analytics-list">
                <?php foreach ( $items as $item ) : ?>
                    <?php
                    $label = isset( $item['label'] ) ? (string) $item['label'] : '';
                    $count = isset( $item['count'] ) ? absint( $item['count'] ) : 0;
                    $width = $max_count > 0 ? max( 8, min( 100, (int) round( ( $count / $max_count ) * 100 ) ) ) : 0;
                    ?>
                    <div class="qs-analytics-list-item">
                        <div class="qs-analytics-list-head">
                            <span class="qs-analytics-list-label">
                                <?php if ( $use_code_style ) : ?>
                                    <code><?php echo esc_html( $label ); ?></code>
                                <?php else : ?>
                                    <?php echo esc_html( $label ); ?>
                                <?php endif; ?>
                            </span>
                            <strong><?php echo esc_html( number_format_i18n( $count ) ); ?></strong>
                        </div>
                        <div class="qs-analytics-bar">
                            <span style="width: <?php echo esc_attr( $width ); ?>%;"></span>
                        </div>
                    </div>
                <?php endforeach; ?>
            </div>
        <?php endif; ?>
        <?php
    }

    private static function render_analytics_trends( $trends ) {
        $trends = is_array( $trends ) ? $trends : [];
        $max    = 0;

        foreach ( $trends as $trend ) {
            $daily_max = max(
                isset( $trend['login_failures'] ) ? absint( $trend['login_failures'] ) : 0,
                isset( $trend['rate_limits'] ) ? absint( $trend['rate_limits'] ) : 0,
                isset( $trend['bans'] ) ? absint( $trend['bans'] ) : 0
            );

            if ( $daily_max > $max ) {
                $max = $daily_max;
            }
        }

        if ( empty( $trends ) ) {
            ?>
            <p style="color:#64748b; margin-bottom:0;">暂无可展示的趋势数据。</p>
            <?php
            return;
        }
        ?>
        <div class="qs-trend-legend">
            <span><i class="qs-trend-dot qs-trend-dot-danger"></i> 登录失败</span>
            <span><i class="qs-trend-dot qs-trend-dot-warning"></i> 行为限速</span>
            <span><i class="qs-trend-dot qs-trend-dot-info"></i> 新增封禁</span>
        </div>
        <div class="qs-trend-table">
            <?php foreach ( $trends as $trend ) : ?>
                <?php
                $login_failures = isset( $trend['login_failures'] ) ? absint( $trend['login_failures'] ) : 0;
                $rate_limits    = isset( $trend['rate_limits'] ) ? absint( $trend['rate_limits'] ) : 0;
                $bans           = isset( $trend['bans'] ) ? absint( $trend['bans'] ) : 0;
                $login_width    = $max > 0 ? max( 0, (int) round( ( $login_failures / $max ) * 100 ) ) : 0;
                $limit_width    = $max > 0 ? max( 0, (int) round( ( $rate_limits / $max ) * 100 ) ) : 0;
                $ban_width      = $max > 0 ? max( 0, (int) round( ( $bans / $max ) * 100 ) ) : 0;
                ?>
                <div class="qs-trend-row">
                    <div class="qs-trend-day"><?php echo esc_html( isset( $trend['label'] ) ? $trend['label'] : '' ); ?></div>
                    <div class="qs-trend-bars">
                        <div class="qs-trend-bar-group">
                            <span class="qs-trend-bar qs-trend-bar-danger" style="width: <?php echo esc_attr( $login_width ); ?>%;"></span>
                        </div>
                        <div class="qs-trend-bar-group">
                            <span class="qs-trend-bar qs-trend-bar-warning" style="width: <?php echo esc_attr( $limit_width ); ?>%;"></span>
                        </div>
                        <div class="qs-trend-bar-group">
                            <span class="qs-trend-bar qs-trend-bar-info" style="width: <?php echo esc_attr( $ban_width ); ?>%;"></span>
                        </div>
                    </div>
                    <div class="qs-trend-values">
                        <span><?php echo esc_html( number_format_i18n( $login_failures ) ); ?></span>
                        <span><?php echo esc_html( number_format_i18n( $rate_limits ) ); ?></span>
                        <span><?php echo esc_html( number_format_i18n( $bans ) ); ?></span>
                    </div>
                </div>
            <?php endforeach; ?>
        </div>
        <?php
    }

    private static function render_scan_result_row( $result ) {
        $severity_badge_class = 'qs-badge';
        $severity_text        = '提示';
        $status               = ! empty( $result->status ) ? $result->status : 'open';

        if ( 'critical' === $result->severity ) {
            $severity_badge_class .= ' critical';
            $severity_text = '高危';
        } elseif ( 'warning' === $result->severity ) {
            $severity_badge_class .= ' warning';
            $severity_text = '警告';
        } else {
            $severity_badge_class .= ' info';
        }
        ?>
        <tr
            id="qs-result-row-<?php echo esc_attr( $result->id ); ?>"
            class="qs-result-row is-status-<?php echo esc_attr( $status ); ?>"
            data-result-id="<?php echo esc_attr( $result->id ); ?>"
            data-has-advice="<?php echo ! empty( $result->advice ) ? '1' : '0'; ?>"
            data-status="<?php echo esc_attr( $status ); ?>"
        >
            <td><span class="<?php echo esc_attr( $severity_badge_class ); ?>"><?php echo esc_html( $severity_text ); ?></span></td>
            <td><strong><?php echo esc_html( $result->issue_type ); ?></strong></td>
            <td class="qs-result-status-cell">
                <span class="qs-badge <?php echo esc_attr( self::get_result_status_class( $status ) ); ?>">
                    <?php echo esc_html( self::get_result_status_label( $status ) ); ?>
                </span>
            </td>
            <td>
                <div style="color:#b91c1c; font-weight:500; margin-bottom:4px;"><?php echo esc_html( $result->file_path ); ?></div>
                <div style="font-size:13px; color:#555;"><?php echo esc_html( $result->detail ); ?></div>
                <?php if ( ! empty( $result->advice ) ) : ?>
                    <div class="qs-advice-box" style="display:none; margin-top:10px; padding:12px; background:#fff8e5; border-left:4px solid #f59e0b; font-size:13px; color:#333;">
                        <strong style="display:flex; align-items:center; margin-bottom:5px;">
                            <span class="dashicons dashicons-lightbulb" style="margin-right:4px;"></span>修复建议指南：
                        </strong>
                        <?php echo esc_html( $result->advice ); ?>
                    </div>
                <?php endif; ?>
            </td>
            <td class="qs-result-actions-cell">
                <?php self::render_result_action_buttons( $result ); ?>
            </td>
        </tr>
        <?php
    }

    private static function render_result_action_buttons( $result ) {
        $status     = ! empty( $result->status ) ? $result->status : 'open';
        $has_advice = ! empty( $result->advice );
        ?>
        <div class="qs-result-actions">
            <?php if ( $has_advice ) : ?>
                <button type="button" class="button button-small qs-toggle-advice">查看建议</button>
            <?php endif; ?>

            <?php if ( 'open' === $status ) : ?>
                <button type="button" class="button button-small qs-result-status-btn" data-result-id="<?php echo esc_attr( $result->id ); ?>" data-status="resolved">标记已处理</button>
                <button type="button" class="button button-small qs-result-status-btn" data-result-id="<?php echo esc_attr( $result->id ); ?>" data-status="ignored">忽略</button>
            <?php else : ?>
                <button type="button" class="button button-small qs-result-status-btn" data-result-id="<?php echo esc_attr( $result->id ); ?>" data-status="open">恢复待处理</button>
            <?php endif; ?>
        </div>
        <?php
    }

    private static function render_maintenance_panel() {
        $summary = QS_DB::get_storage_summary();
        ?>
        <div class="qs-panel" style="margin-top:20px;">
            <h2><span class="dashicons dashicons-database-view"></span> 数据维护与清理</h2>
            <p>用于按数据生命周期配置清理过期记录，并删除已过期的封禁数据。下方数字显示的是当前存量，不代表本次清理数量。</p>

            <div class="qs-maintenance-grid">
                <div class="qs-stat-box">
                    <strong>扫描任务</strong>
                    <span><?php echo esc_html( number_format_i18n( $summary['scans'] ) ); ?></span>
                </div>
                <div class="qs-stat-box">
                    <strong>扫描结果</strong>
                    <span><?php echo esc_html( number_format_i18n( $summary['results'] ) ); ?></span>
                </div>
                <div class="qs-stat-box">
                    <strong>审计日志</strong>
                    <span><?php echo esc_html( number_format_i18n( $summary['audit_logs'] ) ); ?></span>
                </div>
                <div class="qs-stat-box">
                    <strong>活动封禁 / 过期封禁</strong>
                    <span><?php echo esc_html( number_format_i18n( $summary['active_bans'] ) . ' / ' . number_format_i18n( $summary['expired_bans'] ) ); ?></span>
                </div>
                <div class="qs-stat-box">
                    <strong>文件基线</strong>
                    <span><?php echo esc_html( number_format_i18n( $summary['baseline_files'] ) ); ?></span>
                </div>
                <div class="qs-stat-box">
                    <strong>手机号归属地缓存</strong>
                    <span><?php echo esc_html( number_format_i18n( isset( $summary['phone_cache'] ) ? $summary['phone_cache'] : 0 ) ); ?></span>
                </div>
                <div class="qs-stat-box">
                    <strong>IP 地区缓存</strong>
                    <span><?php echo esc_html( number_format_i18n( isset( $summary['ip_geo_cache'] ) ? $summary['ip_geo_cache'] : 0 ) ); ?></span>
                </div>
                <div class="qs-stat-box">
                    <strong>地区限制日志</strong>
                    <span><?php echo esc_html( number_format_i18n( isset( $summary['geo_block_logs'] ) ? $summary['geo_block_logs'] : 0 ) ); ?></span>
                </div>
                <div class="qs-stat-box">
                    <strong>REST 路由隔离日志</strong>
                    <span><?php echo esc_html( number_format_i18n( isset( $summary['rest_isolation_logs'] ) ? $summary['rest_isolation_logs'] : 0 ) ); ?></span>
                </div>
                <div class="qs-stat-box">
                    <strong>IP 风险画像缓存</strong>
                    <span><?php echo esc_html( number_format_i18n( isset( $summary['ip_risk_profiles'] ) ? $summary['ip_risk_profiles'] : 0 ) ); ?></span>
                </div>
                <div class="qs-stat-box">
                    <strong>IP 风险登录事件</strong>
                    <span><?php echo esc_html( number_format_i18n( isset( $summary['ip_risk_events'] ) ? $summary['ip_risk_events'] : 0 ) ); ?></span>
                </div>
            </div>

            <div class="qs-notice-box">
                <h4>危险操作提示</h4>
                <p>“清空全部历史数据”会一次性删除扫描任务、扫描结果、审计日志、封禁记录、文件基线、手机号归属地缓存、IP 地区缓存、地区限制日志、REST 路由隔离日志、IP 风险画像缓存和 IP 风险登录事件，且无法恢复。该操作不会删除防护设置和官方规则包，请仅在确认需要瘦身数据表或重置历史记录时使用。</p>
            </div>

            <p class="submit">
                <button type="button" id="qs-cleanup-data" class="button">立即清理过期历史数据</button>
                <button type="button" id="qs-clear-all-history" class="button button-secondary">清空全部历史数据</button>
                <span class="spinner qs-cleanup-spinner" style="float:none; margin-top: 4px;"></span>
                <span id="qs-cleanup-message" style="margin-left:10px; font-weight:bold;"></span>
            </p>
        </div>
        <?php
    }

    private static function render_rules_package_panel() {
        $status       = QS_Rules::get_package_status();
        $source_label = ! empty( $status['source_label'] ) ? $status['source_label'] : '内置规则';
        $version      = ! empty( $status['version'] ) ? $status['version'] : 'unknown';
        $updated_at   = ! empty( $status['updated_at'] ) ? $status['updated_at'] : '内置随插件发布';
        $builtin_ver  = ! empty( $status['builtin_version'] ) ? $status['builtin_version'] : 'unknown';
        $hash_preview = ! empty( $status['hash'] ) ? substr( (string) $status['hash'], 0, 12 ) . '…' : '-';
        ?>
        <div class="qs-panel" style="margin-top:20px;">
            <h2><span class="dashicons dashicons-update"></span> 官方扫描规则更新</h2>
            <p>规则包只影响“扫描判断标准”，不会自动修复网站。导入与回滚都由管理员手动触发，不依赖 WP-Cron。规则包请联系插件作者获取官方版本。</p>

            <div class="qs-notice-box">
                <h4>获取方式</h4>
                <p>官方规则包请联系插件作者获取。请勿使用来源不明的规则文件，以免导入失败或影响扫描判断。</p>
            </div>

            <div class="qs-maintenance-grid">
                <div class="qs-stat-box">
                    <strong>当前来源</strong>
                    <span><?php echo esc_html( $source_label ); ?></span>
                </div>
                <div class="qs-stat-box">
                    <strong>当前规则版本</strong>
                    <span><?php echo esc_html( $version ); ?></span>
                </div>
                <div class="qs-stat-box">
                    <strong>内置规则版本</strong>
                    <span><?php echo esc_html( $builtin_ver ); ?></span>
                </div>
                <div class="qs-stat-box">
                    <strong>规则包哈希</strong>
                    <span><code><?php echo esc_html( $hash_preview ); ?></code></span>
                </div>
            </div>

            <div class="qs-toolbar-row">
                <div class="qs-toolbar-meta">
                    最近生效时间：<strong><?php echo esc_html( $updated_at ); ?></strong>
                    <?php if ( ! empty( $status['has_previous'] ) ) : ?>
                        <br>
                        可回滚版本：<strong><?php echo esc_html( $status['previous_version'] ); ?></strong>
                        <?php if ( ! empty( $status['previous_updated_at'] ) ) : ?>
                            （<?php echo esc_html( $status['previous_updated_at'] ); ?>）
                        <?php endif; ?>
                    <?php else : ?>
                        <br><span>暂无可回滚的上一版官方规则。</span>
                    <?php endif; ?>
                </div>
                <div class="qs-toolbar-actions qs-rules-actions">
                    <input type="file" id="qs-rules-package-file" accept=".json,application/json">
                    <button type="button" id="qs-import-rules-package" class="button button-primary">导入官方规则包</button>
                    <button type="button" id="qs-rollback-rules-package" class="button" <?php disabled( empty( $status['has_previous'] ) ); ?>>回滚上一版规则</button>
                    <span class="spinner qs-rules-spinner" style="float:none; margin-top: 4px;"></span>
                    <span id="qs-rules-message" style="font-weight:bold;"></span>
                </div>
            </div>

            <p class="description" style="margin-bottom:0;">
                请上传作者提供的官方规则包。插件会自动校验文件完整性与官方签名，未签名或非官方规则包会被拒绝导入。
            </p>
        </div>
        <?php
    }

    private static function render_session_management_panel( $sessions, $summary ) {
        $sessions = is_array( $sessions ) ? $sessions : [];
        $summary  = is_array( $summary ) ? $summary : [];
        $current_user_id = get_current_user_id();
        ?>
        <div class="qs-panel">
            <h2><span class="dashicons dashicons-admin-users"></span> 活跃登录会话管理</h2>
            <p>展示当前有效的登录会话，可按设备、按用户或全站范围执行下线操作，不新增额外 cron 任务。</p>

            <div class="qs-toolbar-row">
                <div class="qs-toolbar-meta">
                    当前活跃会话：<strong><?php echo esc_html( number_format_i18n( isset( $summary['sessions'] ) ? $summary['sessions'] : 0 ) ); ?></strong>
                    ，涉及用户：<strong><?php echo esc_html( number_format_i18n( isset( $summary['users'] ) ? $summary['users'] : 0 ) ); ?></strong>
                    <?php if ( ! empty( $summary['current_sessions'] ) ) : ?>
                        ，当前管理员会话：<strong><?php echo esc_html( number_format_i18n( $summary['current_sessions'] ) ); ?></strong>
                    <?php endif; ?>
                </div>
                <div class="qs-toolbar-actions">
                    <button type="button" id="qs-destroy-all-sessions" class="button">强制全部用户重新登录</button>
                    <span class="spinner qs-sessions-spinner" style="float:none; margin-top: 4px;"></span>
                    <span id="qs-sessions-message" style="font-weight:bold;"></span>
                </div>
            </div>

            <table class="wp-list-table widefat fixed striped">
                <thead>
                    <tr>
                        <th style="width:180px;">用户</th>
                        <th style="width:180px;">角色</th>
                        <th style="width:150px;">登录时间</th>
                        <th style="width:150px;">到期时间</th>
                        <th style="width:140px;">来源 IP</th>
                        <th>设备 / User-Agent</th>
                        <th style="width:220px;">操作</th>
                    </tr>
                </thead>
                <tbody>
                    <?php if ( empty( $sessions ) ) : ?>
                        <tr><td colspan="7" style="text-align:center; padding:20px;">当前没有活跃登录会话，或站点暂时未产生可管理的用户会话。</td></tr>
                    <?php else : ?>
                        <?php foreach ( $sessions as $session ) : ?>
                            <?php
                            $row_id           = 'qs-session-row-' . md5( (string) $session['user_id'] . ':' . (string) $session['verifier'] );
                            $is_current_user  = $current_user_id === absint( $session['user_id'] );
                            $preserve_current = $is_current_user ? '1' : '0';
                            ?>
                            <tr id="<?php echo esc_attr( $row_id ); ?>">
                                <td>
                                    <strong><?php echo esc_html( $session['user_login'] ); ?></strong><br>
                                    <span style="color:#64748b;"><?php echo esc_html( $session['display_name'] ); ?></span>
                                    <?php if ( ! empty( $session['is_current'] ) ) : ?>
                                        <div style="margin-top:6px;"><span class="qs-badge info">当前会话</span></div>
                                    <?php endif; ?>
                                </td>
                                <td><?php echo esc_html( implode( '、', (array) $session['roles'] ) ); ?></td>
                                <td><?php echo esc_html( QS_Session_Manager::format_session_time( isset( $session['login'] ) ? $session['login'] : 0 ) ); ?></td>
                                <td><?php echo esc_html( QS_Session_Manager::format_session_time( isset( $session['expiration'] ) ? $session['expiration'] : 0 ) ); ?></td>
                                <td><code><?php echo esc_html( ! empty( $session['ip'] ) ? $session['ip'] : '-' ); ?></code></td>
                                <td>
                                    <div style="font-weight:600; color:#334155;"><?php echo esc_html( $session['ua_summary'] ); ?></div>
                                    <?php if ( ! empty( $session['ua'] ) ) : ?>
                                        <div style="margin-top:4px; color:#64748b; font-size:12px; word-break:break-word;"><?php echo esc_html( $session['ua'] ); ?></div>
                                    <?php endif; ?>
                                </td>
                                <td>
                                    <div class="qs-result-actions">
                                        <?php if ( empty( $session['is_current'] ) ) : ?>
                                            <button
                                                type="button"
                                                class="button button-small qs-destroy-session-btn"
                                                data-user-id="<?php echo esc_attr( $session['user_id'] ); ?>"
                                                data-verifier="<?php echo esc_attr( $session['verifier'] ); ?>"
                                            >下线此设备</button>
                                        <?php endif; ?>
                                        <button
                                            type="button"
                                            class="button button-small qs-destroy-user-sessions-btn"
                                            data-user-id="<?php echo esc_attr( $session['user_id'] ); ?>"
                                            data-preserve-current="<?php echo esc_attr( $preserve_current ); ?>"
                                        ><?php echo $is_current_user ? '仅下线其他会话' : '下线该用户全部会话'; ?></button>
                                    </div>
                                </td>
                            </tr>
                        <?php endforeach; ?>
                    <?php endif; ?>
                </tbody>
            </table>
        </div>
        <?php
    }

    private static function render_theme_overlap_overview_notice() {
        $notice = QS_Protection::get_theme_overlap_overview_notice();

        if ( empty( $notice['message'] ) ) {
            return;
        }
        ?>
        <div class="qs-inline-notice qs-inline-notice-<?php echo esc_attr( ! empty( $notice['tone'] ) ? $notice['tone'] : 'info' ); ?>">
            <?php echo esc_html( $notice['message'] ); ?>
        </div>
        <?php
    }

    private static function render_geo_block_panel( $settings ) {
        $settings        = is_array( $settings ) ? $settings : QS_Protection::get_settings();
        $selected_fields = self::get_setting_field_keys_by_section( 'geo_block' );
        ?>
        <div class="qs-panel" data-setting-fields="<?php echo esc_attr( implode( ',', $selected_fields ) ); ?>">
            <h2><span class="dashicons dashicons-location-alt"></span> 地区限制</h2>
            <p>按真实访客 IP 查询访问地区，命中禁止列表后返回 403 Forbidden，或跳转到已配置的外部地址。本面板仅负责地区限制设置和命中日志。</p>

            <?php self::render_protection_settings_table( $settings, [ 'include_sections' => [ 'geo_block' ] ] ); ?>

            <p class="submit">
                <button type="button" id="qs-save-geo-block" class="button button-primary">保存地区限制设置</button>
                <span class="spinner qs-geo-block-save-spinner" style="float:none; margin-top: 4px;"></span>
                <span id="qs-save-geo-block-message" style="margin-left:10px; font-weight:bold; color:#10b981;"></span>
            </p>
        </div>

        <?php self::render_geo_block_cache_panel(); ?>
        <?php self::render_geo_block_logs_panel( $settings ); ?>
        <?php
    }

    private static function render_geo_block_cache_panel() {
        $summary = QS_DB::get_storage_summary();
        ?>
        <div class="qs-panel" style="margin-top:20px;">
            <h2><span class="dashicons dashicons-database-view"></span> IP 地区缓存</h2>
            <p>地区限制会按“IP + 查询来源”缓存地区结果，减少重复请求外部接口。当前共有 <strong><?php echo esc_html( number_format_i18n( isset( $summary['ip_geo_cache'] ) ? $summary['ip_geo_cache'] : 0 ) ); ?></strong> 条缓存。</p>
            <p class="submit" style="display:flex; align-items:center; gap:8px; flex-wrap:wrap;">
                <button type="button" id="qs-cleanup-ip-geo-cache" class="button">清理过期 IP 地区缓存</button>
                <button type="button" id="qs-clear-ip-geo-cache" class="button button-secondary">清空 IP 地区缓存</button>
                <span class="spinner qs-ip-geo-cache-spinner" style="float:none; margin-top:0;"></span>
                <span id="qs-ip-geo-cache-message" style="font-weight:bold;"></span>
            </p>
            <p class="description">过期清理会删除 180 天未命中的地区缓存；清空后后续访问会重新请求所选 IP 查询来源。</p>
        </div>
        <?php
    }

    private static function render_geo_block_logs_panel( $settings ) {
        $settings       = is_array( $settings ) ? $settings : QS_Protection::get_settings();
        $logs           = QS_DB::get_geo_block_logs( 100 );
        $total          = QS_DB::get_geo_block_log_count();
        $retention_days = isset( $settings['geo_block_log_retention_days'] ) ? absint( $settings['geo_block_log_retention_days'] ) : 180;
        $providers      = QS_Protection::get_geo_block_provider_choices();
        ?>
        <div class="qs-panel" style="margin-top:20px;">
            <h2><span class="dashicons dashicons-list-view"></span> 地区限制日志</h2>
            <p>展示最近 100 条地区限制命中记录。当前共有 <strong><?php echo esc_html( number_format_i18n( $total ) ); ?></strong> 条日志。</p>

            <p class="submit" style="display:flex; align-items:center; gap:8px; flex-wrap:wrap;">
                <button type="button" id="qs-cleanup-geo-block-logs" class="button">清理过期地区限制日志</button>
                <button type="button" id="qs-clear-geo-block-logs" class="button button-secondary">清空地区限制日志</button>
                <span class="spinner qs-geo-block-logs-spinner" style="float:none; margin-top:0;"></span>
                <span id="qs-geo-block-logs-message" style="font-weight:bold;"></span>
            </p>
            <p class="description">过期清理会按当前设置删除早于 <?php echo esc_html( number_format_i18n( $retention_days ) ); ?> 天的日志；填 0 时不会按天数清理。</p>

            <table class="wp-list-table widefat fixed striped">
                <thead>
                    <tr>
                        <th style="width:150px;">时间</th>
                        <th style="width:135px;">IP</th>
                        <th style="width:120px;">地区</th>
                        <th style="width:110px;">来源</th>
                        <th style="width:90px;">动作</th>
                        <th style="width:110px;">原因</th>
                        <th>请求</th>
                        <th>User-Agent</th>
                        <th>Referer</th>
                    </tr>
                </thead>
                <tbody>
                    <?php if ( empty( $logs ) ) : ?>
                        <tr>
                            <td colspan="9" style="text-align:center; padding:20px;">当前还没有地区限制命中日志。</td>
                        </tr>
                    <?php else : ?>
                        <?php foreach ( $logs as $log ) : ?>
                            <?php
                            $country_code  = ! empty( $log->country_code ) ? (string) $log->country_code : '';
                            $country_name  = ! empty( $log->country_name ) ? (string) $log->country_name : '';
                            $country_label = trim( $country_name . ( '' !== $country_code ? ' (' . $country_code . ')' : '' ) );
                            $provider      = ! empty( $log->provider ) ? (string) $log->provider : '';
                            $provider_label = isset( $providers[ $provider ] ) ? $providers[ $provider ] : $provider;
                            $method        = ! empty( $log->request_method ) ? (string) $log->request_method : '';
                            $path          = ! empty( $log->request_path ) ? (string) $log->request_path : '';
                            ?>
                            <tr>
                                <td><?php echo esc_html( ! empty( $log->event_time ) ? (string) $log->event_time : '-' ); ?></td>
                                <td><code><?php echo esc_html( ! empty( $log->ip_address ) ? (string) $log->ip_address : '-' ); ?></code></td>
                                <td><?php echo esc_html( '' !== $country_label ? $country_label : '-' ); ?></td>
                                <td><?php echo esc_html( '' !== $provider_label ? $provider_label : '-' ); ?></td>
                                <td><?php echo esc_html( self::get_geo_block_action_label( ! empty( $log->action ) ? (string) $log->action : '' ) ); ?></td>
                                <td><?php echo esc_html( self::get_geo_block_reason_label( ! empty( $log->reason ) ? (string) $log->reason : '' ) ); ?></td>
                                <td style="word-break:break-all;">
                                    <?php echo esc_html( '' !== $method ? $method : '-' ); ?>
                                    <br><code><?php echo esc_html( '' !== $path ? $path : '-' ); ?></code>
                                </td>
                                <td style="word-break:break-all;"><?php echo esc_html( ! empty( $log->user_agent ) ? (string) $log->user_agent : '-' ); ?></td>
                                <td style="word-break:break-all;"><?php echo esc_html( ! empty( $log->referer ) ? (string) $log->referer : '-' ); ?></td>
                            </tr>
                        <?php endforeach; ?>
                    <?php endif; ?>
                </tbody>
            </table>
        </div>
        <?php
    }

    private static function get_geo_block_action_label( $action ) {
        $action = sanitize_key( (string) $action );

        if ( 'redirect' === $action ) {
            return '外部跳转';
        }

        if ( 'forbidden' === $action ) {
            return '403 Forbidden';
        }

        return '' !== $action ? $action : '-';
    }

    private static function get_geo_block_reason_label( $reason ) {
        $reason = sanitize_key( (string) $reason );

        if ( 'country_denied' === $reason ) {
            return '地区命中';
        }

        if ( 'lookup_failed' === $reason ) {
            return '查询失败';
        }

        return '' !== $reason ? $reason : '-';
    }

    private static function render_route_isolation_panel( $settings ) {
        $mu_plugin_path      = QS_Protection::get_rest_plugin_isolation_mu_plugin_path();
        $mu_plugin_filename  = QS_Protection::get_rest_plugin_isolation_mu_plugin_filename();
        $mu_plugin_installed = QS_Protection::is_rest_plugin_isolation_mu_plugin_installed();
        $selected_fields     = self::get_setting_field_keys_by_section( 'route_isolation' );
        ?>
        <div class="qs-panel" data-setting-fields="<?php echo esc_attr( implode( ',', $selected_fields ) ); ?>">
            <h2><span class="dashicons dashicons-randomize"></span> REST API 路由隔离加载</h2>
            <p>本面板仅负责第三方 REST API 请求的按路由加载，避免访问 A 插件 REST API 时完整加载其他无关插件。</p>

            <?php if ( $mu_plugin_installed ) : ?>
                <p class="description" style="margin-top:6px; color:#15803d;">
                    MU 核心文件已安装：<code><?php echo esc_html( $mu_plugin_path ); ?></code>
                </p>
            <?php else : ?>
                <p class="description" style="margin-top:6px; color:#b91c1c;">
                    尚未检测到 MU 核心文件，请先把 <code><?php echo esc_html( $mu_plugin_filename ); ?></code> 放到：
                    <code style="word-break:break-all;"><?php echo esc_html( $mu_plugin_path ); ?></code>
                </p>
            <?php endif; ?>

            <?php self::render_protection_settings_table( $settings, [ 'include_sections' => [ 'route_isolation' ] ] ); ?>

            <p class="submit">
                <button type="button" id="qs-save-route-isolation" class="button button-primary">保存隔离设置</button>
                <span class="spinner qs-route-isolation-save-spinner" style="float:none; margin-top: 4px;"></span>
                <span id="qs-save-route-isolation-message" style="margin-left:10px; font-weight:bold; color:#10b981;"></span>
            </p>
        </div>
        <?php self::render_route_isolation_monitor_panel( $settings ); ?>
        <?php
    }

    private static function get_security_optimize_field_keys() {
        return [
            'enable_localization_mode',
            'disable_xmlrpc',
            'disable_pingback',
            'hide_wp_version',
            'block_user_enum',
            'disable_app_passwords',
            'disable_file_editor',
            'clean_meta_tags',
            'disable_emoji',
            'disable_embeds',
            'remove_shortlink',
            'remove_rsd_wlw',
            'admin_disable_remote_block_patterns',
            'admin_disable_block_directory',
            'admin_disable_openverse',
            'admin_reduce_editor_preload',
        ];
    }

    private static function get_redis_cache_field_keys() {
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

    private static function get_setting_field_keys_by_section( $section_key ) {
        $section_key = sanitize_key( (string) $section_key );
        $field_keys  = [];

        foreach ( QS_Protection::get_setting_fields() as $field_key => $field ) {
            $field_section = isset( $field['section'] ) ? sanitize_key( (string) $field['section'] ) : '';

            if ( $field_section === $section_key ) {
                $field_keys[] = $field_key;
            }
        }

        return $field_keys;
    }

    private static function render_security_optimize_panel( $settings ) {
        $selected_fields = self::get_security_optimize_field_keys();
        ?>
        <div class="qs-panel" data-setting-fields="<?php echo esc_attr( implode( ',', $selected_fields ) ); ?>">
            <h2><span class="dashicons dashicons-performance"></span> WordPress 安全优化</h2>
            <p>集中管理与暴露面收敛相关的 WordPress 安全优化项，例如减少后台外联、关闭旧接口和限制不必要的暴露。</p>
            <p style="color:#b91c1c; font-weight:bold;"><span class="dashicons dashicons-warning" style="vertical-align:text-bottom; margin-right:4px;"></span>如启灵主题、其他安全插件或服务器层已启用同类能力，请避免重复开启。</p>
            <?php self::render_theme_overlap_overview_notice(); ?>

            <?php self::render_protection_settings_table( $settings, [ 'include_fields' => $selected_fields ] ); ?>

            <p class="submit">
                <button type="button" id="qs-save-security-optimize" class="button button-primary">保存安全优化设置</button>
                <span class="spinner qs-security-optimize-save-spinner" style="float:none; margin-top: 4px;"></span>
                <span id="qs-save-security-optimize-message" style="margin-left:10px; font-weight:bold; color:#10b981;"></span>
            </p>
        </div>
        <?php
    }

    private static function render_redis_cache_panel( $settings ) {
        $selected_fields = self::get_redis_cache_field_keys();
        $status          = QS_Redis_Cache::get_status( $settings );
        $runtime         = isset( $status['runtime'] ) && is_array( $status['runtime'] ) ? $status['runtime'] : [];
        $supports        = isset( $status['supports'] ) && is_array( $status['supports'] ) ? $status['supports'] : [];

        $enabled_label = $status['enabled'] ? '已开启' : '未开启';
        $enabled_tone  = $status['enabled'] ? 'success' : 'neutral';

        if ( $status['dropin_exists'] && $status['dropin_managed'] ) {
            $dropin_label = '已安装（插件托管）';
            $dropin_tone  = 'success';
        } elseif ( $status['dropin_exists'] ) {
            $dropin_label = '已安装（非插件托管）';
            $dropin_tone  = 'warning';
        } else {
            $dropin_label = '未安装';
            $dropin_tone  = 'neutral';
        }

        if ( ! $status['redis_extension'] ) {
            $connection_label = '未加载扩展';
            $connection_tone  = 'critical';
        } elseif ( $status['connection_ok'] ) {
            $connection_label = '连接正常';
            $connection_tone  = 'success';
        } else {
            $connection_label = '连接失败';
            $connection_tone  = 'critical';
        }

        $object_cache_label = $status['using_ext_object_cache'] ? '启用中' : '未接管';
        $object_cache_tone  = $status['using_ext_object_cache'] ? 'info' : 'neutral';
        $probe_disabled     = ! $status['enabled'] || ( $status['dropin_exists'] && ! $status['dropin_managed'] );
        $prefix_keys_label  = number_format_i18n( (int) $status['stats']['prefix_keys'] );

        if ( ! empty( $status['stats']['prefix_keys_truncated'] ) ) {
            $prefix_keys_label .= '+';
        }

        $runtime_cards = [
            [
                'title'   => '最近自检',
                'time'    => self::format_runtime_time( isset( $runtime['last_probe_at'] ) ? $runtime['last_probe_at'] : 0 ),
                'message' => ! empty( $runtime['last_probe_message'] ) ? $runtime['last_probe_message'] : '还没有执行过 Redis 自检。',
                'tone'    => self::get_runtime_tone( isset( $runtime['last_probe_status'] ) ? $runtime['last_probe_status'] : '' ),
                'status'  => self::get_runtime_status_label( isset( $runtime['last_probe_status'] ) ? $runtime['last_probe_status'] : '', '尚未执行' ),
            ],
            [
                'title'   => '最近刷新',
                'time'    => self::format_runtime_time( isset( $runtime['last_flush_at'] ) ? $runtime['last_flush_at'] : 0 ),
                'message' => ! empty( $runtime['last_flush_message'] ) ? $runtime['last_flush_message'] : '还没有手动刷新过 Redis 对象缓存。',
                'tone'    => self::get_runtime_tone( isset( $runtime['last_flush_status'] ) ? $runtime['last_flush_status'] : '' ),
                'status'  => self::get_runtime_status_label( isset( $runtime['last_flush_status'] ) ? $runtime['last_flush_status'] : '', '尚未执行' ),
            ],
            [
                'title'   => '最近同步',
                'time'    => self::format_runtime_time( isset( $runtime['last_sync_at'] ) ? $runtime['last_sync_at'] : 0 ),
                'message' => ! empty( $runtime['last_sync_message'] ) ? $runtime['last_sync_message'] : '还没有记录到 drop-in 同步动作。',
                'tone'    => self::get_runtime_tone( isset( $runtime['last_sync_status'] ) ? $runtime['last_sync_status'] : '' ),
                'status'  => self::get_runtime_status_label( isset( $runtime['last_sync_status'] ) ? $runtime['last_sync_status'] : '', '尚未执行' ),
            ],
        ];
        ?>
        <div class="qs-panel" data-setting-fields="<?php echo esc_attr( implode( ',', $selected_fields ) ); ?>">
            <h2><span class="dashicons dashicons-database"></span> Redis 持久对象缓存</h2>
            <p>提供面向 WordPress 的 Redis 持久对象缓存接入。保存设置后，插件会托管 <code>wp-content/object-cache.php</code>，使对象缓存、Transient 与 <code>wp_cache_*</code> 调用优先进入 Redis。</p>
            <p class="qs-inline-notice">已针对启灵主题与启灵插件生态中的常见对象缓存调用做兼容处理。</p>
            <p style="color:#b91c1c; font-weight:bold;"><span class="dashicons dashicons-warning" style="vertical-align:text-bottom; margin-right:4px;"></span>如站点已由其他 Redis / Object Cache 方案管理 <code>object-cache.php</code>，请避免重复接管。</p>

            <?php self::render_protection_settings_table( $settings, [ 'include_fields' => $selected_fields ] ); ?>

            <p class="submit">
                <button type="button" id="qs-save-redis-cache" class="button button-primary">保存 Redis 缓存设置</button>
                <span class="spinner qs-redis-cache-save-spinner" style="float:none; margin-top: 4px;"></span>
                <span id="qs-save-redis-cache-message" style="margin-left:10px; font-weight:bold; color:#10b981;"></span>
            </p>
        </div>

        <div class="qs-panel" style="margin-top:20px;">
            <h2><span class="dashicons dashicons-performance"></span> Redis 运行状态</h2>
            <div class="qs-redis-status-grid">
                <div class="qs-stat-box qs-redis-stat-box">
                    <span class="dashicons dashicons-admin-settings"></span>
                    <strong>功能开关</strong>
                    <span class="qs-badge <?php echo esc_attr( $enabled_tone ); ?>"><?php echo esc_html( $enabled_label ); ?></span>
                </div>
                <div class="qs-stat-box qs-redis-stat-box">
                    <span class="dashicons dashicons-media-code"></span>
                    <strong>Drop-in 状态</strong>
                    <span class="qs-badge <?php echo esc_attr( $dropin_tone ); ?>"><?php echo esc_html( $dropin_label ); ?></span>
                </div>
                <div class="qs-stat-box qs-redis-stat-box">
                    <span class="dashicons dashicons-cloud"></span>
                    <strong>Redis 连接</strong>
                    <span class="qs-badge <?php echo esc_attr( $connection_tone ); ?>"><?php echo esc_html( $connection_label ); ?></span>
                </div>
                <div class="qs-stat-box qs-redis-stat-box">
                    <span class="dashicons dashicons-update"></span>
                    <strong>WordPress 外部对象缓存</strong>
                    <span class="qs-badge <?php echo esc_attr( $object_cache_tone ); ?>"><?php echo esc_html( $object_cache_label ); ?></span>
                </div>
            </div>

            <div class="qs-toolbar-row">
                <div class="qs-toolbar-meta qs-redis-status-meta">
                    当前 drop-in：<code><?php echo esc_html( $status['dropin_path'] ); ?></code><br>
                    当前缓存前缀：<code><?php echo esc_html( $status['prefix'] ); ?></code><br>
                    当前连接目标：<strong><?php echo esc_html( (string) $status['config']['host'] ); ?><?php echo 0 !== (int) $status['config']['port'] ? ':' . esc_html( (string) $status['config']['port'] ) : ''; ?></strong> / DB <strong><?php echo esc_html( number_format_i18n( (int) $status['config']['database'] ) ); ?></strong><br>
                    Redis 扩展：<?php echo $status['redis_extension'] ? '<strong style="color:#15803d;">已加载</strong>' : '<strong style="color:#b91c1c;">未加载</strong>'; ?><br>
                    当前库 Key 数：<strong><?php echo esc_html( number_format_i18n( (int) $status['stats']['keys'] ) ); ?></strong>
                    <?php if ( ! empty( $status['stats']['used_memory'] ) ) : ?>
                        ，已用内存：<strong><?php echo esc_html( $status['stats']['used_memory'] ); ?></strong>
                    <?php endif; ?>
                    <?php if ( '' !== $status['stats']['hit_rate'] ) : ?>
                        ，命中率：<strong><?php echo esc_html( $status['stats']['hit_rate'] ); ?></strong>
                    <?php endif; ?>
                </div>
                <div class="qs-toolbar-actions">
                    <button type="button" id="qs-run-redis-cache-probe" class="button button-secondary" <?php disabled( $probe_disabled ); ?>>运行缓存自检</button>
                    <button type="button" id="qs-sync-redis-dropin" class="button" <?php disabled( $probe_disabled ); ?>>重新同步 Drop-in</button>
                    <button type="button" id="qs-flush-redis-cache" class="button" <?php disabled( $probe_disabled ); ?>>刷新 Redis 缓存</button>
                    <span class="spinner qs-redis-cache-action-spinner" style="float:none; margin-top: 4px;"></span>
                    <span id="qs-redis-cache-action-message" style="font-weight:bold;"></span>
                </div>
            </div>

            <?php if ( ! $status['can_manage_dropin'] ) : ?>
                <p class="qs-inline-notice qs-inline-notice-warning"><code>wp-content</code> 目录或现有 <code>object-cache.php</code> 不可写，保存设置时可能无法自动安装或移除 drop-in 文件。</p>
            <?php endif; ?>

            <?php if ( $status['dropin_exists'] && ! $status['dropin_managed'] ) : ?>
                <p class="qs-inline-notice qs-inline-notice-warning">检测到现有 <code>object-cache.php</code> 并非由启灵安全防护托管。为避免覆盖其他缓存方案，当前仅展示状态，不执行自动接管或刷新。</p>
            <?php endif; ?>

            <?php if ( ! empty( $status['connection_message'] ) ) : ?>
                <p class="qs-inline-notice <?php echo $status['connection_ok'] ? '' : 'qs-inline-notice-warning'; ?>"><?php echo esc_html( $status['connection_message'] ); ?></p>
            <?php endif; ?>

            <div class="qs-redis-metrics-grid">
                <div class="qs-redis-metric">
                    <strong>命中次数</strong>
                    <span><?php echo esc_html( number_format_i18n( (int) $status['stats']['hits'] ) ); ?></span>
                </div>
                <div class="qs-redis-metric">
                    <strong>未命中次数</strong>
                    <span><?php echo esc_html( number_format_i18n( (int) $status['stats']['misses'] ) ); ?></span>
                </div>
                <div class="qs-redis-metric">
                    <strong>Redis 运行天数</strong>
                    <span><?php echo '' !== $status['stats']['uptime_days'] ? esc_html( $status['stats']['uptime_days'] ) : '-'; ?></span>
                </div>
                <div class="qs-redis-metric">
                    <strong>本站前缀 Key 数</strong>
                    <span><?php echo esc_html( $prefix_keys_label ); ?></span>
                </div>
            </div>

            <div class="qs-redis-diagnostics-grid">
                <div class="qs-redis-diagnostic-card">
                    <strong>Redis 版本</strong>
                    <span><?php echo '' !== $status['stats']['redis_version'] ? esc_html( $status['stats']['redis_version'] ) : '-'; ?></span>
                </div>
                <div class="qs-redis-diagnostic-card">
                    <strong>运行模式</strong>
                    <span><?php echo '' !== $status['stats']['redis_mode'] ? esc_html( strtoupper( $status['stats']['redis_mode'] ) ) : 'Standalone'; ?></span>
                </div>
                <div class="qs-redis-diagnostic-card">
                    <strong>连接耗时</strong>
                    <span><?php echo '' !== $status['connection_latency_ms'] ? esc_html( $status['connection_latency_ms'] . ' ms' ) : '-'; ?></span>
                </div>
                <div class="qs-redis-diagnostic-card">
                    <strong>连接客户端</strong>
                    <span><?php echo esc_html( number_format_i18n( (int) $status['stats']['connected_clients'] ) ); ?></span>
                </div>
                <div class="qs-redis-diagnostic-card">
                    <strong>淘汰 Key</strong>
                    <span><?php echo esc_html( number_format_i18n( (int) $status['stats']['evicted_keys'] ) ); ?></span>
                </div>
                <div class="qs-redis-diagnostic-card">
                    <strong>最大内存</strong>
                    <span><?php echo '' !== $status['stats']['maxmemory'] ? esc_html( $status['stats']['maxmemory'] ) : '未限制'; ?></span>
                </div>
                <div class="qs-redis-diagnostic-card">
                    <strong>对象缓存 API</strong>
                    <span><?php echo ! empty( $supports['wp_cache_api'] ) ? '可用' : '不可用'; ?></span>
                </div>
                <div class="qs-redis-diagnostic-card">
                    <strong>精准分组刷新</strong>
                    <span><?php echo ! empty( $supports['flush_group'] ) ? '支持' : '不支持'; ?></span>
                </div>
                <div class="qs-redis-diagnostic-card">
                    <strong>运行时缓存清空</strong>
                    <span><?php echo ! empty( $supports['flush_runtime'] ) ? '支持' : '不支持'; ?></span>
                </div>
                <div class="qs-redis-diagnostic-card">
                    <strong>批量读取</strong>
                    <span><?php echo ! empty( $supports['get_multiple'] ) ? '支持' : '不支持'; ?></span>
                </div>
            </div>

            <div class="qs-redis-runtime-grid">
                <?php foreach ( $runtime_cards as $card ) : ?>
                    <div class="qs-redis-runtime-card qs-redis-runtime-<?php echo esc_attr( $card['tone'] ); ?>">
                        <div class="qs-redis-runtime-head">
                            <strong><?php echo esc_html( $card['title'] ); ?></strong>
                            <span class="qs-badge <?php echo esc_attr( $card['tone'] ); ?>"><?php echo esc_html( $card['status'] ); ?></span>
                        </div>
                        <span class="qs-redis-runtime-time"><?php echo esc_html( $card['time'] ); ?></span>
                        <p><?php echo esc_html( $card['message'] ); ?></p>
                    </div>
                <?php endforeach; ?>
            </div>

            <?php if ( ! empty( $runtime['last_probe_steps'] ) && is_array( $runtime['last_probe_steps'] ) ) : ?>
                <div class="qs-redis-probe-box">
                    <h3>最近一次缓存自检明细</h3>
                    <div class="qs-redis-probe-steps">
                        <?php foreach ( $runtime['last_probe_steps'] as $probe_step ) : ?>
                            <div class="qs-redis-probe-step <?php echo ! empty( $probe_step['ok'] ) ? 'is-success' : 'is-error'; ?>">
                                <strong><?php echo esc_html( isset( $probe_step['label'] ) ? $probe_step['label'] : '' ); ?></strong>
                                <span><?php echo esc_html( isset( $probe_step['message'] ) ? $probe_step['message'] : '' ); ?></span>
                            </div>
                        <?php endforeach; ?>
                    </div>
                </div>
            <?php endif; ?>
        </div>
        <?php
    }

    private static function render_health_check_panel( $settings ) {
        $report         = QS_Health_Check::get_report( $settings );
        $summary        = isset( $report['summary'] ) && is_array( $report['summary'] ) ? $report['summary'] : [];
        $checks         = isset( $report['checks'] ) && is_array( $report['checks'] ) ? $report['checks'] : [];
        $overall_status = isset( $summary['overall_status'] ) ? sanitize_key( (string) $summary['overall_status'] ) : 'neutral';
        $overall_label  = isset( $summary['overall_label'] ) ? (string) $summary['overall_label'] : '尚无结果';
        $generated_at   = isset( $report['generated_at'] ) ? absint( $report['generated_at'] ) : 0;
        $summary_cards  = [
            [
                'title' => '整体状态',
                'value' => $overall_label,
                'hint'  => '最近一次插件自检的总体判断。',
                'tone'  => $overall_status,
            ],
            [
                'title' => '正常项',
                'value' => number_format_i18n( isset( $summary['success'] ) ? (int) $summary['success'] : 0 ),
                'hint'  => '已通过的基础运行与安全环境检查。',
                'tone'  => 'success',
            ],
            [
                'title' => '警告项',
                'value' => number_format_i18n( isset( $summary['warning'] ) ? (int) $summary['warning'] : 0 ),
                'hint'  => '建议尽快优化，但暂时不一定阻断核心功能。',
                'tone'  => 'warning',
            ],
            [
                'title' => '严重项',
                'value' => number_format_i18n( isset( $summary['critical'] ) ? (int) $summary['critical'] : 0 ),
                'hint'  => '可能直接影响规则可信度、数据库结构或缓存接管。',
                'tone'  => 'critical',
            ],
        ];
        ?>
        <div class="qs-panel">
            <h2><span class="dashicons dashicons-yes-alt"></span> 插件自检中心</h2>
            <p>集中检查插件运行基础，包括数据库结构、规则签名环境、发布包私钥残留、异步任务链路和 Redis 对象缓存接管状态。</p>
            <p class="qs-inline-notice">建议在完成关键设置后执行一次插件自检，用于快速确认运行环境与关键依赖状态。</p>

            <div class="qs-toolbar-row">
                <div class="qs-toolbar-meta qs-health-check-meta">
                    最近一次自检：<strong><?php echo esc_html( self::format_runtime_time( $generated_at ) ); ?></strong><br>
                    本轮共检查 <strong><?php echo esc_html( number_format_i18n( count( $checks ) ) ); ?></strong> 项，
                    已跳过 <strong><?php echo esc_html( number_format_i18n( isset( $summary['neutral'] ) ? (int) $summary['neutral'] : 0 ) ); ?></strong> 项。
                </div>
                <div class="qs-toolbar-actions">
                    <button type="button" id="qs-run-health-check" class="button button-primary">重新执行插件自检</button>
                    <span class="spinner qs-health-check-spinner" style="float:none; margin-top: 4px;"></span>
                    <span id="qs-health-check-message" style="font-weight:bold;"></span>
                </div>
            </div>

            <div class="qs-health-summary-grid">
                <?php foreach ( $summary_cards as $card ) : ?>
                    <div class="qs-health-summary-card is-<?php echo esc_attr( $card['tone'] ); ?>">
                        <strong><?php echo esc_html( $card['title'] ); ?></strong>
                        <span class="qs-health-summary-value"><?php echo esc_html( $card['value'] ); ?></span>
                        <small><?php echo esc_html( $card['hint'] ); ?></small>
                    </div>
                <?php endforeach; ?>
            </div>
        </div>

        <div class="qs-health-check-list">
            <?php if ( empty( $checks ) ) : ?>
                <div class="qs-panel">
                    <p class="qs-health-check-empty">当前还没有可展示的自检结果，请手动执行一次插件自检。</p>
                </div>
            <?php else : ?>
                <?php foreach ( $checks as $check ) : ?>
                    <?php $status = isset( $check['status'] ) ? sanitize_key( (string) $check['status'] ) : 'neutral'; ?>
                    <div class="qs-health-check-card is-<?php echo esc_attr( $status ); ?>">
                        <div class="qs-health-check-head">
                            <strong><?php echo esc_html( isset( $check['label'] ) ? $check['label'] : '' ); ?></strong>
                            <span class="qs-badge <?php echo esc_attr( $status ); ?>">
                                <?php echo esc_html( self::get_health_check_status_label( $status ) ); ?>
                            </span>
                        </div>
                        <p><?php echo esc_html( isset( $check['message'] ) ? $check['message'] : '' ); ?></p>
                        <?php if ( ! empty( $check['detail'] ) ) : ?>
                            <div class="qs-health-check-detail"><?php echo esc_html( $check['detail'] ); ?></div>
                        <?php endif; ?>
                    </div>
                <?php endforeach; ?>
            <?php endif; ?>
        </div>
        <?php
    }

    private static function render_alert_center_panel( $settings ) {
        $settings         = is_array( $settings ) ? $settings : QS_Protection::get_settings();
        $email_recipients = class_exists( 'QS_Alert_Center' ) ? QS_Alert_Center::get_email_recipients( $settings ) : [];
        $selected_channel = class_exists( 'QS_Alert_Center' ) ? QS_Alert_Center::get_selected_push_channel( $settings ) : [];
        $push_available   = class_exists( 'QS_Alert_Center' ) && QS_Alert_Center::has_push_plugin();
        $channel_label    = ! empty( $selected_channel['name'] ) ? $selected_channel['name'] : '未选择';
        ?>
        <div class="qs-panel">
            <h2><span class="dashicons dashicons-megaphone"></span> 安全告警中心</h2>
            <p>用于将关键安全事件推送到邮箱，并复用“启灵消息推送”插件已配置的飞书/钉钉通道。邮件通过 WordPress 发信能力发送，飞书与钉钉复用现有推送配置。</p>

            <?php if ( ! $push_available ) : ?>
                <p class="qs-inline-notice qs-inline-notice-warning">未检测到“启灵消息推送”插件，飞书/钉钉告警暂不可用；邮件告警仍可单独启用。</p>
            <?php else : ?>
                <p class="qs-inline-notice">已检测到“启灵消息推送”插件，飞书/钉钉告警将复用其中已保存的推送通道。</p>
            <?php endif; ?>

            <?php self::render_protection_settings_table( $settings, [ 'include_sections' => [ 'alerts' ] ] ); ?>

            <p class="submit">
                <button type="button" id="qs-save-alert-center" class="button button-primary">保存安全告警设置</button>
                <span class="spinner qs-alert-center-save-spinner" style="float:none; margin-top: 4px;"></span>
                <span id="qs-save-alert-center-message" style="margin-left:10px; font-weight:bold; color:#10b981;"></span>
            </p>
        </div>

        <div class="qs-panel" style="margin-top:20px;">
            <h2><span class="dashicons dashicons-email-alt"></span> 告警链路测试</h2>
            <div class="qs-toolbar-row">
                <div class="qs-toolbar-meta">
                    当前邮件收件人：<strong><?php echo ! empty( $email_recipients ) ? esc_html( implode( '、', $email_recipients ) ) : '未配置'; ?></strong><br>
                    当前飞书/钉钉通道：<strong><?php echo esc_html( $channel_label ); ?></strong><br>
                    告警总开关：<?php echo ! empty( $settings['enable_security_alert_center'] ) ? '<strong style="color:#15803d;">已开启</strong>' : '<strong style="color:#b45309;">未开启</strong>'; ?>
                </div>
                <div class="qs-toolbar-actions">
                    <button type="button" id="qs-send-alert-test" class="button button-secondary">发送测试告警</button>
                    <span class="spinner qs-alert-test-spinner" style="float:none; margin-top: 4px;"></span>
                    <span id="qs-alert-test-message" style="font-weight:bold;"></span>
                </div>
            </div>
            <p class="description" style="margin-bottom:0;">测试消息会按当前配置的发送方式实际发送一次。即使总开关未开启，也可先用于验证邮件与飞书/钉钉通道是否可用。</p>
        </div>
        <?php
    }

    private static function format_runtime_time( $timestamp ) {
        $timestamp = absint( $timestamp );

        if ( $timestamp <= 0 ) {
            return '尚无记录';
        }

        $formatted = date_i18n( get_option( 'date_format' ) . ' ' . get_option( 'time_format' ), $timestamp );
        $relative  = human_time_diff( $timestamp, current_time( 'timestamp' ) );

        return $formatted . '（' . $relative . '前）';
    }

    private static function get_runtime_tone( $status ) {
        $status = sanitize_key( (string) $status );

        if ( 'error' === $status ) {
            return 'critical';
        }

        if ( 'success' === $status ) {
            return 'success';
        }

        if ( 'warning' === $status ) {
            return 'warning';
        }

        return 'neutral';
    }

    private static function get_runtime_status_label( $status, $fallback = '尚无记录' ) {
        $status = sanitize_key( (string) $status );

        if ( 'error' === $status ) {
            return '失败';
        }

        if ( 'success' === $status ) {
            return '成功';
        }

        if ( 'warning' === $status ) {
            return '需留意';
        }

        return $fallback;
    }

    private static function get_health_check_status_label( $status ) {
        $status = sanitize_key( (string) $status );

        if ( 'critical' === $status ) {
            return '严重';
        }

        if ( 'warning' === $status ) {
            return '警告';
        }

        if ( 'success' === $status ) {
            return '正常';
        }

        return '已跳过';
    }

    private static function render_route_isolation_monitor_panel( $settings ) {
        $settings        = is_array( $settings ) ? $settings : QS_Protection::get_settings();
        $monitor_enabled = ! empty( $settings['rest_plugin_isolation_monitor_enabled'] );
        $max_entries     = QS_Protection::get_rest_plugin_isolation_monitor_max_entries( $settings );
        $logs            = QS_Protection::get_rest_plugin_isolation_monitor_logs( $max_entries );
        $total_logs      = method_exists( 'QS_DB', 'get_rest_isolation_log_count' ) ? QS_DB::get_rest_isolation_log_count() : count( $logs );
        ?>
        <div class="qs-panel" style="margin-top:20px;">
            <h2><span class="dashicons dashicons-chart-line"></span> 路由隔离监控面板</h2>
            <p>展示最近的 REST 路由隔离决策，便于核对“命中规则”和“最终加载插件”是否符合预期。监控日志已写入插件独立数据表。</p>
            <p class="description">
                当前监控状态：<?php echo $monitor_enabled ? '<strong style="color:#15803d;">已开启</strong>' : '<strong style="color:#b91c1c;">未开启</strong>'; ?>；
                最大保留条数：<?php echo esc_html( number_format_i18n( $max_entries ) ); ?>；
                当前日志总数：<?php echo esc_html( number_format_i18n( $total_logs ) ); ?>。
            </p>

            <p class="submit" style="margin-top:8px;">
                <button type="button" id="qs-clear-route-isolation-logs" class="button">清空监控日志</button>
                <span class="spinner qs-route-isolation-clear-spinner" style="float:none; margin-top: 4px;"></span>
                <span id="qs-route-isolation-clear-message" style="margin-left:10px; font-weight:bold;"></span>
            </p>

            <div class="qs-iprisk-table-wrap">
                <table class="wp-list-table widefat fixed striped">
                    <thead>
                        <tr>
                            <th style="width:170px;">时间</th>
                            <th style="width:200px;">路由</th>
                            <th style="width:120px;">模式</th>
                            <th style="width:180px;">决策</th>
                            <th style="width:180px;">命中规则</th>
                            <th style="width:120px;">插件数（前→后）</th>
                            <th>最终加载插件（最多展示 12 个）</th>
                        </tr>
                    </thead>
                    <tbody>
                        <?php if ( empty( $logs ) ) : ?>
                            <tr><td colspan="7" style="text-align:center; padding:20px;">暂无监控日志。开启监控后触发一次 qilingtxt 请求即可看到数据。</td></tr>
                        <?php else : ?>
                            <?php foreach ( $logs as $log ) : ?>
                                <?php
                                $mode_label      = ( isset( $log['mode'] ) && 'all_rest' === $log['mode'] ) ? 'all_rest' : 'matched_only';
                                $decision_label  = self::get_route_isolation_decision_label( isset( $log['decision'] ) ? $log['decision'] : '' );
                                $matched_rule    = isset( $log['matched_rule'] ) ? (string) $log['matched_rule'] : '';
                                $final_plugins   = isset( $log['final_plugins'] ) && is_array( $log['final_plugins'] ) ? $log['final_plugins'] : [];
                                $final_plugins   = array_slice( $final_plugins, 0, 12 );
                                $final_plugins_text = empty( $final_plugins ) ? '-' : implode( '、', array_map( 'esc_html', $final_plugins ) );
                                ?>
                                <tr>
                                    <td><?php echo esc_html( isset( $log['time'] ) ? (string) $log['time'] : '' ); ?></td>
                                    <td><code><?php echo esc_html( isset( $log['route'] ) ? (string) $log['route'] : '/' ); ?></code></td>
                                    <td><code><?php echo esc_html( $mode_label ); ?></code></td>
                                    <td><?php echo esc_html( $decision_label ); ?></td>
                                    <td><?php echo '' !== $matched_rule ? '<code>' . esc_html( $matched_rule ) . '</code>' : '-'; ?></td>
                                    <td>
                                        <?php
                                        $before_count = isset( $log['before_count'] ) ? (int) $log['before_count'] : 0;
                                        $after_count  = isset( $log['after_count'] ) ? (int) $log['after_count'] : 0;
                                        echo esc_html( $before_count . ' → ' . $after_count );
                                        ?>
                                    </td>
                                    <td><?php echo wp_kses_post( $final_plugins_text ); ?></td>
                                </tr>
                            <?php endforeach; ?>
                        <?php endif; ?>
                    </tbody>
                </table>
            </div>
        </div>
        <?php
    }

    private static function get_route_isolation_decision_label( $decision ) {
        $decision = sanitize_key( (string) $decision );
        $map      = [
            'isolated_matched' => '命中规则并隔离',
            'isolated_all_rest' => 'all_rest 模式隔离',
            'skip_no_match'    => '未命中规则（跳过隔离）',
            'skip_invalid_allow' => '白名单为空（回退全量）',
            'skip_filtered_empty' => '过滤结果为空（回退全量）',
            'skip_not_rest'    => '非 REST 请求',
        ];

        return isset( $map[ $decision ] ) ? $map[ $decision ] : ( '' !== $decision ? $decision : '未知' );
    }

    private static function render_protection_settings_table( $settings, $args = [] ) {
        $sections        = QS_Protection::get_setting_sections();
        $fields          = QS_Protection::get_setting_fields();
        $section_fields  = [];
        $include_sections = isset( $args['include_sections'] ) ? array_values( array_filter( (array) $args['include_sections'], 'is_string' ) ) : [];
        $exclude_sections = isset( $args['exclude_sections'] ) ? array_values( array_filter( (array) $args['exclude_sections'], 'is_string' ) ) : [];
        $include_fields   = isset( $args['include_fields'] ) ? array_values( array_filter( (array) $args['include_fields'], 'is_string' ) ) : [];
        $exclude_fields   = isset( $args['exclude_fields'] ) ? array_values( array_filter( (array) $args['exclude_fields'], 'is_string' ) ) : [];

        if ( ! empty( $include_fields ) ) {
            $fields = array_intersect_key( $fields, array_fill_keys( $include_fields, true ) );
        }

        if ( ! empty( $exclude_fields ) ) {
            foreach ( $exclude_fields as $field_key ) {
                unset( $fields[ $field_key ] );
            }
        }

        if ( ! empty( $include_sections ) ) {
            $section_whitelist = array_fill_keys( $include_sections, true );
            $sections          = array_intersect_key( $sections, $section_whitelist );
        }

        if ( ! empty( $exclude_sections ) ) {
            foreach ( $exclude_sections as $section_key ) {
                unset( $sections[ $section_key ] );
            }
        }

        foreach ( $fields as $key => $field ) {
            $section = isset( $field['section'] ) ? $field['section'] : 'misc';

            if ( ! isset( $sections[ $section ] ) ) {
                continue;
            }

            if ( ! isset( $section_fields[ $section ] ) ) {
                $section_fields[ $section ] = [];
            }

            $section_fields[ $section ][ $key ] = $field;
        }
        ?>
        <table class="form-table" role="presentation">
            <tbody>
                <?php
                $is_first_section = true;

                foreach ( $sections as $section_key => $section ) :
                    if ( empty( $section_fields[ $section_key ] ) ) {
                        continue;
                    }

                    if ( ! $is_first_section ) :
                        ?>
                        <tr>
                            <td colspan="2"><hr></td>
                        </tr>
                        <?php
                    endif;

                    $is_first_section = false;
                    ?>
                    <tr>
                        <th colspan="2" scope="row" style="padding-bottom:0;">
                            <h3 style="margin:0 0 6px;"><?php echo esc_html( $section['title'] ); ?></h3>
                            <?php if ( ! empty( $section['description'] ) ) : ?>
                                <p class="description" style="margin:0 0 10px;"><?php echo esc_html( $section['description'] ); ?></p>
                            <?php endif; ?>
                        </th>
                    </tr>
                    <?php

                    foreach ( $section_fields[ $section_key ] as $field_key => $field ) :
                        self::render_protection_setting_row( $field_key, $field, $settings );
                    endforeach;
                endforeach;
                ?>
            </tbody>
        </table>
        <?php
    }

    private static function render_protection_setting_row( $field_key, $field, $settings ) {
        $value       = isset( $settings[ $field_key ] ) ? $settings[ $field_key ] : ( isset( $field['default'] ) ? $field['default'] : '' );
        $type        = isset( $field['type'] ) ? $field['type'] : 'text';
        $input_id    = 'qs_' . $field_key;
        $input_class = 'qs-setting-field ' . ( isset( $field['class'] ) ? $field['class'] : '' );
        ?>
        <tr>
            <th scope="row">
                <label for="<?php echo esc_attr( $input_id ); ?>">
                    <?php echo esc_html( $field['label'] ); ?>
                </label>
            </th>
            <td>
                <?php if ( 'checkbox' === $type ) : ?>
                    <label>
                        <input
                            type="checkbox"
                            id="<?php echo esc_attr( $input_id ); ?>"
                            class="<?php echo esc_attr( trim( $input_class ) ); ?>"
                            data-setting-key="<?php echo esc_attr( $field_key ); ?>"
                            value="1"
                            <?php checked( ! empty( $value ) ); ?>
                        >
                        <?php echo ! empty( $field['recommended'] ) ? '开启 (推荐)' : '开启'; ?>
                    </label>
                <?php elseif ( 'multi_checkbox' === $type ) : ?>
                    <div class="qs-setting-multi-checkbox-group">
                        <?php
                        $enabled_items = QS_Protection::parse_list_setting( $value );
                        foreach ( (array) $field['choices'] as $choice_value => $choice_label ) :
                            $choice_id = $input_id . '_' . $choice_value;
                            ?>
                            <div style="margin-bottom: 6px;">
                                <label for="<?php echo esc_attr( $choice_id ); ?>">
                                    <input
                                        type="checkbox"
                                        id="<?php echo esc_attr( $choice_id ); ?>"
                                        class="qs-setting-field qs-setting-multi-checkbox"
                                        data-setting-key="<?php echo esc_attr( $field_key ); ?>"
                                        value="<?php echo esc_attr( $choice_value ); ?>"
                                        <?php checked( in_array( $choice_value, $enabled_items, true ) ); ?>
                                    >
                                    <?php echo esc_html( $choice_label ); ?>
                                </label>
                            </div>
                        <?php endforeach; ?>
                    </div>
                <?php elseif ( 'textarea' === $type ) : ?>
                    <textarea
                        id="<?php echo esc_attr( $input_id ); ?>"
                        class="<?php echo esc_attr( trim( $input_class ) ); ?>"
                        data-setting-key="<?php echo esc_attr( $field_key ); ?>"
                        rows="<?php echo isset( $field['rows'] ) ? esc_attr( $field['rows'] ) : 4; ?>"
                    ><?php echo esc_textarea( $value ); ?></textarea>
                <?php elseif ( 'select' === $type ) : ?>
                    <select
                        id="<?php echo esc_attr( $input_id ); ?>"
                        class="<?php echo esc_attr( trim( $input_class ) ); ?>"
                        data-setting-key="<?php echo esc_attr( $field_key ); ?>"
                    >
                        <?php foreach ( (array) $field['choices'] as $choice_value => $choice_label ) : ?>
                            <option value="<?php echo esc_attr( $choice_value ); ?>" <?php selected( (string) $value, (string) $choice_value ); ?>>
                                <?php echo esc_html( $choice_label ); ?>
                            </option>
                        <?php endforeach; ?>
                    </select>
                <?php else : ?>
                    <?php if ( ! empty( $field['prefix'] ) ) : ?>
                        <code style="display:inline-block; margin-right:8px;"><?php echo esc_html( $field['prefix'] ); ?></code>
                    <?php endif; ?>
                    <input
                        type="<?php echo esc_attr( 'number' === $type ? 'number' : ( 'password' === $type ? 'password' : 'text' ) ); ?>"
                        id="<?php echo esc_attr( $input_id ); ?>"
                        class="<?php echo esc_attr( trim( $input_class ) ); ?>"
                        data-setting-key="<?php echo esc_attr( $field_key ); ?>"
                        value="<?php echo esc_attr( $value ); ?>"
                        <?php if ( isset( $field['placeholder'] ) ) : ?>placeholder="<?php echo esc_attr( $field['placeholder'] ); ?>"<?php endif; ?>
                        <?php if ( isset( $field['min'] ) ) : ?>min="<?php echo esc_attr( $field['min'] ); ?>"<?php endif; ?>
                        <?php if ( isset( $field['max'] ) ) : ?>max="<?php echo esc_attr( $field['max'] ); ?>"<?php endif; ?>
                        <?php if ( isset( $field['step'] ) ) : ?>step="<?php echo esc_attr( $field['step'] ); ?>"<?php endif; ?>
                    >
                <?php endif; ?>

                <?php if ( ! empty( $field['description_html'] ) ) : ?>
                    <p class="description" style="margin-top:6px;"><?php echo wp_kses_post( $field['description_html'] ); ?></p>
                <?php elseif ( ! empty( $field['description'] ) ) : ?>
                    <p class="description" style="margin-top:6px;"><?php echo esc_html( $field['description'] ); ?></p>
                <?php endif; ?>

                <?php foreach ( QS_Protection::get_field_runtime_notes( $field_key ) as $note ) : ?>
                    <p class="description qs-runtime-note qs-runtime-note-<?php echo esc_attr( ! empty( $note['tone'] ) ? $note['tone'] : 'info' ); ?>">
                        <?php
                        if ( ! empty( $note['html'] ) ) {
                            echo wp_kses_post( $note['html'] );
                        } else {
                            echo esc_html( $note['message'] );
                        }
                        ?>
                    </p>
                <?php endforeach; ?>
            </td>
        </tr>
        <?php
    }

    private static function render_usage_help_panel() {
        ?>
        <div class="qs-panel">
            <h2><span class="dashicons dashicons-book-alt"></span> 使用说明</h2>
            <p>建议先配置代理与真实 IP，再按需开启安全优化、本地化/白标模式、地区限制、登录保护和行为限速。上线初期先观察日志，确认没有误拦截后再提高拦截力度。</p>
            <p style="font-weight:bold; margin-bottom:6px;">作者联系方式</p>
            <p style="margin-top:0;">微信/QQ：19577566　版权：启灵生态圈</p>
        </div>
        <?php
    }
}
