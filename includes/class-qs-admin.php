<?php
/**
 * 安全防护插件 - 后台管理界面
 */
if ( ! defined( 'ABSPATH' ) ) exit;

class QS_Admin {

    public static function init() {
        add_action( 'admin_menu', [ __CLASS__, 'add_menu_pages' ] );
        add_action( 'admin_enqueue_scripts', [ __CLASS__, 'enqueue_assets' ] );
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
            'proxyPresets'       => QS_Protection::get_proxy_presets_for_js(),
            'defaultProxyHeaders' => QS_Protection::get_default_proxy_headers(),
        ] );
    }

    public static function render_dashboard() {
        $last_scan       = QS_DB::get_last_scan();
        $analytics       = QS_DB::get_security_analytics( 7 );
        $ip_risk_data    = QS_DB::get_ip_risk_analytics( 7, 80 );
        $settings        = QS_Protection::get_settings();
        $sessions        = QS_Session_Manager::get_active_sessions( 200 );
        $session_summary = QS_Session_Manager::get_active_session_summary( $sessions );
        $baseline_count  = QS_DB::get_file_baseline_count();
        $baseline_paths  = QS_Protection::get_file_integrity_paths( $settings );
        $scan_step_count = count( QS_Scanner::get_scan_steps() );
        $scan_time_text = '尚未体检';
        $issues_text = '';
        if ( $last_scan ) {
            $scan_time_text = $last_scan->status === 'completed' ? $last_scan->end_time : '体检被中断';
            $issues_text = $last_scan->total_issues > 0 ? "⚠️ 发现 {$last_scan->total_issues} 项风险！" : '✅ 状态良好，未发现风险';
        }
        ?>
        <div class="wrap qs-wrap">
            <h1 class="qs-title">
                <span class="dashicons dashicons-shield"></span> 启灵安全防护中心
            </h1>
            
            <h2 class="nav-tab-wrapper">
                <a href="#tab-scanner" class="nav-tab nav-tab-active" id="qs-tab-scanner">全盘安全体检</a>
                <a href="#tab-insights" class="nav-tab" id="qs-tab-insights">安全态势分析</a>
                <a href="#tab-iprisk" class="nav-tab" id="qs-tab-iprisk">IP 风险画像</a>
                <a href="#tab-security-optimize" class="nav-tab" id="qs-tab-security-optimize">安全优化</a>
                <a href="#tab-protection" class="nav-tab" id="qs-tab-protection">主动防护防火墙</a>
                <a href="#tab-route-isolation" class="nav-tab" id="qs-tab-route-isolation">REST 路由隔离</a>
                <a href="#tab-domain" class="nav-tab" id="qs-tab-domain">域名安全替换</a>
                <a href="#tab-nginx" class="nav-tab" id="qs-tab-nginx">Nginx 安全建议</a>
                <a href="#tab-audit" class="nav-tab" id="qs-tab-audit">操作审计日志</a>
                <a href="#tab-bans" class="nav-tab" id="qs-tab-bans">动态 IP 封禁</a>
                <a href="#tab-sessions" class="nav-tab" id="qs-tab-sessions">用户会话管理</a>
                <a href="#tab-help" class="nav-tab" id="qs-tab-help">使用说明</a>
            </h2>

            <!-- Tab 1: 扫描器 -->
            <div id="tab-content-scanner" class="qs-tab-content">
                <div class="qs-dashboard-grid" style="margin-top:20px;">
                <!-- 左侧：控制面板与进度 -->
                <div class="qs-panel">
                    <h2><span class="dashicons dashicons-search"></span> 深度安全体检</h2>
                    <p>一键扫描整站安全隐患，包括后门木马、代码漏洞、权限暴露、敏感文件泄露等。</p>
                    
                    <button id="qs-start-scan" class="button button-primary button-hero">
                        🚀 开始全盘体检
                    </button>
                    
                    <div id="qs-progress-area" style="display:none; margin-top: 20px;">
                        <h4 id="qs-current-task">正在准备体检...</h4>
                        <div class="qs-progress-bar">
                            <div class="qs-progress-fill" id="qs-progress-fill" style="width: 0%;"></div>
                        </div>
                        <p id="qs-progress-text">0 / <?php echo esc_html( $scan_step_count ); ?> 阶段</p>
                    </div>
                </div>

                <!-- 右侧：体检概览及历史 -->
                <div class="qs-panel">
                    <h2><span class="dashicons dashicons-chart-pie"></span> 安全概览</h2>
                    <div class="qs-stats">
                        <div class="qs-stat-box safety-unknown">
                            <span class="dashicons dashicons-clock"></span>
                            <strong>上次体检时间</strong>
                            <span id="qs-last-scan-status"><?php echo esc_html($scan_time_text); ?></span><br>
                            <?php if ($issues_text): ?>
                                <span style="font-weight:bold; margin-top:5px; display:inline-block; font-size:14px; color: <?php echo $last_scan->total_issues > 0 ? '#ef4444' : '#10b981'; ?>;">
                                    <?php echo esc_html($issues_text); ?>
                                </span>
                            <?php endif; ?>
                        </div>
                    </div>

                    <div class="qs-toolbar-row qs-baseline-toolbar">
                        <div class="qs-toolbar-meta">
                            文件基线状态：
                            <strong>
                                <?php echo $baseline_count > 0 ? esc_html( '已记录 ' . number_format_i18n( $baseline_count ) . ' 个文件' ) : '尚未建立'; ?>
                            </strong>
                            <br>
                            <span>
                                <?php echo ! empty( $settings['enable_file_integrity_baseline'] ) ? '当前已启用基线检测。' : '当前未启用基线检测。'; ?>
                                <?php if ( ! empty( $baseline_paths ) ) : ?>
                                    监控目录：<?php echo esc_html( implode( '、', $baseline_paths ) ); ?>
                                <?php endif; ?>
                            </span>
                        </div>
                        <div class="qs-toolbar-actions">
                            <button type="button" id="qs-rebuild-file-baseline" class="button">重建文件基线</button>
                            <span class="spinner qs-baseline-spinner" style="float:none; margin-top: 4px;"></span>
                            <span id="qs-baseline-message" style="font-weight:bold;"></span>
                        </div>
                    </div>
                    <p class="description" style="margin-bottom:0;">
                        默认不会自动建立第一份基线；请先确认当前站点文件状态可信，再手动点击“重建文件基线”。如果你明确接受首扫自动建档，也可以在扫描设置里开启“允许首次自动建立文件基线”。
                    </p>
                </div>
            </div>

            <!-- 下方：体检结果详情表 -->
            <div class="qs-panel" id="qs-results-panel" style="<?php echo $last_scan ? '' : 'display:none;'; ?> margin-top: 20px;">
                <h2><span class="dashicons dashicons-list-view"></span> 体检报告</h2>
                <table class="wp-list-table widefat fixed striped qs-results-table">
                    <thead>
                        <tr>
                            <th style="width: 100px;">严重等级</th>
                            <th style="width: 200px;">风险类型</th>
                            <th style="width: 100px;">处理状态</th>
                            <th>文件路径 / 描述摘要</th>
                            <th style="width: 220px;">处理动作</th>
                        </tr>
                    </thead>
                    <tbody id="qs-results-body">
                        <?php if ( $last_scan && $last_scan->status === 'completed' ): ?>
                            <?php 
                            $db_results = QS_DB::get_results( $last_scan->id ); 
                            if ( empty($db_results) ):
                            ?>
                                <tr><td colspan="5" style="text-align:center; padding: 20px; font-weight:bold; color:#10b981;">🎉 恭喜，本次体检未发现任何安全漏洞风险！</td></tr>
                            <?php else: ?>
                                <?php foreach ( $db_results as $res ) : ?>
                                    <?php self::render_scan_result_row( $res ); ?>
                                <?php endforeach; ?>
                            <?php endif; ?>
                        <?php else: ?>
                            <tr id="qs-placeholder-row"><td colspan="5" style="text-align:center; color:#999; padding:20px;">请点击“开始全盘体检”生成最新安全报告。</td></tr>
                        <?php endif; ?>
                    </tbody>
                </table>
            </div>

            <div style="margin-top:20px; color:#666;">
                <p>启灵专属定制化防护插件。更安全的防护建议在服务端和 CDN 实现，插件端只能做基础防护。</p>
            </div>
            </div> <!-- End Tab 1 -->

            <!-- Tab 2: 安全态势 -->
            <div id="tab-content-insights" class="qs-tab-content" style="display:none; margin-top:20px;">
                <?php self::render_security_insights_panel( $analytics ); ?>
            </div> <!-- End Tab 2 -->

            <!-- Tab 3: IP 风险画像 -->
            <div id="tab-content-iprisk" class="qs-tab-content" style="display:none; margin-top:20px;">
                <?php self::render_ip_risk_panel( $ip_risk_data, $settings ); ?>
            </div> <!-- End Tab 4 -->

            <!-- Tab 4: 安全优化 -->
            <div id="tab-content-security-optimize" class="qs-tab-content" style="display:none; margin-top:20px;">
                <?php self::render_security_optimize_panel( $settings ); ?>
            </div> <!-- End Tab 4 -->

            <!-- Tab 5: 主动防护设置 -->
            <div id="tab-content-protection" class="qs-tab-content" style="display:none; margin-top:20px;">
                <div class="qs-panel">
                    <h2><span class="dashicons dashicons-lock"></span> 站点主动加固设置</h2>
                    <p style="color:#b91c1c; font-weight:bold;">⚠️ 警告：如果您的主题或其他安全插件已经开启了以下功能，请勿在此重复开启，以免发生规则冲突！</p>
                    <?php self::render_theme_overlap_overview_notice(); ?>

                    <?php self::render_protection_settings_table( $settings, [ 'exclude_sections' => [ 'route_isolation', 'security_optimize' ] ] ); ?>

                    <p class="submit">
                        <button type="button" id="qs-save-protection" class="button button-primary">保存防护设置</button>
                        <span class="spinner qs-save-spinner" style="float:none; margin-top: 4px;"></span>
                        <span id="qs-save-message" style="margin-left:10px; font-weight:bold; color:#10b981;"></span>
                    </p>
                </div>
                <?php self::render_maintenance_panel(); ?>
                <?php self::render_rules_package_panel(); ?>
            </div> <!-- End Tab 3 -->

            <!-- Tab 6: REST 路由隔离 -->
            <div id="tab-content-route-isolation" class="qs-tab-content" style="display:none; margin-top:20px;">
                <?php self::render_route_isolation_panel( $settings ); ?>
            </div> <!-- End Tab 6 -->

            <!-- Tab 7: 域名安全替换 -->
            <div id="tab-content-domain" class="qs-tab-content" style="display:none; margin-top:20px;">
                <?php self::render_domain_replace_panel(); ?>
            </div> <!-- End Tab 7 -->

            <!-- Tab 8: Nginx 建议 -->
            <div id="tab-content-nginx" class="qs-tab-content" style="display:none; margin-top:20px;">
                <div class="qs-panel">
                    <h2><span class="dashicons dashicons-editor-code"></span> Nginx 服务器级安全加固建议</h2>
                    
                    <div class="qs-notice-box">
                        <h4>⚠️ 重要提示</h4>
                        <p>以下配置仅供 Nginx 服务器环境参考使用。修改服务器配置文件具有一定风险，请在操作前务必备份原始配置文件。部分规则需要根据您的实际域名和路径进行微调。</p>
                    </div>

                    <p>将以下规则复制并粘贴到您的 Nginx 站点配置文件的 <code>server { ... }</code> 块中，然后重启 Nginx 即可生效。</p>
                    
                    <div class="qs-nginx-code-block">
<pre><code># ================================================================
# 启灵安全防护：Nginx 深度加固推荐规则
# ================================================================

# 1. 安全响应头 (增强浏览器端防御)
add_header Strict-Transport-Security "max-age=31536000; includeSubDomains" always;
add_header X-Frame-Options "SAMEORIGIN" always;
add_header X-Content-Type-Options "nosniff" always;
add_header Referrer-Policy "strict-origin-when-cross-origin" always;
add_header Permissions-Policy "geolocation=(), microphone=(), camera=()" always;

# 2. 内容安全策略 (CSP) - 防止 XSS 注入
# 注意：如果您的主题使用了大量外部资源，请根据报错情况调整以下域名白名单
add_header Content-Security-Policy "default-src 'self'; script-src 'self' 'unsafe-inline' 'unsafe-eval' https:; style-src 'self' 'unsafe-inline' https:; img-src 'self' data: https:; font-src 'self' data: https:; connect-src 'self' https:; object-src 'none'; frame-ancestors 'self'; form-action 'self'; base-uri 'self';" always;

# 3. 限制请求方法 (只允许常见方法)
if ($request_method !~ ^(GET|POST|HEAD)$) {
    return 444;
}

# 4. 禁止带有任意 rest_route 参数的异常请求
if ($arg_rest_route != "") {
    return 403;
}

# 5. 放行标准 robots.txt
location = /robots.txt {
    allow all;
    log_not_found off;
    access_log off;
}

# 6. 保护 WP-JSON 路径
location = /wp-json {
    return 301 https://$host/;
}
location = /wp-json/ {
    return 301 https://$host/;
}

# 7. 屏蔽高风险 oEmbed 探测
location ~* ^/wp-json/oembed/1\.0(/.*)?$ {
    return 403;
}

# 8. 其余常规 REST API 仍交给 WordPress 处理
location ~* ^/wp-json(/.*)?$ {
    try_files $uri $uri/ /index.php?$args;
}

# 9. 严禁访问日志、备份、调试文件
location ~* \.(log|logs|debug|txt|sql|bak|swp)$ {
    deny all;
    access_log off;
    log_not_found off;
}

location = /wp-content/debug.log {
    deny all;
}

location ~* ^/wp-content/.*\.(log|txt|debug)$ {
    deny all;
}

# 10. 隐藏以点开头的配置文件 (如 .env, .git)
location ~ /\.(?!well-known).* {
    deny all;
}

# 11. 保护 WordPress 核心敏感文件
location ~* ^/(wp-config\.php|readme\.html|license\.txt)$ {
    deny all;
}

# 12. 禁止通过 HTTP 直接执行 wp-includes 中的 PHP
location ~* ^/wp-includes/.*\.php$ {
    deny all;
}

# 13. 【重中之重】Uploads 目录禁止执行任何 PHP 脚本
# 防止黑客上传图片马并利用漏洞执行
location ~* ^/wp-content/uploads/.*\.php$ {
    deny all;
}</code></pre>
                    </div>
                </div>
            </div> <!-- End Tab 6 -->

            <!-- Tab 7: 操作审计 -->
            <div id="tab-content-audit" class="qs-tab-content" style="display:none; margin-top:20px;">
                <div class="qs-panel">
                    <h2><span class="dashicons dashicons-welcome-view-site"></span> 关键操作审计日志</h2>
                    <p>记录网站后台关键敏感操作，并包含登录成功、登录失败、来源入口和失败累积次数，方便排查撞库和爆破。最多展示最近 100 条记录。</p>
                    <?php $audit_summary = QS_DB::get_storage_summary(); ?>
                    <div class="qs-toolbar-row">
                        <div class="qs-toolbar-meta">
                            当前审计日志总数：<strong><?php echo esc_html( number_format_i18n( $audit_summary['audit_logs'] ) ); ?></strong>
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
                                <th style="width:160px;">时间</th>
                                <th style="width:120px;">操作人</th>
                                <th style="width:150px;">动作类型</th>
                                <th>详情</th>
                                <th style="width:150px;">出处 IP</th>
                            </tr>
                        </thead>
                        <tbody>
                            <?php 
                            $logs = QS_DB::get_audit_logs(100); 
                            if ( empty($logs) ):
                            ?>
                                <tr><td colspan="5" style="text-align:center; padding: 20px;">暂无操作记录，或您尚未在【主动防护防火墙】中开启审计功能。</td></tr>
                            <?php else: ?>
                                <?php foreach ( $logs as $log ): ?>
                                <tr>
                                    <td><?php echo esc_html($log->time); ?></td>
                                    <td><strong><?php echo esc_html($log->username); ?></strong></td>
                                    <td><span class="qs-badge <?php echo esc_attr( self::get_audit_action_badge_class( $log->action_type ) ); ?>"><?php echo esc_html($log->action_type); ?></span></td>
                                    <td><?php echo esc_html($log->action_detail); ?></td>
                                    <td><code><?php echo esc_html($log->ip_address); ?></code></td>
                                </tr>
                                <?php endforeach; ?>
                            <?php endif; ?>
                        </tbody>
                    </table>
                </div>
            </div> <!-- End Tab 7 -->

            <!-- Tab 8: 动态 IP 封禁 -->
            <div id="tab-content-bans" class="qs-tab-content" style="display:none; margin-top:20px;">
                <div class="qs-panel">
                    <h2><span class="dashicons dashicons-lock"></span> 动态恶意 IP 封禁列表</h2>
                    <p>由启灵 WAF 防火墙自动拦截并封锁的高危恶意 IP。封禁期内（默认 24 小时），这些 IP 无法访问网站的任何资源。</p>
                    
                    <table class="wp-list-table widefat fixed striped">
                        <thead>
                            <tr>
                                <th style="width:150px;">恶意 IP 来源</th>
                                <th>封禁原因 (触发防线)</th>
                                <th style="width:160px;">拦截时间</th>
                                <th style="width:160px;">到期时间</th>
                                <th style="width:100px;">操作</th>
                            </tr>
                        </thead>
                        <tbody>
                            <?php 
                            $banned_ips = QS_DB::get_banned_ips(100); 
                            if ( empty($banned_ips) ):
                            ?>
                                <tr><td colspan="5" style="text-align:center; padding: 20px; color:#10b981; font-weight:bold;">当前没有被封禁的 IP。网站十分安全！</td></tr>
                            <?php else: ?>
                                <?php foreach ( $banned_ips as $ban ): ?>
                                <tr id="qs-ban-row-<?php echo esc_attr(md5($ban->ip_address)); ?>">
                                    <td><code style="color:#ef4444; font-weight:bold;"><?php echo esc_html($ban->ip_address); ?></code></td>
                                    <td style="color:#b91c1c;"><?php echo esc_html($ban->reason); ?></td>
                                    <td><?php echo esc_html($ban->ban_time); ?></td>
                                    <td><?php echo esc_html($ban->expire_time); ?></td>
                                    <td>
                                        <button type="button" class="button button-small qs-unban-btn" data-ip="<?php echo esc_attr($ban->ip_address); ?>" data-row="qs-ban-row-<?php echo esc_attr(md5($ban->ip_address)); ?>">立即解封</button>
                                    </td>
                                </tr>
                                <?php endforeach; ?>
                            <?php endif; ?>
                        </tbody>
                    </table>
                </div>
            </div> <!-- End Tab 8 -->

            <!-- Tab 9: 用户会话管理 -->
            <div id="tab-content-sessions" class="qs-tab-content" style="display:none; margin-top:20px;">
                <?php self::render_session_management_panel( $sessions, $session_summary ); ?>
            </div> <!-- End Tab 9 -->

            <!-- Tab 10: 使用说明 -->
            <div id="tab-content-help" class="qs-tab-content" style="display:none; margin-top:20px;">
                <?php self::render_usage_help_panel(); ?>
            </div> <!-- End Tab 10 -->

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
            <p>这里聚合最近 24 小时的攻击痕迹、最近 7 天的封禁趋势，以及当前仍未处理的高危风险项，方便你快速判断站点是否正在被撞库、扫站或接口滥用。</p>

            <?php if ( empty( $settings['enable_audit_log'] ) ) : ?>
                <div class="qs-inline-notice qs-inline-notice-warning">
                    当前“关键操作审计日志”还没开启。要让“登录失败”“行为限速命中”“被打入口”等统计完整显示，请先在防护设置里开启审计日志。
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
            <p>按天展示登录失败、行为限速命中和新增封禁数量。若某天突然冲高，通常意味着站点正在被集中扫描或爆破。</p>
            <?php self::render_analytics_trends( isset( $analytics['trends'] ) ? $analytics['trends'] : [] ); ?>
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
            <p>这个面板只分析“登录成功 / 登录失败尝试”的来源 IP，不会分析普通游客访问。用于识别高风险来源、异常登录模式和风险信号标签。</p>

            <?php if ( ! $enabled ) : ?>
                <div class="qs-inline-notice qs-inline-notice-warning">
                    你还没有开启“登录 IP 风险画像”。请到「主动防护防火墙 -> 登录 IP 风险画像」先开启后再观察数据。
                </div>
            <?php else : ?>
                <div class="qs-inline-notice">
                    当前模式：<?php echo esc_html( 'external' === $query_mode ? '外部任务' : ( 'async' === $query_mode ? '异步查询（WP-Cron）' : '同步查询' ) ); ?>，
                    触发范围：<?php echo esc_html( self::get_ip_risk_scope_label( $scope ) ); ?>，
                    每次最多调用来源：<?php echo esc_html( number_format_i18n( $max_provider_num ) ); ?>。
                    未填写 API Key 的收费来源会自动回退到公共来源查询，不会让画像功能空跑。
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
                    数据维护：你可以清空画像缓存、清空画像事件，或全部清空。单个 IP 记录可在“查看详情”面板内删除。
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
                <h4>外部自动任务监控链接</h4>
                <p>如果你希望完全不依赖 WP-Cron 自动清理过期数据或自动刷新 IP，可将下方链接加入宝塔计划任务（访问 URL）或 UptimeRobot 监控中：</p>
                <p>
                    <strong>自动刷新待处理 IP：</strong><br>
                    <code><?php echo esc_url( QS_Protection::get_ip_risk_external_cron_url( $settings ) ); ?></code>
                </p>
                <p>
                    <strong>自动清理过期历史画像（建议每天执行一次）：</strong><br>
                    <code><?php echo esc_url( QS_Protection::get_ip_risk_external_cleanup_url( $settings ) ); ?></code>
                </p>
                <p class="description">
                    * 访问密钥已自动包含在 URL 中，请勿轻易泄露给他人。
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
            'ipregistry' => [ 'label' => 'IPRegistry', 'requires_key' => false, 'key_field' => 'ipregistry_key' ],
            'ipdata'     => [ 'label' => 'IPData', 'requires_key' => true, 'key_field' => 'ipdata_key' ],
            'ip_api'     => [ 'label' => 'IP-API (延迟高)', 'requires_key' => false, 'key_field' => '' ],
            'ipinfo'     => [ 'label' => 'IPinfo', 'requires_key' => false, 'key_field' => 'ipinfo_token' ],
            'ip_sb'      => [ 'label' => 'IP.SB (延迟高)', 'requires_key' => false, 'key_field' => '' ],
            'ipbset'     => [ 'label' => 'IPBSET (即时数科)', 'requires_key' => true, 'key_field' => 'ipbset_key' ],
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
            <p>这里用于手动收口过期历史数据。清理规则会读取上面的“数据生命周期”配置，只删除超过保留天数的扫描/审计记录，并始终删除已经过期的封禁记录。下方数字显示的是当前剩余总量，不是本次删除数量。</p>

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
                <p>“清空全部历史数据”会一次性删除扫描任务、扫描结果、审计日志、封禁记录、文件基线、手机号归属地缓存、IP 风险画像缓存和 IP 风险登录事件，且无法恢复。该操作不会删除防护设置和官方规则包，请仅在确认需要瘦身数据表或重置历史记录时使用。</p>
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
            <p>这里展示当前仍然有效的登录会话。你可以强制单个设备下线、把某个用户的全部会话踢下线，或让全站其他用户重新登录。不会新增任何 cron 任务。</p>

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

    private static function render_domain_replace_panel() {
        $targets = class_exists( 'QS_Domain_Replace' ) ? QS_Domain_Replace::get_targets() : [];
        ?>
        <div class="qs-panel">
            <h2><span class="dashicons dashicons-admin-site"></span> 域名安全替换（序列化安全）</h2>
            <p style="color:#374151;">
                用于站点换域名后的安全替换，自动处理 PHP 序列化数据，避免出现“模块/设置读不出来”的问题。强烈建议先完整备份数据库。
            </p>
            <p class="description" style="margin-top:-4px; margin-bottom:16px;">
                现在已支持单独替换媒体库图片/文件的附件链接（guid）以及常见附件元数据；如果站点启用了启灵积分商城或启灵社区，也会自动提供对应插件的数据表替换目标。启灵积分商城范围包含商品图、SKU 图、规格值图、分类图、订单商品快照图和评价晒图。此类第三方插件目标只会在检测到相关数据表时显示，且默认不勾选，建议按需手动选择。
            </p>

            <table class="form-table">
                <tr>
                    <th scope="row">旧域名/旧地址</th>
                    <td>
                        <input type="text" id="qs-domain-old" class="regular-text" placeholder="例如 oldsite.com 或 https://oldsite.com" />
                    </td>
                </tr>
                <tr>
                    <th scope="row">新域名/新地址</th>
                    <td>
                        <input type="text" id="qs-domain-new" class="regular-text" placeholder="例如 newsite.com 或 https://newsite.com" />
                    </td>
                </tr>
                <tr>
                    <th scope="row">替换策略</th>
                    <td>
                        <label style="display:inline-flex; align-items:center; gap:8px;">
                            <input type="checkbox" id="qs-domain-include-schemes" checked />
                            自动包含 http/https/协议相对地址
                        </label>
                        <p class="description" style="margin-top:6px;">会同时替换 <code>http://</code>、<code>https://</code> 和 <code>//</code> 开头的地址。</p>
                    </td>
                </tr>
                <tr>
                    <th scope="row">替换范围</th>
                    <td>
                        <div style="display:flex; flex-direction:column; gap:10px;">
                            <?php if ( empty( $targets ) ) : ?>
                                <span style="color:#ef4444;">未检测到可替换的数据库表。</span>
                            <?php else : ?>
                                <?php foreach ( $targets as $key => $target ) : ?>
                                    <?php
                                    $checked = ! empty( $target['default'] ) ? 'checked' : '';
                                    $danger  = ! empty( $target['danger'] );
                                    ?>
                                    <label style="display:flex; align-items:flex-start; gap:10px;">
                                        <input type="checkbox"
                                               class="qs-domain-target"
                                               data-target="<?php echo esc_attr( $key ); ?>"
                                               data-label="<?php echo esc_attr( $target['label'] ); ?>"
                                               <?php echo $checked; ?> />
                                        <span>
                                            <strong style="<?php echo $danger ? 'color:#b91c1c;' : ''; ?>"><?php echo esc_html( $target['label'] ); ?></strong>
                                            <span style="margin-left:6px;color:#6b7280;">
                                                <?php echo esc_html( isset( $target['table'] ) ? (string) $target['table'] : '' ); ?>
                                            </span><br/>
                                            <span style="color:#6b7280;"><?php echo esc_html( $target['desc'] ); ?></span>
                                        </span>
                                    </label>
                                <?php endforeach; ?>
                            <?php endif; ?>
                        </div>
                    </td>
                </tr>
            </table>

            <p class="submit" style="display:flex; align-items:center; gap:10px;">
                <button type="button" class="button" id="qs-domain-preview">预览影响</button>
                <button type="button" class="button button-primary" id="qs-domain-execute">执行替换</button>
                <span class="spinner" id="qs-domain-spinner" style="float:none;"></span>
                <span id="qs-domain-message" style="font-weight:bold;"></span>
            </p>

            <div id="qs-domain-progress" style="margin-top:10px; color:#374151;"></div>
            <div id="qs-domain-result" style="margin-top:10px; color:#1f2937;"></div>
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

    private static function render_route_isolation_panel( $settings ) {
        $mu_plugin_path      = QS_Protection::get_rest_plugin_isolation_mu_plugin_path();
        $mu_plugin_filename  = QS_Protection::get_rest_plugin_isolation_mu_plugin_filename();
        $mu_plugin_installed = QS_Protection::is_rest_plugin_isolation_mu_plugin_installed();
        ?>
        <div class="qs-panel">
            <h2><span class="dashicons dashicons-randomize"></span> REST API 路由隔离加载</h2>
            <p>这个面板只负责第三方 REST API 请求的按路由加载，避免使用A插件的REST API时把其他无关插件也完整加载一遍。</p>

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

    private static function render_security_optimize_panel( $settings ) {
        $selected_fields = [
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
        ?>
        <div class="qs-panel">
            <h2><span class="dashicons dashicons-performance"></span> WordPress 安全优化</h2>
            <p>这里聚合的是“本身不属于防火墙，但对收敛暴露面、减少后台外联、降低旧接口攻击面有帮助”的优化项。</p>
            <p style="color:#b91c1c; font-weight:bold;">⚠️ 如果你当前站点已经在启灵主题、其他安全插件或服务器层启用了相同能力，请不要重复开启。</p>
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

    private static function render_route_isolation_monitor_panel( $settings ) {
        $settings        = is_array( $settings ) ? $settings : QS_Protection::get_settings();
        $monitor_enabled = ! empty( $settings['rest_plugin_isolation_monitor_enabled'] );
        $max_entries     = QS_Protection::get_rest_plugin_isolation_monitor_max_entries( $settings );
        $logs            = QS_Protection::get_rest_plugin_isolation_monitor_logs( $max_entries );
        ?>
        <div class="qs-panel" style="margin-top:20px;">
            <h2><span class="dashicons dashicons-chart-line"></span> 路由隔离监控面板</h2>
            <p>展示最近的 REST 路由隔离决策，便于核对“命中规则”和“最终加载插件”是否符合预期。</p>
            <p class="description">
                当前监控状态：<?php echo $monitor_enabled ? '<strong style="color:#15803d;">已开启</strong>' : '<strong style="color:#b91c1c;">未开启</strong>'; ?>；
                最大保留条数：<?php echo esc_html( number_format_i18n( $max_entries ) ); ?>。
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
                        type="<?php echo esc_attr( 'number' === $type ? 'number' : 'text' ); ?>"
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
            <p style="font-weight:bold; margin-bottom:6px;">作者联系方式</p>
            <p style="margin-top:0;">微信/QQ：19577566　版权：启灵生态圈</p>
            <hr>
            <p style="font-weight:bold; margin-bottom:6px;">插件简介</p>
            <p style="margin-top:0;">启灵安全防护插件用于 WordPress 站点的日常安全巡检与主动防护，覆盖扫描、审计、封禁与防火墙等常见能力。</p>
            <ul style="margin-top:8px;">
                <li>全盘安全体检：扫描常见恶意代码、可疑文件与高风险配置。</li>
                <li>主动防护防火墙：支持登录防爆破、行为限速、请求过滤与安全响应头。</li>
                <li>操作审计与封禁：记录关键后台动作，自动封禁恶意来源 IP。</li>
            </ul>
        </div>
        <?php
    }
}
