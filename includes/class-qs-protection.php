<?php
/**
 * 安全防护插件 - 主动防护与防火墙模块
 */
if ( ! defined( 'ABSPATH' ) ) {
    exit;
}

class QS_Protection {

    public static function get_setting_sections() {
        $sections = [
            'hardening' => [
                'title'       => '基础加固',
                'description' => '适合大多数 WordPress 站点的基础收敛项，建议先从这里开启。',
            ],
            'security_optimize' => [
                'title'       => '安全优化',
                'description' => '把启灵主题里对安全有帮助的 WordPress 收敛项单独抽出来，便于非启灵主题站点直接复用。',
            ],
            'route_isolation' => [
                'title'       => 'API 路由按需加载',
                'description' => '针对第三方 REST API 请求按路由加载必要插件，减少无关插件重复加载。核心插件可保持常驻。',
            ],
            'whitelist' => [
                'title'       => '白名单与例外',
                'description' => '给可信来源留出安全例外，避免把内部办公网、反代探针或自定义接口误拦截。',
            ],
            'network' => [
                'title'       => '代理与真实 IP',
                'description' => '站点位于 CDN、WAF 或反向代理后面时，请在这里声明可信代理与转发头，确保封禁、审计和限速命中真实访客。',
            ],
            'audit'     => [
                'title'       => '审计与追踪',
                'description' => '记录关键后台动作，便于回溯异常登录、配置变更和内容删除。',
            ],
            'login'     => [
                'title'       => '登录入口保护',
                'description' => '控制暴力破解阈值和隐藏登录入口的策略，避免完全写死。',
            ],
            'behavior'  => [
                'title'       => '行为型限速防护',
                'description' => '不是靠关键字匹配，而是按请求频率识别爆破、扫站和接口滥用。建议先观察，再切换到拦截或封禁。',
            ],
            'waf'       => [
                'title'       => 'WAF 与响应防护',
                'description' => '防火墙规则、爬虫拦截和响应头都允许按站点情况扩展。',
            ],
            'scanner'   => [
                'title'       => '扫描引擎高级设置',
                'description' => '大站点通常需要调大扫描上限、补充敏感后缀或排除缓存目录。',
            ],
            'phone'     => [
                'title'       => '手机号归属地',
                'description' => '基于本地号段库 qiphone.dat 解析手机号归属地，可给主题用户中心提供归属地展示与后续分析数据来源。',
            ],
            'ip_risk'   => [
                'title'       => '登录 IP 风险画像',
                'description' => '仅针对登录成功与登录尝试的来源 IP 做风险画像，不会扫描普通游客前台访问。支持多数据源聚合、异步刷新、外部定时任务与本地缓存。',
            ],
            'maintenance' => [
                'title'       => '数据生命周期',
                'description' => '控制历史报告和审计记录的保留策略，避免数据表越积越大。',
            ],
        ];

        return apply_filters( 'qs_setting_sections', $sections );
    }

    public static function get_setting_fields() {
        $fields = [
            'disable_xmlrpc'            => [
                'section'     => 'hardening',
                'type'        => 'checkbox',
                'label'       => '禁用 XML-RPC 接口',
                'description' => '彻底关闭 xmlrpc.php，减少暴力破解和 DDoS 放大攻击面。',
                'default'     => false,
                'recommended' => true,
            ],
            'hide_wp_version'           => [
                'section'     => 'hardening',
                'type'        => 'checkbox',
                'label'       => '隐藏 WordPress 版本号',
                'description' => '移除前台 head 和 feed 中的版本标识，降低版本指纹暴露。',
                'default'     => false,
            ],
            'block_user_enum'           => [
                'section'     => 'hardening',
                'type'        => 'checkbox',
                'label'       => '拦截用户枚举探测',
                'description' => '阻止未授权访问 /wp-json/wp/v2/users、/?author=N 与用户站点地图等常见枚举入口。',
                'default'     => false,
            ],
            'disable_file_editor'       => [
                'section'     => 'hardening',
                'type'        => 'checkbox',
                'label'       => '禁止后台编辑源码',
                'description' => '禁用主题/插件文件编辑器，避免后台被接管后直接写木马。',
                'default'     => false,
                'recommended' => true,
            ],
            'disable_app_passwords'     => [
                'section'     => 'hardening',
                'type'        => 'checkbox',
                'label'       => '禁用应用程序密码',
                'description' => '如果站点不依赖外部客户端登录，建议关闭 Application Passwords。',
                'default'     => false,
            ],
            'disable_emoji'             => [
                'section'     => 'security_optimize',
                'type'        => 'checkbox',
                'label'       => '禁用 Emoji 脚本',
                'description' => '移除 WordPress 自带 Emoji 检测脚本、样式和相关资源提示，减少前后台多余暴露面与无用请求。',
                'default'     => false,
            ],
            'disable_embeds'            => [
                'section'     => 'security_optimize',
                'type'        => 'checkbox',
                'label'       => '禁用 oEmbed',
                'description' => '关闭 oEmbed REST 路由、发现链接和前端宿主脚本，减少外部嵌入相关暴露面。',
                'default'     => false,
            ],
            'remove_shortlink'          => [
                'section'     => 'security_optimize',
                'type'        => 'checkbox',
                'label'       => '移除短链接',
                'description' => '移除页面 head 与响应头中的短链接输出，减少不必要的站点元信息暴露。',
                'default'     => false,
            ],
            'remove_rsd_wlw'            => [
                'section'     => 'security_optimize',
                'type'        => 'checkbox',
                'label'       => '移除 RSD / WLW',
                'description' => '移除 Really Simple Discovery 和 Windows Live Writer 相关发现链接，减少旧接口指纹暴露。',
                'default'     => false,
            ],
            'admin_disable_remote_block_patterns' => [
                'section'     => 'security_optimize',
                'type'        => 'checkbox',
                'label'       => '关闭远程区块 Patterns',
                'description' => '后台编辑器不再请求 WordPress.org 的远程区块样式库，减少后台对外联机依赖。',
                'default'     => false,
            ],
            'admin_disable_block_directory' => [
                'section'     => 'security_optimize',
                'type'        => 'checkbox',
                'label'       => '关闭区块目录搜索',
                'description' => '关闭编辑器中的在线区块目录，减少后台远程搜索与第三方资源加载。',
                'default'     => false,
            ],
            'admin_disable_openverse'   => [
                'section'     => 'security_optimize',
                'type'        => 'checkbox',
                'label'       => '关闭 Openverse 媒体面板',
                'description' => '关闭 Gutenberg 媒体选择器中的 Openverse 远程资源入口，避免后台额外外联。',
                'default'     => false,
            ],
            'admin_reduce_editor_preload' => [
                'section'     => 'security_optimize',
                'type'        => 'checkbox',
                'label'       => '精简编辑器预加载接口',
                'description' => '减少编辑器预加载的区块目录与样式库请求，降低后台一次性暴露和联机负担。',
                'default'     => false,
            ],
            'clean_meta_tags'           => [
                'section'     => 'hardening',
                'type'        => 'checkbox',
                'label'       => '清理头部多余 Meta 标签',
                'description' => '移除 rsd、wlwmanifest、shortlink、REST 发现链接等暴露信息。',
                'default'     => false,
            ],
            'disable_pingback'          => [
                'section'     => 'hardening',
                'type'        => 'checkbox',
                'label'       => '拦截 XML-RPC Pingback',
                'description' => '只关闭 Pingback 相关方法，减少被滥用做反射放大攻击的风险。',
                'default'     => false,
            ],
            'enable_rest_api_guard'     => [
                'section'     => 'hardening',
                'type'        => 'checkbox',
                'label'       => '启用 REST API 精细防护',
                'description' => '对游客访问的敏感 REST 路由做更细的规则控制，并可观察未知公开路由访问痕迹。',
                'default'     => false,
                'recommended' => true,
            ],
            'rest_api_guard_mode'       => [
                'section'     => 'hardening',
                'type'        => 'select',
                'label'       => 'REST API 防护模式',
                'description' => '观察模式只记录日志；拦截模式会直接阻止命中敏感路由的游客访问。',
                'default'     => 'observe',
                'choices'     => [
                    'observe' => '仅观察记录',
                    'block'   => '直接拦截敏感路由',
                ],
            ],
            'rest_api_public_block_prefixes' => [
                'section'     => 'hardening',
                'type'        => 'textarea',
                'label'       => 'REST 敏感公开路由前缀',
                'description' => '每行一个 REST 路由前缀，例如 /wp/v2/users。未登录访客命中这些前缀时，将按上面的模式观察或拦截。',
                'default'     => "/wp/v2/users\n/wp/v2/settings\n/wp/v2/plugins\n/wp/v2/themes\n/wp-site-health/v1\n/wp-block-editor/v1",
                'rows'        => 5,
            ],
            'rest_api_public_allow_prefixes' => [
                'section'     => 'hardening',
                'type'        => 'textarea',
                'label'       => 'REST 允许公开访问前缀',
                'description' => '用于“观察未知公开路由”时的白名单。常见公开内容接口可放在这里，避免重复记录。',
                'default'     => "/oembed/1.0\n/wp/v2/posts\n/wp/v2/pages\n/wp/v2/media\n/wp/v2/categories\n/wp/v2/tags\n/wp/v2/search",
                'rows'        => 5,
            ],
            'rest_api_observe_unknown_public' => [
                'section'     => 'hardening',
                'type'        => 'checkbox',
                'label'       => '观察未知公开 REST 路由',
                'description' => '对未登录访客访问、且不在允许前缀中的公开 REST 路由记录审计，帮助识别插件暴露出来的 API 面。',
                'default'     => false,
            ],
            'rest_plugin_isolation_enabled' => [
                'section'     => 'route_isolation',
                'type'        => 'checkbox',
                'label'       => '启用 REST 路由按需加载隔离',
                'description' => '仅影响 REST 路由。命中你配置的路由后，将仅加载该路由需要的插件与核心常驻插件。',
                'default'     => false,
            ],
            'rest_plugin_isolation_mode' => [
                'section'     => 'route_isolation',
                'type'        => 'select',
                'label'       => '隔离模式',
                'description' => '建议先使用“仅隔离命中规则”逐步上线。',
                'default'     => 'matched_only',
                'choices'     => [
                    'matched_only' => '仅隔离命中规则的 REST 路由（推荐）',
                    'all_rest'     => '所有 REST 请求都启用路由白名单（高级）',
                ],
            ],
            'rest_plugin_isolation_core_plugins' => [
                'section'     => 'route_isolation',
                'type'        => 'textarea',
                'label'       => '核心常驻插件（每行一个）',
                'description' => '格式：插件目录/主文件.php。这里的插件在隔离命中时始终加载，可用于保持站点核心能力。',
                'default'     => 'qilingsecurity/qilingsecurity.php',
                'rows'        => 4,
            ],
            'rest_plugin_isolation_rules' => [
                'section'          => 'route_isolation',
                'type'             => 'textarea',
                'label'            => '路由与插件白名单规则',
                'description_html' => '每行一条规则：<code>/qilingtxt/v1/ =&gt; qilingtxt/qilingtxt.php</code>。可写多个插件，用英文逗号分隔；以 <code>#</code> 开头的行为注释。',
                'default'          => self::get_rest_plugin_isolation_default_rules_as_text(),
                'rows'             => 8,
            ],
            'rest_plugin_isolation_monitor_enabled' => [
                'section'     => 'route_isolation',
                'type'        => 'checkbox',
                'label'       => '启用隔离监控日志',
                'description' => '只记录 REST 路由隔离决策（命中规则、最终加载插件数等），用于排查是否按预期生效。',
                'default'     => false,
            ],
            'rest_plugin_isolation_monitor_max_entries' => [
                'section'     => 'route_isolation',
                'type'        => 'number',
                'label'       => '监控日志最大保留条数',
                'description' => '超过上限会自动丢弃最旧日志。建议 50-200。',
                'default'     => 100,
                'min'         => 20,
                'max'         => 500,
                'step'        => 10,
                'class'       => 'small-text',
            ],
            'trusted_ips'               => [
                'section'     => 'whitelist',
                'type'        => 'textarea',
                'label'       => '可信 IP / 网段白名单',
                'description' => '每行一个 IP 或 CIDR 网段，例如 127.0.0.1、192.168.1.0/24。白名单不会触发封禁、WAF 和登录限流。',
                'default'     => '',
                'rows'        => 4,
            ],
            'trusted_request_paths'     => [
                'section'     => 'whitelist',
                'type'        => 'textarea',
                'label'       => '可信请求路径前缀',
                'description' => '每行一个路径前缀，例如 /wp-json/my-app/ 或 /healthz。命中后跳过 WAF 和扫描器 UA 拦截。',
                'default'     => '',
                'rows'        => 4,
            ],
            'proxy_preset'              => [
                'section'     => 'network',
                'type'        => 'select',
                'label'       => '代理 / CDN 预设',
                'description' => '按当前站点所处的代理环境选择预设。预设会给出推荐请求头顺序；第三方 CDN 的可信代理 IP / 网段仍建议按厂商官方列表手动维护。',
                'default'     => 'manual',
                'choices'     => self::get_proxy_preset_choices(),
            ],
            'trusted_proxy_ips'         => [
                'section'     => 'network',
                'type'        => 'textarea',
                'label'       => '可信代理 IP / 网段',
                'description' => '每行一个反向代理、CDN 或 WAF 的出口 IP / CIDR。只有命中这里的 REMOTE_ADDR，插件才会信任转发头解析真实用户 IP。若链路上有多层代理，请把所有可信代理出口都写全。',
                'default'     => '',
                'rows'        => 4,
            ],
            'trusted_proxy_headers'     => [
                'section'     => 'network',
                'type'        => 'textarea',
                'label'       => '真实 IP 请求头优先级',
                'description' => '每行一个服务器变量名，例如 HTTP_CF_CONNECTING_IP、HTTP_X_FORWARDED_FOR。将按从上到下的顺序解析；留空时会回退到所选预设的推荐顺序。X-Forwarded-For 会从右向左剥离可信代理，避免被前置伪造链污染。',
                'default'     => '',
                'rows'        => 4,
            ],
            'trust_proxy_headers_without_ip' => [
                'section'     => 'network',
                'type'        => 'checkbox',
                'label'       => '宽松模式：仅凭请求头识别真实 IP',
                'description' => '开启后，不再要求 REMOTE_ADDR 命中“可信代理 IP / 网段”，只要命中上面的真实 IP 请求头就会解析。这更省事，但安全性更低，恶意请求可伪造头部来源。',
                'default'     => false,
            ],
            'enable_audit_log'          => [
                'section'     => 'audit',
                'type'        => 'checkbox',
                'label'       => '启用关键操作审计日志',
                'description' => '记录登录、登出、插件启停、系统设置更新、文章删除和核心升级。',
                'default'     => false,
            ],
            'limit_login_attempts'      => [
                'section'     => 'login',
                'type'        => 'checkbox',
                'label'       => '开启限制登录尝试防撞库',
                'description' => '达到失败阈值后自动封禁来源 IP，防止持续爆破密码。',
                'default'     => false,
            ],
            'login_max_attempts'        => [
                'section'     => 'login',
                'type'        => 'number',
                'label'       => '允许失败次数',
                'description' => '连续失败达到该值后，来源 IP 会被暂时封禁。',
                'default'     => 5,
                'min'         => 1,
                'max'         => 20,
                'step'        => 1,
                'class'       => 'small-text',
            ],
            'login_lockout_hours'       => [
                'section'     => 'login',
                'type'        => 'number',
                'label'       => '封禁时长（小时）',
                'description' => '暴力破解触发后的封禁时长，可按业务风险级别调整。',
                'default'     => 24,
                'min'         => 1,
                'max'         => 720,
                'step'        => 1,
                'class'       => 'small-text',
            ],
            'hide_login_error_details'  => [
                'section'     => 'login',
                'type'        => 'checkbox',
                'label'       => '隐藏登录错误细节',
                'description' => '统一返回通用登录失败提示，避免暴露“用户名不存在 / 密码错误”等可被枚举利用的差异信息。',
                'default'     => true,
                'recommended' => true,
            ],
            'max_concurrent_sessions'   => [
                'section'     => 'login',
                'type'        => 'number',
                'label'       => '单用户最大并发登录设备数',
                'description' => '填 0 表示不限制。大于 0 时，用户登录后若活跃会话超过该值，会自动下线最早的旧会话并保留当前设备。',
                'default'     => 0,
                'min'         => 0,
                'max'         => 20,
                'step'        => 1,
                'class'       => 'small-text',
            ],
            'custom_login_url'          => [
                'section'     => 'login',
                'type'        => 'text',
                'label'       => '自定义隐藏后台入口',
                'description' => '留空即不开启。启用后会给登录、找回密码、登出等核心链接自动补充暗号。',
                'default'     => '',
                'placeholder' => '例如: woshiadmin',
                'prefix'      => site_url( 'wp-login.php?' ),
                'class'       => 'regular-text',
            ],
            'enable_ip_risk_profile'   => [
                'section'     => 'ip_risk',
                'type'        => 'checkbox',
                'label'       => '启用登录 IP 风险画像',
                'description' => '仅在“登录成功 / 登录失败尝试”时触发，不会对普通游客页面请求做画像。',
                'default'     => false,
            ],
            'ip_risk_scope'            => [
                'section'     => 'ip_risk',
                'type'        => 'select',
                'label'       => '画像触发范围',
                'description' => '控制在登录链路的哪个阶段触发风险画像。',
                'default'     => 'both',
                'choices'     => [
                    'both'         => '登录成功 + 登录失败尝试',
                    'attempt_only' => '仅登录失败尝试',
                    'success_only' => '仅登录成功',
                ],
            ],
            'ip_risk_query_mode'       => [
                'section'     => 'ip_risk',
                'type'        => 'select',
                'label'       => '查询模式',
                'description' => '同步模式会在登录流程里即时查询；异步模式使用 WP-Cron；外部任务模式用于宝塔/第三方定时访问任务地址。',
                'default'     => 'async',
                'choices'     => [
                    'external' => '外部任务（推荐）',
                    'async' => '异步（WP-Cron）',
                    'sync'  => '同步即时查询',
                ],
            ],
            'ip_risk_external_cron_key' => [
                'section'     => 'ip_risk',
                'type'        => 'text',
                'label'       => '外部任务访问密钥',
                'description' => '用于校验定时任务请求。仅支持字母、数字、下划线和中划线；留空时会使用站点派生密钥。',
                'default'     => '',
                'placeholder' => '例如: ql_iprisk_2026_xxx',
                'class'       => 'regular-text',
            ],
            'ip_risk_external_batch_size' => [
                'section'     => 'ip_risk',
                'type'        => 'number',
                'label'       => '外部任务每次处理 IP 数',
                'description' => '每次定时访问最多处理多少个待刷新 IP。建议 10~50。',
                'default'     => 20,
                'min'         => 1,
                'max'         => 200,
                'step'        => 1,
                'class'       => 'small-text',
            ],
            'ip_risk_cache_ttl_hours'  => [
                'section'     => 'ip_risk',
                'type'        => 'number',
                'label'       => '画像缓存有效期（小时）',
                'description' => '命中有效缓存时不重复请求外部来源，减少耗时与成本。',
                'default'     => 168,
                'min'         => 1,
                'max'         => 2160,
                'step'        => 1,
                'class'       => 'small-text',
            ],
            'ip_risk_provider_timeout_ms' => [
                'section'     => 'ip_risk',
                'type'        => 'number',
                'label'       => '单来源超时（毫秒）',
                'description' => '单个外部来源请求超时时间。建议 800~2500 毫秒之间。',
                'default'     => 1500,
                'min'         => 300,
                'max'         => 10000,
                'step'        => 100,
                'class'       => 'small-text',
            ],
            'ip_risk_max_provider_calls' => [
                'section'     => 'ip_risk',
                'type'        => 'number',
                'label'       => '每次最多调用来源数',
                'description' => '按下方来源顺序从上到下调用，超出数量会被跳过，用于控制性能和成本。',
                'default'     => 5,
                'min'         => 1,
                'max'         => 10,
                'step'        => 1,
                'class'       => 'small-text',
            ],
            'ip_risk_providers'        => [
                'section'     => 'ip_risk',
                'type'        => 'multi_checkbox',
                'label'       => '风险来源（勾选启用）',
                'description' => '勾选即启用该来源。未填写 Key 的收费来源会自动回退公共来源。',
                'default'     => "ipregistry\nipdata\nip_api\nipinfo\nip_sb",
                'choices'     => [
                    'ipregistry' => 'IPRegistry',
                    'ipdata'     => 'IPData',
                    'ipinfo'     => 'IPinfo (仅用于 IP 查询对比)',
                    'ipbset'     => 'IPBSET (即时数科)',
                    'ip_api'     => 'IP-API (延迟高, 仅用于 IP 查询对比)',
                    'ip_sb'      => 'IP.SB (延迟高, 仅用于 IP 查询对比)',
                ],
            ],
            'ip_risk_ipbset_key'       => [
                'section'     => 'ip_risk',
                'type'        => 'text',
                'label'       => 'IPBSET (即时数科) API Key',
                'description' => '访问 api.jishishuke.com 时的接口密钥。',
                'default'     => '',
                'class'       => 'regular-text',
            ],
            'ip_risk_ipregistry_key'   => [
                'section'     => 'ip_risk',
                'type'        => 'text',
                'label'       => 'IPRegistry API Key（可选）',
                'description' => '留空时自动回退到公共来源查询。',
                'default'     => '',
                'class'       => 'regular-text',
            ],
            'ip_risk_ipdata_key'       => [
                'section'     => 'ip_risk',
                'type'        => 'text',
                'label'       => 'IPData API Key（可选）',
                'description' => '留空时自动回退到公共来源查询。',
                'default'     => '',
                'class'       => 'regular-text',
            ],
            'ip_risk_ipinfo_token'     => [
                'section'     => 'ip_risk',
                'type'        => 'text',
                'label'       => 'IPinfo Token（可选）',
                'description' => '可留空；留空时按 IPinfo 公共额度查询。',
                'default'     => '',
                'class'       => 'regular-text',
            ],
            'enable_behavior_rate_limit' => [
                'section'     => 'behavior',
                'type'        => 'checkbox',
                'label'       => '启用行为型请求限速',
                'description' => '按 IP + 入口 + 时间窗跟踪高频请求，适合拦截撞库、扫站和接口滥用。',
                'default'     => false,
                'recommended' => true,
            ],
            'behavior_rate_limit_mode'  => [
                'section'     => 'behavior',
                'type'        => 'select',
                'label'       => '触发后动作',
                'description' => '观察模式只记录日志；拦截模式返回 429；封禁模式会额外把来源 IP 加入临时封禁列表。',
                'default'     => 'observe',
                'choices'     => [
                    'observe' => '仅观察记录',
                    'block'   => '直接拦截',
                    'ban'     => '拦截并临时封禁',
                ],
            ],
            'behavior_rate_limit_ban_hours' => [
                'section'     => 'behavior',
                'type'        => 'number',
                'label'       => '行为封禁时长（小时）',
                'description' => '仅在上面选择“拦截并临时封禁”时生效。',
                'default'     => 12,
                'min'         => 1,
                'max'         => 720,
                'step'        => 1,
                'class'       => 'small-text',
            ],
            'waf_core'                  => [
                'section'     => 'waf',
                'type'        => 'checkbox',
                'label'       => '启用核心 WAF 规则',
                'description' => '检查 GET/POST/COOKIE 中的高风险特征，发现异常请求立即中断。',
                'default'     => false,
                'recommended' => true,
            ],
            'block_bad_uploads'         => [
                'section'     => 'waf',
                'type'        => 'checkbox',
                'label'       => '拦截高危上传文件名',
                'description' => '阻止危险后缀、双后缀伪装文件和其他明显不适合作为媒体上传的执行型文件。',
                'default'     => false,
            ],
            'upload_disallowed_extensions' => [
                'section'     => 'waf',
                'type'        => 'textarea',
                'label'       => '上传禁止后缀列表',
                'description' => '每行或逗号一个后缀，不需要写点号。会用于上传即时拦截和 uploads 历史扫描。',
                'default'     => "php\nphp3\nphp4\nphp5\nphp7\nphp8\nphtml\nphar\njsp\njspx\nasp\naspx\ncgi\npl\npy\nsh\nexe\ncom\nbat\ncmd",
                'rows'        => 5,
            ],
            'strict_upload_validation' => [
                'section'     => 'waf',
                'type'        => 'checkbox',
                'label'       => '严格校验上传文件内容与后缀',
                'description' => '对常见图片和 SVG 做内容校验，阻止“扩展名像图片，实际内容不是图片”的伪装上传。',
                'default'     => false,
                'recommended' => true,
            ],
            'block_svg_uploads'        => [
                'section'     => 'waf',
                'type'        => 'checkbox',
                'label'       => '禁止上传 SVG 文件',
                'description' => '即使其他插件或代码放开了 SVG 上传，这里也能再次拦截。适合不需要 SVG 的普通站点。',
                'default'     => false,
            ],
            'upload_mime_ignored_extensions' => [
                'section'     => 'waf',
                'type'        => 'textarea',
                'label'       => '上传 MIME 校验忽略后缀',
                'description' => '每行或逗号一个后缀。适合为极少数你明确知道会误报的文件类型放行 MIME 一致性校验。',
                'default'     => '',
                'rows'        => 3,
            ],
            'block_bad_scanners'        => [
                'section'     => 'waf',
                'type'        => 'checkbox',
                'label'       => '拦截已知漏洞扫描器 User-Agent',
                'description' => '结合内置黑名单和自定义关键字，阻断明显恶意的自动化扫描。',
                'default'     => false,
            ],
            'extra_bad_bots'            => [
                'section'     => 'waf',
                'type'        => 'textarea',
                'label'       => '额外拦截 User-Agent 关键字',
                'description' => '每行或逗号一个关键字，会与内置扫描器黑名单合并。',
                'default'     => '',
                'rows'        => 4,
            ],
            'disable_directory_index'   => [
                'section'     => 'waf',
                'type'        => 'checkbox',
                'label'       => '提示关闭目录浏览',
                'description' => '该项只保留配置提醒，不会自动改写 .htaccess 或 Nginx 规则。',
                'default'     => false,
            ],
            'add_security_headers'      => [
                'section'     => 'waf',
                'type'        => 'checkbox',
                'label'       => '追加安全响应头',
                'description' => '发送 X-Frame-Options、nosniff、Referrer-Policy 等默认头部。',
                'default'     => false,
                'recommended' => true,
            ],
            'extra_security_headers'    => [
                'section'     => 'waf',
                'type'        => 'textarea',
                'label'       => '自定义响应头',
                'description' => '每行一个 Header-Name: value，会在默认安全头之外追加。',
                'default'     => '',
                'rows'        => 4,
            ],
            'scan_max_files'            => [
                'section'     => 'scanner',
                'type'        => 'number',
                'label'       => '单次目录遍历上限',
                'description' => '默认 10000；站点文件特别多时可调大，避免扫描被截断。',
                'default'     => 10000,
                'min'         => 1000,
                'max'         => 200000,
                'step'        => 500,
                'class'       => 'small-text',
            ],
            'image_scan_max_kb'         => [
                'section'     => 'scanner',
                'type'        => 'number',
                'label'       => '图片内容扫描上限（KB）',
                'description' => '超过该大小的图片只做扩展名检查，不再读取内容做正则匹配。',
                'default'     => 500,
                'min'         => 50,
                'max'         => 5120,
                'step'        => 50,
                'class'       => 'small-text',
            ],
            'code_scan_max_kb'          => [
                'section'     => 'scanner',
                'type'        => 'number',
                'label'       => '代码文件读取上限（KB）',
                'description' => '代码审计和主题 JS 挂马扫描只读取文件前 N KB，避免超大文件导致扫描超时或内存暴涨。',
                'default'     => 512,
                'min'         => 64,
                'max'         => 20480,
                'step'        => 64,
                'class'       => 'small-text',
            ],
            'extra_sensitive_extensions' => [
                'section'     => 'scanner',
                'type'        => 'textarea',
                'label'       => '额外敏感文件后缀',
                'description' => '每行或逗号一个后缀，不需要写点号，例如 pem、key、7z。',
                'default'     => '',
                'rows'        => 3,
            ],
            'scan_excluded_paths'       => [
                'section'     => 'scanner',
                'type'        => 'textarea',
                'label'       => '扫描排除路径片段',
                'description' => '每行一个路径片段，命中后跳过，例如 /wp-content/cache/。',
                'default'     => '',
                'rows'        => 3,
            ],
            'enable_file_integrity_baseline' => [
                'section'     => 'scanner',
                'type'        => 'checkbox',
                'label'       => '启用文件完整性基线检测',
                'description' => '对照可信基线报告新增、被改动、被删除的文件，不会自动修复。默认需要你手动确认后再建立第一份基线。',
                'default'     => false,
                'recommended' => true,
            ],
            'auto_initialize_file_baseline' => [
                'section'     => 'scanner',
                'type'        => 'checkbox',
                'label'       => '允许首次自动建立文件基线',
                'description' => '仅在你确认当前站点文件状态可信时开启。开启后，如果基线为空，扫描会直接把当前磁盘状态视为基线；关闭则需要手动点击“重建文件基线”。',
                'default'     => false,
            ],
            'file_integrity_paths'      => [
                'section'     => 'scanner',
                'type'        => 'textarea',
                'label'       => '文件基线监控目录',
                'description' => '每行一个相对站点根目录的路径，例如 wp-content/themes、wp-content/plugins。留空则使用默认目录。',
                'default'     => '',
                'rows'        => 4,
            ],
            'file_integrity_max_files'  => [
                'section'     => 'scanner',
                'type'        => 'number',
                'label'       => '文件基线扫描上限',
                'description' => '用于建立和比对文件基线的最大文件数。站点文件特别多时可适当调大。',
                'default'     => 20000,
                'min'         => 1000,
                'max'         => 300000,
                'step'        => 500,
                'class'       => 'small-text',
            ],
            'admin_privileged_user_threshold' => [
                'section'     => 'scanner',
                'type'        => 'number',
                'label'       => '管理员数量预警阈值',
                'description' => '当具备管理员角色的账号数量超过该值时，体检会给出提醒。用于发现账号扩散或权限长期失控。',
                'default'     => 3,
                'min'         => 1,
                'max'         => 100,
                'step'        => 1,
                'class'       => 'small-text',
            ],
            'admin_weak_usernames'      => [
                'section'     => 'scanner',
                'type'        => 'textarea',
                'label'       => '弱管理员用户名规则',
                'description' => '每行一个用户名规则，例如 admin、administrator、root。支持以 * 结尾做前缀匹配，例如 test*。',
                'default'     => "admin\nadministrator\nroot\ntest\nwebmaster\nmanager",
                'rows'        => 4,
            ],
            'persistence_scan_ignored_hooks' => [
                'section'     => 'scanner',
                'type'        => 'textarea',
                'label'       => 'Cron 扫描忽略 Hook',
                'description' => '每行一个 hook 名。适合把你确认安全但执行频率较高的自定义 cron 任务加入例外，降低误报。',
                'default'     => '',
                'rows'        => 4,
            ],
            'db_autoload_option_warn_kb' => [
                'section'     => 'scanner',
                'type'        => 'number',
                'label'       => '单个 Autoload Option 预警阈值（KB）',
                'description' => '当某个 autoload 选项体积超过该值时，数据库风险扫描会给出提醒。',
                'default'     => 256,
                'min'         => 32,
                'max'         => 10240,
                'step'        => 32,
                'class'       => 'small-text',
            ],
            'db_autoload_total_warn_mb' => [
                'section'     => 'scanner',
                'type'        => 'number',
                'label'       => 'Autoload 总体积预警阈值（MB）',
                'description' => '数据库风险扫描会统计 autoload 总体积。值过大通常意味着配置膨胀、缓存滥存，或有 payload 被塞进自动加载项。',
                'default'     => 3,
                'min'         => 1,
                'max'         => 512,
                'step'        => 1,
                'class'       => 'small-text',
            ],
            'db_suspicious_option_limit' => [
                'section'     => 'scanner',
                'type'        => 'number',
                'label'       => '疑似风险 Option 扫描上限',
                'description' => '用于限制数据库风险扫描中“疑似挂马/注入 option”的单次输出数量，避免在大站上刷出过多重复结果。',
                'default'     => 30,
                'min'         => 5,
                'max'         => 300,
                'step'        => 5,
                'class'       => 'small-text',
            ],
            'db_scan_ignored_options' => [
                'section'     => 'scanner',
                'type'        => 'textarea',
                'label'       => '数据库扫描忽略 Option 规则',
                'description' => '每行一个 option 名或规则，支持以 * 结尾做前缀匹配。例如 _transient_*、_site_transient_*、cron。',
                'default'     => "_transient_*\n_site_transient_*\ncron\nrewrite_rules\nqs_rule_package_active\nqs_rule_package_previous\nqs_protection_settings\nqs_db_schema_version",
                'rows'        => 4,
            ],
            'enable_phone_location_lookup' => [
                'section'     => 'phone',
                'type'        => 'checkbox',
                'label'       => '启用手机号归属地本地查询',
                'description' => '开启后会读取插件目录 phone/qiphone.dat 并在首查后写入独立缓存表。关闭后将完全跳过手机号归属地解析。',
                'default'     => false,
            ],
            'scan_retention_days'       => [
                'section'     => 'maintenance',
                'type'        => 'number',
                'label'       => '扫描报告保留天数',
                'description' => '手动清理时会删除早于该天数的已完成扫描和对应结果。填 0 表示不自动按天数清理扫描记录。',
                'default'     => 60,
                'min'         => 0,
                'max'         => 3650,
                'step'        => 1,
                'class'       => 'small-text',
            ],
            'audit_retention_days'      => [
                'section'     => 'maintenance',
                'type'        => 'number',
                'label'       => '审计日志保留天数',
                'description' => '手动清理时会删除早于该天数的审计日志。填 0 表示不按天数清理审计日志。',
                'default'     => 90,
                'min'         => 0,
                'max'         => 3650,
                'step'        => 1,
                'class'       => 'small-text',
            ],
            'ip_risk_retention_days'   => [
                'section'     => 'maintenance',
                'type'        => 'number',
                'label'       => 'IP 风险数据保留天数',
                'description' => '手动清理“过期历史数据”时会删除早于该天数的 IP 风险登录事件和长期未命中的 IP 风险画像缓存。填 0 表示不按天数清理。',
                'default'     => 180,
                'min'         => 0,
                'max'         => 3650,
                'step'        => 1,
                'class'       => 'small-text',
            ],
            'delete_data_on_uninstall'  => [
                'section'     => 'maintenance',
                'type'        => 'checkbox',
                'label'       => '卸载插件时删除全部数据表',
                'description' => '开启后，卸载插件时会删除扫描报告、审计日志、封禁记录和插件设置。',
                'default'     => false,
            ],
        ];

        $fields = array_merge( $fields, self::get_rate_limit_setting_fields() );

        return apply_filters( 'qs_setting_fields', $fields, self::get_setting_sections() );
    }

    public static function get_default_settings() {
        $defaults = [];

        foreach ( self::get_setting_fields() as $key => $field ) {
            $defaults[ $key ] = array_key_exists( 'default', $field ) ? $field['default'] : '';
        }

        return $defaults;
    }

    public static function get_default_proxy_headers() {
        return apply_filters(
            'qs_default_proxy_headers',
            [
                'HTTP_CF_CONNECTING_IP',
                'HTTP_X_REAL_IP',
                'HTTP_X_FORWARDED_FOR',
            ]
        );
    }

    public static function get_default_proxy_headers_as_string() {
        return implode( "\n", self::get_default_proxy_headers() );
    }

    public static function get_default_file_integrity_paths() {
        return apply_filters(
            'qs_default_file_integrity_paths',
            [
                'wp-content/themes',
                'wp-content/plugins',
                'wp-content/mu-plugins',
                'wp-content/uploads',
            ]
        );
    }

    public static function get_rest_plugin_isolation_mu_plugin_filename() {
        return 'qs-route-isolation-loader.php';
    }

    public static function get_rest_plugin_isolation_mu_plugin_path() {
        $mu_plugin_dir = defined( 'WPMU_PLUGIN_DIR' ) ? WPMU_PLUGIN_DIR : ( defined( 'WP_CONTENT_DIR' ) ? WP_CONTENT_DIR . '/mu-plugins' : ABSPATH . 'wp-content/mu-plugins' );

        return rtrim( (string) $mu_plugin_dir, "/\\" ) . '/' . self::get_rest_plugin_isolation_mu_plugin_filename();
    }

    public static function is_rest_plugin_isolation_mu_plugin_installed() {
        $path = self::get_rest_plugin_isolation_mu_plugin_path();

        return '' !== $path && file_exists( $path );
    }

    public static function get_rest_plugin_isolation_default_rule_lines() {
        $default_lines = [
            '/qilingtxt/v1/ => qilingtxt/qilingtxt.php',
        ];
        $default_lines = apply_filters( 'qs_rest_plugin_isolation_default_rule_lines', $default_lines );
        $default_lines = is_array( $default_lines ) ? $default_lines : [];

        $normalized = [];

        foreach ( $default_lines as $line ) {
            $rule = self::parse_rest_plugin_isolation_rule_line( $line );

            if ( empty( $rule ) ) {
                continue;
            }

            $normalized[] = $rule['route'] . ' => ' . implode( ', ', $rule['plugins'] );
        }

        if ( empty( $normalized ) ) {
            $normalized[] = '/qilingtxt/v1/ => qilingtxt/qilingtxt.php';
        }

        return array_values( array_unique( $normalized ) );
    }

    public static function get_rest_plugin_isolation_default_rules_as_text() {
        return implode( "\n", self::get_rest_plugin_isolation_default_rule_lines() );
    }

    public static function maybe_sync_rest_plugin_isolation_rules() {
        $default_lines = self::get_rest_plugin_isolation_default_rule_lines();
        $default_rules = self::parse_rest_plugin_isolation_rules_setting( implode( "\n", $default_lines ) );

        if ( empty( $default_rules ) ) {
            return;
        }

        $normalized_default_lines = [];
        foreach ( $default_rules as $rule ) {
            if ( empty( $rule['route'] ) || empty( $rule['plugins'] ) ) {
                continue;
            }

            $normalized_default_lines[] = $rule['route'] . ' => ' . implode( ', ', $rule['plugins'] );
        }

        if ( empty( $normalized_default_lines ) ) {
            return;
        }

        $signature_option_key = 'qs_rest_plugin_isolation_rule_sync_signature';
        $signature            = md5( implode( "\n", $normalized_default_lines ) );
        $saved_signature      = (string) get_option( $signature_option_key, '' );

        if ( $saved_signature === $signature ) {
            return;
        }

        $settings     = get_option( 'qs_protection_settings', [] );
        $settings     = is_array( $settings ) ? $settings : [];
        $current_text = isset( $settings['rest_plugin_isolation_rules'] ) ? (string) $settings['rest_plugin_isolation_rules'] : '';
        $current_text = self::sanitize_rest_plugin_isolation_rules_setting( $current_text );
        $current_rules = self::parse_rest_plugin_isolation_rules_setting( $current_text );

        $rule_map = [];

        foreach ( $current_rules as $rule ) {
            $route = isset( $rule['route'] ) ? (string) $rule['route'] : '';
            if ( '' === $route ) {
                continue;
            }

            $plugins = isset( $rule['plugins'] ) ? (array) $rule['plugins'] : [];
            if ( ! isset( $rule_map[ $route ] ) ) {
                $rule_map[ $route ] = [];
            }

            $rule_map[ $route ] = array_values( array_unique( array_merge( $rule_map[ $route ], $plugins ) ) );
        }

        foreach ( $default_rules as $rule ) {
            $route = isset( $rule['route'] ) ? (string) $rule['route'] : '';
            if ( '' === $route ) {
                continue;
            }

            $plugins = isset( $rule['plugins'] ) ? (array) $rule['plugins'] : [];
            if ( ! isset( $rule_map[ $route ] ) ) {
                $rule_map[ $route ] = [];
            }

            $rule_map[ $route ] = array_values( array_unique( array_merge( $rule_map[ $route ], $plugins ) ) );
        }

        $merged_rules = [];
        foreach ( $rule_map as $route => $plugins ) {
            $plugins = array_values( array_unique( array_filter( $plugins ) ) );
            if ( '' === $route || empty( $plugins ) ) {
                continue;
            }

            $merged_rules[] = [
                'route'   => $route,
                'plugins' => $plugins,
            ];
        }

        usort(
            $merged_rules,
            static function( $left, $right ) {
                return strlen( $right['route'] ) <=> strlen( $left['route'] );
            }
        );

        $merged_lines = [];
        foreach ( $merged_rules as $rule ) {
            $merged_lines[] = $rule['route'] . ' => ' . implode( ', ', $rule['plugins'] );
        }
        $merged_text = implode( "\n", $merged_lines );

        if ( $merged_text !== $current_text ) {
            $settings['rest_plugin_isolation_rules'] = $merged_text;
            update_option( 'qs_protection_settings', self::sanitize_settings( $settings ) );
        }

        update_option( $signature_option_key, $signature, false );
    }

    public static function get_rest_plugin_isolation_monitor_option_key() {
        return 'qs_rest_plugin_isolation_monitor_logs';
    }

    public static function get_proxy_presets() {
        $presets = [
            'manual' => [
                'label'         => '手动自定义',
                'headers'       => self::get_default_proxy_headers(),
                'proxy_ips'     => [],
                'summary'       => '保留当前手动配置。适合已经明确知道代理链路与请求头的站点。',
                'docs'          => [],
                'requires_manual_proxy_ips' => true,
            ],
            'loopback' => [
                'label'         => '同机 Nginx / 宝塔 / Apache 反代',
                'headers'       => [ 'HTTP_X_REAL_IP', 'HTTP_X_FORWARDED_FOR' ],
                'proxy_ips'     => [ '127.0.0.1/32', '::1/128' ],
                'summary'       => '适合同机反向代理回源到 PHP-FPM / Apache。会默认信任回环地址。',
                'docs'          => [],
                'requires_manual_proxy_ips' => false,
            ],
            'generic_proxy' => [
                'label'         => '通用反向代理 / 负载均衡',
                'headers'       => [ 'HTTP_X_REAL_IP', 'HTTP_X_FORWARDED_FOR' ],
                'proxy_ips'     => [],
                'summary'       => '适合自建 Nginx、HAProxy、SLB、Ingress 等前置代理。需要你手动填写代理出口 IP / 网段。',
                'docs'          => [],
                'requires_manual_proxy_ips' => true,
            ],
            'cloudflare' => [
                'label'         => 'Cloudflare',
                'headers'       => [ 'HTTP_CF_CONNECTING_IP', 'HTTP_X_FORWARDED_FOR' ],
                'proxy_ips'     => [],
                'summary'       => '优先读取 Cloudflare 的 CF-Connecting-IP；可信代理 IP 请按 Cloudflare 官方 IP 列表维护。',
                'docs'          => [
                    [ 'label' => '请求头文档', 'url' => 'https://developers.cloudflare.com/fundamentals/reference/http-request-headers/' ],
                    [ 'label' => 'IP 段列表', 'url' => 'https://www.cloudflare.com/ips/' ],
                ],
                'requires_manual_proxy_ips' => true,
            ],
            'aliyun_cdn' => [
                'label'         => '阿里云 CDN / DCDN',
                'headers'       => [ 'HTTP_ALI_CDN_REAL_IP', 'HTTP_X_FORWARDED_FOR' ],
                'proxy_ips'     => [],
                'summary'       => '优先读取 Ali-Cdn-Real-Ip；可信代理 IP / 网段建议按阿里云当前回源节点列表维护。',
                'docs'          => [
                    [ 'label' => 'CDN 请求头文档', 'url' => 'https://help.aliyun.com/zh/cdn/user-guide/configure-custom-request-headers' ],
                    [ 'label' => 'DCDN 请求头文档', 'url' => 'https://help.aliyun.com/zh/edge-security-acceleration/dcdn/configure-custom-request-headers' ],
                ],
                'requires_manual_proxy_ips' => true,
            ],
            'huawei_cdn' => [
                'label'         => '华为云 CDN / WAF',
                'headers'       => [ 'HTTP_X_FORWARDED_FOR' ],
                'proxy_ips'     => [],
                'summary'       => '华为云官方文档明确说明 CDN / WAF 回源会通过 X-Forwarded-For 传递客户端真实 IP。',
                'docs'          => [
                    [ 'label' => 'CDN 获取客户端真实 IP', 'url' => 'https://support.huaweicloud.com/intl/zh-cn/cdn_faq/cdn_faq_0153.html' ],
                    [ 'label' => 'WAF 回源 IP / XFF 说明', 'url' => 'https://support.huaweicloud.com/waf_faq/waf_01_0095.html' ],
                ],
                'requires_manual_proxy_ips' => true,
            ],
            'tencent_cdn' => [
                'label'         => '腾讯云 CDN',
                'headers'       => [ 'HTTP_X_FORWARDED_FOR' ],
                'proxy_ips'     => [],
                'summary'       => '腾讯云 CDN 默认回源头通常使用 X-Forwarded-For 传递访客来源地址。',
                'docs'          => [
                    [ 'label' => '回源请求头文档', 'url' => 'https://cloud.tencent.com/document/product/228/45078' ],
                ],
                'requires_manual_proxy_ips' => true,
            ],
            'tencent_edgeone' => [
                'label'         => '腾讯云 EdgeOne',
                'headers'       => [ 'HTTP_X_FORWARDED_FOR', 'HTTP_EO_CONNECTING_IP' ],
                'proxy_ips'     => [],
                'summary'       => '优先用 X-Forwarded-For；EO-Connecting-IP 可作为补充。可信代理 IP / 网段建议按 EdgeOne 官方网段维护。',
                'docs'          => [
                    [ 'label' => '默认回源请求头', 'url' => 'https://cloud.tencent.com/document/product/1552/87654' ],
                    [ 'label' => '回源 IP 网段', 'url' => 'https://cloud.tencent.com/document/product/1552/76086' ],
                ],
                'requires_manual_proxy_ips' => true,
            ],
            'qiniu_cdn' => [
                'label'         => '七牛云 CDN',
                'headers'       => [ 'HTTP_X_FORWARDED_FOR' ],
                'proxy_ips'     => [],
                'summary'       => '按七牛官方七层代理/负载均衡文档与 CDN 回源配置文档推断，保守使用 X-Forwarded-For 作为回源真实 IP 头。',
                'docs'          => [
                    [ 'label' => 'CDN 回源配置', 'url' => 'https://developer.qiniu.com/fusion/4943/back-to-the-source-configuration' ],
                    [ 'label' => '七层转发真实 IP', 'url' => 'https://developer.qiniu.com/fec/2216/load-balancing-load-balancing-forward-seven-layers-for-visiting-real-ip-method' ],
                ],
                'requires_manual_proxy_ips' => true,
            ],
            'upyun_cdn' => [
                'label'         => '又拍云 CDN',
                'headers'       => [ 'HTTP_X_REAL_IP', 'HTTP_X_FORWARDED_FOR', 'HTTP_CLIENT_IP' ],
                'proxy_ips'     => [],
                'summary'       => '又拍云官方文档明确说明回源会同时传递 X-Real-IP、X-Forwarded-For 和 Client-IP。',
                'docs'          => [
                    [ 'label' => '传递最终用户 IP', 'url' => 'https://help.upyun.com/knowledge-base/%E4%BC%A0%E9%80%92%E6%9C%80%E7%BB%88%E7%94%A8%E6%88%B7-ip/' ],
                ],
                'requires_manual_proxy_ips' => true,
            ],
            'baidu_cloud' => [
                'label'         => '百度智能云 CDN / 动态加速',
                'headers'       => [ 'HTTP_X_FORWARDED_FOR' ],
                'proxy_ips'     => [],
                'summary'       => '目前未查到百度智能云公开的权威回源头说明，这里保守按常见 CDN 回源链路预设为 X-Forwarded-For；建议你上线前抓包或看源站日志确认。',
                'docs'          => [
                    [ 'label' => 'CDN 产品页', 'url' => 'https://cloud.baidu.com/product/CDN/tui.html' ],
                    [ 'label' => '动态加速产品页', 'url' => 'https://cloud.baidu.com/product/drcdn.html' ],
                ],
                'requires_manual_proxy_ips' => true,
            ],
            'aws_cloudfront' => [
                'label'         => 'AWS CloudFront',
                'headers'       => [ 'HTTP_X_FORWARDED_FOR' ],
                'proxy_ips'     => [],
                'summary'       => 'CloudFront 到源站常用 X-Forwarded-For 传递访客地址。若你启用了额外 Origin Request Policy，也可以再手动调整头顺序。',
                'docs'          => [
                    [ 'label' => 'X-Forwarded-For 行为', 'url' => 'https://docs.aws.amazon.com/AmazonCloudFront/latest/DeveloperGuide/RequestAndResponseBehaviorCustomOrigin.html' ],
                    [ 'label' => '附加请求头', 'url' => 'https://docs.aws.amazon.com/AmazonCloudFront/latest/DeveloperGuide/adding-cloudfront-headers.html' ],
                ],
                'requires_manual_proxy_ips' => true,
            ],
            'fastly' => [
                'label'         => 'Fastly',
                'headers'       => [ 'HTTP_X_FORWARDED_FOR', 'HTTP_FASTLY_CLIENT_IP' ],
                'proxy_ips'     => [],
                'summary'       => '默认优先用 X-Forwarded-For。Fastly-Client-IP 只有在你确认边缘已重写/清洗该头时才建议保留。',
                'docs'          => [
                    [ 'label' => 'Fastly-Client-IP 文档', 'url' => 'https://www.fastly.com/documentation/reference/http/http-headers/Fastly-Client-IP/' ],
                    [ 'label' => 'X-Forwarded-For 文档', 'url' => 'https://www.fastly.com/documentation/reference/http/http-headers/X-Forwarded-For/' ],
                ],
                'requires_manual_proxy_ips' => true,
            ],
            'azure_frontdoor' => [
                'label'         => 'Azure Front Door',
                'headers'       => [ 'HTTP_X_AZURE_CLIENTIP', 'HTTP_X_FORWARDED_FOR' ],
                'proxy_ips'     => [],
                'summary'       => '优先读取 X-Azure-ClientIP，并保留 X-Forwarded-For 作为补充链路。',
                'docs'          => [
                    [ 'label' => 'Front Door 请求头文档', 'url' => 'https://learn.microsoft.com/en-us/azure/frontdoor/front-door-http-headers-protocol' ],
                ],
                'requires_manual_proxy_ips' => true,
            ],
            'akamai' => [
                'label'         => 'Akamai',
                'headers'       => [ 'HTTP_TRUE_CLIENT_IP', 'HTTP_X_FORWARDED_FOR' ],
                'proxy_ips'     => [],
                'summary'       => '需要源站侧已经开启 True-Client-IP 相关能力；未开启时请保留 X-Forwarded-For 兜底。',
                'docs'          => [
                    [ 'label' => 'True-Client-IP 文档', 'url' => 'https://techdocs.akamai.com/edge-diagnostics/docs/pragma-headers#true-client-ip' ],
                ],
                'requires_manual_proxy_ips' => true,
            ],
        ];

        return apply_filters( 'qs_proxy_presets', $presets );
    }

    public static function get_proxy_preset_choices() {
        $choices = [];

        foreach ( self::get_proxy_presets() as $preset_id => $preset ) {
            $choices[ $preset_id ] = isset( $preset['label'] ) ? $preset['label'] : $preset_id;
        }

        return $choices;
    }

    public static function get_active_proxy_preset( $settings = null ) {
        $settings  = is_array( $settings ) ? $settings : self::get_settings();
        $preset_id = isset( $settings['proxy_preset'] ) ? sanitize_key( (string) $settings['proxy_preset'] ) : 'manual';
        $presets   = self::get_proxy_presets();

        if ( ! isset( $presets[ $preset_id ] ) ) {
            $preset_id = 'manual';
        }

        $preset = $presets[ $preset_id ];
        $preset['id'] = $preset_id;

        return $preset;
    }

    public static function get_proxy_presets_for_js() {
        $export = [];

        foreach ( self::get_proxy_presets() as $preset_id => $preset ) {
            $export[ $preset_id ] = [
                'headers'               => ! empty( $preset['headers'] ) && is_array( $preset['headers'] ) ? array_values( $preset['headers'] ) : [],
                'proxyIps'              => ! empty( $preset['proxy_ips'] ) && is_array( $preset['proxy_ips'] ) ? array_values( $preset['proxy_ips'] ) : [],
                'requiresManualProxyIps' => ! empty( $preset['requires_manual_proxy_ips'] ),
            ];
        }

        return $export;
    }

    private static function get_proxy_preset_docs_html( $preset ) {
        if ( empty( $preset['docs'] ) || ! is_array( $preset['docs'] ) ) {
            return '';
        }

        $links = [];

        foreach ( $preset['docs'] as $doc ) {
            $url   = ! empty( $doc['url'] ) ? esc_url( $doc['url'] ) : '';
            $label = ! empty( $doc['label'] ) ? esc_html( $doc['label'] ) : '';

            if ( '' === $url || '' === $label ) {
                continue;
            }

            $links[] = '<a href="' . $url . '" target="_blank" rel="noopener noreferrer">' . $label . '</a>';
        }

        return empty( $links ) ? '' : implode( ' / ', $links );
    }

    public static function get_rate_limit_presets() {
        $presets = [
            'xmlrpc' => [
                'label'            => '限制 XML-RPC 高频请求',
                'description'      => '拦截对 /xmlrpc.php 的高频探测和撞库请求。适合大多数普通站点。',
                'default_enabled'  => false,
                'default_requests' => 12,
                'default_window'   => 10,
                'match'            => 'xmlrpc',
                'guest_only'       => false,
            ],
            'rest'   => [
                'label'            => '限制公开 REST API 高频请求',
                'description'      => '只统计未登录访客对 /wp-json/ 的 GET/HEAD 高频访问。若前台高度依赖公开 REST 接口，请先用观察模式。',
                'default_enabled'  => false,
                'default_requests' => 120,
                'default_window'   => 5,
                'match'            => 'rest',
                'guest_only'       => true,
            ],
            'search' => [
                'label'            => '限制站内搜索高频请求',
                'description'      => '缓解机器人批量探测站内搜索接口。',
                'default_enabled'  => false,
                'default_requests' => 30,
                'default_window'   => 5,
                'match'            => 'search',
                'guest_only'       => true,
            ],
            'comment' => [
                'label'            => '限制评论提交高频请求',
                'description'      => '适合拦截评论刷屏和垃圾评论机器。',
                'default_enabled'  => false,
                'default_requests' => 8,
                'default_window'   => 10,
                'match'            => 'comment',
                'guest_only'       => true,
            ],
        ];

        return apply_filters( 'qs_rate_limit_presets', $presets );
    }

    public static function get_rate_limit_rules( $settings = null ) {
        $settings = is_array( $settings ) ? $settings : self::get_settings();

        if ( empty( $settings['enable_behavior_rate_limit'] ) ) {
            return [];
        }

        $mode      = isset( $settings['behavior_rate_limit_mode'] ) ? sanitize_key( $settings['behavior_rate_limit_mode'] ) : 'observe';
        $ban_hours = max( 1, absint( $settings['behavior_rate_limit_ban_hours'] ) );
        $rules     = [];

        foreach ( self::get_rate_limit_presets() as $preset_id => $preset ) {
            if ( empty( $settings[ 'rate_limit_' . $preset_id . '_enabled' ] ) ) {
                continue;
            }

            $rules[ $preset_id ] = [
                'id'             => $preset_id,
                'label'          => isset( $preset['label'] ) ? $preset['label'] : $preset_id,
                'max_requests'   => max( 1, absint( $settings[ 'rate_limit_' . $preset_id . '_requests' ] ) ),
                'window_minutes' => max( 1, absint( $settings[ 'rate_limit_' . $preset_id . '_window_minutes' ] ) ),
                'mode'           => in_array( $mode, [ 'observe', 'block', 'ban' ], true ) ? $mode : 'observe',
                'ban_hours'      => $ban_hours,
                'match'          => isset( $preset['match'] ) ? $preset['match'] : $preset_id,
                'guest_only'     => ! empty( $preset['guest_only'] ),
            ];
        }

        return apply_filters( 'qs_rate_limit_rules', $rules, $settings, self::get_rate_limit_presets() );
    }

    public static function get_theme_overlap_context() {
        static $context = null;

        if ( null !== $context ) {
            return $context;
        }

        $template   = function_exists( 'get_template' ) ? (string) get_template() : '';
        $stylesheet = function_exists( 'get_stylesheet' ) ? (string) get_stylesheet() : '';

        $context = [
            'active'      => in_array( 'qiling', [ $template, $stylesheet ], true ),
            'template'    => $template,
            'stylesheet'  => $stylesheet,
            'theme_label' => '启灵主题「设置 - 优化」',
        ];

        return apply_filters( 'qs_theme_overlap_context', $context );
    }

    public static function get_theme_overlap_map() {
        $map = [
            'disable_xmlrpc'      => [
                'mode'    => 'single_exact',
                'options' => [
                    [ 'id' => 'disable_xmlrpc', 'label' => '禁用 XML-RPC' ],
                ],
            ],
            'hide_wp_version'     => [
                'mode'    => 'single_exact',
                'options' => [
                    [ 'id' => 'remove_wp_version', 'label' => '隐藏 WP 版本号' ],
                ],
            ],
            'block_user_enum'     => [
                'mode'    => 'combo_partial',
                'options' => [
                    [ 'id' => 'restrict_rest_users', 'label' => '仅屏蔽 REST 用户端点' ],
                    [ 'id' => 'disable_author_archive', 'label' => '禁用作者存档页' ],
                ],
            ],
            'disable_file_editor' => [
                'mode'    => 'single_exact',
                'options' => [
                    [ 'id' => 'disable_file_edit', 'label' => '禁用文件编辑器' ],
                ],
            ],
            'disable_app_passwords' => [
                'mode'    => 'single_exact',
                'options' => [
                    [ 'id' => 'disable_application_passwords', 'label' => '禁用应用密码' ],
                ],
            ],
            'disable_emoji'        => [
                'mode'    => 'single_exact',
                'options' => [
                    [ 'id' => 'disable_emoji', 'label' => '禁用 Emoji 脚本' ],
                ],
            ],
            'disable_embeds'       => [
                'mode'    => 'single_exact',
                'options' => [
                    [ 'id' => 'disable_embeds', 'label' => '禁用 oEmbed' ],
                ],
            ],
            'remove_shortlink'     => [
                'mode'    => 'single_exact',
                'options' => [
                    [ 'id' => 'remove_shortlink', 'label' => '移除短链接' ],
                ],
            ],
            'remove_rsd_wlw'       => [
                'mode'    => 'single_exact',
                'options' => [
                    [ 'id' => 'remove_rsd_wlw', 'label' => '移除 RSD/WLW' ],
                ],
            ],
            'clean_meta_tags'     => [
                'mode'    => 'group_partial',
                'options' => [
                    [ 'id' => 'remove_shortlink', 'label' => '移除短链接' ],
                    [ 'id' => 'remove_rsd_wlw', 'label' => '移除 RSD/WLW' ],
                    [ 'id' => 'remove_json_api_link', 'label' => '移除 JSON API 链接' ],
                    [ 'id' => 'disable_embeds', 'label' => '禁用 oEmbed' ],
                ],
            ],
            'disable_pingback'    => [
                'mode'    => 'single_covering',
                'options' => [
                    [ 'id' => 'disable_pingback', 'label' => '禁用 Pingback/Trackback' ],
                ],
            ],
            'admin_disable_remote_block_patterns' => [
                'mode'    => 'single_exact',
                'options' => [
                    [ 'id' => 'admin_disable_remote_block_patterns', 'label' => '关闭远程区块 Patterns' ],
                ],
            ],
            'admin_disable_block_directory' => [
                'mode'    => 'single_exact',
                'options' => [
                    [ 'id' => 'admin_disable_block_directory', 'label' => '关闭区块目录搜索' ],
                ],
            ],
            'admin_disable_openverse' => [
                'mode'    => 'single_exact',
                'options' => [
                    [ 'id' => 'admin_disable_openverse', 'label' => '关闭 Openverse 媒体面板' ],
                ],
            ],
            'admin_reduce_editor_preload' => [
                'mode'    => 'single_exact',
                'options' => [
                    [ 'id' => 'admin_reduce_editor_preload', 'label' => '精简编辑器预加载接口' ],
                ],
            ],
        ];

        return apply_filters( 'qs_theme_overlap_map', $map );
    }

    public static function get_theme_overlap_overview_notice() {
        $context = self::get_theme_overlap_context();

        if ( empty( $context['active'] ) ) {
            return [];
        }

        $notice = [
            'tone'    => 'warning',
            'message' => '检测到当前站点正在使用启灵主题。下方部分安全优化项与主题「设置 - 优化」存在重叠；如果你已经在主题里开启同类功能，这里就不要重复开启，建议统一只保留一处。',
        ];

        return apply_filters( 'qs_theme_overlap_overview_notice', $notice, $context );
    }

    public static function get_field_runtime_notes( $field_key ) {
        static $settings = null;

        $context      = self::get_theme_overlap_context();
        $map          = self::get_theme_overlap_map();
        $notes        = [];
        $settings     = is_array( $settings ) ? $settings : self::get_settings();
        $proxy_preset = self::get_active_proxy_preset( $settings );
        $relaxed_ip_mode = ! empty( $settings['trust_proxy_headers_without_ip'] );

        if ( 'proxy_preset' === $field_key ) {
            $header_text = ! empty( $proxy_preset['headers'] ) ? implode( '、', (array) $proxy_preset['headers'] ) : implode( '、', self::get_default_proxy_headers() );
            $summary     = ! empty( $proxy_preset['summary'] ) ? $proxy_preset['summary'] : '将按当前预设为你推荐真实 IP 请求头顺序。';
            $docs_html   = self::get_proxy_preset_docs_html( $proxy_preset );

            $notes[] = [
                'tone'    => 'info',
                'message' => sprintf( '当前预设推荐的请求头顺序：%s。%s', $header_text, $summary ),
            ];

            if ( ! empty( $docs_html ) ) {
                $notes[] = [
                    'tone' => 'info',
                    'html' => '官方参考：' . $docs_html,
                ];
            }

            if ( ! empty( $proxy_preset['requires_manual_proxy_ips'] ) ) {
                $notes[] = [
                    'tone'    => $relaxed_ip_mode ? 'info' : 'warning',
                    'message' => $relaxed_ip_mode
                        ? '该预设默认建议手动维护代理 IP 网段。你当前已开启“仅凭请求头识别真实 IP”，可暂时留空，但请注意请求头可被伪造。'
                        : '该预设不会内置第三方 CDN 的代理 IP 网段，避免厂商网段变更后过期。请把厂商官方 IP / CIDR 手动维护在下面“可信代理 IP / 网段”里。',
                ];
            }

            if ( in_array( $proxy_preset['id'], [ 'qiniu_cdn', 'baidu_cloud' ], true ) ) {
                $notes[] = [
                    'tone'    => 'warning',
                    'message' => '该预设的真实 IP 头顺序属于保守兼容配置，建议你上线前抓取一条真实回源请求，或直接查看源站日志，再确认是否需要调整头顺序。',
                ];
            }
        }

        if ( in_array( $field_key, [ 'trusted_proxy_ips', 'trusted_proxy_headers' ], true ) && class_exists( 'QS_Audit' ) ) {
            $debug = QS_Audit::get_ip_resolution_debug_info();

            if ( ! empty( $debug['strict_proxy_mode'] ) && ! empty( $debug['proxy_trusted'] ) && ! empty( $debug['forwarded_ip'] ) ) {
                $notes[] = [
                    'tone'    => 'info',
                    'message' => sprintf(
                        '当前请求解析结果：REMOTE_ADDR=%s，已信任代理并从 %s 读取到真实 IP=%s。',
                        $debug['remote_addr'],
                        $debug['forwarded_from'],
                        $debug['resolved_ip']
                    ),
                ];
            } elseif ( empty( $debug['strict_proxy_mode'] ) && ! empty( $debug['forwarded_ip'] ) ) {
                $notes[] = [
                    'tone'    => 'warning',
                    'message' => sprintf(
                        '当前请求解析结果：REMOTE_ADDR=%s，宽松模式已直接信任 %s 并解析出 IP=%s。若请求头可被客户端直连伪造，建议关闭宽松模式并补齐可信代理 IP / 网段。',
                        $debug['remote_addr'],
                        $debug['forwarded_from'],
                        $debug['resolved_ip']
                    ),
                ];
            } elseif ( ! empty( $debug['headers_seen'] ) ) {
                $notes[] = [
                    'tone'    => ! empty( $debug['strict_proxy_mode'] ) ? 'warning' : 'info',
                    'message' => sprintf(
                        ! empty( $debug['strict_proxy_mode'] )
                            ? '当前请求里已经出现了转发头，但 REMOTE_ADDR=%s 没有命中可信代理列表，所以插件不会信任这些头部。为避免伪造来源 IP，请把真实反代出口 IP / 网段补进上面的“可信代理 IP / 网段”后再启用封禁类策略。'
                            : '当前请求里出现了转发头，但没有从当前头部顺序解析出有效 IP。请确认“真实 IP 请求头优先级”是否与 CDN 回源头一致。',
                        $debug['remote_addr']
                    ),
                ];
            } else {
                $notes[] = [
                    'tone'    => 'info',
                    'message' => sprintf(
                        '当前请求解析结果：REMOTE_ADDR=%s，当前生效 IP=%s。若站点挂了 CDN/反代但这里没有变化，请补充可信代理与转发头。',
                        $debug['remote_addr'],
                        $debug['resolved_ip']
                    ),
                ];
            }
        }

        if ( 'trusted_proxy_ips' === $field_key ) {
            if ( ! empty( $proxy_preset['proxy_ips'] ) ) {
                $notes[] = [
                    'tone'    => 'info',
                    'message' => '当前预设会在这里留空时自动信任：' . implode( '、', (array) $proxy_preset['proxy_ips'] ) . '。',
                ];
            } elseif ( ! empty( $proxy_preset['requires_manual_proxy_ips'] ) ) {
                $notes[] = [
                    'tone'    => $relaxed_ip_mode ? 'info' : 'warning',
                    'message' => $relaxed_ip_mode
                        ? '当前预设建议手动维护可信代理 IP / CIDR。你已开启宽松模式，留空也会解析请求头，但建议后续补齐网段以降低伪造风险。'
                        : '当前预设要求你手动维护可信代理 IP / CIDR。没有这里的网段，插件即使看到了厂商请求头也不会信任。',
                ];
            }
        }

        if ( 'trusted_proxy_headers' === $field_key ) {
            $headers             = self::get_trusted_proxy_headers( $settings );
            $custom_headers      = self::parse_list_setting( isset( $settings['trusted_proxy_headers'] ) ? $settings['trusted_proxy_headers'] : '' );
            $preset_header_list  = array_map( [ __CLASS__, 'normalize_server_header_name' ], ! empty( $proxy_preset['headers'] ) ? (array) $proxy_preset['headers'] : [] );
            $headers_message     = empty( $headers ) ? '当前没有可用的真实 IP 请求头。' : '当前生效的真实 IP 请求头顺序：' . implode( '、', $headers ) . '。';
            $headers_tone        = 'info';

            if ( empty( $custom_headers ) ) {
                $headers_message .= ' 你现在使用的是预设/默认回退值。';
            } elseif ( array_values( $headers ) === array_values( $preset_header_list ) ) {
                $headers_message .= ' 你当前保存的是与所选预设一致的显式顺序。';
            } else {
                $headers_tone     = 'warning';
                $headers_message .= ' 你现在使用的是手动自定义顺序。';
            }

            $notes[] = [
                'tone'    => $headers_tone,
                'message' => $headers_message,
            ];
        }

        if ( 'trust_proxy_headers_without_ip' === $field_key ) {
            $notes[] = [
                'tone'    => ! empty( $settings['trust_proxy_headers_without_ip'] ) ? 'warning' : 'info',
                'message' => ! empty( $settings['trust_proxy_headers_without_ip'] )
                    ? '你已开启宽松模式：只要命中请求头就会解析真实 IP，不再强制校验 REMOTE_ADDR 是否来自可信代理。请仅在你确认源站不会被公网直连伪造头部时使用。'
                    : '当前使用严格模式：只有 REMOTE_ADDR 命中可信代理列表时，才会信任转发头。安全性更高。',
            ];
        }

        if ( 'enable_file_integrity_baseline' === $field_key && class_exists( 'QS_DB' ) ) {
            $baseline_count = QS_DB::get_file_baseline_count();

            if ( $baseline_count > 0 ) {
                $notes[] = [
                    'tone'    => 'info',
                    'message' => sprintf( '当前已保存 %d 条文件基线记录。后续扫描会对照这份基线报告新增、修改和缺失文件。', $baseline_count ),
                ];
            } else {
                $notes[] = [
                    'tone'    => 'warning',
                    'message' => '当前还没有文件基线。出于安全考虑，首次体检默认不会自动把当前文件状态视为可信；请先确认站点干净，再手动点击“重建文件基线”，或显式开启“允许首次自动建立文件基线”。',
                ];
            }
        }

        if ( 'auto_initialize_file_baseline' === $field_key ) {
            $notes[] = [
                'tone'    => empty( $settings['auto_initialize_file_baseline'] ) ? 'info' : 'warning',
                'message' => empty( $settings['auto_initialize_file_baseline'] )
                    ? '当前是更保守的默认模式：没有现成基线时，扫描只会提醒你先手动确认并建档。'
                    : '当前已允许首次自动建立基线。只有在你确认当前磁盘文件就是可信状态时，才建议这样做。',
            ];
        }

        if ( 'file_integrity_paths' === $field_key ) {
            $custom_paths = self::parse_list_setting( isset( $settings['file_integrity_paths'] ) ? $settings['file_integrity_paths'] : '' );

            if ( empty( $custom_paths ) ) {
                $notes[] = [
                    'tone'    => 'info',
                    'message' => '当前将使用默认监控目录：' . implode( '、', self::get_default_file_integrity_paths() ) . '。',
                ];
            }
        }

        if ( 'admin_privileged_user_threshold' === $field_key && function_exists( 'count_users' ) ) {
            $counts      = count_users();
            $admin_count = isset( $counts['avail_roles']['administrator'] ) ? absint( $counts['avail_roles']['administrator'] ) : 0;

            $notes[] = [
                'tone'    => $admin_count > self::get_admin_privileged_user_threshold( $settings ) ? 'warning' : 'info',
                'message' => sprintf( '当前站点已有 %d 个管理员角色账号。该阈值只影响手动体检时的提醒，不会自动改用户权限。', $admin_count ),
            ];
        }

        if ( 'persistence_scan_ignored_hooks' === $field_key ) {
            $notes[] = [
                'tone'    => 'info',
                'message' => '这里的异常 Cron 扫描只会在你手动点击“全盘体检”时分析现有计划任务，不会给站点新增任何 wp-cron 定时任务。',
            ];
        }

        if ( 'db_autoload_total_warn_mb' === $field_key ) {
            global $wpdb;

            if ( isset( $wpdb->options ) ) {
                $autoload_values = apply_filters( 'qs_db_scan_autoload_values', [ 'yes', 'on', 'auto', 'auto-on' ] );
                $autoload_values = array_values( array_filter( array_map( 'strval', (array) $autoload_values ) ) );

                if ( ! empty( $autoload_values ) ) {
                    $placeholders = implode( ',', array_fill( 0, count( $autoload_values ), '%s' ) );
                    $sql          = "SELECT COALESCE(SUM(LENGTH(option_value)), 0) FROM {$wpdb->options} WHERE autoload IN ($placeholders)";
                    $bytes        = (int) $wpdb->get_var( $wpdb->prepare( $sql, $autoload_values ) );

                    $notes[] = [
                        'tone'    => $bytes > self::get_db_autoload_total_warn_bytes( $settings ) ? 'warning' : 'info',
                        'message' => sprintf( '当前数据库中 autoload 总体积约为 %s。这里只做体检提示，不会自动修改任何 option。', size_format( $bytes ) ),
                    ];
                }
            }
        }

        if ( in_array( $field_key, [ 'db_suspicious_option_limit', 'db_scan_ignored_options' ], true ) ) {
            $notes[] = [
                'tone'    => 'info',
                'message' => '数据库风险扫描只会读取 wp_options / network options 并写入扫描报告，不会自动删除、替换或修复数据库内容。',
            ];
        }

        if ( 'upload_disallowed_extensions' === $field_key ) {
            $notes[] = [
                'tone'    => 'info',
                'message' => '这里的后缀规则既会用于上传即时拦截，也会用于全盘体检里的 uploads 历史风险扫描。后缀只需写扩展名本身，不需要带点号。',
            ];
        }

        if ( 'strict_upload_validation' === $field_key ) {
            $notes[] = [
                'tone'    => 'info',
                'message' => '严格上传校验只会拦截新上传文件，不会改写媒体库里已有文件；历史遗留问题请通过全盘体检里的 uploads 扫描查看。',
            ];
        }

        if ( 'block_svg_uploads' === $field_key ) {
            $notes[] = [
                'tone'    => 'info',
                'message' => 'WordPress 默认并不开放 SVG 上传。这个开关主要用于你站点里已经有其他插件或自定义代码允许 SVG 时，再额外加一道保险。',
            ];
        }

        if ( 'rest_api_guard_mode' === $field_key ) {
            if ( empty( $settings['enable_rest_api_guard'] ) ) {
                $notes[] = [
                    'tone'    => 'info',
                    'message' => 'REST API 精细防护总开关还没开启。建议先打开总开关，并从“仅观察记录”开始，先看日志里有哪些游客访问的路由。',
                ];
            } elseif ( empty( $settings['enable_audit_log'] ) ) {
                $notes[] = [
                    'tone'    => 'warning',
                    'message' => '当前已开启 REST API 精细防护，但审计日志未开启。这样“仅观察记录”模式不会留下可见记录，建议同时开启“关键操作审计日志”。',
                ];
            } elseif ( 'block' === ( isset( $settings['rest_api_guard_mode'] ) ? $settings['rest_api_guard_mode'] : 'observe' ) ) {
                $notes[] = [
                    'tone'    => 'warning',
                    'message' => '当前是直接拦截模式。建议先确认下面的“敏感公开路由前缀”只包含你明确不希望游客访问的接口，避免误伤业务 API。',
                ];
            }
        }

        if ( 'rest_api_public_block_prefixes' === $field_key && ! empty( $settings['block_user_enum'] ) ) {
            $notes[] = [
                'tone'    => 'info',
                'message' => '你已经开启了“拦截用户枚举探测”。如果这里同时包含 /wp/v2/users，也是合理的双保险，但通常以一处为主即可。',
            ];
        }

        if ( 'rest_api_public_allow_prefixes' === $field_key || 'rest_api_observe_unknown_public' === $field_key ) {
            $notes[] = [
                'tone'    => 'info',
                'message' => '未知公开路由观察只做审计，不会阻止请求；它主要用于帮你盘出哪些插件额外暴露了 REST API。',
            ];
        }

        if ( 'rest_plugin_isolation_enabled' === $field_key ) {
            $mu_plugin_path = self::get_rest_plugin_isolation_mu_plugin_path();

            if ( self::is_rest_plugin_isolation_mu_plugin_installed() ) {
                $notes[] = [
                    'tone'    => 'info',
                    'message' => 'MU 核心文件已就位。开启该开关后，命中规则的 REST API 请求将进入按路由加载模式。',
                ];
            } else {
                $notes[] = [
                    'tone' => 'warning',
                    'html' => '尚未检测到 MU 核心文件，当前开关不会生效。请先把 <code>' . esc_html( self::get_rest_plugin_isolation_mu_plugin_filename() ) . '</code> 放到：<br><code style="word-break:break-all;">' . esc_html( $mu_plugin_path ) . '</code>',
                ];
            }
        }

        if ( 'rest_plugin_isolation_mode' === $field_key && 'all_rest' === ( isset( $settings['rest_plugin_isolation_mode'] ) ? $settings['rest_plugin_isolation_mode'] : 'matched_only' ) ) {
            $notes[] = [
                'tone'    => 'warning',
                'message' => '你选择了“所有 REST 请求都启用路由白名单”。未命中规则的 REST 请求只会保留核心常驻插件，可能导致未配置插件的接口不可用。',
            ];
        }

        if ( 'rest_plugin_isolation_rules' === $field_key ) {
            $rules = self::get_rest_plugin_isolation_rules( $settings );

            if ( empty( $rules ) ) {
                $notes[] = [
                    'tone'    => 'warning',
                    'message' => '当前没有有效路由规则。若启用隔离，建议至少保留一条业务规则（例如 qilingtxt）。',
                ];
            } else {
                $notes[] = [
                    'tone'    => 'info',
                    'message' => sprintf( '当前已识别 %d 条有效路由规则。按“最长前缀优先”匹配插件白名单。', count( $rules ) ),
                ];
            }
        }

        if ( 'rest_plugin_isolation_monitor_enabled' === $field_key ) {
            $notes[] = [
                'tone'    => ! empty( $settings['rest_plugin_isolation_monitor_enabled'] ) ? 'info' : 'warning',
                'message' => ! empty( $settings['rest_plugin_isolation_monitor_enabled'] )
                    ? '监控日志已开启。该功能用于排查隔离命中，不建议在高并发站点长期保持开启。'
                    : '监控日志未开启。建议测试期间先开启，确认隔离策略稳定后可关闭。',
            ];
        }

        if ( 'rest_plugin_isolation_monitor_max_entries' === $field_key ) {
            $notes[] = [
                'tone'    => 'info',
                'message' => sprintf( '当前最多保留 %d 条隔离监控日志。', self::get_rest_plugin_isolation_monitor_max_entries( $settings ) ),
            ];
        }

        if ( 'ip_risk_query_mode' === $field_key ) {
            $mode = self::get_ip_risk_query_mode( $settings );

            if ( 'external' === $mode ) {
                $cron_url = self::get_ip_risk_external_cron_url( $settings );
                $notes[]  = [
                    'tone' => 'warning',
                    'html' => '当前已启用外部任务模式。请在宝塔/第三方监控中按分钟访问此地址：<br><code style="word-break:break-all;">' . esc_html( $cron_url ) . '</code><br>建议每 1~3 分钟访问一次。',
                ];
            } elseif ( 'async' === $mode ) {
                $notes[] = [
                    'tone'    => 'info',
                    'message' => '当前是 WP-Cron 异步模式。若你希望彻底不依赖 WP-Cron，可切换到“外部任务（推荐）”。',
                ];
            } else {
                $notes[] = [
                    'tone'    => 'info',
                    'message' => '当前是同步模式：每次登录流程都会即时查询外部来源，结果最实时但会增加登录耗时。',
                ];
            }
        }

        if ( 'ip_risk_external_cron_key' === $field_key ) {
            $custom_key = isset( $settings['ip_risk_external_cron_key'] ) ? (string) $settings['ip_risk_external_cron_key'] : '';
            $notes[]    = [
                'tone'    => '' === trim( $custom_key ) ? 'warning' : 'info',
                'message' => '' === trim( $custom_key )
                    ? '当前未填写自定义密钥，将使用站点派生密钥（更省事，但建议生产环境手动填写独立密钥）。'
                    : '已使用自定义密钥。若你怀疑任务地址泄露，可直接修改此密钥并更新第三方定时任务。',
            ];
        }

        if ( 'behavior_rate_limit_mode' === $field_key ) {
            $mode = isset( $settings['behavior_rate_limit_mode'] ) ? $settings['behavior_rate_limit_mode'] : 'observe';

            if ( empty( $settings['enable_behavior_rate_limit'] ) ) {
                $notes[] = [
                    'tone'    => 'info',
                    'message' => '行为型限速总开关还没开启。建议先开总开关，并从“仅观察记录”开始，确认没有误伤后再切到拦截或封禁。',
                ];
            } elseif ( 'observe' === $mode ) {
                $notes[] = [
                    'tone'    => empty( $settings['enable_audit_log'] ) ? 'warning' : 'info',
                    'message' => empty( $settings['enable_audit_log'] )
                        ? '当前是“仅观察记录”，但审计日志未开启。这样命中限速时不会留下可见记录，建议同时开启“关键操作审计日志”。'
                        : '当前是“仅观察记录”，命中结果会写入操作审计日志。建议先观察一段时间，再决定是否切到拦截或封禁。',
                ];
            } elseif ( 'ban' === $mode ) {
                $notes[] = [
                    'tone'    => 'warning',
                    'message' => '当前选择了“拦截并临时封禁”。如果站点接了 CDN 或反向代理，请先把可信代理 IP 和真实 IP 请求头配置准确，再启用封禁。',
                ];
            }
        }

        if ( 'max_concurrent_sessions' === $field_key ) {
            $limit = self::get_max_concurrent_sessions( $settings );

            if ( $limit <= 0 ) {
                $notes[] = [
                    'tone'    => 'info',
                    'message' => '当前未启用并发设备限制。填 3 代表同一账号最多同时在线 3 台设备，超额后会自动下线较早会话。',
                ];
            } else {
                $notes[] = [
                    'tone'    => empty( $settings['enable_audit_log'] ) ? 'warning' : 'info',
                    'message' => empty( $settings['enable_audit_log'] )
                        ? sprintf( '当前已限制同账号最多 %d 台设备在线，但审计日志未开启。建议开启审计日志，便于追踪“会话并发限制触发”记录。', $limit )
                        : sprintf( '当前已限制同账号最多 %d 台设备在线。用户登录超限时会自动下线较早会话，并写入审计记录。', $limit ),
                ];
            }
        }

        if ( 'rate_limit_xmlrpc_enabled' === $field_key && ! empty( $settings['disable_xmlrpc'] ) ) {
            $notes[] = [
                'tone'    => 'info',
                'message' => '你已经开启了“禁用 XML-RPC 接口”。这种情况下，通常不需要再单独给 XML-RPC 开行为限速，二选一即可。',
            ];
        }

        if ( empty( $context['active'] ) || empty( $map[ $field_key ] ) ) {
            return apply_filters( 'qs_setting_runtime_notes', $notes, $field_key, $context, [] );
        }

        $config         = $map[ $field_key ];
        $all_options    = self::get_theme_overlap_options( $config );
        $all_labels     = self::implode_option_labels( $all_options );

        switch ( $config['mode'] ) {
            case 'single_exact':
                $label   = isset( $all_options[0]['label'] ) ? $all_options[0]['label'] : '';
                $notes[] = [
                    'tone'    => 'info',
                    'message' => $context['theme_label'] . ' 里也提供「' . $label . '」。如果你已经在主题里开了，这里就不要重复开启，二选一即可。',
                ];
                break;

            case 'single_covering':
                $label   = isset( $all_options[0]['label'] ) ? $all_options[0]['label'] : '';
                $notes[] = [
                    'tone'    => 'info',
                    'message' => $context['theme_label'] . ' 里的「' . $label . '」覆盖范围更大。如果你已经在主题里开了，这里通常就不用再开。',
                ];
                break;

            case 'combo_partial':
                $notes[] = [
                    'tone'    => 'info',
                    'message' => $context['theme_label'] . ' 里的「' . $all_labels . '」与这里部分重叠。如果你准备在主题侧处理，通常需要把这些相关项一起开；否则直接用插件这项更省事。',
                ];
                break;

            case 'group_partial':
                $notes[] = [
                    'tone'    => 'info',
                    'message' => $context['theme_label'] . ' 里的「' . $all_labels . '」与这里的头部清理部分重叠。如果你已经在主题里处理了，这里一般就不用再开。',
                ];
                break;
        }

        return apply_filters( 'qs_setting_runtime_notes', $notes, $field_key, $context, $config );
    }

    public static function get_settings() {
        return self::sanitize_settings( get_option( 'qs_protection_settings', [] ) );
    }

    public static function sanitize_settings( $raw_settings ) {
        $raw_settings = is_array( $raw_settings ) ? $raw_settings : [];
        $defaults     = self::get_default_settings();
        $sanitized    = [];

        foreach ( self::get_setting_fields() as $key => $field ) {
            $value = array_key_exists( $key, $raw_settings ) ? $raw_settings[ $key ] : $defaults[ $key ];
            $type  = isset( $field['type'] ) ? $field['type'] : 'text';

            switch ( $type ) {
                case 'checkbox':
                    $sanitized[ $key ] = ! empty( $value ) && '0' !== (string) $value;
                    break;

                case 'number':
                    $sanitized[ $key ] = self::sanitize_number_setting( $value, $field );
                    break;

                case 'textarea':
                case 'multi_checkbox':
                    $sanitized_text = self::sanitize_multiline_text( $value );
                    if ( 'ip_risk_providers' === $key ) {
                        $sanitized_text = self::sanitize_ip_risk_provider_list_setting( $sanitized_text );
                    } elseif ( 'rest_plugin_isolation_core_plugins' === $key ) {
                        $sanitized_text = self::sanitize_plugin_basename_list_setting( $sanitized_text );
                    } elseif ( 'rest_plugin_isolation_rules' === $key ) {
                        $sanitized_text = self::sanitize_rest_plugin_isolation_rules_setting( $sanitized_text );
                    }
                    $sanitized[ $key ] = $sanitized_text;
                    break;

                case 'select':
                    $sanitized[ $key ] = self::sanitize_select_setting( $value, $field );
                    break;

                case 'text':
                default:
                    if ( 'custom_login_url' === $key ) {
                        $sanitized[ $key ] = self::sanitize_custom_login_key( $value );
                    } elseif ( 'ip_risk_external_cron_key' === $key ) {
                        $sanitized[ $key ] = self::sanitize_external_cron_key( $value );
                    } else {
                        $sanitized[ $key ] = sanitize_text_field( (string) $value );
                    }
                    break;
            }
        }

        return array_merge( $defaults, $sanitized );
    }

    private static function sanitize_ip_risk_provider_list_setting( $value ) {
        $allowed = [ 'ipregistry', 'ipdata', 'ip_api', 'ipinfo', 'ip_sb', 'ipbset' ];
        $items   = self::parse_list_setting( $value );

        $items = array_map(
            static function( $item ) {
                return sanitize_key( str_replace( '-', '_', (string) $item ) );
            },
            $items
        );
        $items = array_values(
            array_filter(
                array_unique( $items ),
                static function( $item ) use ( $allowed ) {
                    return in_array( $item, $allowed, true );
                }
            )
        );

        if ( empty( $items ) ) {
            $items = [ 'ip_api', 'ipinfo', 'ip_sb' ];
        }

        return implode( "\n", $items );
    }

    public static function sanitize_custom_login_key( $value ) {
        $value = sanitize_text_field( (string) $value );
        $value = preg_replace( '/[^A-Za-z0-9_-]/', '', $value );

        return trim( $value );
    }

    public static function parse_list_setting( $value ) {
        if ( is_array( $value ) ) {
            $value = implode( "\n", array_map( 'strval', $value ) );
        }

        $items = preg_split( '/[\r\n,]+/', (string) $value );
        $items = array_map( 'trim', $items );
        $items = array_filter(
            $items,
            static function( $item ) {
                return '' !== $item;
            }
        );

        return array_values( array_unique( $items ) );
    }

    private static function normalize_plugin_basename_setting( $value ) {
        $value = trim( str_replace( '\\', '/', (string) $value ) );
        $value = ltrim( $value, '/' );

        if ( '' === $value || false !== strpos( $value, '..' ) ) {
            return '';
        }

        if ( ! preg_match( '#^[A-Za-z0-9._-]+(?:/[A-Za-z0-9._-]+)*\.php$#', $value ) ) {
            return '';
        }

        return $value;
    }

    private static function parse_plugin_basename_list_setting( $value ) {
        $items = self::parse_list_setting( $value );
        $items = array_map( [ __CLASS__, 'normalize_plugin_basename_setting' ], $items );
        $items = array_values( array_unique( array_filter( $items ) ) );

        return $items;
    }

    private static function sanitize_plugin_basename_list_setting( $value ) {
        return implode( "\n", self::parse_plugin_basename_list_setting( $value ) );
    }

    private static function normalize_rest_isolation_route_prefix( $value ) {
        $value = trim( (string) $value );

        if ( '' === $value ) {
            return '';
        }

        $value = str_replace( '\\', '/', $value );
        $value = preg_replace( '#^https?://[^/]+#i', '', $value );
        $value = preg_replace( '/\s+/', '', $value );

        if ( false !== strpos( $value, '?' ) ) {
            $value = (string) strtok( $value, '?' );
        }

        if ( 0 === strpos( $value, '/wp-json' ) ) {
            $value = substr( $value, 8 );
        } elseif ( 0 === strpos( $value, 'wp-json/' ) ) {
            $value = substr( $value, 7 );
        }

        $value = rtrim( $value, '*' );
        $value = preg_replace( '#/+#', '/', $value );

        if ( '' === $value || '/' === $value ) {
            return '/';
        }

        if ( '/' !== substr( $value, 0, 1 ) ) {
            $value = '/' . $value;
        }

        if ( '/' !== $value ) {
            $value = rtrim( $value, '/' );
        }

        return $value;
    }

    private static function parse_rest_plugin_isolation_rule_line( $line ) {
        $line = trim( (string) $line );

        if ( '' === $line || 0 === strpos( $line, '#' ) || false === strpos( $line, '=>' ) ) {
            return [];
        }

        list( $route_part, $plugins_part ) = array_map( 'trim', explode( '=>', $line, 2 ) );
        $route   = self::normalize_rest_isolation_route_prefix( $route_part );
        $plugins = self::parse_plugin_basename_list_setting( $plugins_part );

        // 路由隔离仅作用于 REST API，不处理 admin-ajax action。
        if ( '/admin-ajax' === $route || 0 === strpos( $route, '/admin-ajax/' ) ) {
            return [];
        }

        if ( '' === $route || empty( $plugins ) ) {
            return [];
        }

        return [
            'route'   => $route,
            'plugins' => $plugins,
        ];
    }

    private static function parse_rest_plugin_isolation_rules_setting( $value ) {
        if ( is_array( $value ) ) {
            $value = implode( "\n", array_map( 'strval', $value ) );
        }

        $lines = preg_split( '/\r\n|\r|\n/', (string) $value );
        $rules = [];

        foreach ( $lines as $line ) {
            $rule = self::parse_rest_plugin_isolation_rule_line( $line );

            if ( empty( $rule ) ) {
                continue;
            }

            $route = $rule['route'];

            if ( ! isset( $rules[ $route ] ) ) {
                $rules[ $route ] = [];
            }

            $rules[ $route ] = array_values( array_unique( array_merge( $rules[ $route ], $rule['plugins'] ) ) );
        }

        $normalized_rules = [];

        foreach ( $rules as $route => $plugins ) {
            $normalized_rules[] = [
                'route'   => $route,
                'plugins' => array_values( array_unique( array_filter( $plugins ) ) ),
            ];
        }

        usort(
            $normalized_rules,
            static function( $left, $right ) {
                return strlen( $right['route'] ) <=> strlen( $left['route'] );
            }
        );

        return $normalized_rules;
    }

    private static function sanitize_rest_plugin_isolation_rules_setting( $value ) {
        $rules = self::parse_rest_plugin_isolation_rules_setting( $value );
        $lines = [];

        foreach ( $rules as $rule ) {
            if ( empty( $rule['route'] ) || empty( $rule['plugins'] ) ) {
                continue;
            }

            $lines[] = $rule['route'] . ' => ' . implode( ', ', $rule['plugins'] );
        }

        return implode( "\n", $lines );
    }

    public static function parse_header_setting( $value ) {
        $headers = [];

        if ( is_array( $value ) ) {
            $value = implode( "\n", array_map( 'strval', $value ) );
        }

        $lines = preg_split( '/\r\n|\r|\n/', (string) $value );
        $lines = array_map( 'trim', $lines );
        $lines = array_filter(
            $lines,
            static function( $line ) {
                return '' !== $line;
            }
        );

        foreach ( $lines as $line ) {
            if ( false === strpos( $line, ':' ) ) {
                continue;
            }

            list( $name, $header_value ) = array_map( 'trim', explode( ':', $line, 2 ) );

            if ( '' === $name || '' === $header_value ) {
                continue;
            }

            $headers[ $name ] = $header_value;
        }

        return $headers;
    }

    public static function get_trusted_proxy_ips( $settings = null ) {
        $settings = is_array( $settings ) ? $settings : self::get_settings();
        $ips      = self::parse_list_setting( $settings['trusted_proxy_ips'] );

        if ( empty( $ips ) ) {
            $preset = self::get_active_proxy_preset( $settings );
            $ips    = ! empty( $preset['proxy_ips'] ) && is_array( $preset['proxy_ips'] ) ? array_values( $preset['proxy_ips'] ) : [];
        }

        return apply_filters( 'qs_trusted_proxy_setting_ips', $ips, $settings );
    }

    public static function get_trusted_proxy_headers( $settings = null ) {
        $settings = is_array( $settings ) ? $settings : self::get_settings();
        $headers  = self::parse_list_setting( $settings['trusted_proxy_headers'] );

        if ( empty( $headers ) ) {
            $preset  = self::get_active_proxy_preset( $settings );
            $headers = ! empty( $preset['headers'] ) && is_array( $preset['headers'] ) ? $preset['headers'] : self::get_default_proxy_headers();
        }

        $headers = array_map( [ __CLASS__, 'normalize_server_header_name' ], $headers );
        $headers = array_values( array_unique( array_filter( $headers ) ) );

        return apply_filters( 'qs_trusted_proxy_headers_setting', $headers, $settings );
    }

    public static function get_file_integrity_paths( $settings = null ) {
        $settings = is_array( $settings ) ? $settings : self::get_settings();
        $paths    = self::parse_list_setting( $settings['file_integrity_paths'] );

        if ( empty( $paths ) ) {
            $paths = self::get_default_file_integrity_paths();
        }

        $paths = array_map(
            static function( $path ) {
                $path = str_replace( '\\', '/', trim( (string) $path ) );
                $path = trim( $path, '/' );

                if ( '' === $path || false !== strpos( $path, '..' ) ) {
                    return '';
                }

                return $path;
            },
            $paths
        );
        $paths = array_values( array_filter( array_unique( $paths ) ) );

        return apply_filters( 'qs_file_integrity_paths', $paths, $settings );
    }

    public static function get_rest_plugin_isolation_core_plugins( $settings = null ) {
        $settings = is_array( $settings ) ? $settings : self::get_settings();
        $plugins  = self::parse_plugin_basename_list_setting( isset( $settings['rest_plugin_isolation_core_plugins'] ) ? $settings['rest_plugin_isolation_core_plugins'] : '' );

        if ( ! in_array( 'qilingsecurity/qilingsecurity.php', $plugins, true ) ) {
            $plugins[] = 'qilingsecurity/qilingsecurity.php';
        }

        return apply_filters( 'qs_rest_plugin_isolation_core_plugins', array_values( array_unique( $plugins ) ), $settings );
    }

    public static function get_rest_plugin_isolation_rules( $settings = null ) {
        $settings = is_array( $settings ) ? $settings : self::get_settings();
        $rules    = self::parse_rest_plugin_isolation_rules_setting( isset( $settings['rest_plugin_isolation_rules'] ) ? $settings['rest_plugin_isolation_rules'] : '' );

        return apply_filters( 'qs_rest_plugin_isolation_rules', $rules, $settings );
    }

    public static function get_rest_plugin_isolation_monitor_max_entries( $settings = null ) {
        $settings = is_array( $settings ) ? $settings : self::get_settings();
        $max      = isset( $settings['rest_plugin_isolation_monitor_max_entries'] ) ? absint( $settings['rest_plugin_isolation_monitor_max_entries'] ) : 100;

        return max( 20, min( 500, $max ) );
    }

    public static function get_rest_plugin_isolation_monitor_logs( $limit = 100 ) {
        $logs = get_option( self::get_rest_plugin_isolation_monitor_option_key(), [] );
        $logs = is_array( $logs ) ? $logs : [];

        $limit = absint( $limit );
        if ( $limit <= 0 ) {
            $limit = self::get_rest_plugin_isolation_monitor_max_entries();
        }
        $limit = max( 1, min( 500, $limit ) );
        $logs  = array_slice( $logs, 0, $limit );

        $sanitized_logs = [];

        foreach ( $logs as $log ) {
            if ( ! is_array( $log ) ) {
                continue;
            }

            $route        = self::normalize_rest_isolation_route_prefix( isset( $log['route'] ) ? $log['route'] : '' );
            $matched_rule = self::normalize_rest_isolation_route_prefix( isset( $log['matched_rule'] ) ? $log['matched_rule'] : '' );
            $mode         = isset( $log['mode'] ) ? sanitize_key( (string) $log['mode'] ) : 'matched_only';
            $decision     = isset( $log['decision'] ) ? sanitize_key( (string) $log['decision'] ) : 'unknown';

            if ( ! in_array( $mode, [ 'matched_only', 'all_rest' ], true ) ) {
                $mode = 'matched_only';
            }

            $sanitized_logs[] = [
                'time'            => isset( $log['time'] ) ? sanitize_text_field( (string) $log['time'] ) : '',
                'route'           => '' !== $route ? $route : '/',
                'mode'            => $mode,
                'decision'        => $decision,
                'matched_rule'    => $matched_rule,
                'before_count'    => isset( $log['before_count'] ) ? max( 0, (int) $log['before_count'] ) : 0,
                'after_count'     => isset( $log['after_count'] ) ? max( 0, (int) $log['after_count'] ) : 0,
                'matched_plugins' => self::parse_plugin_basename_list_setting( isset( $log['matched_plugins'] ) ? $log['matched_plugins'] : [] ),
                'final_plugins'   => self::parse_plugin_basename_list_setting( isset( $log['final_plugins'] ) ? $log['final_plugins'] : [] ),
            ];
        }

        return $sanitized_logs;
    }

    public static function clear_rest_plugin_isolation_monitor_logs() {
        $key   = self::get_rest_plugin_isolation_monitor_option_key();
        $logs  = get_option( $key, [] );
        $count = is_array( $logs ) ? count( $logs ) : 0;

        delete_option( $key );

        return $count;
    }

    public static function get_admin_privileged_user_threshold( $settings = null ) {
        $settings = is_array( $settings ) ? $settings : self::get_settings();

        return max( 1, absint( $settings['admin_privileged_user_threshold'] ) );
    }

    public static function get_admin_weak_usernames( $settings = null ) {
        $settings = is_array( $settings ) ? $settings : self::get_settings();
        $rules    = self::parse_list_setting( $settings['admin_weak_usernames'] );
        $rules    = array_map( 'strtolower', array_map( 'trim', $rules ) );
        $rules    = array_values( array_unique( array_filter( $rules ) ) );

        return apply_filters( 'qs_admin_weak_usernames', $rules, $settings );
    }

    public static function get_persistence_scan_ignored_hooks( $settings = null ) {
        $settings = is_array( $settings ) ? $settings : self::get_settings();
        $hooks    = self::parse_list_setting( $settings['persistence_scan_ignored_hooks'] );
        $hooks    = array_map( 'sanitize_key', $hooks );
        $hooks    = array_values( array_unique( array_filter( $hooks ) ) );

        return apply_filters( 'qs_persistence_scan_ignored_hooks', $hooks, $settings );
    }

    public static function get_db_autoload_option_warn_bytes( $settings = null ) {
        $settings = is_array( $settings ) ? $settings : self::get_settings();

        return max( 32, absint( $settings['db_autoload_option_warn_kb'] ) ) * 1024;
    }

    public static function get_db_autoload_total_warn_bytes( $settings = null ) {
        $settings = is_array( $settings ) ? $settings : self::get_settings();

        return max( 1, absint( $settings['db_autoload_total_warn_mb'] ) ) * MB_IN_BYTES;
    }

    public static function get_db_suspicious_option_limit( $settings = null ) {
        $settings = is_array( $settings ) ? $settings : self::get_settings();

        return max( 5, absint( $settings['db_suspicious_option_limit'] ) );
    }

    public static function get_db_scan_ignored_options( $settings = null ) {
        $settings = is_array( $settings ) ? $settings : self::get_settings();
        $rules    = self::parse_list_setting( $settings['db_scan_ignored_options'] );
        $rules    = array_merge(
            $rules,
            [
                'qs_rule_package_active',
                'qs_rule_package_previous',
                'qs_protection_settings',
                'qs_db_schema_version',
            ]
        );
        $rules    = array_map( 'strtolower', array_map( 'trim', $rules ) );
        $rules    = array_values( array_unique( array_filter( $rules ) ) );

        return apply_filters( 'qs_db_scan_ignored_options', $rules, $settings );
    }

    public static function get_upload_disallowed_extensions( $settings = null ) {
        $settings   = is_array( $settings ) ? $settings : self::get_settings();
        $extensions = self::parse_list_setting( $settings['upload_disallowed_extensions'] );
        $extensions = array_map(
            static function( $extension ) {
                return ltrim( strtolower( trim( (string) $extension ) ), '.' );
            },
            $extensions
        );
        $extensions = array_values( array_unique( array_filter( $extensions ) ) );

        return apply_filters( 'qs_upload_disallowed_extensions', $extensions, $settings );
    }

    public static function get_upload_mime_ignored_extensions( $settings = null ) {
        $settings   = is_array( $settings ) ? $settings : self::get_settings();
        $extensions = self::parse_list_setting( $settings['upload_mime_ignored_extensions'] );
        $extensions = array_map(
            static function( $extension ) {
                return ltrim( strtolower( trim( (string) $extension ) ), '.' );
            },
            $extensions
        );
        $extensions = array_values( array_unique( array_filter( $extensions ) ) );

        return apply_filters( 'qs_upload_mime_ignored_extensions', $extensions, $settings );
    }

    public static function get_rest_api_guard_mode( $settings = null ) {
        $settings = is_array( $settings ) ? $settings : self::get_settings();
        $mode     = isset( $settings['rest_api_guard_mode'] ) ? sanitize_key( (string) $settings['rest_api_guard_mode'] ) : 'observe';

        if ( ! in_array( $mode, [ 'observe', 'block' ], true ) ) {
            $mode = 'observe';
        }

        return apply_filters( 'qs_rest_api_guard_mode', $mode, $settings );
    }

    public static function get_rest_api_public_block_prefixes( $settings = null ) {
        $settings = is_array( $settings ) ? $settings : self::get_settings();
        $rules    = self::parse_list_setting( $settings['rest_api_public_block_prefixes'] );
        $rules    = array_map( [ __CLASS__, 'normalize_rest_route_prefix' ], $rules );
        $rules    = array_values( array_unique( array_filter( $rules ) ) );

        return apply_filters( 'qs_rest_api_public_block_prefixes', $rules, $settings );
    }

    public static function get_rest_api_public_allow_prefixes( $settings = null ) {
        $settings = is_array( $settings ) ? $settings : self::get_settings();
        $rules    = self::parse_list_setting( $settings['rest_api_public_allow_prefixes'] );
        $rules    = array_map( [ __CLASS__, 'normalize_rest_route_prefix' ], $rules );
        $rules    = array_values( array_unique( array_filter( $rules ) ) );

        return apply_filters( 'qs_rest_api_public_allow_prefixes', $rules, $settings );
    }

    public static function is_phone_location_lookup_enabled( $settings = null ) {
        $settings = is_array( $settings ) ? $settings : self::get_settings();
        $enabled  = ! empty( $settings['enable_phone_location_lookup'] );

        return (bool) apply_filters( 'qs_phone_location_lookup_enabled', $enabled, $settings );
    }

    public static function is_ip_risk_profile_enabled( $settings = null ) {
        $settings = is_array( $settings ) ? $settings : self::get_settings();
        $enabled  = ! empty( $settings['enable_ip_risk_profile'] );

        return (bool) apply_filters( 'qs_ip_risk_profile_enabled', $enabled, $settings );
    }

    public static function get_ip_risk_scope( $settings = null ) {
        $settings = is_array( $settings ) ? $settings : self::get_settings();
        $scope    = isset( $settings['ip_risk_scope'] ) ? sanitize_key( (string) $settings['ip_risk_scope'] ) : 'both';

        if ( ! in_array( $scope, [ 'both', 'attempt_only', 'success_only' ], true ) ) {
            $scope = 'both';
        }

        return apply_filters( 'qs_ip_risk_scope', $scope, $settings );
    }

    public static function should_capture_ip_risk_for_event( $event_type, $settings = null ) {
        $event_type = sanitize_key( (string) $event_type );
        $scope      = self::get_ip_risk_scope( $settings );

        if ( 'success_only' === $scope ) {
            return 'login_success' === $event_type;
        }

        if ( 'attempt_only' === $scope ) {
            return 'login_failed' === $event_type;
        }

        return in_array( $event_type, [ 'login_success', 'login_failed' ], true );
    }

    public static function get_ip_risk_query_mode( $settings = null ) {
        $settings = is_array( $settings ) ? $settings : self::get_settings();
        $mode     = isset( $settings['ip_risk_query_mode'] ) ? sanitize_key( (string) $settings['ip_risk_query_mode'] ) : 'async';

        if ( ! in_array( $mode, [ 'external', 'async', 'sync' ], true ) ) {
            $mode = 'async';
        }

        return apply_filters( 'qs_ip_risk_query_mode', $mode, $settings );
    }

    public static function get_ip_risk_external_cron_key( $settings = null, $allow_fallback = true ) {
        $settings = is_array( $settings ) ? $settings : self::get_settings();
        $key      = isset( $settings['ip_risk_external_cron_key'] ) ? self::sanitize_external_cron_key( $settings['ip_risk_external_cron_key'] ) : '';

        if ( '' !== $key || ! $allow_fallback ) {
            return $key;
        }

        return substr( hash_hmac( 'sha256', home_url( '/' ), wp_salt( 'auth' ) ), 0, 32 );
    }

    public static function get_ip_risk_external_batch_size( $settings = null ) {
        $settings = is_array( $settings ) ? $settings : self::get_settings();
        $batch    = isset( $settings['ip_risk_external_batch_size'] ) ? absint( $settings['ip_risk_external_batch_size'] ) : 20;

        return max( 1, min( 200, $batch ) );
    }

    public static function get_ip_risk_external_cron_url( $settings = null ) {
        $settings = is_array( $settings ) ? $settings : self::get_settings();
        $key      = self::get_ip_risk_external_cron_key( $settings, true );

        return add_query_arg(
            [
                'qs_ip_risk_task' => 'run',
                'key'             => $key,
            ],
            home_url( '/' )
        );
    }

    public static function get_ip_risk_external_cleanup_url( $settings = null ) {
        $settings = is_array( $settings ) ? $settings : self::get_settings();
        $key      = self::get_ip_risk_external_cron_key( $settings, true );

        return add_query_arg(
            [
                'qs_ip_risk_task' => 'cleanup',
                'key'             => $key,
                'days'            => 30,
            ],
            home_url( '/' )
        );
    }

    public static function get_ip_risk_cache_ttl_seconds( $settings = null ) {
        $settings = is_array( $settings ) ? $settings : self::get_settings();
        $hours    = isset( $settings['ip_risk_cache_ttl_hours'] ) ? absint( $settings['ip_risk_cache_ttl_hours'] ) : 168;

        return max( HOUR_IN_SECONDS, $hours * HOUR_IN_SECONDS );
    }

    public static function get_ip_risk_provider_timeout_seconds( $settings = null ) {
        $settings   = is_array( $settings ) ? $settings : self::get_settings();
        $timeout_ms = isset( $settings['ip_risk_provider_timeout_ms'] ) ? absint( $settings['ip_risk_provider_timeout_ms'] ) : 1500;
        $timeout_ms = max( 300, min( 10000, $timeout_ms ) );

        return (float) ( $timeout_ms / 1000 );
    }

    public static function get_ip_risk_max_provider_calls( $settings = null ) {
        $settings = is_array( $settings ) ? $settings : self::get_settings();
        $max      = isset( $settings['ip_risk_max_provider_calls'] ) ? absint( $settings['ip_risk_max_provider_calls'] ) : 5;

        return max( 1, min( 10, $max ) );
    }

    public static function get_ip_risk_provider_list( $settings = null ) {
        $settings = is_array( $settings ) ? $settings : self::get_settings();
        $list     = self::parse_list_setting( isset( $settings['ip_risk_providers'] ) ? $settings['ip_risk_providers'] : '' );
        $allowed  = [
            'ipregistry',
            'ipdata',
            'ip_api',
            'ipinfo',
            'ip_sb',
            'ipbset',
        ];

        $list = array_map(
            static function( $item ) {
                return sanitize_key( str_replace( '-', '_', (string) $item ) );
            },
            $list
        );
        $list = array_values(
            array_filter(
                array_unique( $list ),
                static function( $item ) use ( $allowed ) {
                    return in_array( $item, $allowed, true );
                }
            )
        );

        if ( empty( $list ) ) {
            $list = [ 'ip_api', 'ipinfo', 'ip_sb' ];
        }

        return $list;
    }

    public static function get_ip_risk_provider_credentials( $settings = null ) {
        $settings = is_array( $settings ) ? $settings : self::get_settings();

        return [
            'ipregistry_key' => isset( $settings['ip_risk_ipregistry_key'] ) ? sanitize_text_field( (string) $settings['ip_risk_ipregistry_key'] ) : '',
            'ipdata_key'     => isset( $settings['ip_risk_ipdata_key'] ) ? sanitize_text_field( (string) $settings['ip_risk_ipdata_key'] ) : '',
            'ipinfo_token'   => isset( $settings['ip_risk_ipinfo_token'] ) ? sanitize_text_field( (string) $settings['ip_risk_ipinfo_token'] ) : '',
            'ipbset_key'     => isset( $settings['ip_risk_ipbset_key'] ) ? sanitize_text_field( (string) $settings['ip_risk_ipbset_key'] ) : '',
        ];
    }

    public static function get_login_rate_limit_config( $settings = null ) {
        $settings = is_array( $settings ) ? $settings : self::get_settings();

        return [
            'max_attempts'  => max( 1, absint( $settings['login_max_attempts'] ) ),
            'lockout_hours' => max( 1, absint( $settings['login_lockout_hours'] ) ),
        ];
    }

    public static function get_max_concurrent_sessions( $settings = null ) {
        $settings = is_array( $settings ) ? $settings : self::get_settings();

        return max( 0, absint( $settings['max_concurrent_sessions'] ) );
    }

    public static function get_bad_bot_signatures( $settings = null ) {
        $settings = is_array( $settings ) ? $settings : self::get_settings();
        $bad_bots = [
            'sqlmap',
            'nmap',
            'zmeu',
            'nikto',
            'dirbuster',
            'gobuster',
            'python-requests',
            'python-urllib',
            'wget',
            'curl',
            'java/',
        ];

        $bad_bots = array_merge( $bad_bots, self::parse_list_setting( $settings['extra_bad_bots'] ) );
        $bad_bots = array_values( array_unique( array_map( 'strtolower', $bad_bots ) ) );

        return apply_filters( 'qs_bad_bot_signatures', $bad_bots, $settings );
    }

    public static function get_security_headers( $settings = null ) {
        $settings = is_array( $settings ) ? $settings : self::get_settings();
        $headers  = [
            'X-Frame-Options'       => 'SAMEORIGIN',
            'X-Content-Type-Options' => 'nosniff',
            'Referrer-Policy'       => 'strict-origin-when-cross-origin',
            'X-XSS-Protection'      => '1; mode=block',
        ];

        if ( is_ssl() ) {
            $headers['Strict-Transport-Security'] = 'max-age=31536000; includeSubDomains';
        }

        $headers = array_merge( $headers, self::parse_header_setting( $settings['extra_security_headers'] ) );

        return apply_filters( 'qs_security_headers', $headers, $settings );
    }

    public static function get_waf_rules( $settings = null ) {
        $settings = is_array( $settings ) ? $settings : self::get_settings();
        $rules    = [
            [
                'needle' => 'union select',
                'reason' => 'SQL 注入特征',
                'ban'    => true,
                'scopes' => [ 'get', 'cookie' ],
            ],
            [
                'needle' => 'base64_decode(',
                'reason' => '代码执行特征',
                'ban'    => true,
                'scopes' => [ 'get', 'cookie' ],
            ],
            [
                'needle' => 'exec(',
                'reason' => '命令执行特征',
                'ban'    => true,
                'scopes' => [ 'get', 'cookie' ],
            ],
            [
                'needle' => '%3cscript',
                'reason' => 'XSS 特征',
                'ban'    => false,
                'scopes' => [ 'get' ],
            ],
            [
                'needle' => '<script>',
                'reason' => 'XSS 特征',
                'ban'    => false,
                'scopes' => [ 'get' ],
            ],
            [
                'needle' => 'document.cookie',
                'reason' => 'XSS 特征',
                'ban'    => false,
                'scopes' => [ 'get' ],
            ],
        ];

        return apply_filters( 'qs_waf_rules', $rules, $settings );
    }

    private static function get_theme_overlap_options( $config ) {
        return ! empty( $config['options'] ) && is_array( $config['options'] ) ? array_values( $config['options'] ) : [];
    }

    private static function implode_option_labels( $options ) {
        $labels = array_map(
            static function( $option ) {
                return isset( $option['label'] ) ? $option['label'] : '';
            },
            (array) $options
        );

        $labels = array_filter(
            $labels,
            static function( $label ) {
                return '' !== $label;
            }
        );

        return implode( '、', array_values( array_unique( $labels ) ) );
    }

    private static function sanitize_number_setting( $value, $field ) {
        $value = absint( $value );

        if ( isset( $field['min'] ) && $value < absint( $field['min'] ) ) {
            $value = absint( $field['default'] );
        }

        if ( isset( $field['max'] ) && $value > absint( $field['max'] ) ) {
            $value = absint( $field['max'] );
        }

        return $value;
    }

    private static function sanitize_select_setting( $value, $field ) {
        $value   = sanitize_key( (string) $value );
        $choices = isset( $field['choices'] ) && is_array( $field['choices'] ) ? array_keys( $field['choices'] ) : [];

        if ( empty( $choices ) || in_array( $value, $choices, true ) ) {
            return $value;
        }

        return isset( $field['default'] ) ? sanitize_key( (string) $field['default'] ) : '';
    }

    private static function sanitize_multiline_text( $value ) {
        if ( is_array( $value ) ) {
            $value = implode( "\n", array_map( 'strval', $value ) );
        }

        $value = sanitize_textarea_field( (string) $value );
        $lines = preg_split( '/\r\n|\r|\n/', $value );
        $lines = array_map( 'trim', $lines );
        $lines = array_filter(
            $lines,
            static function( $line ) {
                return '' !== $line;
            }
        );

        return implode( "\n", $lines );
    }

    private static function sanitize_external_cron_key( $value ) {
        $value = sanitize_text_field( (string) $value );
        $value = preg_replace( '/[^A-Za-z0-9_-]/', '', $value );
        $value = is_string( $value ) ? $value : '';

        return substr( $value, 0, 64 );
    }

    private static function normalize_server_header_name( $header_name ) {
        $header_name = strtoupper( trim( (string) $header_name ) );

        if ( '' === $header_name ) {
            return '';
        }

        $header_name = str_replace( '-', '_', $header_name );

        if ( in_array( $header_name, [ 'REMOTE_ADDR', 'CONTENT_TYPE', 'CONTENT_LENGTH', 'CONTENT_MD5' ], true ) ) {
            return $header_name;
        }

        if ( 0 !== strpos( $header_name, 'HTTP_' ) ) {
            $header_name = 'HTTP_' . $header_name;
        }

        return preg_replace( '/[^A-Z0-9_]/', '', $header_name );
    }

    private static function get_rate_limit_setting_fields() {
        $fields = [];

        foreach ( self::get_rate_limit_presets() as $preset_id => $preset ) {
            $enabled_key = 'rate_limit_' . $preset_id . '_enabled';
            $request_key = 'rate_limit_' . $preset_id . '_requests';
            $window_key  = 'rate_limit_' . $preset_id . '_window_minutes';

            $fields[ $enabled_key ] = [
                'section'     => 'behavior',
                'type'        => 'checkbox',
                'label'       => isset( $preset['label'] ) ? $preset['label'] : $preset_id,
                'description' => isset( $preset['description'] ) ? $preset['description'] : '',
                'default'     => ! empty( $preset['default_enabled'] ),
            ];
            $fields[ $request_key ] = [
                'section'     => 'behavior',
                'type'        => 'number',
                'label'       => ( isset( $preset['label'] ) ? $preset['label'] : $preset_id ) . '：允许请求次数',
                'description' => '超过该次数后触发上面的行为动作。',
                'default'     => isset( $preset['default_requests'] ) ? absint( $preset['default_requests'] ) : 20,
                'min'         => 1,
                'max'         => 5000,
                'step'        => 1,
                'class'       => 'small-text',
            ];
            $fields[ $window_key ] = [
                'section'     => 'behavior',
                'type'        => 'number',
                'label'       => ( isset( $preset['label'] ) ? $preset['label'] : $preset_id ) . '：统计窗口（分钟）',
                'description' => '在这个时间窗内累计请求次数。',
                'default'     => isset( $preset['default_window'] ) ? absint( $preset['default_window'] ) : 5,
                'min'         => 1,
                'max'         => 1440,
                'step'        => 1,
                'class'       => 'small-text',
            ];
        }

        return $fields;
    }

    private static function get_login_gate_cookie_name() {
        return 'qs_login_gate_' . md5( home_url( '/' ) );
    }

    private static function get_login_gate_cookie_value( $secret_key ) {
        return wp_hash( $secret_key . '|' . home_url( '/' ), 'auth' );
    }

    private static function set_login_gate_cookie( $secret_key ) {
        $cookie_name  = self::get_login_gate_cookie_name();
        $cookie_value = self::get_login_gate_cookie_value( $secret_key );
        $expires      = time() + ( 12 * HOUR_IN_SECONDS );
        $cookie_path  = COOKIEPATH ? COOKIEPATH : '/';
        $secure       = is_ssl();

        setcookie( $cookie_name, $cookie_value, $expires, $cookie_path, COOKIE_DOMAIN, $secure, true );

        if ( SITECOOKIEPATH && SITECOOKIEPATH !== $cookie_path ) {
            setcookie( $cookie_name, $cookie_value, $expires, SITECOOKIEPATH, COOKIE_DOMAIN, $secure, true );
        }

        $_COOKIE[ $cookie_name ] = $cookie_value;
    }

    private static function has_login_gate_cookie( $secret_key ) {
        $cookie_name = self::get_login_gate_cookie_name();

        if ( empty( $_COOKIE[ $cookie_name ] ) ) {
            return false;
        }

        $cookie_value = sanitize_text_field( wp_unslash( $_COOKIE[ $cookie_name ] ) );

        return hash_equals( self::get_login_gate_cookie_value( $secret_key ), $cookie_value );
    }

    private static function is_wp_login_request() {
        $script_name = isset( $_SERVER['SCRIPT_NAME'] ) ? wp_unslash( $_SERVER['SCRIPT_NAME'] ) : '';

        return 'wp-login.php' === basename( $script_name );
    }

    private static function get_login_request_action() {
        $action = isset( $_REQUEST['action'] ) ? sanitize_key( wp_unslash( $_REQUEST['action'] ) ) : '';

        return $action ? $action : 'login';
    }

    private static function is_login_action_allowed_without_secret( $action ) {
        $allowed_actions = [
            'logout',
            'lostpassword',
            'retrievepassword',
            'resetpass',
            'rp',
            'postpass',
            'register',
            'checkemail',
            'confirm_admin_email',
        ];

        return in_array( $action, $allowed_actions, true ) || isset( $_REQUEST['interim-login'] );
    }

    private static function append_secret_to_url( $url, $secret_key ) {
        if ( empty( $url ) ) {
            return $url;
        }

        $query = wp_parse_url( $url, PHP_URL_QUERY );
        if ( $query ) {
            parse_str( $query, $query_args );
            if ( isset( $query_args[ $secret_key ] ) ) {
                return $url;
            }
        }

        return add_query_arg( $secret_key, '1', $url );
    }

    private static function protect_custom_login_url( $secret_key ) {
        if ( ! self::is_wp_login_request() ) {
            return;
        }

        if ( isset( $_GET[ $secret_key ] ) ) {
            self::set_login_gate_cookie( $secret_key );
        }

        if ( self::has_login_gate_cookie( $secret_key ) || is_user_logged_in() ) {
            return;
        }

        if ( self::is_login_action_allowed_without_secret( self::get_login_request_action() ) ) {
            return;
        }

        status_header( 404 );
        nocache_headers();
        wp_die( '<h1>404 Not Found</h1><p>The requested URL was not found on this server.</p>', 'Not Found', [ 'response' => 404 ] );
    }

    private static function flatten_request_values( $value ) {
        if ( is_array( $value ) ) {
            $values = [];

            foreach ( $value as $nested_value ) {
                $values = array_merge( $values, self::flatten_request_values( $nested_value ) );
            }

            return $values;
        }

        if ( is_scalar( $value ) ) {
            return [ (string) $value ];
        }

        return [];
    }

    private static function filter_upload_prefilter( $file, $settings ) {
        $file = is_array( $file ) ? $file : [];

        if ( ! empty( $file['error'] ) || empty( $file['name'] ) ) {
            return $file;
        }

        $filename             = sanitize_file_name( wp_basename( (string) $file['name'] ) );
        $extension            = strtolower( pathinfo( $filename, PATHINFO_EXTENSION ) );
        $disallowed_exts      = self::get_upload_disallowed_extensions( $settings );
        $mime_ignored_exts    = self::get_upload_mime_ignored_extensions( $settings );
        $tmp_name             = isset( $file['tmp_name'] ) ? (string) $file['tmp_name'] : '';

        if ( ! empty( $settings['block_bad_uploads'] ) && self::has_disallowed_upload_extension( $filename, $disallowed_exts ) ) {
            $message = '启灵上传防护：该文件命中了危险后缀或双后缀伪装规则，已被拦截。';
            self::record_upload_block_event( '危险上传后缀', $filename );
            $file['error'] = $message;

            return $file;
        }

        if ( ! empty( $settings['block_svg_uploads'] ) && 'svg' === $extension ) {
            $message = '启灵上传防护：当前站点已禁止上传 SVG 文件。';
            self::record_upload_block_event( 'SVG 上传拦截', $filename );
            $file['error'] = $message;

            return $file;
        }

        if ( empty( $settings['strict_upload_validation'] ) ) {
            return $file;
        }

        if ( '' === $tmp_name || ! is_readable( $tmp_name ) ) {
            return $file;
        }

        $validation_error = self::validate_upload_mime_consistency( $filename, $tmp_name, $extension, $mime_ignored_exts );

        if ( is_wp_error( $validation_error ) ) {
            self::record_upload_block_event( '上传内容校验失败', $filename, $validation_error->get_error_message() );
            $file['error'] = $validation_error->get_error_message();
        }

        return $file;
    }

    private static function has_disallowed_upload_extension( $filename, $disallowed_extensions ) {
        $segments = array_values( array_filter( explode( '.', strtolower( (string) $filename ) ) ) );

        if ( count( $segments ) < 2 ) {
            return false;
        }

        $extensions_to_check = array_slice( $segments, 1 );

        foreach ( $extensions_to_check as $extension ) {
            if ( in_array( $extension, (array) $disallowed_extensions, true ) ) {
                return true;
            }
        }

        return false;
    }

    private static function validate_upload_mime_consistency( $filename, $tmp_name, $extension, $ignored_extensions ) {
        $extension = strtolower( trim( (string) $extension ) );

        if ( '' === $extension || in_array( $extension, (array) $ignored_extensions, true ) ) {
            return true;
        }

        if ( 'svg' === $extension ) {
            return self::validate_svg_upload_contents( $filename, $tmp_name );
        }

        $image_extensions = apply_filters(
            'qs_upload_image_extensions',
            [ 'jpg', 'jpeg', 'jpe', 'png', 'gif', 'webp', 'bmp', 'avif', 'heic', 'heif' ]
        );

        if ( ! in_array( $extension, $image_extensions, true ) ) {
            return true;
        }

        $detected_image_mime = function_exists( 'wp_get_image_mime' ) ? wp_get_image_mime( $tmp_name ) : false;
        $filetype_check      = wp_check_filetype_and_ext( $tmp_name, $filename, get_allowed_mime_types() );
        $reported_type       = ! empty( $filetype_check['type'] ) ? strtolower( (string) $filetype_check['type'] ) : '';

        if ( false === $detected_image_mime || '' === $detected_image_mime ) {
            return new WP_Error( 'qs_upload_image_mismatch', '启灵上传防护：文件扩展名看起来像图片，但内容未通过真实图片校验，已拦截。' );
        }

        $detected_image_mime = strtolower( (string) $detected_image_mime );

        if ( 0 !== strpos( $detected_image_mime, 'image/' ) ) {
            return new WP_Error( 'qs_upload_image_mismatch', '启灵上传防护：文件扩展名看起来像图片，但真实 MIME 类型不是图片，已拦截。' );
        }

        if ( '' !== $reported_type && 0 !== strpos( $reported_type, 'image/' ) ) {
            return new WP_Error( 'qs_upload_image_mismatch', '启灵上传防护：文件扩展名与内容 MIME 类型不一致，已拦截伪装上传。' );
        }

        return true;
    }

    private static function validate_svg_upload_contents( $filename, $tmp_name ) {
        $content = self::read_upload_temp_excerpt( $tmp_name, 131072 );

        if ( '' === $content ) {
            return new WP_Error( 'qs_upload_svg_invalid', '启灵上传防护：SVG 文件无法读取或内容为空，已拒绝上传。' );
        }

        if ( false === stripos( $content, '<svg' ) ) {
            return new WP_Error( 'qs_upload_svg_invalid', '启灵上传防护：该文件扩展名为 SVG，但内容不包含有效的 <svg> 根标签，已拦截。' );
        }

        if ( preg_match( '/<(script|foreignObject)\b|onload\s*=|onerror\s*=|javascript:/i', $content ) ) {
            return new WP_Error( 'qs_upload_svg_scripted', '启灵上传防护：检测到包含脚本或事件处理器的高风险 SVG，已拦截。' );
        }

        $filetype_check = wp_check_filetype_and_ext( $tmp_name, $filename, get_allowed_mime_types() );
        $reported_type  = ! empty( $filetype_check['type'] ) ? strtolower( (string) $filetype_check['type'] ) : '';

        if ( '' !== $reported_type && false === strpos( $reported_type, 'svg' ) && false === strpos( $reported_type, 'xml' ) ) {
            return new WP_Error( 'qs_upload_svg_mismatch', '启灵上传防护：SVG 扩展名与实际 MIME 类型不匹配，已拦截。' );
        }

        return true;
    }

    private static function read_upload_temp_excerpt( $file_path, $max_bytes = 65535 ) {
        $file_path = (string) $file_path;

        if ( '' === $file_path || ! is_file( $file_path ) || ! is_readable( $file_path ) ) {
            return '';
        }

        $handle = @fopen( $file_path, 'rb' );

        if ( false === $handle ) {
            return '';
        }

        $content = @fread( $handle, max( 256, absint( $max_bytes ) ) );
        fclose( $handle );

        return is_string( $content ) ? $content : '';
    }

    private static function normalize_rest_route_prefix( $prefix ) {
        $prefix = trim( (string) $prefix );

        if ( '' === $prefix ) {
            return '';
        }

        $parsed_path = wp_parse_url( $prefix, PHP_URL_PATH );
        if ( is_string( $parsed_path ) && '' !== $parsed_path ) {
            $prefix = $parsed_path;
        }

        $prefix = str_replace( '\\', '/', $prefix );
        $prefix = preg_replace( '#/+#', '/', $prefix );
        $prefix = '/' . ltrim( (string) $prefix, '/' );

        if ( 0 === strpos( $prefix, '/index.php/wp-json/' ) ) {
            $prefix = substr( $prefix, strlen( '/index.php/wp-json' ) );
        } elseif ( '/index.php/wp-json' === $prefix ) {
            return '';
        }

        if ( 0 === strpos( $prefix, '/wp-json/' ) ) {
            $prefix = substr( $prefix, strlen( '/wp-json' ) );
        } elseif ( '/wp-json' === $prefix ) {
            return '';
        }

        $prefix = '/' . trim( $prefix, '/' );

        return '/' === $prefix ? '' : $prefix;
    }

    private static function route_matches_prefix_rules( $route, $rules ) {
        $route = self::normalize_rest_route_prefix( $route );

        if ( '' === $route ) {
            return false;
        }

        foreach ( (array) $rules as $rule ) {
            $rule = self::normalize_rest_route_prefix( $rule );

            if ( '' === $rule ) {
                continue;
            }

            if ( untrailingslashit( $route ) === untrailingslashit( $rule ) ) {
                return true;
            }

            if ( 0 === strpos( trailingslashit( $route ), trailingslashit( $rule ) ) ) {
                return true;
            }
        }

        return false;
    }

    private static function record_rest_guard_event( $action_type, $route, $method, $settings, $extra = '' ) {
        $route = self::normalize_rest_route_prefix( $route );

        if ( '' === $route ) {
            return;
        }

        $method        = strtoupper( sanitize_text_field( (string) $method ) );
        $ip            = QS_Audit::get_real_ip( $settings );
        $transient_ttl = (int) apply_filters( 'qs_rest_guard_event_ttl', 600, $action_type, $route, $method, $settings );
        $transient_key = 'qs_rest_guard_' . md5( $action_type . '|' . $route . '|' . $method . '|' . $ip );

        if ( $transient_ttl > 0 && get_transient( $transient_key ) ) {
            return;
        }

        if ( $transient_ttl > 0 ) {
            set_transient( $transient_key, 1, $transient_ttl );
        }

        $detail = '游客访问 REST 路由 [' . $route . ']；方法 [' . $method . ']';

        if ( '' !== $extra ) {
            $detail .= '；' . sanitize_text_field( (string) $extra );
        }

        QS_Audit::record_event(
            $action_type,
            $detail,
            [
                'ip' => $ip,
            ]
        );
    }

    private static function handle_rest_api_guard( $result, $server, $request, $settings ) {
        if ( $result instanceof WP_Error || is_user_logged_in() || QS_Audit::is_current_request_trusted( $settings ) ) {
            return $result;
        }

        if ( ! is_object( $request ) || ! method_exists( $request, 'get_route' ) ) {
            return $result;
        }

        $route = self::normalize_rest_route_prefix( $request->get_route() );

        if ( '' === $route ) {
            return $result;
        }

        $method           = method_exists( $request, 'get_method' ) ? strtoupper( (string) $request->get_method() ) : 'GET';
        $guard_mode       = self::get_rest_api_guard_mode( $settings );
        $blocked_prefixes = self::get_rest_api_public_block_prefixes( $settings );

        if ( self::route_matches_prefix_rules( $route, $blocked_prefixes ) ) {
            self::record_rest_guard_event( 'REST 敏感路由命中', $route, $method, $settings, '命中敏感公开路由规则。' );

            if ( 'block' === $guard_mode ) {
                return new WP_Error(
                    'qs_rest_guard_blocked',
                    '启灵安全防护：当前游客访问的 REST 路由属于敏感接口，已被策略拦截。',
                    [ 'status' => 403 ]
                );
            }

            return $result;
        }

        if ( empty( $settings['rest_api_observe_unknown_public'] ) || ! in_array( $method, [ 'GET', 'HEAD' ], true ) ) {
            return $result;
        }

        $allowed_prefixes = self::get_rest_api_public_allow_prefixes( $settings );

        if ( self::route_matches_prefix_rules( $route, $allowed_prefixes ) ) {
            return $result;
        }

        self::record_rest_guard_event( 'REST 未知路由访问', $route, $method, $settings, '该路由不在允许公开前缀名单中，建议确认是否确需对游客开放。' );

        return $result;
    }

    private static function record_upload_block_event( $action_type, $filename, $detail = '' ) {
        $message = '文件 [' . sanitize_file_name( (string) $filename ) . '] 上传被拦截。';

        if ( '' !== $detail ) {
            $message .= ' ' . sanitize_text_field( (string) $detail );
        }

        QS_Audit::record_event( $action_type, $message );
    }

    public static function init() {
        $settings = self::get_settings();

        // 优先修复全局 REMOTE_ADDR，确保 WP 核心会话、评论等逻辑与插件识别的真实 IP 一致
        $_SERVER['REMOTE_ADDR'] = QS_Audit::get_real_ip( $settings );

        $current_ip = $_SERVER['REMOTE_ADDR'];
        if ( QS_DB::is_ip_banned( $current_ip ) ) {
            header( 'HTTP/1.1 403 Forbidden' );
            die( 'Access Denied: Your IP [' . esc_html( $current_ip ) . '] has been locked by Qiling Security Firewall due to malicious activity.' );
        }

        if ( ! empty( $settings['disable_xmlrpc'] ) ) {
            add_filter( 'xmlrpc_enabled', '__return_false' );
            add_filter( 'pings_open', '__return_false' );
        }

        if ( ! empty( $settings['hide_wp_version'] ) ) {
            remove_action( 'wp_head', 'wp_generator' );
            add_filter( 'the_generator', '__return_empty_string' );
        }

        if ( ! empty( $settings['block_user_enum'] ) ) {
            add_filter(
                'rest_endpoints',
                function( $endpoints ) {
                    if ( isset( $endpoints['/wp/v2/users'] ) && ! current_user_can( 'list_users' ) ) {
                        unset( $endpoints['/wp/v2/users'] );
                    }

                    if ( isset( $endpoints['/wp/v2/users/(?P<id>[\d]+)'] ) && ! current_user_can( 'list_users' ) ) {
                        unset( $endpoints['/wp/v2/users/(?P<id>[\d]+)'] );
                    }

                    return $endpoints;
                }
            );

            add_filter(
                'rest_pre_dispatch',
                function( $result, $server, $request ) {
                    if ( $result instanceof WP_Error || current_user_can( 'list_users' ) ) {
                        return $result;
                    }

                    if ( ! is_object( $request ) || ! method_exists( $request, 'get_route' ) ) {
                        return $result;
                    }

                    $route = self::normalize_rest_route_prefix( $request->get_route() );

                    if ( 0 === strpos( $route, '/wp/v2/users' ) ) {
                        return new WP_Error(
                            'qs_user_enum_blocked',
                            '启灵安全防护：当前接口不对游客开放。',
                            [ 'status' => 403 ]
                        );
                    }

                    return $result;
                },
                4,
                3
            );

            add_filter(
                'wp_sitemaps_add_provider',
                function( $provider, $name ) {
                    if ( 'users' === (string) $name && ! current_user_can( 'list_users' ) ) {
                        return false;
                    }

                    return $provider;
                },
                10,
                2
            );

            if ( ! is_admin() && isset( $_REQUEST['author'] ) ) {
                wp_die( 'User enumeration is blocked by Qiling Security.', 'Forbidden', [ 'response' => 403 ] );
            }
        }

        if ( ! empty( $settings['enable_rest_api_guard'] ) ) {
            add_filter(
                'rest_pre_dispatch',
                function( $result, $server, $request ) use ( $settings ) {
                    return self::handle_rest_api_guard( $result, $server, $request, $settings );
                },
                5,
                3
            );
        }

        if ( ! empty( $settings['disable_file_editor'] ) && ! defined( 'DISALLOW_FILE_EDIT' ) ) {
            add_filter(
                'map_meta_cap',
                function( $caps, $cap ) {
                    if ( in_array( $cap, [ 'edit_files', 'edit_plugins', 'edit_themes' ], true ) ) {
                        return [ 'do_not_allow' ];
                    }

                    return $caps;
                },
                10,
                2
            );
        }

        if ( ! empty( $settings['disable_app_passwords'] ) ) {
            add_filter( 'wp_is_application_passwords_available', '__return_false' );
            add_filter( 'wp_is_application_passwords_available_for_user', '__return_false' );
        }

        if ( ! empty( $settings['disable_emoji'] ) ) {
            remove_action( 'wp_head', 'print_emoji_detection_script', 7 );
            remove_action( 'admin_print_scripts', 'print_emoji_detection_script' );
            remove_action( 'wp_print_styles', 'print_emoji_styles' );
            remove_action( 'admin_print_styles', 'print_emoji_styles' );
            remove_filter( 'the_content_feed', 'wp_staticize_emoji' );
            remove_filter( 'comment_text_rss', 'wp_staticize_emoji' );
            remove_filter( 'wp_mail', 'wp_staticize_emoji_for_email' );

            add_filter(
                'tiny_mce_plugins',
                function( $plugins ) {
                    return is_array( $plugins ) ? array_diff( $plugins, [ 'wpemoji' ] ) : [];
                }
            );

            add_filter(
                'wp_resource_hints',
                function( $urls, $relation_type ) {
                    if ( 'dns-prefetch' !== $relation_type || ! is_array( $urls ) ) {
                        return $urls;
                    }

                    return array_values(
                        array_filter(
                            $urls,
                            function( $url ) {
                                return false === strpos( (string) $url, 'https://s.w.org/images/core/emoji/' );
                            }
                        )
                    );
                },
                10,
                2
            );
        }

        if ( ! empty( $settings['disable_embeds'] ) ) {
            remove_action( 'rest_api_init', 'wp_oembed_register_route' );
            remove_filter( 'oembed_dataparse', 'wp_filter_oembed_result', 10 );
            remove_action( 'wp_head', 'wp_oembed_add_discovery_links' );
            remove_action( 'wp_head', 'wp_oembed_add_host_js' );
            add_filter( 'embed_oembed_discover', '__return_false' );
            add_filter(
                'rewrite_rules_array',
                function( $rules ) {
                    if ( ! is_array( $rules ) ) {
                        return $rules;
                    }

                    foreach ( $rules as $rule => $rewrite ) {
                        if ( false !== strpos( (string) $rewrite, 'embed=true' ) ) {
                            unset( $rules[ $rule ] );
                        }
                    }

                    return $rules;
                }
            );
        }

        if ( ! empty( $settings['remove_shortlink'] ) ) {
            remove_action( 'wp_head', 'wp_shortlink_wp_head', 10, 0 );
            remove_action( 'template_redirect', 'wp_shortlink_header', 11 );
        }

        if ( ! empty( $settings['remove_rsd_wlw'] ) ) {
            remove_action( 'wp_head', 'rsd_link' );
            remove_action( 'wp_head', 'wlwmanifest_link' );
        }

        if ( ! empty( $settings['clean_meta_tags'] ) ) {
            remove_action( 'wp_head', 'rsd_link' );
            remove_action( 'wp_head', 'wlwmanifest_link' );
            remove_action( 'wp_head', 'wp_shortlink_wp_head', 10, 0 );
            remove_action( 'wp_head', 'rest_output_link_wp_head', 10 );
            remove_action( 'wp_head', 'wp_oembed_add_discovery_links', 10 );
        }

        if ( ! empty( $settings['waf_core'] ) ) {
            add_action(
                'init',
                function() use ( $settings ) {
                    if ( QS_Audit::is_current_request_trusted( $settings ) ) {
                        return;
                    }

                    if ( is_user_logged_in() && current_user_can( 'edit_posts' ) ) {
                        return;
                    }

                    $waf_rules      = self::get_waf_rules( $settings );
                    $request_scopes = [
                        'get'    => $_GET,
                        'post'   => $_POST,
                        'cookie' => $_COOKIE,
                    ];

                    foreach ( $request_scopes as $scope => $superglobal ) {
                        foreach ( self::flatten_request_values( $superglobal ) as $value ) {
                            $lower_val = strtolower( $value );

                            foreach ( $waf_rules as $rule ) {
                                if ( empty( $rule['needle'] ) || empty( $rule['scopes'] ) || ! in_array( $scope, (array) $rule['scopes'], true ) ) {
                                    continue;
                                }

                                if ( false === strpos( $lower_val, strtolower( (string) $rule['needle'] ) ) ) {
                                    continue;
                                }

                                $ip          = QS_Audit::get_real_ip();
                                $ban_message = '当前请求已被阻断，但不会自动封禁。';

                                if ( ! empty( $rule['ban'] ) && ! is_user_logged_in() ) {
                                    QS_DB::ban_ip( $ip, '触发高置信度 WAF 规则: ' . $rule['needle'], 24 );
                                    $ban_message = '异常来源 IP 已被临时封禁 24 小时。';
                                }

                                wp_die(
                                    '<h1>安全警告</h1><p>启灵安全防火墙已拦截可疑请求。</p><p>特征命中：<code>' . esc_html( $rule['needle'] ) . '</code></p><p>' . esc_html( $ban_message ) . '</p>',
                                    'WAF Intercepted',
                                    [ 'response' => 403 ]
                                );
                            }
                        }
                    }
                },
                1
            );
        }

        if ( ! empty( $settings['block_bad_uploads'] ) || ! empty( $settings['strict_upload_validation'] ) || ! empty( $settings['block_svg_uploads'] ) ) {
            add_filter(
                'wp_handle_upload_prefilter',
                function( $file ) use ( $settings ) {
                    return self::filter_upload_prefilter( $file, $settings );
                }
            );

            add_filter(
                'wp_handle_sideload_prefilter',
                function( $file ) use ( $settings ) {
                    return self::filter_upload_prefilter( $file, $settings );
                }
            );
        }

        if ( ! empty( $settings['block_bad_scanners'] ) ) {
            add_action(
                'init',
                function() use ( $settings ) {
                    if ( QS_Audit::is_current_request_trusted( $settings ) ) {
                        return;
                    }

                    $ua       = isset( $_SERVER['HTTP_USER_AGENT'] ) ? strtolower( (string) wp_unslash( $_SERVER['HTTP_USER_AGENT'] ) ) : '';
                    $bad_bots = self::get_bad_bot_signatures( $settings );

                    if ( '' === $ua ) {
                        return;
                    }

                    foreach ( $bad_bots as $bot ) {
                        if ( '' !== $bot && false !== strpos( $ua, strtolower( $bot ) ) ) {
                            wp_die( '启灵安全黑名单防护：拒绝自动化漏洞扫描器和恶意机器爬虫的异常请求。', 'Access Denied', [ 'response' => 403 ] );
                        }
                    }
                },
                1
            );
        }

        if ( ! empty( $settings['add_security_headers'] ) ) {
            add_action(
                'send_headers',
                function() use ( $settings ) {
                    if ( headers_sent() ) {
                        return;
                    }

                    foreach ( self::get_security_headers( $settings ) as $header_name => $header_value ) {
                        header( $header_name . ': ' . $header_value );
                    }
                }
            );
        }

        if ( ! empty( $settings['disable_pingback'] ) ) {
            add_filter(
                'xmlrpc_methods',
                function( $methods ) {
                    unset( $methods['pingback.ping'] );
                    unset( $methods['pingback.extensions.getPingbacks'] );
                    return $methods;
                }
            );

            add_filter(
                'wp_headers',
                function( $headers ) {
                    unset( $headers['X-Pingback'] );
                    return $headers;
                }
            );
        }

        if ( ! empty( $settings['admin_disable_remote_block_patterns'] ) ) {
            add_filter( 'should_load_remote_block_patterns', '__return_false' );
        }

        if ( ! empty( $settings['admin_disable_block_directory'] ) ) {
            add_filter( 'block_directory_enabled', '__return_false' );
            add_filter(
                'block_editor_settings_all',
                function( $editor_settings ) {
                    if ( is_array( $editor_settings ) ) {
                        $editor_settings['enableBlockDirectory'] = false;
                    }

                    return $editor_settings;
                },
                20
            );
        }

        if ( ! empty( $settings['admin_disable_openverse'] ) ) {
            add_filter(
                'block_editor_settings_all',
                function( $editor_settings ) {
                    if ( is_array( $editor_settings ) ) {
                        $editor_settings['enableOpenverseMediaCategory'] = false;
                    }

                    return $editor_settings;
                },
                20
            );
        }

        if ( ! empty( $settings['admin_reduce_editor_preload'] ) ) {
            add_filter(
                'block_editor_rest_api_preload_paths',
                function( $preload_paths ) {
                    if ( ! is_array( $preload_paths ) ) {
                        return $preload_paths;
                    }

                    $skip_needles = [
                        '/wp/v2/block-directory/search',
                        '/wp/v2/pattern-directory/patterns',
                    ];
                    $filtered     = [];
                    $seen         = [];

                    foreach ( $preload_paths as $entry ) {
                        $path   = '';
                        $method = 'GET';

                        if ( is_array( $entry ) ) {
                            $path   = isset( $entry[0] ) ? (string) $entry[0] : '';
                            $method = isset( $entry[1] ) ? (string) $entry[1] : 'GET';
                        } elseif ( is_string( $entry ) ) {
                            $path = $entry;
                        }

                        $path = trim( $path );
                        if ( '' === $path ) {
                            continue;
                        }

                        $skip = false;
                        foreach ( $skip_needles as $needle ) {
                            if ( false !== strpos( $path, $needle ) ) {
                                $skip = true;
                                break;
                            }
                        }

                        if ( $skip ) {
                            continue;
                        }

                        $dedupe_key = md5( $method . '|' . $path );
                        if ( isset( $seen[ $dedupe_key ] ) ) {
                            continue;
                        }

                        $seen[ $dedupe_key ] = true;
                        $filtered[]          = $entry;
                    }

                    $preload_limit = (int) apply_filters( 'qs_editor_preload_limit', 0, $filtered, $preload_paths );
                    if ( $preload_limit > 0 && count( $filtered ) > $preload_limit ) {
                        $filtered = array_slice( $filtered, 0, $preload_limit );
                    }

                    return $filtered;
                },
                10
            );
        }

        if ( ! empty( $settings['hide_login_error_details'] ) ) {
            add_filter(
                'login_errors',
                function( $error ) {
                    $error = (string) $error;

                    if ( false !== strpos( $error, '启灵安全拦截' ) ) {
                        return $error;
                    }

                    return '<strong>错误</strong>：用户名或密码错误，请重试。';
                },
                999
            );
        }

        if ( ! empty( $settings['limit_login_attempts'] ) ) {
            $rate_limit = self::get_login_rate_limit_config( $settings );

            add_filter(
                'authenticate',
                function( $user, $username, $password ) use ( $rate_limit ) {
                    if ( empty( $username ) || empty( $password ) ) {
                        return $user;
                    }

                    $ip = QS_Audit::get_real_ip();
                    if ( ! $ip || '0.0.0.0' === $ip ) {
                        return $user;
                    }

                    if ( QS_Audit::is_ip_whitelisted( $ip ) ) {
                        return $user;
                    }

                    if ( QS_DB::is_ip_banned( $ip ) ) {
                        return new WP_Error(
                            'too_many_retries',
                            sprintf(
                                '<strong>启灵安全拦截</strong>：当前来源 IP 已因连续输错密码被临时锁定，请在 %d 小时后再试。',
                                $rate_limit['lockout_hours']
                            )
                        );
                    }

                    return $user;
                },
                30,
                3
            );

            add_action(
                'wp_login_failed',
                function( $username ) use ( $rate_limit ) {
                    $ip = QS_Audit::get_real_ip();
                    if ( ! $ip || '0.0.0.0' === $ip || QS_Audit::is_ip_whitelisted( $ip ) ) {
                        return;
                    }

                    $ban_username   = sanitize_user( (string) $username, true );
                    $ban_username   = '' !== $ban_username ? $ban_username : 'unknown';
                    $transient_name = 'qs_login_fails_' . md5( $ip );
                    $attempts       = (int) get_transient( $transient_name );
                    $attempts++;
                    set_transient( $transient_name, $attempts, HOUR_IN_SECONDS * 24 );

                    if ( $attempts < $rate_limit['max_attempts'] ) {
                        return;
                    }

                    if ( ! QS_DB::is_ip_banned( $ip ) ) {
                        QS_DB::ban_ip( $ip, "密码连续猜测爆破用户: {$ban_username}", $rate_limit['lockout_hours'] );
                    }
                }
            );

            add_action(
                'wp_login',
                function() {
                    $ip = QS_Audit::get_real_ip();
                    if ( $ip && '0.0.0.0' !== $ip ) {
                        $transient_name = 'qs_login_fails_' . md5( $ip );
                        delete_transient( $transient_name );
                    }
                },
                10,
                2
            );
        }

        if ( self::get_max_concurrent_sessions( $settings ) > 0 ) {
            $max_sessions = self::get_max_concurrent_sessions( $settings );

            add_action(
                'wp_login',
                function( $user_login, $user ) use ( $max_sessions ) {
                    $user_id = isset( $user->ID ) ? absint( $user->ID ) : 0;

                    if ( ! $user_id ) {
                        return;
                    }

                    $removed = QS_Session_Manager::enforce_max_sessions( $user_id, $max_sessions, true );

                    if ( $removed <= 0 ) {
                        return;
                    }

                    $safe_login = sanitize_user( (string) $user_login, true );
                    $safe_login = '' !== $safe_login ? $safe_login : ( isset( $user->user_login ) ? sanitize_user( (string) $user->user_login, true ) : 'unknown' );

                    QS_Audit::record_event(
                        '会话并发限制触发',
                        sprintf( '用户 [%s] 登录后超过并发设备上限 %d，已自动下线 %d 个较早会话。', $safe_login, $max_sessions, $removed ),
                        [
                            'user_id'  => $user_id,
                            'username' => $safe_login,
                        ]
                    );
                },
                30,
                2
            );
        }

        if ( ! empty( $settings['custom_login_url'] ) ) {
            $secret_key = self::sanitize_custom_login_key( $settings['custom_login_url'] );

            if ( $secret_key ) {
                add_action(
                    'init',
                    function() use ( $secret_key ) {
                        self::protect_custom_login_url( $secret_key );
                    },
                    0
                );

                add_filter(
                    'login_url',
                    function( $url ) use ( $secret_key ) {
                        return self::append_secret_to_url( $url, $secret_key );
                    },
                    10,
                    3
                );

                add_filter(
                    'lostpassword_url',
                    function( $url ) use ( $secret_key ) {
                        return self::append_secret_to_url( $url, $secret_key );
                    },
                    10,
                    2
                );

                add_filter(
                    'logout_url',
                    function( $url ) use ( $secret_key ) {
                        return self::append_secret_to_url( $url, $secret_key );
                    },
                    10,
                    2
                );

                add_filter(
                    'register_url',
                    function( $url ) use ( $secret_key ) {
                        return self::append_secret_to_url( $url, $secret_key );
                    },
                    10,
                    1
                );

                add_filter(
                    'site_url',
                    function( $url, $path ) use ( $secret_key ) {
                        if ( 0 === strpos( ltrim( (string) $path, '/' ), 'wp-login.php' ) ) {
                            return self::append_secret_to_url( $url, $secret_key );
                        }

                        return $url;
                    },
                    10,
                    4
                );

                add_filter(
                    'network_site_url',
                    function( $url, $path ) use ( $secret_key ) {
                        if ( 0 === strpos( ltrim( (string) $path, '/' ), 'wp-login.php' ) ) {
                            return self::append_secret_to_url( $url, $secret_key );
                        }

                        return $url;
                    },
                    10,
                    3
                );
            }
        }
    }
}
