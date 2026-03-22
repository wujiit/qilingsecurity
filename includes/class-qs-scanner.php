<?php
/**
 * 安全防护插件 - 核心扫描引擎
 */
if ( ! defined( 'ABSPATH' ) ) {
    exit;
}

class QS_Scanner {

    const CHUNKED_STEP_STATE_VERSION = 1;

    public static function get_scan_steps() {
        $steps = [
            [
                'id'              => 'sensitive_files',
                'name'            => '全盘敏感文件扫描',
                'method'          => 'scan_sensitive_files',
                'success_message' => '敏感文件扫描完成',
            ],
            [
                'id'              => 'uploads_webshell',
                'name'            => 'Uploads 目录后门查杀',
                'method'          => 'scan_uploads_webshell',
                'success_message' => '木马后门扫描完成',
            ],
            [
                'id'              => 'code_vulnerability',
                'name'            => '主题/插件代码安全审计',
                'method'          => 'scan_code_vulnerabilities',
                'success_message' => '代码漏洞审计完成',
            ],
            [
                'id'              => 'component_vulnerabilities',
                'name'            => '插件/主题已知漏洞情报比对',
                'method'          => 'scan_component_vulnerabilities',
                'success_message' => '已知漏洞情报比对完成',
            ],
            [
                'id'              => 'admin_accounts',
                'name'            => '异常管理员账号与权限审计',
                'method'          => 'scan_admin_accounts',
                'success_message' => '管理员账号与权限审计完成',
            ],
            [
                'id'              => 'persistence_vectors',
                'name'            => '异常 Cron / MU 插件 / Drop-in 持久化扫描',
                'method'          => 'scan_persistence_vectors',
                'success_message' => '持久化驻留点扫描完成',
            ],
            [
                'id'              => 'database_risks',
                'name'            => '数据库风险与异常 Option 扫描',
                'method'          => 'scan_database_risks',
                'success_message' => '数据库风险扫描完成',
            ],
            [
                'id'              => 'permissions',
                'name'            => '网站核心目录及权限检测',
                'method'          => 'scan_permissions_and_hardening',
                'success_message' => '系统加固检查完成',
            ],
            [
                'id'              => 'api_exposure',
                'name'            => '公网敏感 API 暴露探测',
                'method'          => 'scan_api_exposure',
                'success_message' => 'API 暴露检测完成',
            ],
            [
                'id'              => 'dark_links',
                'name'            => '全站暗链与防挂马深度查杀',
                'method'          => 'scan_dark_links',
                'success_message' => '暗链与前端挂马筛查完成',
            ],
            [
                'id'              => 'file_integrity_baseline',
                'name'            => '主题/插件/上传目录变更基线比对',
                'method'          => 'scan_file_integrity_baseline',
                'success_message' => '文件基线比对完成',
            ],
            [
                'id'              => 'core_integrity',
                'name'            => '核心文件完整性校验',
                'method'          => 'scan_core_integrity',
                'success_message' => '核心文件完整性校验完成',
            ],
        ];

        return apply_filters( 'qs_scan_steps', $steps );
    }

    public function execute_scan_step( $step_id, $method, $scan_id, $state = [] ) {
        $step_id = sanitize_key( (string) $step_id );
        $method  = sanitize_text_field( (string) $method );
        $state   = is_array( $state ) ? $state : [];

        if ( $this->is_chunked_scan_step( $step_id ) ) {
            return $this->execute_chunked_scan_step( $step_id, $scan_id, $state );
        }

        if ( '' === $method || ! method_exists( $this, $method ) ) {
            return [
                'error' => '无效的扫描步骤方法。',
            ];
        }

        $results = $this->$method( $scan_id );
        $results = array_values( array_filter( (array) $results ) );

        return [
            'done'     => true,
            'state'    => [],
            'results'  => $results,
            'count'    => count( $results ),
            'progress' => [
                'scanned'   => 0,
                'matches'   => count( $results ),
                'truncated' => false,
                'label'     => $this->get_scan_step_progress_label( $step_id ),
            ],
        ];
    }

    private function is_chunked_scan_step( $step_id ) {
        return in_array( sanitize_key( (string) $step_id ), [ 'sensitive_files', 'uploads_webshell', 'code_vulnerability', 'dark_links' ], true );
    }

    private function execute_chunked_scan_step( $step_id, $scan_id, $state ) {
        switch ( $step_id ) {
            case 'sensitive_files':
                return $this->scan_sensitive_files_chunk( $scan_id, $state );
            case 'uploads_webshell':
                return $this->scan_uploads_webshell_chunk( $scan_id, $state );
            case 'code_vulnerability':
                return $this->scan_code_vulnerabilities_chunk( $scan_id, $state );
            case 'dark_links':
                return $this->scan_dark_links_chunk( $scan_id, $state );
            default:
                return [
                    'error' => '未知的分片扫描步骤。',
                ];
        }
    }

    private function scan_sensitive_files_chunk( $scan_id, $state ) {
        $root_path  = ABSPATH;
        $extensions = $this->get_sensitive_extensions();
        $excludes   = apply_filters( 'qs_sensitive_file_name_excludes', [ 'readme.txt', 'license.txt', 'robots.txt' ] );

        return $this->run_chunked_directory_step(
            $state,
            [ $root_path ],
            function( $item ) use ( $root_path, $extensions, $excludes, $scan_id ) {
                $matches = [];
                $control = [];

                if ( $item->isFile() ) {
                    $ext      = strtolower( $item->getExtension() );
                    $filename = strtolower( $item->getFilename() );

                    if ( in_array( $ext, $extensions, true ) && ! in_array( $filename, $excludes, true ) ) {
                        $rel_path = str_replace( '\\', '/', str_replace( $root_path, '', $item->getPathname() ) );

                        if ( in_array( $ext, [ 'log', 'sql' ], true ) ) {
                            QS_DB::insert_result(
                                $scan_id,
                                'SENSITIVE_FILE_CRITICAL',
                                $rel_path,
                                'critical',
                                "发现高度敏感的文件泄露 ({$filename})，黑客可直接通过浏览器下载！这会导致订单、密码等核心数据被脱裤。",
                                '请立即通过 FTP 彻底删除此文件！如果是项目必需的运行日志（如 debug.log），请将其移动到网站根目录之外，或者在宝塔/Nginx 配置中严格拦截对 .log 和 .sql 后缀文件的 HTTP 访问。'
                            );
                        } else {
                            QS_DB::insert_result(
                                $scan_id,
                                'SENSITIVE_FILE',
                                $rel_path,
                                'warning',
                                "发现敏感文件后缀 (.{$ext})，可能暴露备份或配置数据。",
                                '建议立即将此文件通过 FTP 删除，或将其移动至无法通过 HTTP 公网访问的安全目录（如 /home/ 或根目录之外）。'
                            );
                        }

                        $matches[] = $rel_path;
                    }
                }

                if ( $item->isDir() && '.git' === $item->getFilename() ) {
                    $rel_path = str_replace( '\\', '/', str_replace( $root_path, '', $item->getPathname() ) );
                    QS_DB::insert_result(
                        $scan_id,
                        'GIT_EXPOSURE',
                        $rel_path,
                        'critical',
                        '发现 .git 版本控制目录，极易导致全站源码与敏感配置泄露！',
                        '强烈建议立即删除线上的 .git 隐藏目录，或配置 Nginx/Apache 规则彻底屏蔽对 /.git/ 目录的外部访问。'
                    );
                    $matches[] = $rel_path;
                    $control['skip_children'] = true;
                }

                if ( ! empty( $matches ) ) {
                    $control['matches'] = $matches;
                }

                return $control;
            },
            [ '/wp-admin', '/wp-includes' ],
            '已扫描 %d 项，命中 %d 个敏感对象'
        );
    }

    private function scan_uploads_webshell_chunk( $scan_id, $state ) {
        $uploads              = wp_upload_dir();
        $uploads_dir          = isset( $uploads['basedir'] ) ? (string) $uploads['basedir'] : '';
        $max_scan_bytes       = $this->get_image_scan_max_bytes();
        $settings             = $this->get_scanner_settings();
        $dangerous_extensions = QS_Protection::get_upload_disallowed_extensions( $settings );
        $mime_ignored_exts    = QS_Protection::get_upload_mime_ignored_extensions( $settings );

        if ( '' === $uploads_dir || ! is_dir( $uploads_dir ) ) {
            return [
                'done'     => true,
                'state'    => [],
                'results'  => [],
                'count'    => 0,
                'progress' => [
                    'scanned'   => 0,
                    'matches'   => 0,
                    'truncated' => false,
                    'label'     => $this->get_scan_step_progress_label( 'uploads_webshell' ),
                ],
            ];
        }

        return $this->run_chunked_directory_step(
            $state,
            [ $uploads_dir ],
            function( $item ) use ( $scan_id, $max_scan_bytes, $dangerous_extensions, $mime_ignored_exts ) {
                if ( ! $item->isFile() ) {
                    return [];
                }

                $matches  = [];
                $filename = strtolower( $item->getFilename() );
                $ext      = strtolower( $item->getExtension() );
                $rel_path = str_replace( '\\', '/', str_replace( ABSPATH, '', $item->getPathname() ) );

                if ( in_array( $ext, $dangerous_extensions, true ) ) {
                    QS_DB::insert_result(
                        $scan_id,
                        'WEBSHELL_FILE',
                        $rel_path,
                        'critical',
                        'Uploads 上传目录中发现了危险可执行后缀文件，极大概率是绕过上传限制后留下的后门或恶意载荷！',
                        '请立即核查该文件是否为您主动上传；如果无法确认来源，请优先隔离或删除，并同时检查媒体上传权限和上传拦截规则是否已开启。'
                    );
                    $matches[] = $rel_path;

                    return [
                        'matches' => $matches,
                    ];
                }

                if ( $this->filename_contains_dangerous_double_extension( $filename, $dangerous_extensions ) ) {
                    QS_DB::insert_result(
                        $scan_id,
                        'WEBSHELL_DOUBLE_EXT',
                        $rel_path,
                        'critical',
                        '文件包含双重后缀 (如 .php.jpg)，可能被用于绕过上传限制造成解析漏洞。',
                        '此类文件极度可疑，建议立即删除，并通知技术排查是否有攻击者正在尝试上传绕过。'
                    );
                    $matches[] = $rel_path;
                }

                if ( in_array( $ext, [ 'jpg', 'jpeg', 'png', 'gif' ], true ) && $item->getSize() < $max_scan_bytes ) {
                    $content = $this->read_file_excerpt( $item->getPathname(), $max_scan_bytes );
                    if ( '' !== $content && $this->contains_any_case_insensitive( $content, [ 'eval', 'assert', 'base64_decode', 'system', 'exec', 'shell_exec', 'phpinfo' ] ) && preg_match( '/(eval|assert|base64_decode|system|exec|shell_exec|phpinfo)\s*\(/i', $content ) ) {
                        QS_DB::insert_result(
                            $scan_id,
                            'WEBSHELL_CONTENT',
                            $rel_path,
                            'critical',
                            '图片文件内部疑似被注入了木马执行代码 (如 eval, system)！',
                            '这绝对是恶意文件！攻击者将 PHP 恶意代码嵌入了图片中。请立即删除此图片，并排查服务器是否存在本地文件包含漏洞 (LFI)。'
                        );
                        $matches[] = $rel_path;
                    }
                }

                $upload_type_issue = $this->inspect_existing_upload_file( $item->getPathname(), $filename, $ext, $mime_ignored_exts );

                if ( ! empty( $upload_type_issue['issue_type'] ) ) {
                    QS_DB::insert_result(
                        $scan_id,
                        $upload_type_issue['issue_type'],
                        $rel_path,
                        $upload_type_issue['severity'],
                        $upload_type_issue['detail'],
                        $upload_type_issue['advice']
                    );
                    $matches[] = $rel_path;
                }

                return [
                    'matches' => $matches,
                ];
            },
            [],
            '已扫描 %d 个上传目录对象，命中 %d 个风险文件'
        );
    }

    private function scan_code_vulnerabilities_chunk( $scan_id, $state ) {
        $scan_dirs      = [ WP_CONTENT_DIR . '/themes', WP_CONTENT_DIR . '/plugins' ];
        $max_scan_bytes = $this->get_code_scan_max_bytes();
        $vulns          = $this->get_code_vulnerability_patterns();

        return $this->run_chunked_directory_step(
            $state,
            $scan_dirs,
            function( $item ) use ( $vulns, $scan_id, $max_scan_bytes ) {
                if ( ! $item->isFile() || 'php' !== strtolower( $item->getExtension() ) || 'index.php' === strtolower( $item->getFilename() ) ) {
                    return [];
                }

                $content = $this->read_file_excerpt( $item->getPathname(), $max_scan_bytes );
                if ( '' === $content || ! $this->contains_code_risk_hint( $content ) ) {
                    return [];
                }

                $rel_path = $this->get_relative_site_path( $item->getPathname() );
                if ( '' === $rel_path ) {
                    return [];
                }

                foreach ( $vulns as $type => $regex ) {
                    if ( '' !== $regex && 1 === @preg_match( $regex, $content ) ) {
                        QS_DB::insert_result(
                            $scan_id,
                            'CODE_VULN_' . $type,
                            $rel_path,
                            'warning',
                            "审计到疑似危险函数调用 ({$type})，可能存在漏洞闭环，请联系开发者核查。",
                            '由于这是静态代码特征匹配，可能存在误报。请您将此提示截图发给主题或插件作者二次确认；如果插件常年未更新且并非必须使用，建议停用。'
                        );

                        return [
                            'matches' => [ $rel_path ],
                        ];
                    }
                }

                return [];
            },
            [],
            '已审计 %d 个代码对象，命中 %d 个可疑文件'
        );
    }

    private function scan_dark_links_chunk( $scan_id, $state ) {
        $state          = is_array( $state ) ? $state : [];
        $state['phase'] = isset( $state['phase'] ) ? sanitize_key( (string) $state['phase'] ) : 'database';
        $results        = [];

        if ( 'database' === $state['phase'] ) {
            $results         = $this->scan_dark_links_database_phase( $scan_id );
            $state['phase']  = 'filesystem';
            $state['walker'] = [];

            if ( ! empty( $results ) ) {
                $state['match_total'] = isset( $state['match_total'] ) ? (int) $state['match_total'] + count( $results ) : count( $results );
            }
        }

        $theme_dir = get_stylesheet_directory();

        if ( ! is_dir( $theme_dir ) ) {
            return [
                'done'     => true,
                'state'    => [],
                'results'  => $results,
                'count'    => count( $results ),
                'progress' => [
                    'scanned'   => 0,
                    'matches'   => isset( $state['match_total'] ) ? (int) $state['match_total'] : count( $results ),
                    'truncated' => false,
                    'label'     => $this->get_scan_step_progress_label( 'dark_links' ),
                ],
            ];
        }

        $max_scan_bytes = $this->get_code_scan_max_bytes();
        $chunk_state    = isset( $state['walker'] ) && is_array( $state['walker'] ) ? $state['walker'] : [];
        if ( ! isset( $chunk_state['match_total'] ) && isset( $state['match_total'] ) ) {
            $chunk_state['match_total'] = (int) $state['match_total'];
        }
        $chunk_result   = $this->run_chunked_directory_step(
            $chunk_state,
            [ $theme_dir ],
            function( $item ) use ( $scan_id, $max_scan_bytes ) {
                if ( ! $item->isFile() || 'js' !== strtolower( $item->getExtension() ) ) {
                    return [];
                }

                $content = $this->read_file_excerpt( $item->getPathname(), $max_scan_bytes );
                if ( '' === $content || ! $this->contains_any_case_insensitive( $content, [ '\\x', 'String.fromCharCode', 'document.write', '<script', 'eval' ] ) ) {
                    return [];
                }

                $is_malicious = false;
                $detail_msg   = '';

                if ( preg_match( '/(\\\\x[0-9a-fA-F]{2}){10,}/', $content ) ) {
                    $is_malicious = true;
                    $detail_msg   = '包含高密度的十六进制混淆代码 (Hex Obfuscation)。';
                } elseif ( preg_match( '/String\.fromCharCode\s*\([^)]+\)/i', $content ) && preg_match( '/(eval|document\.write)/i', $content ) ) {
                    $is_malicious = true;
                    $detail_msg   = '包含 String.fromCharCode 编码配合执行语句，是典型的反溯源挂马特征。';
                } elseif ( preg_match( '/document\.write\s*\(\s*[\'"]<script\s+src=[\'"]https?:\/\/(?!' . preg_quote( parse_url( site_url(), PHP_URL_HOST ), '/' ) . ')/i', $content ) ) {
                    $is_malicious = true;
                    $detail_msg   = '包含直接通过 document.write 跨域调用外部隐蔽脚本的指令。';
                }

                if ( ! $is_malicious ) {
                    return [];
                }

                $rel_path = $this->get_relative_site_path( $item->getPathname() );
                if ( '' === $rel_path ) {
                    return [];
                }

                QS_DB::insert_result(
                    $scan_id,
                    'MALICIOUS_JS',
                    $rel_path,
                    'critical',
                    "前端 JavaScript 核心文件中发现了疑似被篡改的网页挂马跳转脚本！\n{$detail_msg}",
                    '这会导致您的客户访问网站时被暗中跳转到博彩、色情等恶意网站，或者弹出广告。请立即通过 FTP 覆盖还原该文件，如果无法还原，请暂时更名该 js 禁用它。'
                );

                return [
                    'matches' => [ $rel_path ],
                ];
            },
            [],
            '已检查 %d 个主题前端对象，命中 %d 个暗链/挂马风险'
        );

        $state['walker']         = isset( $chunk_result['state'] ) ? (array) $chunk_result['state'] : [];
        $state['match_total']    = isset( $chunk_result['progress']['matches'] ) ? (int) $chunk_result['progress']['matches'] : ( isset( $state['match_total'] ) ? (int) $state['match_total'] : 0 );
        $chunk_result['results'] = array_values( array_merge( $results, isset( $chunk_result['results'] ) ? (array) $chunk_result['results'] : [] ) );
        $chunk_result['count']   = count( $chunk_result['results'] );

        if ( ! empty( $chunk_result['done'] ) ) {
            $chunk_result['state'] = [];
            return $chunk_result;
        }

        $chunk_result['state'] = $state;

        return $chunk_result;
    }

    /**
     * 第一步：扫描敏感文件
     */
    public function scan_sensitive_files( $scan_id ) {
        $root_path  = ABSPATH;
        $extensions = $this->get_sensitive_extensions();
        $excludes   = apply_filters( 'qs_sensitive_file_name_excludes', [ 'readme.txt', 'license.txt', 'robots.txt' ] );
        $results    = [];

        $this->scan_directory_recursively(
            $root_path,
            function( $item ) use ( $root_path, $extensions, $excludes, &$results, $scan_id ) {
                if ( $item->isFile() ) {
                    $ext      = strtolower( $item->getExtension() );
                    $filename = strtolower( $item->getFilename() );

                    if ( in_array( $ext, $extensions, true ) && ! in_array( $filename, $excludes, true ) ) {
                        $rel_path = str_replace( '\\', '/', str_replace( $root_path, '', $item->getPathname() ) );

                        if ( in_array( $ext, [ 'log', 'sql' ], true ) ) {
                            QS_DB::insert_result(
                                $scan_id,
                                'SENSITIVE_FILE_CRITICAL',
                                $rel_path,
                                'critical',
                                "发现高度敏感的文件泄露 ({$filename})，黑客可直接通过浏览器下载！这会导致订单、密码等核心数据被脱裤。",
                                '请立即通过 FTP 彻底删除此文件！如果是项目必需的运行日志（如 debug.log），请将其移动到网站根目录之外，或者在宝塔/Nginx 配置中严格拦截对 .log 和 .sql 后缀文件的 HTTP 访问。'
                            );
                        } else {
                            QS_DB::insert_result(
                                $scan_id,
                                'SENSITIVE_FILE',
                                $rel_path,
                                'warning',
                                "发现敏感文件后缀 (.{$ext})，可能暴露备份或配置数据。",
                                '建议立即将此文件通过 FTP 删除，或将其移动至无法通过 HTTP 公网访问的安全目录（如 /home/ 或根目录之外）。'
                            );
                        }

                        $results[] = $rel_path;
                    }
                }

                if ( $item->isDir() && '.git' === $item->getFilename() ) {
                    $rel_path = str_replace( '\\', '/', str_replace( $root_path, '', $item->getPathname() ) );
                    QS_DB::insert_result(
                        $scan_id,
                        'GIT_EXPOSURE',
                        $rel_path,
                        'critical',
                        '发现 .git 版本控制目录，极易导致全站源码与敏感配置泄露！',
                        '强烈建议立即删除线上的 .git 隐藏目录，或配置 Nginx/Apache 规则彻底屏蔽对 /.git/ 目录的外部访问。'
                    );
                    $results[] = $rel_path;
                }
            },
            [ '/wp-admin', '/wp-includes' ]
        );

        return $results;
    }

    /**
     * 第二步：Uploads 目录下 Webshell 和可疑 PHP 扫描
     */
    public function scan_uploads_webshell( $scan_id ) {
        $uploads              = wp_upload_dir();
        $uploads_dir          = $uploads['basedir'];
        $max_scan_bytes       = $this->get_image_scan_max_bytes();
        $settings             = $this->get_scanner_settings();
        $dangerous_extensions = QS_Protection::get_upload_disallowed_extensions( $settings );
        $mime_ignored_exts    = QS_Protection::get_upload_mime_ignored_extensions( $settings );
        $results              = [];

        if ( ! is_dir( $uploads_dir ) ) {
            return $results;
        }

        $this->scan_directory_recursively(
            $uploads_dir,
            function( $item ) use ( &$results, $scan_id, $max_scan_bytes, $dangerous_extensions, $mime_ignored_exts ) {
                if ( ! $item->isFile() ) {
                    return;
                }

                $filename = strtolower( $item->getFilename() );
                $ext      = strtolower( $item->getExtension() );
                $rel_path = str_replace( '\\', '/', str_replace( ABSPATH, '', $item->getPathname() ) );

                if ( in_array( $ext, $dangerous_extensions, true ) ) {
                    QS_DB::insert_result(
                        $scan_id,
                        'WEBSHELL_FILE',
                        $rel_path,
                        'critical',
                        'Uploads 上传目录中发现了危险可执行后缀文件，极大概率是绕过上传限制后留下的后门或恶意载荷！',
                        '请立即核查该文件是否为您主动上传；如果无法确认来源，请优先隔离或删除，并同时检查媒体上传权限和上传拦截规则是否已开启。'
                    );
                    $results[] = $rel_path;
                    return;
                }

                if ( $this->filename_contains_dangerous_double_extension( $filename, $dangerous_extensions ) ) {
                    QS_DB::insert_result(
                        $scan_id,
                        'WEBSHELL_DOUBLE_EXT',
                        $rel_path,
                        'critical',
                        '文件包含双重后缀 (如 .php.jpg)，可能被用于绕过上传限制造成解析漏洞。',
                        '此类文件极度可疑，建议立即删除，并通知技术排查是否有攻击者正在尝试上传绕过。'
                    );
                    $results[] = $rel_path;
                }

                if ( in_array( $ext, [ 'jpg', 'jpeg', 'png', 'gif' ], true ) && $item->getSize() < $max_scan_bytes ) {
                    $content = @file_get_contents( $item->getPathname() );
                    if ( $content && preg_match( '/(eval|assert|base64_decode|system|exec|shell_exec|phpinfo)\s*\(/i', $content ) ) {
                        QS_DB::insert_result(
                            $scan_id,
                            'WEBSHELL_CONTENT',
                            $rel_path,
                            'critical',
                            '图片文件内部疑似被注入了木马执行代码 (如 eval, system)！',
                            '这绝对是恶意文件！攻击者将 PHP 恶意代码嵌入了图片中。请立即删除此图片，并排查服务器是否存在本地文件包含漏洞 (LFI)。'
                        );
                        $results[] = $rel_path;
                    }
                }

                $upload_type_issue = $this->inspect_existing_upload_file( $item->getPathname(), $filename, $ext, $mime_ignored_exts );

                if ( ! empty( $upload_type_issue['issue_type'] ) ) {
                    QS_DB::insert_result(
                        $scan_id,
                        $upload_type_issue['issue_type'],
                        $rel_path,
                        $upload_type_issue['severity'],
                        $upload_type_issue['detail'],
                        $upload_type_issue['advice']
                    );
                    $results[] = $rel_path;
                }
            }
        );

        return $results;
    }

    /**
     * 第三步：主题 / 插件代码 RCE 漏洞检测
     */
    public function scan_code_vulnerabilities( $scan_id ) {
        $scan_dirs       = [ WP_CONTENT_DIR . '/themes', WP_CONTENT_DIR . '/plugins' ];
        $results         = [];
        $max_scan_bytes  = $this->get_code_scan_max_bytes();
        $vulns           = $this->get_code_vulnerability_patterns();

        foreach ( $scan_dirs as $dir ) {
            if ( ! is_dir( $dir ) ) {
                continue;
            }

            $this->scan_directory_recursively(
                $dir,
                function( $item ) use ( $vulns, &$results, $scan_id, $max_scan_bytes ) {
                    if ( ! $item->isFile() || 'php' !== $item->getExtension() || 'index.php' === $item->getFilename() ) {
                        return;
                    }

                    $content = $this->read_file_excerpt( $item->getPathname(), $max_scan_bytes );
                    if ( '' === $content ) {
                        return;
                    }

                    $rel_path = $this->get_relative_site_path( $item->getPathname() );
                    if ( '' === $rel_path ) {
                        return;
                    }

                    foreach ( $vulns as $type => $regex ) {
                        if ( preg_match( $regex, $content ) ) {
                            QS_DB::insert_result(
                                $scan_id,
                                'CODE_VULN_' . $type,
                                $rel_path,
                                'warning',
                                "审计到疑似危险函数调用 ({$type})，可能存在漏洞闭环，请联系开发者核查。",
                                '由于这是静态代码特征匹配，可能存在误报。请您将此提示截图发给主题或插件作者二次确认；如果插件常年未更新且并非必须使用，建议停用。'
                            );
                            $results[] = $rel_path;
                            break;
                        }
                    }
                }
            );
        }

        return $results;
    }

    /**
     * 第四步：插件 / 主题已知漏洞情报比对
     */
    public function scan_component_vulnerabilities( $scan_id ) {
        $feed      = $this->get_component_vulnerability_feed();
        $results   = [];
        $components = array_merge(
            $this->get_installed_plugin_components(),
            $this->get_installed_theme_components()
        );

        if ( empty( $feed ) || empty( $components ) ) {
            return $results;
        }

        foreach ( $components as $component ) {
            $component_type_label = 'plugin' === $component['component_type'] ? '插件' : '主题';
            $component_scope      = ! empty( $component['active'] ) ? '当前正在启用' : '当前未启用';

            foreach ( $feed as $entry ) {
                if ( $entry['component_type'] !== $component['component_type'] || $entry['slug'] !== $component['slug'] ) {
                    continue;
                }

                if ( ! $this->component_version_matches_constraints( $component['version'], $entry['affected_versions'] ) ) {
                    continue;
                }

                $path_label = sprintf( '%s：%s (%s)', $component_type_label, $component['name'], $component['version'] );
                $detail     = sprintf(
                    '%s [%s] %s，命中已知漏洞情报：%s。受影响版本范围：%s。',
                    $component_type_label,
                    $component['name'],
                    $component_scope,
                    $entry['title'],
                    $entry['affected_versions']
                );

                if ( ! empty( $entry['fixed_in'] ) ) {
                    $detail .= sprintf( ' 官方修复版本参考：%s。', $entry['fixed_in'] );
                }

                if ( ! empty( $entry['cve'] ) ) {
                    $detail .= sprintf( ' 漏洞编号：%s。', $entry['cve'] );
                }

                if ( ! empty( $entry['source'] ) ) {
                    $detail .= sprintf( ' 情报来源：%s。', $entry['source'] );
                }

                $advice = ! empty( $entry['fixed_in'] )
                    ? sprintf( '建议尽快将该%s升级到 %s 或更高版本；如暂时无法升级，请先停用并评估是否存在公开利用风险。', $component_type_label, $entry['fixed_in'] )
                    : sprintf( '建议尽快核查该%s是否已有官方更新、临时缓解措施或替代方案；若该组件并非业务必需，可优先停用。', $component_type_label );

                if ( ! empty( $entry['reference'] ) ) {
                    $advice .= ' 参考链接：' . $entry['reference'];
                }

                QS_DB::insert_result(
                    $scan_id,
                    'COMPONENT_VULNERABILITY',
                    $path_label,
                    $entry['severity'],
                    $detail,
                    $advice
                );

                $results[] = $component['component_type'] . ':' . $component['slug'] . ':' . $entry['id'];
            }
        }

        return array_values( array_unique( $results ) );
    }

    /**
     * 第五步：管理员账号与高权限账号审计
     */
    public function scan_admin_accounts( $scan_id ) {
        $settings             = $this->get_scanner_settings();
        $results              = [];
        $admin_users          = get_users( [ 'role' => 'administrator' ] );
        $privileged_threshold = QS_Protection::get_admin_privileged_user_threshold( $settings );
        $weak_username_rules  = QS_Protection::get_admin_weak_usernames( $settings );
        $privileged_caps      = apply_filters(
            'qs_privileged_capabilities',
            [ 'manage_options', 'edit_users', 'install_plugins', 'activate_plugins', 'update_core' ],
            $settings
        );

        if ( count( $admin_users ) > $privileged_threshold ) {
            QS_DB::insert_result(
                $scan_id,
                'ADMIN_COUNT_HIGH',
                '管理员账号数量',
                'warning',
                sprintf( '当前站点存在 %d 个管理员角色账号，已超过预警阈值 %d。管理员账号过多会放大撞库、内部误操作和权限滥用风险。', count( $admin_users ), $privileged_threshold ),
                '请逐个复核这些管理员是否仍在使用、是否属于当前团队成员；不再需要的管理员请及时降权或删除。你也可以在安全插件设置里调整“管理员数量预警阈值”。'
            );
            $results[] = 'administrator_count';
        }

        foreach ( (array) $admin_users as $user ) {
            $login = strtolower( (string) $user->user_login );

            foreach ( $weak_username_rules as $rule ) {
                if ( ! $this->username_matches_rule( $login, $rule ) ) {
                    continue;
                }

                QS_DB::insert_result(
                    $scan_id,
                    'ADMIN_WEAK_USERNAME',
                    '管理员账号：' . $user->user_login,
                    'warning',
                    sprintf( '管理员账号 [%s] 命中了弱用户名规则 [%s]。此类用户名容易被撞库脚本优先尝试。', $user->user_login, $rule ),
                    '建议把该账号降权后新建一个更难枚举的管理员账号，或至少确保此账号使用高强度独立密码，并结合会话管理及时清理异常登录设备。'
                );
                $results[] = $user->user_login;
                break;
            }
        }

        foreach ( get_users() as $user ) {
            if ( ! $this->user_has_any_capability( $user, $privileged_caps ) ) {
                continue;
            }

            if ( in_array( 'administrator', (array) $user->roles, true ) ) {
                continue;
            }

            QS_DB::insert_result(
                $scan_id,
                'PRIVILEGED_CUSTOM_ROLE',
                '高权限账号：' . $user->user_login,
                'warning',
                sprintf( '账号 [%s] 虽然不在 administrator 角色中，但具备高权限能力（如 manage_options / edit_users / install_plugins）。这通常意味着存在自定义高权限角色。', $user->user_login ),
                '请确认这是你主动设计的自定义角色，而不是插件或恶意代码扩权造成的。建议检查该用户的角色定义、最近权限变更记录和对应插件来源。'
            );
            $results[] = $user->user_login;
        }

        return array_values( array_unique( $results ) );
    }

    /**
     * 第六步：Cron / MU 插件 / Drop-in 常驻加载点排查
     */
    public function scan_persistence_vectors( $scan_id ) {
        $settings      = $this->get_scanner_settings();
        $results       = [];
        $ignored_hooks = QS_Protection::get_persistence_scan_ignored_hooks( $settings );
        $seen          = [];

        if ( function_exists( '_get_cron_array' ) ) {
            $cron_array = _get_cron_array();

            foreach ( (array) $cron_array as $timestamp => $hooks ) {
                foreach ( (array) $hooks as $hook => $events ) {
                    foreach ( (array) $events as $signature => $event ) {
                        $analysis = $this->analyze_cron_event( $hook, $event, $ignored_hooks, $settings );

                        if ( empty( $analysis['issue_type'] ) ) {
                            continue;
                        }

                        $dedupe_key = $analysis['issue_type'] . '|' . $hook;

                        if ( isset( $seen[ $dedupe_key ] ) ) {
                            continue;
                        }

                        $seen[ $dedupe_key ] = true;

                        QS_DB::insert_result(
                            $scan_id,
                            $analysis['issue_type'],
                            'Cron Hook：' . $hook,
                            $analysis['severity'],
                            $analysis['detail'],
                            $analysis['advice']
                        );
                        $results[] = 'cron:' . $hook;
                    }
                }
            }
        }

        foreach ( $this->get_mu_plugin_files() as $file_path ) {
            $analysis = $this->analyze_persistence_file( $file_path, 'MU 插件' );

            if ( empty( $analysis['issue_type'] ) ) {
                continue;
            }

            if ( 'MU_PLUGIN_PRESENT' === $analysis['issue_type'] && ! $this->is_mu_plugin_entry_file( $file_path ) ) {
                continue;
            }

            QS_DB::insert_result(
                $scan_id,
                $analysis['issue_type'],
                $this->get_relative_site_path( $file_path ),
                $analysis['severity'],
                $analysis['detail'],
                $analysis['advice']
            );
            $results[] = $file_path;
        }

        foreach ( $this->get_dropin_files() as $dropin_name => $dropin_label ) {
            $file_path = WP_CONTENT_DIR . '/' . $dropin_name;

            if ( ! is_file( $file_path ) ) {
                continue;
            }

            $analysis = $this->analyze_persistence_file( $file_path, $dropin_label );

            if ( empty( $analysis['issue_type'] ) ) {
                continue;
            }

            QS_DB::insert_result(
                $scan_id,
                $analysis['issue_type'],
                $this->get_relative_site_path( $file_path ),
                $analysis['severity'],
                $analysis['detail'],
                $analysis['advice']
            );
            $results[] = $file_path;
        }

        return array_values( array_unique( $results ) );
    }

    /**
     * 第六步：数据库风险与异常 Option 扫描
     */
    public function scan_database_risks( $scan_id ) {
        $settings                 = $this->get_scanner_settings();
        $results                  = [];
        $ignored_option_rules     = QS_Protection::get_db_scan_ignored_options( $settings );
        $autoload_option_warn     = QS_Protection::get_db_autoload_option_warn_bytes( $settings );
        $autoload_total_warn      = QS_Protection::get_db_autoload_total_warn_bytes( $settings );
        $suspicious_option_limit  = QS_Protection::get_db_suspicious_option_limit( $settings );
        $autoload_total_bytes     = $this->get_total_autoload_bytes();
        $large_autoload_options   = $this->get_large_autoload_options( max( 20, $suspicious_option_limit ), $autoload_option_warn );
        $suspicious_option_rows   = $this->get_suspicious_option_candidates( $suspicious_option_limit );
        $missing_plugins          = $this->get_missing_active_plugins();
        $missing_network_plugins  = $this->get_missing_network_active_plugins();

        if ( $autoload_total_bytes > $autoload_total_warn ) {
            QS_DB::insert_result(
                $scan_id,
                'DB_AUTOLOAD_TOTAL_HIGH',
                'wp_options.autoload',
                'warning',
                sprintf(
                    '当前 autoload 总体积约为 %s，已超过预警阈值 %s。autoload 选项会在每次请求时自动载入，体积异常时常见于缓存滥存、配置膨胀，或有 payload 被塞进自动加载项。',
                    size_format( $autoload_total_bytes ),
                    size_format( $autoload_total_warn )
                ),
                '建议结合下方的大体积 autoload option 逐项核查来源；重点检查是否有异常插件把整段 HTML/JS/PHP 代码写入自动加载项。这里只做扫描提示，不会自动修改数据库。'
            );
            $results[] = 'autoload_total';
        }

        foreach ( $large_autoload_options as $row ) {
            $option_name = isset( $row['option_name'] ) ? (string) $row['option_name'] : '';
            $size_bytes  = isset( $row['size_bytes'] ) ? absint( $row['size_bytes'] ) : 0;

            if ( '' === $option_name || $size_bytes < $autoload_option_warn || $this->is_option_name_ignored( $option_name, $ignored_option_rules ) ) {
                continue;
            }

            QS_DB::insert_result(
                $scan_id,
                'DB_AUTOLOAD_OPTION_LARGE',
                'Option：' . $option_name,
                'warning',
                sprintf(
                    '发现体积异常的 autoload option [%s]，当前大小约为 %s。若其中存入了大段脚本、远程地址、缓存碎片或异常序列化内容，会同时带来性能和安全风险。',
                    $option_name,
                    size_format( $size_bytes )
                ),
                '请确认这个 option 是否来自你认可的插件/主题；如果它并非业务必需，建议联系开发者进一步核查其来源、更新逻辑和是否存在异常注入。'
            );
            $results[] = 'autoload:' . $option_name;
        }

        foreach ( $suspicious_option_rows as $row ) {
            $option_name   = isset( $row['option_name'] ) ? (string) $row['option_name'] : '';
            $option_excerpt = isset( $row['option_excerpt'] ) ? (string) $row['option_excerpt'] : '';

            if ( '' === $option_name || $this->is_option_name_ignored( $option_name, $ignored_option_rules ) ) {
                continue;
            }

            $severity = $this->is_critical_option_payload( $option_name, $option_excerpt ) ? 'critical' : 'warning';
            $preview  = $this->sanitize_option_preview( $option_excerpt );

            QS_DB::insert_result(
                $scan_id,
                'DB_OPTION_SUSPICIOUS',
                'Option：' . $option_name,
                $severity,
                sprintf(
                    '检测到疑似异常的数据库 option [%s]。名称或内容命中了挂马/注入特征。内容摘录：%s',
                    $option_name,
                    $preview ? $preview : '（内容不可安全展示）'
                ),
                '请核查该 option 由哪个主题、插件或自定义代码写入；若你并不认识它，建议进一步检查最近安装/更新记录、管理员操作日志，以及是否有前台挂马或 SEO 暗链同时出现。'
            );
            $results[] = 'option:' . $option_name;
        }

        foreach ( $missing_plugins as $plugin_file ) {
            QS_DB::insert_result(
                $scan_id,
                'DB_ACTIVE_PLUGIN_MISSING',
                'Option：active_plugins',
                'warning',
                sprintf( '数据库记录中仍标记插件 [%s] 为启用状态，但插件文件已不存在。若这不是正常卸载后遗留，可能说明数据库配置与磁盘状态不一致。', $plugin_file ),
                '请检查该插件是否被手工删除、部署遗漏，或被异常代码篡改了启用列表。由于本插件只做扫描，不会自动停用或修正 active_plugins。'
            );
            $results[] = 'active_plugin:' . $plugin_file;
        }

        foreach ( $missing_network_plugins as $plugin_file ) {
            QS_DB::insert_result(
                $scan_id,
                'DB_NETWORK_PLUGIN_MISSING',
                'Site Option：active_sitewide_plugins',
                'warning',
                sprintf( '网络启用插件列表中仍存在 [%s]，但对应插件文件已不存在。多站点环境下这类残留尤其需要核查。', $plugin_file ),
                '请确认这是否是正常卸载遗留，或曾有异常部署/篡改行为。建议在网络管理后台和文件系统中对照检查来源。'
            );
            $results[] = 'network_plugin:' . $plugin_file;
        }

        return array_values( array_unique( $results ) );
    }

    /**
     * 第七步：目录权限及核心配置加固
     */
    public function scan_permissions_and_hardening( $scan_id ) {
        $results    = [];
        $check_dirs = [ ABSPATH, WP_CONTENT_DIR, WP_CONTENT_DIR . '/uploads' ];

        foreach ( $check_dirs as $dir ) {
            if ( is_dir( $dir ) && '0777' === substr( sprintf( '%o', fileperms( $dir ) ), -4 ) ) {
                $rel_path = str_replace( '\\', '/', str_replace( ABSPATH, '', $dir ) );
                $rel_path = $rel_path ? $rel_path : '网站根目录';

                QS_DB::insert_result(
                    $scan_id,
                    'PERMISSIONS_777',
                    $rel_path,
                    'critical',
                    '目录权限为极度危险的 777 (全员可读写)。',
                    '请立即通过宝塔面板、主机控制台或 FTP 工具，将该目录权限重置为标准的 755 (目录) 或 644 (文件)。'
                );
                $results[] = $rel_path;
            }
        }

        $wp_config = ABSPATH . 'wp-config.php';
        if ( file_exists( $wp_config ) && is_writable( $wp_config ) ) {
            $perms = substr( sprintf( '%o', fileperms( $wp_config ) ), -4 );

            QS_DB::insert_result(
                $scan_id,
                'CONFIG_WRITABLE',
                'wp-config.php',
                'warning',
                "核心配置文件当前权限为 {$perms}（脚本可写）。",
                '为了极致安全，如果网站已经配置稳定，请将 wp-config.php 这一个文件的权限单独修改为非常严格的 440 或 400 防篡改。'
            );
            $results[] = 'wp-config.php';
        }

        if ( defined( 'WP_DEBUG' ) && WP_DEBUG ) {
            QS_DB::insert_result(
                $scan_id,
                'HARDENING_DEBUG',
                'wp-config.php',
                'warning',
                'WP_DEBUG 调试模式开启中！这可能会在网站出错白屏时泄露数据库或绝对路径信息给黑客。',
                "请编辑根目录下的 wp-config.php，寻找 'define(WP_DEBUG, true);'，将其修改为 false 或者直接删除该行代码以关闭调试。"
            );
            $results[] = 'WP_DEBUG';
        }

        return $results;
    }

    /**
     * 第八步：敏感 API 接口暴露检测
     */
    public function scan_api_exposure( $scan_id ) {
        $results = [];
        $apis    = $this->get_api_endpoints();

        foreach ( $apis as $endpoint => $name ) {
            $url      = site_url( $endpoint );
            $response = wp_remote_head( $url, [ 'timeout' => 3, 'sslverify' => false ] );
            $code     = wp_remote_retrieve_response_code( $response );

            if ( 200 === $code ) {
                QS_DB::insert_result(
                    $scan_id,
                    'API_EXPOSE',
                    $endpoint,
                    'warning',
                    "敏感接口 {$name} 可以被外网公开访问！此行为容易被自动化程序进行扫描嗅探或恶意攻击。",
                    '建议：如果您的业务不依赖此接口，请在本插件的【主动防护设置】中开启相应的防火墙直接将其阻断。如果您正在使用小程序/App获取该接口数据，请忽略此警告。'
                );
                $results[] = $endpoint;
            }
        }

        return $results;
    }

    /**
     * 第九步：网站暗链与恶意 JS 挂马深度探测
     */
    public function scan_dark_links( $scan_id ) {
        global $wpdb;

        $results           = [];
        $max_scan_bytes    = $this->get_code_scan_max_bytes();
        $dark_css_patterns = $this->get_dark_link_patterns();
        $regex_str         = implode( '|', $dark_css_patterns );

        $suspicious_posts = $wpdb->get_results(
            $wpdb->prepare(
                "SELECT ID, post_title, post_content
                 FROM {$wpdb->posts}
                 WHERE post_status = 'publish'
                 AND post_content REGEXP %s
                 LIMIT 50",
                $regex_str
            )
        );

        if ( ! empty( $suspicious_posts ) ) {
            $site_host = parse_url( site_url(), PHP_URL_HOST );

            foreach ( $suspicious_posts as $post ) {
                $is_malicious = false;
                $content      = $post->post_content;

                if ( preg_match( '/display\s*:\s*none/i', $content ) ) {
                    $is_malicious = true;
                } elseif ( preg_match( '/position\s*:\s*absolute\s*;\s*(left|top)\s*:\s*-999/i', $content ) ) {
                    $is_malicious = true;
                } elseif ( false !== strpos( $content, 'base64_decode' ) ) {
                    $is_malicious = true;
                } elseif ( preg_match( '/<iframe[\s\S]*?src=["\']?https?:\/\/(?!' . preg_quote( $site_host, '/' ) . ')[\s\S]*?width\s*=\s*["\']?0["\']?/i', $content ) ) {
                    $is_malicious = true;
                }

                if ( $is_malicious ) {
                    QS_DB::insert_result(
                        $scan_id,
                        'DARK_LINK_DB',
                        "文章ID: {$post->ID} ({$post->post_title})",
                        'critical',
                        '在此文章内容中发现了疑似 SEO 黑帽暗链或隐藏不可见的 iframe 标签。',
                        '这通常是因为编辑器漏洞或数据库被脱库注入。请进入后台重新编辑此文章，在“文本”(HTML)模式下清除设置了 display:none 或负坐标隐藏的超链接网页。'
                    );
                    $results[] = clone $post;
                }
            }
        }

        $active_theme_dir = get_stylesheet_directory();
        if ( is_dir( $active_theme_dir ) ) {
            $this->scan_directory_recursively(
                $active_theme_dir,
                function( $item ) use ( &$results, $scan_id, $max_scan_bytes ) {
                    if ( ! $item->isFile() || 'js' !== $item->getExtension() ) {
                        return;
                    }

                    $content = $this->read_file_excerpt( $item->getPathname(), $max_scan_bytes );
                    if ( '' === $content ) {
                        return;
                    }

                    $is_malicious = false;
                    $detail_msg   = '';

                    if ( preg_match( '/(\\\\x[0-9a-fA-F]{2}){10,}/', $content ) ) {
                        $is_malicious = true;
                        $detail_msg   = '包含高密度的十六进制混淆代码 (Hex Obfuscation)。';
                    } elseif ( preg_match( '/String\.fromCharCode\s*\([^)]+\)/i', $content ) && preg_match( '/(eval|document\.write)/i', $content ) ) {
                        $is_malicious = true;
                        $detail_msg   = '包含 String.fromCharCode 编码配合执行语句，是典型的反溯源挂马特征。';
                    } elseif ( preg_match( '/document\.write\s*\(\s*[\'"]<script\s+src=[\'"]https?:\/\/(?!' . preg_quote( parse_url( site_url(), PHP_URL_HOST ), '/' ) . ')/i', $content ) ) {
                        $is_malicious = true;
                        $detail_msg   = '包含直接通过 document.write 跨域调用外部隐蔽脚本的指令。';
                    }

                    if ( $is_malicious ) {
                        $rel_path = $this->get_relative_site_path( $item->getPathname() );

                        if ( '' === $rel_path ) {
                            return;
                        }

                        QS_DB::insert_result(
                            $scan_id,
                            'MALICIOUS_JS',
                            $rel_path,
                            'critical',
                            "前端 JavaScript 核心文件中发现了疑似被篡改的网页挂马跳转脚本！\n{$detail_msg}",
                            '这会导致您的客户访问网站时被暗中跳转到博彩、色情等恶意网站，或者弹出广告。请立即通过 FTP 覆盖还原该文件，如果无法还原，请暂时更名该 js 禁用它。'
                        );
                        $results[] = $rel_path;
                    }
                }
            );
        }

        return $results;
    }

    /**
     * 第十一步：WordPress 核心文件完整性校验 (防篡改检测)
     */
    public function scan_core_integrity( $scan_id ) {
        global $wp_version;

        $results  = [];
        $locale   = get_locale();
        $api_url  = "https://api.wordpress.org/core/checksums/1.0/?version={$wp_version}&locale={$locale}";
        $response = wp_remote_get( $api_url, [ 'timeout' => 15 ] );

        if ( is_wp_error( $response ) ) {
            return $results;
        }

        $body = wp_remote_retrieve_body( $response );
        $data = json_decode( $body, true );

        if ( ! isset( $data['checksums'] ) || ! is_array( $data['checksums'] ) ) {
            return $results;
        }

        foreach ( $data['checksums'] as $file => $expected_md5 ) {
            if ( 0 === strpos( $file, 'wp-content' ) || false !== strpos( $file, 'wp-config-sample.php' ) ) {
                continue;
            }

            $local_path = ABSPATH . $file;

            if ( ! file_exists( $local_path ) ) {
                QS_DB::insert_result(
                    $scan_id,
                    'CORE_FILE_MISSING',
                    $file,
                    'warning',
                    "WP 核心文件缺失：{$file}",
                    '发现系统核心文件丢失，这可能会导致功能异常或预留了渗透空间。建议通过官方渠道重新下载同版本 WordPress 覆盖还原核心文件。'
                );
                $results[] = $file;
                continue;
            }

            if ( md5_file( $local_path ) !== $expected_md5 ) {
                QS_DB::insert_result(
                    $scan_id,
                    'CORE_FILE_TAMPERED',
                    $file,
                    'critical',
                    "核心文件已被篡改：{$file} (本地 MD5 不匹配)",
                    '警告！该文件与官方标准版本不符，极大概率已被黑客修改并植入了恶意后门代码。请立即从官网下载干净的 WordPress 压缩包，并手动覆盖替换该文件！'
                );
                $results[] = $file;
            }
        }

        return $results;
    }

    /**
     * 第十步：主题 / 插件 / 上传目录文件基线比对
     */
    public function scan_file_integrity_baseline( $scan_id ) {
        $settings = $this->get_scanner_settings();
        $results  = [];

        if ( empty( $settings['enable_file_integrity_baseline'] ) ) {
            return $results;
        }

        $snapshot     = $this->collect_file_integrity_snapshot();
        $current_map  = isset( $snapshot['map'] ) && is_array( $snapshot['map'] ) ? $snapshot['map'] : [];
        $record_count = isset( $snapshot['count'] ) ? absint( $snapshot['count'] ) : 0;

        if ( empty( $current_map ) ) {
            return $results;
        }

        $baseline = QS_DB::get_file_baseline_map();

        if ( empty( $baseline ) ) {
            if ( empty( $settings['auto_initialize_file_baseline'] ) ) {
                QS_DB::insert_result(
                    $scan_id,
                    'FILE_BASELINE_SETUP_REQUIRED',
                    '文件完整性基线',
                    'warning',
                    '当前还没有可信的文件完整性基线。出于安全考虑，本次扫描不会自动把现有磁盘状态当成基线。',
                    '请先结合核心校验、恶意代码扫描结果和近期发版情况确认当前站点文件可信，然后在后台手动点击“重建文件基线”；如果你明确接受首次扫描直接建档，也可以到设置里开启“允许首次自动建立文件基线”。'
                );
                $results[] = 'baseline_setup_required';

                if ( ! empty( $snapshot['truncated'] ) ) {
                    QS_DB::insert_result(
                        $scan_id,
                        'FILE_BASELINE_TRUNCATED',
                        '文件完整性基线',
                        'warning',
                        sprintf( '本次基线预扫描只遍历了前 %d 个文件，已触发文件上限。', $record_count ),
                        '请先把“文件基线扫描上限”调高，再执行“重建文件基线”，避免第一份基线不完整。'
                    );
                    $results[] = 'baseline_truncated';
                }

                return $results;
            }

            $saved = QS_DB::replace_file_baseline_snapshot( array_values( $current_map ) );

            QS_DB::insert_result(
                $scan_id,
                'FILE_BASELINE_CREATED',
                '文件完整性基线',
                'info',
                sprintf( '已按当前文件状态自动建立首份文件完整性基线，共记录 %d 个文件。后续扫描会基于这份基线报告新增、修改和缺失文件。', $saved ),
                '只有在你确认当前站点文件就是可信状态时，才建议启用“允许首次自动建立文件基线”。如果后续有正常升级发布，请在后台点击“重建文件基线”。'
            );
            $results[] = 'baseline_created';

            if ( ! empty( $snapshot['truncated'] ) ) {
                QS_DB::insert_result(
                    $scan_id,
                    'FILE_BASELINE_TRUNCATED',
                    '文件完整性基线',
                    'warning',
                    sprintf( '本次建立基线时只记录了前 %d 个文件，已触发文件上限。当前基线可能不完整。', $record_count ),
                    '请在安全插件设置里调大“文件基线扫描上限”，然后重新执行“重建文件基线”。'
                );
                $results[] = 'baseline_truncated';
            }

            return $results;
        }

        foreach ( $current_map as $file_path => $record ) {
            if ( ! isset( $baseline[ $file_path ] ) ) {
                list( $severity, $advice ) = $this->get_file_integrity_change_meta( $file_path, 'created' );

                QS_DB::insert_result(
                    $scan_id,
                    'FILE_BASELINE_NEW',
                    $file_path,
                    $severity,
                    '检测到相对基线新增的文件。若这不是最近主动安装插件、升级主题或上传资源造成的，请重点核查。',
                    $advice
                );
                $results[] = $file_path;
                continue;
            }

            $baseline_record = $baseline[ $file_path ];
            $current_hash    = isset( $record['file_hash'] ) ? (string) $record['file_hash'] : '';
            $baseline_hash   = isset( $baseline_record['hash'] ) ? (string) $baseline_record['hash'] : '';

            if ( '' === $current_hash || $current_hash === $baseline_hash ) {
                continue;
            }

            list( $severity, $advice ) = $this->get_file_integrity_change_meta( $file_path, 'modified' );

            QS_DB::insert_result(
                $scan_id,
                'FILE_BASELINE_CHANGED',
                $file_path,
                $severity,
                '检测到相对基线已被修改的文件。若这不是正常升级发布产生的变更，请优先核查该文件是否被篡改。',
                $advice
            );
            $results[] = $file_path;
        }

        foreach ( $baseline as $file_path => $baseline_record ) {
            if ( isset( $current_map[ $file_path ] ) ) {
                continue;
            }

            list( $severity, $advice ) = $this->get_file_integrity_change_meta( $file_path, 'deleted' );

            QS_DB::insert_result(
                $scan_id,
                'FILE_BASELINE_MISSING',
                $file_path,
                $severity,
                '检测到相对基线缺失的文件。若这不是正常删除或升级迁移造成的，可能存在异常清理、覆盖失败或被恶意替换。',
                $advice
            );
            $results[] = $file_path;
        }

        if ( ! empty( $snapshot['truncated'] ) ) {
            QS_DB::insert_result(
                $scan_id,
                'FILE_BASELINE_TRUNCATED',
                '文件完整性基线',
                'warning',
                sprintf( '本次基线比对只扫描了前 %d 个文件，已触发文件上限，结果可能不完整。', $record_count ),
                '请在安全插件设置里调大“文件基线扫描上限”，然后重新体检或重建基线。'
            );
            $results[] = 'baseline_truncated';
        }

        return array_values( array_unique( $results ) );
    }

    public function rebuild_file_integrity_baseline() {
        $snapshot = $this->collect_file_integrity_snapshot();
        $records  = isset( $snapshot['map'] ) && is_array( $snapshot['map'] ) ? array_values( $snapshot['map'] ) : [];
        $saved    = QS_DB::replace_file_baseline_snapshot( $records );

        return [
            'count'     => $saved,
            'truncated' => ! empty( $snapshot['truncated'] ),
        ];
    }

    private function run_chunked_directory_step( $state, $roots, $callback, $excluded_path_fragments = [], $progress_template = '' ) {
        $scan_limit              = $this->get_scan_limit();
        $chunk_limit             = $this->get_scan_chunk_item_limit();
        $chunk_time_budget       = $this->get_scan_chunk_time_budget();
        $excluded_dir_names      = apply_filters( 'qs_scan_excluded_dir_names', [ 'node_modules', 'vendor', 'cache' ] );
        $excluded_path_fragments = $this->get_scan_excluded_paths( $excluded_path_fragments );
        $roots                   = $this->normalize_chunk_scan_roots( $roots );
        $state                   = $this->normalize_chunk_step_state( $state, $roots );
        $started_at              = microtime( true );
        $chunk_processed         = 0;
        $matches                 = [];

        while ( ! empty( $roots ) && $state['root_index'] < count( $roots ) ) {
            if ( $state['processed_total'] >= $scan_limit ) {
                $state['truncated'] = true;
                break;
            }

            if ( $chunk_processed >= $chunk_limit || ( microtime( true ) - $started_at ) >= $chunk_time_budget ) {
                break;
            }

            $current_root = $roots[ $state['root_index'] ];

            if ( empty( $state['queue'] ) ) {
                $state['queue']     = [ $current_root ];
                $state['queue_pos'] = 0;
                $state['current']   = '';
                $state['offset']    = 0;
            }

            if ( '' === $state['current'] ) {
                if ( $state['queue_pos'] >= count( $state['queue'] ) ) {
                    $state['root_index']++;
                    $state['queue']     = [];
                    $state['queue_pos'] = 0;
                    $state['current']   = '';
                    $state['offset']    = 0;
                    continue;
                }

                $state['current'] = (string) $state['queue'][ $state['queue_pos'] ];
                $state['offset']  = 0;
            }

            $entries = @scandir( $state['current'] );
            if ( ! is_array( $entries ) ) {
                $state['current'] = '';
                $state['offset']  = 0;
                $state['queue_pos']++;
                continue;
            }

            $entry_count = count( $entries );

            while ( $state['offset'] < $entry_count ) {
                if ( $state['processed_total'] >= $scan_limit ) {
                    $state['truncated'] = true;
                    break 2;
                }

                if ( $chunk_processed >= $chunk_limit || ( microtime( true ) - $started_at ) >= $chunk_time_budget ) {
                    break 2;
                }

                $entry = (string) $entries[ $state['offset'] ];
                $state['offset']++;

                if ( '.' === $entry || '..' === $entry ) {
                    continue;
                }

                $item_path = $state['current'] . '/' . $entry;
                if ( is_link( $item_path ) ) {
                    continue;
                }

                $normalized_path = $this->normalize_existing_path( $item_path );
                if ( '' === $normalized_path || ! $this->is_path_within_site_root( $normalized_path ) ) {
                    continue;
                }

                $item = new SplFileInfo( $normalized_path );
                if ( $item->isDir() && in_array( $item->getFilename(), $excluded_dir_names, true ) ) {
                    continue;
                }

                if ( $this->path_matches_any_fragment( $normalized_path, $excluded_path_fragments ) ) {
                    continue;
                }

                $result        = call_user_func( $callback, $item );
                $parsed_result = $this->parse_chunk_scan_callback_result( $result );

                if ( $item->isDir() && empty( $parsed_result['skip_children'] ) ) {
                    $state['queue'][] = $normalized_path;
                }

                $chunk_processed++;
                $state['processed_total']++;

                foreach ( $parsed_result['matches'] as $match ) {
                    if ( '' === $match ) {
                        continue;
                    }

                    $matches[] = $match;
                    $state['match_total']++;
                }
            }

            if ( $state['offset'] >= $entry_count ) {
                $state['current'] = '';
                $state['offset']  = 0;
                $state['queue_pos']++;
            }
        }

        $done = empty( $roots ) || $state['root_index'] >= count( $roots ) || ! empty( $state['truncated'] );

        return [
            'done'     => $done,
            'state'    => $done ? [] : $state,
            'results'  => array_values( array_unique( $matches ) ),
            'count'    => count( array_unique( $matches ) ),
            'progress' => [
                'scanned'   => (int) $state['processed_total'],
                'matches'   => (int) $state['match_total'],
                'truncated' => ! empty( $state['truncated'] ),
                'label'     => '' !== $progress_template
                    ? sprintf( $progress_template, (int) $state['processed_total'], (int) $state['match_total'] )
                    : '',
            ],
        ];
    }

    private function normalize_chunk_scan_roots( $roots ) {
        $normalized = [];

        foreach ( (array) $roots as $root ) {
            $root = $this->normalize_existing_path( $root );
            if ( '' === $root || ! is_dir( $root ) || ! $this->is_path_within_site_root( $root ) ) {
                continue;
            }

            $normalized[] = $root;
        }

        return array_values( array_unique( $normalized ) );
    }

    private function normalize_chunk_step_state( $state, $roots ) {
        $state   = is_array( $state ) ? $state : [];
        $version = isset( $state['version'] ) ? (int) $state['version'] : 0;

        if ( self::CHUNKED_STEP_STATE_VERSION !== $version ) {
            $state = [];
        }

        $state['version']         = self::CHUNKED_STEP_STATE_VERSION;
        $state['root_index']      = isset( $state['root_index'] ) ? max( 0, (int) $state['root_index'] ) : 0;
        $state['queue']           = isset( $state['queue'] ) && is_array( $state['queue'] ) ? array_values( array_filter( $state['queue'] ) ) : [];
        $state['queue_pos']       = isset( $state['queue_pos'] ) ? max( 0, (int) $state['queue_pos'] ) : 0;
        $state['current']         = isset( $state['current'] ) ? (string) $state['current'] : '';
        $state['offset']          = isset( $state['offset'] ) ? max( 0, (int) $state['offset'] ) : 0;
        $state['processed_total'] = isset( $state['processed_total'] ) ? max( 0, (int) $state['processed_total'] ) : 0;
        $state['match_total']     = isset( $state['match_total'] ) ? max( 0, (int) $state['match_total'] ) : 0;
        $state['truncated']       = ! empty( $state['truncated'] );

        if ( $state['root_index'] >= count( $roots ) ) {
            $state['root_index'] = 0;
            $state['queue']      = [];
            $state['queue_pos']  = 0;
            $state['current']    = '';
            $state['offset']     = 0;
        }

        return $state;
    }

    private function parse_chunk_scan_callback_result( $result ) {
        $parsed = [
            'matches'       => [],
            'skip_children' => false,
        ];

        if ( is_array( $result ) && ( array_key_exists( 'matches', $result ) || array_key_exists( 'skip_children', $result ) ) ) {
            $matches = isset( $result['matches'] ) ? (array) $result['matches'] : [];
            foreach ( $matches as $match ) {
                $match = sanitize_text_field( (string) $match );
                if ( '' !== $match ) {
                    $parsed['matches'][] = $match;
                }
            }

            $parsed['skip_children'] = ! empty( $result['skip_children'] );
            return $parsed;
        }

        foreach ( (array) $result as $match ) {
            $match = sanitize_text_field( (string) $match );
            if ( '' !== $match ) {
                $parsed['matches'][] = $match;
            }
        }

        return $parsed;
    }

    private function path_matches_any_fragment( $path, $fragments ) {
        $path = (string) $path;

        if ( '' === $path ) {
            return false;
        }

        foreach ( (array) $fragments as $fragment ) {
            $fragment = trim( (string) $fragment );

            if ( '' !== $fragment && false !== strpos( $path, $fragment ) ) {
                return true;
            }
        }

        return false;
    }

    private function get_scan_chunk_item_limit() {
        $limit = (int) apply_filters( 'qs_scan_chunk_item_limit', 400, $this->get_scanner_settings() );

        return max( 50, min( 2000, $limit ) );
    }

    private function get_scan_chunk_time_budget() {
        $budget = (float) apply_filters( 'qs_scan_chunk_time_budget_seconds', 2.5, $this->get_scanner_settings() );

        return max( 0.5, min( 10.0, $budget ) );
    }

    private function get_scan_step_progress_label( $step_id ) {
        $labels = [
            'sensitive_files'    => '全盘敏感文件扫描',
            'uploads_webshell'   => 'Uploads 目录后门查杀',
            'code_vulnerability' => '主题/插件代码安全审计',
            'dark_links'         => '全站暗链与防挂马深度查杀',
        ];

        return isset( $labels[ $step_id ] ) ? $labels[ $step_id ] : sanitize_text_field( (string) $step_id );
    }

    private function contains_any_case_insensitive( $content, $needles ) {
        $content = (string) $content;

        if ( '' === $content ) {
            return false;
        }

        foreach ( (array) $needles as $needle ) {
            $needle = (string) $needle;

            if ( '' !== $needle && false !== stripos( $content, $needle ) ) {
                return true;
            }
        }

        return false;
    }

    private function contains_code_risk_hint( $content ) {
        return $this->contains_any_case_insensitive(
            $content,
            [ 'system', 'exec', 'shell_exec', 'passthru', 'proc_open', 'popen', 'curl_exec', 'wp_remote_get', 'fsockopen', 'file_put_contents', 'fwrite', '$_GET', '$_POST', '$_REQUEST' ]
        );
    }

    private function scan_dark_links_database_phase( $scan_id ) {
        global $wpdb;

        $results           = [];
        $dark_css_patterns = $this->get_dark_link_patterns();
        $regex_str         = implode( '|', $dark_css_patterns );

        $suspicious_posts = $wpdb->get_results(
            $wpdb->prepare(
                "SELECT ID, post_title, post_content
                 FROM {$wpdb->posts}
                 WHERE post_status = 'publish'
                 AND post_content REGEXP %s
                 LIMIT 50",
                $regex_str
            )
        );

        if ( empty( $suspicious_posts ) ) {
            return $results;
        }

        $site_host = parse_url( site_url(), PHP_URL_HOST );

        foreach ( $suspicious_posts as $post ) {
            $is_malicious = false;
            $content      = $post->post_content;

            if ( preg_match( '/display\s*:\s*none/i', $content ) ) {
                $is_malicious = true;
            } elseif ( preg_match( '/position\s*:\s*absolute\s*;\s*(left|top)\s*:\s*-999/i', $content ) ) {
                $is_malicious = true;
            } elseif ( false !== strpos( $content, 'base64_decode' ) ) {
                $is_malicious = true;
            } elseif ( preg_match( '/<iframe[\s\S]*?src=["\']?https?:\/\/(?!' . preg_quote( $site_host, '/' ) . ')[\s\S]*?width\s*=\s*["\']?0["\']?/i', $content ) ) {
                $is_malicious = true;
            }

            if ( ! $is_malicious ) {
                continue;
            }

            QS_DB::insert_result(
                $scan_id,
                'DARK_LINK_DB',
                "文章ID: {$post->ID} ({$post->post_title})",
                'critical',
                '在此文章内容中发现了疑似 SEO 黑帽暗链或隐藏不可见的 iframe 标签。',
                '这通常是因为编辑器漏洞或数据库被脱库注入。请进入后台重新编辑此文章，在“文本”(HTML)模式下清除设置了 display:none 或负坐标隐藏的超链接网页。'
            );
            $results[] = 'post:' . $post->ID;
        }

        return array_values( array_unique( $results ) );
    }

    private function get_scanner_settings() {
        return QS_Protection::get_settings();
    }

    private function get_sensitive_extensions() {
        $settings   = $this->get_scanner_settings();
        $extensions = [ 'log', 'sql', 'env', 'bak', 'old', 'config', 'git', 'zip', 'tar', 'gz', 'rar' ];
        $extra      = QS_Protection::parse_list_setting( $settings['extra_sensitive_extensions'] );
        $extra      = array_map(
            static function( $ext ) {
                return ltrim( strtolower( $ext ), '.' );
            },
            $extra
        );

        $extensions = array_merge( $extensions, $extra );

        return array_values( array_unique( apply_filters( 'qs_sensitive_file_extensions', $extensions, $settings ) ) );
    }

    private function get_scan_excluded_paths( $base_exclusions = [] ) {
        $settings   = $this->get_scanner_settings();
        $extra      = QS_Protection::parse_list_setting( $settings['scan_excluded_paths'] );
        $exclusions = array_merge( $base_exclusions, $extra );

        return array_values( array_unique( apply_filters( 'qs_scan_excluded_paths', $exclusions, $settings ) ) );
    }

    private function get_api_endpoints() {
        $apis     = QS_Rules::get_rule(
            'scan_api_endpoints',
            [
                '/wp-json/wp/v2/users' => '用户枚举 (User Enumeration)',
                '/xmlrpc.php'          => 'XML-RPC (容易被滥用发起 DDoS 或爆破密码)',
                '/wp-sitemap-users-1.xml' => '用户站点地图枚举 (User Sitemap Enumeration)',
            ]
        );

        return is_array( $apis ) ? $apis : [];
    }

    private function get_dark_link_patterns() {
        $patterns = QS_Rules::get_rule(
            'dark_link_patterns',
            [
                'display:[[:space:]]*none',
                'position:[[:space:]]*absolute',
                'base64_decode',
                '<iframe',
            ]
        );

        return is_array( $patterns ) ? $patterns : [];
    }

    private function get_code_vulnerability_patterns() {
        $patterns = QS_Rules::get_rule(
            'code_vulnerability_patterns',
            [
                'RCE'   => '/\b(system|exec|shell_exec|passthru|proc_open|popen)\s*\(/i',
                'SSRF'  => '/\b(curl_exec|wp_remote_get|fsockopen)\s*\(.*(\$_GET|\$_POST|\$_REQUEST)/i',
                'WRITE' => '/\b(file_put_contents|fwrite)\s*\(.*(\$_GET|\$_POST|\$_REQUEST)/i',
            ]
        );

        return is_array( $patterns ) ? $patterns : [];
    }

    private function get_component_vulnerability_feed() {
        $feed = QS_Rules::get_rule( 'component_vulnerability_feed', [] );

        return is_array( $feed ) ? array_values( $feed ) : [];
    }

    private function get_installed_plugin_components() {
        if ( ! function_exists( 'get_plugins' ) ) {
            require_once ABSPATH . 'wp-admin/includes/plugin.php';
        }

        $plugins    = function_exists( 'get_plugins' ) ? get_plugins() : [];
        $components = [];

        foreach ( $plugins as $plugin_file => $plugin_data ) {
            $slug = dirname( (string) $plugin_file );

            if ( '.' === $slug || '' === $slug ) {
                $slug = basename( (string) $plugin_file, '.php' );
            }

            $slug = strtolower( preg_replace( '/[^a-z0-9._-]/', '', (string) $slug ) );

            if ( '' === $slug ) {
                continue;
            }

            $components[] = [
                'component_type' => 'plugin',
                'slug'           => $slug,
                'name'           => ! empty( $plugin_data['Name'] ) ? (string) $plugin_data['Name'] : $slug,
                'version'        => ! empty( $plugin_data['Version'] ) ? (string) $plugin_data['Version'] : '',
                'active'         => function_exists( 'is_plugin_active' ) && ( is_plugin_active( $plugin_file ) || is_plugin_active_for_network( $plugin_file ) ),
            ];
        }

        return $components;
    }

    private function get_installed_theme_components() {
        $themes     = function_exists( 'wp_get_themes' ) ? wp_get_themes() : [];
        $stylesheet = function_exists( 'get_stylesheet' ) ? (string) get_stylesheet() : '';
        $template   = function_exists( 'get_template' ) ? (string) get_template() : '';
        $components = [];

        foreach ( $themes as $theme_slug => $theme ) {
            $slug = strtolower( preg_replace( '/[^a-z0-9._-]/', '', (string) $theme_slug ) );

            if ( '' === $slug ) {
                continue;
            }

            $components[] = [
                'component_type' => 'theme',
                'slug'           => $slug,
                'name'           => $theme->get( 'Name' ) ? (string) $theme->get( 'Name' ) : $slug,
                'version'        => $theme->get( 'Version' ) ? (string) $theme->get( 'Version' ) : '',
                'active'         => $slug === $stylesheet || $slug === $template,
            ];
        }

        return $components;
    }

    private function component_version_matches_constraints( $version, $constraints ) {
        $version     = trim( (string) $version );
        $constraints = trim( (string) $constraints );

        if ( '' === $version || '' === $constraints ) {
            return false;
        }

        if ( in_array( strtolower( $constraints ), [ '*', 'all', 'any' ], true ) ) {
            return true;
        }

        $groups = preg_split( '/\s*\|\|\s*/', $constraints );

        foreach ( (array) $groups as $group ) {
            if ( $this->component_version_matches_group( $version, $group ) ) {
                return true;
            }
        }

        return false;
    }

    private function component_version_matches_group( $version, $group ) {
        $clauses = preg_split( '/\s*,\s*/', trim( (string) $group ) );

        foreach ( (array) $clauses as $clause ) {
            $clause = trim( (string) $clause );

            if ( '' === $clause ) {
                continue;
            }

            if ( preg_match( '/^([0-9A-Za-z._-]+)\s*-\s*([0-9A-Za-z._-]+)$/', $clause, $matches ) ) {
                if ( ! version_compare( $version, $matches[1], '>=' ) || ! version_compare( $version, $matches[2], '<=' ) ) {
                    return false;
                }

                continue;
            }

            if ( preg_match( '/^(<=|>=|<|>|=|==|!=)\s*([0-9A-Za-z._-]+)$/', $clause, $matches ) ) {
                $operator = '==' === $matches[1] ? '=' : $matches[1];

                if ( ! version_compare( $version, $matches[2], $operator ) ) {
                    return false;
                }

                continue;
            }

            if ( ! version_compare( $version, $clause, '=' ) ) {
                return false;
            }
        }

        return true;
    }

    private function get_upload_image_extensions() {
        $extensions = QS_Rules::get_rule( 'upload_image_extensions', [ 'jpg', 'jpeg', 'jpe', 'png', 'gif', 'webp', 'bmp', 'avif', 'heic', 'heif' ] );
        $extensions = array_values( array_filter( array_map( 'strtolower', (array) $extensions ) ) );

        return $extensions;
    }

    private function get_upload_svg_script_regex() {
        $regex    = (string) QS_Rules::get_rule( 'upload_svg_script_regex', '/<(script|foreignObject)\b|onload\s*=|onerror\s*=|javascript:/i' );

        return $regex;
    }

    private function get_upload_active_script_regex() {
        $regex    = (string) QS_Rules::get_rule( 'upload_active_script_regex', '/(eval\s*\(|document\.write|String\.fromCharCode|base64_decode|<script\b)/i' );

        return $regex;
    }

    private function get_persistence_safe_high_frequency_hooks( $settings ) {
        $safe_hooks = QS_Rules::get_rule( 'persistence_safe_high_frequency_hooks', [ 'action_scheduler_run_queue', 'as_async_request_queue_runner' ] );

        return is_array( $safe_hooks ) ? $safe_hooks : [];
    }

    private function get_persistence_suspicious_keyword_patterns( $settings ) {
        $patterns = QS_Rules::get_rule( 'persistence_suspicious_keywords', [ 'base64', 'eval', 'shell', 'payload', 'backdoor', 'malware', 'inject', 'cmd', 'remote' ] );

        return is_array( $patterns ) ? $patterns : [];
    }

    private function get_persistence_suspicious_hook_regex( $settings ) {
        $regex = (string) QS_Rules::get_rule( 'persistence_suspicious_hook_regex', '/(?:[a-f0-9]{24,}|base64|eval|shell|gzinflate|cmd|payload|backdoor)/i' );

        return $regex;
    }

    private function get_persistence_file_exec_regex( $settings ) {
        $regex = (string) QS_Rules::get_rule( 'persistence_file_exec_regex', '/\b(base64_decode|gzinflate|str_rot13|assert|eval|shell_exec|system|passthru|proc_open)\s*\(/i' );

        return $regex;
    }

    private function get_db_suspicious_option_name_patterns( $settings ) {
        $patterns = QS_Rules::get_rule( 'db_suspicious_option_name_patterns', [ 'payload', 'backdoor', 'malware', 'shell', 'inject', 'spam', 'eval', 'base64', 'hidden_link', 'seo_spam' ] );

        return is_array( $patterns ) ? $patterns : [];
    }

    private function get_db_suspicious_option_value_patterns( $settings ) {
        $patterns = QS_Rules::get_rule( 'db_suspicious_option_value_patterns', [ '<script', '<iframe', 'base64_decode', 'gzinflate', 'document.write', 'fromcharcode', 'data:text/html', 'onerror=', 'onload=', 'shell_exec', 'eval(', 'assert(', 'javascript:' ] );

        return is_array( $patterns ) ? $patterns : [];
    }

    private function get_db_critical_option_keywords() {
        return QS_Rules::get_rule( 'db_critical_option_keywords', [ '<script', '<iframe', 'base64_decode', 'gzinflate', 'document.write', 'fromcharcode', 'shell_exec', 'eval(', 'assert(', 'javascript:' ] );
    }

    private function get_image_scan_max_bytes() {
        $settings = $this->get_scanner_settings();
        return max( 1, absint( $settings['image_scan_max_kb'] ) ) * 1024;
    }

    private function get_code_scan_max_bytes() {
        $settings = $this->get_scanner_settings();

        return max( 64, absint( $settings['code_scan_max_kb'] ) ) * 1024;
    }

    private function get_scan_limit() {
        $settings = $this->get_scanner_settings();
        return max( 1, absint( $settings['scan_max_files'] ) );
    }

    private function user_has_any_capability( $user, $capabilities ) {
        foreach ( (array) $capabilities as $capability ) {
            if ( user_can( $user, $capability ) ) {
                return true;
            }
        }

        return false;
    }

    private function username_matches_rule( $username, $rule ) {
        $username = strtolower( trim( (string) $username ) );
        $rule     = strtolower( trim( (string) $rule ) );

        if ( '' === $username || '' === $rule ) {
            return false;
        }

        if ( '*' === substr( $rule, -1 ) ) {
            return 0 === strpos( $username, rtrim( $rule, '*' ) );
        }

        return $username === $rule;
    }

    private function filename_contains_dangerous_double_extension( $filename, $dangerous_extensions ) {
        $segments = array_values( array_filter( explode( '.', strtolower( (string) $filename ) ) ) );

        if ( count( $segments ) < 3 ) {
            return false;
        }

        $embedded_extensions = array_slice( $segments, 1, -1 );

        foreach ( $embedded_extensions as $extension ) {
            if ( in_array( $extension, (array) $dangerous_extensions, true ) ) {
                return true;
            }
        }

        return false;
    }

    private function inspect_existing_upload_file( $file_path, $filename, $extension, $mime_ignored_extensions ) {
        $file_path               = (string) $file_path;
        $filename                = strtolower( (string) $filename );
        $extension               = strtolower( (string) $extension );
        $mime_ignored_extensions = array_values( array_filter( array_map( 'strtolower', (array) $mime_ignored_extensions ) ) );

        if ( '' === $file_path || '' === $extension || in_array( $extension, $mime_ignored_extensions, true ) ) {
            return [];
        }

        $image_extensions = $this->get_upload_image_extensions();

        if ( in_array( $extension, $image_extensions, true ) ) {
            $real_image_mime = function_exists( 'wp_get_image_mime' ) ? wp_get_image_mime( $file_path ) : false;

            if ( false === $real_image_mime || '' === $real_image_mime ) {
                return [
                    'issue_type' => 'UPLOAD_MIME_MISMATCH',
                    'severity'   => 'warning',
                    'detail'     => '该文件扩展名看起来是图片，但实际内容未通过真实图片校验。常见于伪装上传、损坏文件或被替换的恶意载荷。',
                    'advice'     => '请核查该文件来源；如果它并非你刚上传的正常媒体文件，建议检查上传入口是否被绕过，并确认“严格校验上传文件内容与后缀”已开启。',
                ];
            }
        }

        if ( 'svg' === $extension ) {
            $content = $this->read_file_excerpt( $file_path, 131072 );
            $regex   = $this->get_upload_svg_script_regex();

            if ( '' !== $content && @preg_match( $regex, $content ) ) {
                return [
                    'issue_type' => 'UPLOAD_SVG_SCRIPTED',
                    'severity'   => 'critical',
                    'detail'     => 'Uploads 目录中的 SVG 文件包含脚本标签、事件处理器或 javascript: 片段。这种 SVG 通常可直接在浏览器中执行恶意脚本。',
                    'advice'     => '如果站点并不依赖 SVG，建议直接删除并在安全设置里开启“禁止上传 SVG 文件”；如果业务必须使用 SVG，请确保它经过专门的净化处理。',
                ];
            }

            return [];
        }

        if ( in_array( $extension, [ 'js', 'html', 'htm' ], true ) ) {
            $content = $this->read_file_excerpt( $file_path, 131072 );
            $regex   = $this->get_upload_active_script_regex();

            if ( '' !== $content && @preg_match( $regex, $content ) ) {
                return [
                    'issue_type' => 'UPLOAD_ACTIVE_SCRIPT',
                    'severity'   => 'critical',
                    'detail'     => 'Uploads 目录中的前端可执行文件命中了可疑脚本特征。攻击者常把恶意 JS/HTML 投放到 uploads 后再被页面引用执行。',
                    'advice'     => '请核查该文件是否为业务必需资源；如果你不认识它，建议立刻检查来源页面、最近上传记录和外链引用情况。',
                ];
            }
        }

        return [];
    }

    private function analyze_cron_event( $hook, $event, $ignored_hooks, $settings ) {
        $hook       = sanitize_key( (string) $hook );
        $event      = is_array( $event ) ? $event : [];
        $args_text  = $this->stringify_scan_value( isset( $event['args'] ) ? $event['args'] : [] );
        $interval   = isset( $event['interval'] ) ? absint( $event['interval'] ) : 0;
        $schedule   = isset( $event['schedule'] ) ? sanitize_key( (string) $event['schedule'] ) : 'single';
        $safe_hooks = $this->get_persistence_safe_high_frequency_hooks( $settings );
        $suspicious_keyword_patterns = $this->get_persistence_suspicious_keyword_patterns( $settings );
        $suspicious_hook_regex = $this->get_persistence_suspicious_hook_regex( $settings );

        if ( '' === $hook || in_array( $hook, (array) $ignored_hooks, true ) ) {
            return [];
        }

        $hook_match_result = '' !== $suspicious_hook_regex ? @preg_match( $suspicious_hook_regex, $hook ) : 0;
        $hook_matched      = 1 === $hook_match_result;

        if ( $hook_matched || $this->string_contains_any( $args_text, $suspicious_keyword_patterns ) ) {
            return [
                'issue_type' => 'CRON_SUSPICIOUS',
                'severity'   => 'warning',
                'detail'     => sprintf( '发现可疑的计划任务 Hook [%s]。该任务名称或参数中包含高风险关键词，常见于持久化后门、自恢复脚本或异常远程拉取逻辑。', $hook ),
                'advice'     => '请全局搜索该 hook 名称，确认它来自哪个主题、插件或自定义代码；如果你并不认识它，请优先检查最近新增插件、MU 插件和可疑代码投放点。',
            ];
        }

        if ( $interval > 0 && $interval < 300 && ! in_array( $hook, $safe_hooks, true ) ) {
            return [
                'issue_type' => 'CRON_HIGH_FREQUENCY',
                'severity'   => 'warning',
                'detail'     => sprintf( '计划任务 [%s] 的执行间隔仅 %d 秒（schedule=%s），频率明显偏高。若来源不明，可能被用于周期性回连、自恢复或高频资源消耗。', $hook, $interval, $schedule ? $schedule : 'custom' ),
                'advice'     => '请核查该任务是否确为业务必需；如果它是你确认安全的自定义 cron，可把 hook 名加入“Cron 扫描忽略 Hook”列表，避免后续重复告警。',
            ];
        }

        if ( '' !== $args_text && preg_match( '#https?://#i', $args_text ) && ! in_array( $hook, $safe_hooks, true ) ) {
            return [
                'issue_type' => 'CRON_REMOTE_ARGS',
                'severity'   => 'warning',
                'detail'     => sprintf( '计划任务 [%s] 的参数中包含远程 URL。若该任务来源不明，可能被用于定时请求远端控制地址或加载外部 payload。', $hook ),
                'advice'     => '请检查该任务参数里出现的域名、用途和来源插件；如果这并非你主动配置的业务回调任务，建议重点排查。',
            ];
        }

        return [];
    }

    private function get_mu_plugin_files() {
        $mu_dir = defined( 'WPMU_PLUGIN_DIR' ) ? WPMU_PLUGIN_DIR : WP_CONTENT_DIR . '/mu-plugins';

        if ( ! is_dir( $mu_dir ) ) {
            return [];
        }

        $files    = [];
        $iterator = $this->get_directory_file_iterator( $mu_dir );

        if ( ! $iterator ) {
            return [];
        }

        foreach ( $iterator as $item ) {
            if ( ! $item->isFile() ) {
                continue;
            }

            $extension = strtolower( $item->getExtension() );
            $filename  = strtolower( $item->getFilename() );

            if ( 'php' !== $extension || 'index.php' === $filename ) {
                continue;
            }

            $files[] = str_replace( '\\', '/', $item->getPathname() );
        }

        sort( $files );

        return $files;
    }

    private function is_mu_plugin_entry_file( $file_path ) {
        $mu_dir    = defined( 'WPMU_PLUGIN_DIR' ) ? WPMU_PLUGIN_DIR : WP_CONTENT_DIR . '/mu-plugins';
        $parent    = str_replace( '\\', '/', dirname( (string) $file_path ) );
        $root_dir  = rtrim( str_replace( '\\', '/', $mu_dir ), '/' );

        return '' !== $root_dir && $parent === $root_dir;
    }

    private function get_dropin_files() {
        return apply_filters(
            'qs_dropin_files',
            [
                'advanced-cache.php' => 'Drop-in：advanced-cache.php',
                'db.php'             => 'Drop-in：db.php',
                'object-cache.php'   => 'Drop-in：object-cache.php',
                'sunrise.php'        => 'Drop-in：sunrise.php',
                'install.php'        => 'Drop-in：install.php',
                'maintenance.php'    => 'Drop-in：maintenance.php',
            ],
            $this->get_scanner_settings()
        );
    }

    private function analyze_persistence_file( $file_path, $label ) {
        $relative_path = $this->get_relative_site_path( $file_path );
        $content       = $this->read_file_excerpt( $file_path );
        $regex         = $this->get_persistence_file_exec_regex( $this->get_scanner_settings() );

        if ( '' !== $content && '' !== $regex && 1 === @preg_match( $regex, $content ) ) {
            return [
                'issue_type' => false !== strpos( (string) $label, 'MU 插件' ) ? 'MU_PLUGIN_SUSPICIOUS' : 'DROPIN_SUSPICIOUS',
                'severity'   => 'critical',
                'detail'     => sprintf( '%s [%s] 会在每次请求中常驻加载，且文件内容命中了混淆或执行型高危函数特征。若这不是你明确安装的系统组件，极有可能是持久化后门。', $label, $relative_path ),
                'advice'     => '请立即核查该文件来源、最近修改时间和部署记录；如果并非你主动安装的常驻组件，建议先隔离备份并用干净文件覆盖恢复。',
            ];
        }

        return [
            'issue_type' => false !== strpos( (string) $label, 'MU 插件' ) ? 'MU_PLUGIN_PRESENT' : 'DROPIN_PRESENT',
            'severity'   => 'info',
            'detail'     => sprintf( '发现 %s [%s]。这类文件会绕过普通插件停用流程，在每次请求中常驻加载。', $label, $relative_path ),
            'advice'     => '如果这是你主动安装的缓存、加速、多站点或平台组件，可忽略；如果你不认识它，请检查文件头注释、最近修改时间以及所属插件/运维系统来源。',
        ];
    }

    private function read_file_excerpt( $file_path, $max_bytes = 65535 ) {
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

    private function stringify_scan_value( $value ) {
        if ( is_scalar( $value ) ) {
            return sanitize_text_field( (string) $value );
        }

        if ( empty( $value ) ) {
            return '';
        }

        return sanitize_text_field( wp_json_encode( $value ) );
    }

    private function string_contains_any( $haystack, $needles ) {
        $haystack = strtolower( (string) $haystack );

        if ( '' === $haystack ) {
            return false;
        }

        foreach ( (array) $needles as $needle ) {
            $needle = strtolower( trim( (string) $needle ) );

            if ( '' !== $needle && false !== strpos( $haystack, $needle ) ) {
                return true;
            }
        }

        return false;
    }

    private function get_total_autoload_bytes() {
        global $wpdb;

        $autoload_values = apply_filters( 'qs_db_scan_autoload_values', [ 'yes', 'on', 'auto', 'auto-on' ], $this->get_scanner_settings() );
        $autoload_values = array_values( array_filter( array_map( 'strval', (array) $autoload_values ) ) );

        if ( empty( $autoload_values ) ) {
            return 0;
        }

        $placeholders = implode( ',', array_fill( 0, count( $autoload_values ), '%s' ) );
        $table        = $wpdb->options;
        $sql          = "SELECT COALESCE(SUM(LENGTH(option_value)), 0) FROM $table WHERE autoload IN ($placeholders)";

        return (int) $wpdb->get_var( $wpdb->prepare( $sql, $autoload_values ) );
    }

    private function get_large_autoload_options( $limit, $threshold_bytes ) {
        global $wpdb;

        $limit           = max( 1, absint( $limit ) );
        $threshold_bytes = max( 1, absint( $threshold_bytes ) );
        $autoload_values = apply_filters( 'qs_db_scan_autoload_values', [ 'yes', 'on', 'auto', 'auto-on' ], $this->get_scanner_settings() );
        $autoload_values = array_values( array_filter( array_map( 'strval', (array) $autoload_values ) ) );

        if ( empty( $autoload_values ) ) {
            return [];
        }

        $placeholders = implode( ',', array_fill( 0, count( $autoload_values ), '%s' ) );
        $params       = array_merge( $autoload_values, [ $threshold_bytes, $limit ] );
        $table        = $wpdb->options;
        $sql          = "SELECT option_name, LENGTH(option_value) AS size_bytes
            FROM $table
            WHERE autoload IN ($placeholders)
            AND LENGTH(option_value) >= %d
            ORDER BY LENGTH(option_value) DESC, option_id DESC
            LIMIT %d";

        return $wpdb->get_results( $wpdb->prepare( $sql, $params ), ARRAY_A );
    }

    private function get_suspicious_option_candidates( $limit ) {
        global $wpdb;

        $settings       = $this->get_scanner_settings();
        $limit          = max( 1, absint( $limit ) );
        $name_patterns  = $this->get_db_suspicious_option_name_patterns( $settings );
        $value_patterns = $this->get_db_suspicious_option_value_patterns( $settings );
        $name_regex     = $this->build_mysql_regex_from_terms( $name_patterns );
        $value_regex    = $this->build_mysql_regex_from_terms( $value_patterns );

        if ( '' === $name_regex || '' === $value_regex ) {
            return [];
        }

        $table = $wpdb->options;
        $sql   = "SELECT option_name, LEFT(option_value, %d) AS option_excerpt, LENGTH(option_value) AS size_bytes, autoload
            FROM $table
            WHERE option_name REGEXP %s OR option_value REGEXP %s
            ORDER BY LENGTH(option_value) DESC, option_id DESC
            LIMIT %d";

        return $wpdb->get_results(
            $wpdb->prepare( $sql, 4096, $name_regex, $value_regex, $limit ),
            ARRAY_A
        );
    }

    private function build_mysql_regex_from_terms( $terms ) {
        $terms = array_filter(
            array_map(
                static function( $term ) {
                    $term = trim( (string) $term );
                    return '' !== $term ? preg_quote( $term, '/' ) : '';
                },
                (array) $terms
            )
        );

        return empty( $terms ) ? '' : implode( '|', $terms );
    }

    private function is_option_name_ignored( $option_name, $rules ) {
        $option_name = strtolower( trim( (string) $option_name ) );

        if ( '' === $option_name ) {
            return true;
        }

        foreach ( (array) $rules as $rule ) {
            if ( $this->option_name_matches_rule( $option_name, $rule ) ) {
                return true;
            }
        }

        return false;
    }

    private function option_name_matches_rule( $option_name, $rule ) {
        $option_name = strtolower( trim( (string) $option_name ) );
        $rule        = strtolower( trim( (string) $rule ) );

        if ( '' === $option_name || '' === $rule ) {
            return false;
        }

        if ( '*' === substr( $rule, -1 ) ) {
            return 0 === strpos( $option_name, rtrim( $rule, '*' ) );
        }

        return $option_name === $rule;
    }

    private function sanitize_option_preview( $value ) {
        $value = (string) $value;

        if ( '' === $value ) {
            return '';
        }

        $value = wp_strip_all_tags( $value );
        $value = preg_replace( '/\s+/', ' ', $value );
        $value = trim( sanitize_text_field( $value ) );

        if ( '' === $value ) {
            return '';
        }

        return function_exists( 'mb_substr' ) ? mb_substr( $value, 0, 180 ) : substr( $value, 0, 180 );
    }

    private function is_critical_option_payload( $option_name, $option_excerpt ) {
        $haystack = strtolower( (string) $option_name . "\n" . (string) $option_excerpt );

        return $this->string_contains_any(
            $haystack,
            $this->get_db_critical_option_keywords()
        );
    }

    private function get_missing_active_plugins() {
        $plugins = [];

        foreach ( (array) get_option( 'active_plugins', [] ) as $plugin_file ) {
            $plugin_file = ltrim( (string) $plugin_file, '/' );

            if ( '' === $plugin_file || $this->plugin_file_exists( $plugin_file ) ) {
                continue;
            }

            $plugins[] = $plugin_file;
        }

        return array_values( array_unique( $plugins ) );
    }

    private function get_missing_network_active_plugins() {
        if ( ! is_multisite() ) {
            return [];
        }

        $plugins = [];
        $network = get_site_option( 'active_sitewide_plugins', [] );

        foreach ( array_keys( (array) $network ) as $plugin_file ) {
            $plugin_file = ltrim( (string) $plugin_file, '/' );

            if ( '' === $plugin_file || $this->plugin_file_exists( $plugin_file ) ) {
                continue;
            }

            $plugins[] = $plugin_file;
        }

        return array_values( array_unique( $plugins ) );
    }

    private function plugin_file_exists( $plugin_file ) {
        $plugin_file = ltrim( str_replace( '\\', '/', (string) $plugin_file ), '/' );

        if ( '' === $plugin_file ) {
            return false;
        }

        return file_exists( WP_PLUGIN_DIR . '/' . $plugin_file );
    }

    private function get_file_integrity_limit() {
        $settings = $this->get_scanner_settings();
        return max( 1, absint( $settings['file_integrity_max_files'] ) );
    }

    private function get_file_integrity_roots() {
        $roots     = [];
        $site_root = $this->get_site_root_path();

        if ( '' === $site_root ) {
            return $roots;
        }

        foreach ( QS_Protection::get_file_integrity_paths( $this->get_scanner_settings() ) as $path ) {
            $normalized = str_replace( '\\', '/', trim( (string) $path ) );
            $normalized = trim( $normalized, '/' );

            if ( '' === $normalized || false !== strpos( $normalized, '..' ) ) {
                continue;
            }

            $absolute = $this->normalize_existing_path( trailingslashit( $site_root ) . $normalized );
            if ( '' === $absolute || ! $this->is_path_within_site_root( $absolute ) ) {
                continue;
            }

            $scope = 'custom';

            if ( 0 === strpos( $normalized, 'wp-content/themes' ) ) {
                $scope = 'themes';
            } elseif ( 0 === strpos( $normalized, 'wp-content/plugins' ) ) {
                $scope = 'plugins';
            } elseif ( 0 === strpos( $normalized, 'wp-content/mu-plugins' ) ) {
                $scope = 'mu-plugins';
            } elseif ( 0 === strpos( $normalized, 'wp-content/uploads' ) ) {
                $scope = 'uploads';
            }

            $roots[] = [
                'relative_root' => $normalized,
                'absolute_root' => $absolute,
                'scope'         => $scope,
            ];
        }

        return $roots;
    }

    private function collect_file_integrity_snapshot() {
        $records   = [];
        $count     = 0;
        $limit     = $this->get_file_integrity_limit();
        $truncated = false;

        foreach ( $this->get_file_integrity_roots() as $root ) {
            $iterator = $this->get_directory_file_iterator( $root['absolute_root'] );

            if ( ! $iterator ) {
                continue;
            }

            foreach ( $iterator as $item ) {
                if ( ! $item->isFile() ) {
                    continue;
                }

                if ( $count >= $limit ) {
                    $truncated = true;
                    break 2;
                }

                $absolute_path = $this->normalize_existing_path( $item->getPathname() );
                if ( '' === $absolute_path || ! $this->is_path_within_site_root( $absolute_path ) ) {
                    continue;
                }

                $relative_path = $this->get_relative_site_path( $absolute_path );

                if ( '' === $relative_path ) {
                    continue;
                }

                $file_hash = @hash_file( 'sha256', $absolute_path );

                if ( false === $file_hash ) {
                    continue;
                }

                $records[ $relative_path ] = [
                    'file_path'  => $relative_path,
                    'file_hash'  => $file_hash,
                    'file_size'  => (int) $item->getSize(),
                    'file_mtime' => (int) $item->getMTime(),
                    'scope'      => $root['scope'],
                ];
                $count++;
            }
        }

        ksort( $records );

        return [
            'map'       => $records,
            'count'     => count( $records ),
            'truncated' => $truncated,
        ];
    }

    private function get_file_integrity_change_meta( $file_path, $change_type ) {
        $file_path = strtolower( (string) $file_path );
        $ext       = strtolower( pathinfo( $file_path, PATHINFO_EXTENSION ) );
        $severity  = 'warning';
        $advice    = '请先确认这是否是最近主动发布、安装插件、升级主题或上传文件造成的正常变更；确认无误后，可在后台手动重建文件基线。';

        if ( in_array( $ext, [ 'php', 'phtml', 'php5', 'php7' ], true ) ) {
            $severity = 'critical';
            $advice   = '该变更涉及可执行脚本文件，请优先核查源码差异、最近发布记录和服务器操作日志；如果无法确认来源，建议先用干净备份覆盖还原，再进一步排查。';
        } elseif ( 'deleted' === $change_type ) {
            $severity = 'warning';
            $advice   = '请确认该文件是否在最近升级或人工清理中被正常删除；如果不是，建议核查部署过程、文件权限以及是否存在恶意清理行为。';
        } elseif ( false !== strpos( $file_path, '/uploads/' ) && in_array( $ext, [ 'js', 'svg', 'html', 'htm' ], true ) ) {
            $severity = 'warning';
            $advice   = '该变更发生在 uploads 目录，且文件具备前端执行能力。请确认是否为业务必需文件，避免被人借上传目录投放恶意脚本。';
        }

        return [ $severity, $advice ];
    }

    private function get_site_root_path() {
        static $site_root = null;

        if ( null !== $site_root ) {
            return $site_root;
        }

        $resolved  = realpath( ABSPATH );
        $site_root = rtrim( wp_normalize_path( false !== $resolved ? (string) $resolved : ABSPATH ), '/' );

        return $site_root;
    }

    private function normalize_existing_path( $path ) {
        $path = trim( (string) $path );

        if ( '' === $path ) {
            return '';
        }

        $resolved = realpath( $path );

        if ( false === $resolved ) {
            return '';
        }

        return rtrim( wp_normalize_path( (string) $resolved ), '/' );
    }

    private function is_path_within_site_root( $absolute_path ) {
        $absolute_path = rtrim( wp_normalize_path( (string) $absolute_path ), '/' );
        $site_root     = $this->get_site_root_path();

        if ( '' === $absolute_path || '' === $site_root ) {
            return false;
        }

        return $absolute_path === $site_root || 0 === strpos( $absolute_path, $site_root . '/' );
    }

    private function get_relative_site_path( $absolute_path ) {
        $absolute_path = $this->normalize_existing_path( $absolute_path );
        $root_path     = $this->get_site_root_path();

        if ( '' === $absolute_path || '' === $root_path || ! $this->is_path_within_site_root( $absolute_path ) || $absolute_path === $root_path ) {
            return '';
        }

        return ltrim( substr( $absolute_path, strlen( $root_path ) ), '/' );
    }

    private function get_directory_file_iterator( $dir, $excluded_path_fragments = [] ) {
        if ( ! is_dir( $dir ) ) {
            return null;
        }

        $excluded_dir_names      = apply_filters( 'qs_scan_excluded_dir_names', [ 'node_modules', 'vendor', 'cache' ] );
        $excluded_path_fragments = $this->get_scan_excluded_paths( $excluded_path_fragments );
        $directory_iterator      = new RecursiveDirectoryIterator( $dir, RecursiveDirectoryIterator::SKIP_DOTS );
        $filter_iterator         = new RecursiveCallbackFilterIterator(
            $directory_iterator,
            function( $item ) use ( $excluded_dir_names, $excluded_path_fragments ) {
                if ( $item->isLink() ) {
                    return false;
                }

                $pathname = $this->normalize_existing_path( $item->getPathname() );
                if ( '' === $pathname || ! $this->is_path_within_site_root( $pathname ) ) {
                    return false;
                }

                if ( $item->isDir() && in_array( $item->getFilename(), $excluded_dir_names, true ) ) {
                    return false;
                }

                foreach ( $excluded_path_fragments as $fragment ) {
                    if ( '' !== $fragment && false !== strpos( $pathname, $fragment ) ) {
                        return false;
                    }
                }

                return true;
            }
        );

        return new RecursiveIteratorIterator(
            $filter_iterator,
            RecursiveIteratorIterator::LEAVES_ONLY
        );
    }

    /**
     * 辅助遍历方法
     */
    private function scan_directory_recursively( $dir, $callback, $excluded_path_fragments = [] ) {
        if ( ! is_dir( $dir ) ) {
            return;
        }

        $excluded_dir_names      = apply_filters( 'qs_scan_excluded_dir_names', [ 'node_modules', 'vendor', 'cache' ] );
        $excluded_path_fragments = $this->get_scan_excluded_paths( $excluded_path_fragments );
        $directory_iterator      = new RecursiveDirectoryIterator( $dir, RecursiveDirectoryIterator::SKIP_DOTS );
        $filter_iterator         = new RecursiveCallbackFilterIterator(
            $directory_iterator,
            function( $item ) use ( $excluded_dir_names, $excluded_path_fragments ) {
                if ( $item->isLink() ) {
                    return false;
                }

                $pathname = $this->normalize_existing_path( $item->getPathname() );
                if ( '' === $pathname || ! $this->is_path_within_site_root( $pathname ) ) {
                    return false;
                }

                if ( $item->isDir() && in_array( $item->getFilename(), $excluded_dir_names, true ) ) {
                    return false;
                }

                foreach ( $excluded_path_fragments as $fragment ) {
                    if ( '' !== $fragment && false !== strpos( $pathname, $fragment ) ) {
                        return false;
                    }
                }

                return true;
            }
        );

        $iterator = new RecursiveIteratorIterator(
            $filter_iterator,
            RecursiveIteratorIterator::SELF_FIRST
        );
        $count    = 0;
        $limit    = $this->get_scan_limit();

        foreach ( $iterator as $item ) {
            if ( $count >= $limit ) {
                break;
            }

            call_user_func( $callback, $item );
            $count++;
        }
    }
}
