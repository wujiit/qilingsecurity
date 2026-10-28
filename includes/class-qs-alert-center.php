<?php
/**
 * 安全告警中心
 */
if ( ! defined( 'ABSPATH' ) ) {
    exit;
}

class QS_Alert_Center {

    const SOURCE_PREFIX = 'qiling-security-alert';

    public static function init() {
        add_filter( 'qilinghook_request_args', [ __CLASS__, 'filter_qilinghook_request_args' ], 10, 4 );
    }

    public static function get_event_choices() {
        return [
            'scan_risk'     => '全盘体检发现风险',
            'login_lockout' => '登录爆破触发封禁',
            'rate_limit'    => '行为限速触发',
            'ip_risk'       => '登录 IP 风险画像命中',
            'waf_block'     => 'WAF 命中并阻断',
            'upload_block'  => '上传防护拦截',
            'geo_block'     => '地区限制',
            'session_limit' => '会话并发限制触发',
            'rest_guard'    => 'REST 敏感路由访问',
        ];
    }

    public static function get_event_label( $event_key ) {
        $choices = self::get_event_choices();

        return isset( $choices[ $event_key ] ) ? $choices[ $event_key ] : sanitize_text_field( (string) $event_key );
    }

    public static function is_enabled( $settings = null ) {
        $settings = is_array( $settings ) ? $settings : QS_Protection::get_settings();

        return ! empty( $settings['enable_security_alert_center'] );
    }

    public static function has_push_plugin() {
        return function_exists( 'qilinghook_send' ) && class_exists( 'QilingHook_Plugin' );
    }

    public static function get_available_push_channels() {
        $channels = [];

        if ( ! self::has_push_plugin() ) {
            return $channels;
        }

        $plugin = QilingHook_Plugin::get_instance();

        if ( ! is_object( $plugin ) || ! method_exists( $plugin, 'get_settings' ) ) {
            return $channels;
        }

        $settings = $plugin->get_settings();
        $list     = isset( $settings['channels'] ) && is_array( $settings['channels'] ) ? $settings['channels'] : [];

        foreach ( $list as $channel ) {
            if ( ! is_array( $channel ) ) {
                continue;
            }

            $channel_id = isset( $channel['id'] ) ? sanitize_key( (string) $channel['id'] ) : '';
            if ( '' === $channel_id ) {
                continue;
            }

            $channels[ $channel_id ] = [
                'id'       => $channel_id,
                'name'     => isset( $channel['name'] ) ? sanitize_text_field( (string) $channel['name'] ) : $channel_id,
                'provider' => isset( $channel['provider'] ) ? sanitize_key( (string) $channel['provider'] ) : 'feishu',
                'enabled'  => ! empty( $channel['enabled'] ),
            ];
        }

        return $channels;
    }

    public static function get_push_channel_choices() {
        $choices  = [ '' => '请选择启灵推送通道' ];
        $channels = self::get_available_push_channels();

        if ( empty( $channels ) ) {
            $choices[''] = self::has_push_plugin() ? '当前还没有可用通道' : '未检测到启灵消息推送插件';

            return $choices;
        }

        foreach ( $channels as $channel_id => $channel ) {
            $provider_label        = 'dingtalk' === $channel['provider'] ? '钉钉' : '飞书';
            $status_label          = $channel['enabled'] ? '' : '（已禁用）';
            $choices[ $channel_id ] = $channel['name'] . ' [' . $provider_label . ']' . $status_label;
        }

        return $choices;
    }

    public static function get_selected_push_channel( $settings = null ) {
        $settings   = is_array( $settings ) ? $settings : QS_Protection::get_settings();
        $channel_id = isset( $settings['security_alert_push_channel_id'] ) ? sanitize_key( (string) $settings['security_alert_push_channel_id'] ) : '';
        $channels   = self::get_available_push_channels();

        if ( '' === $channel_id || ! isset( $channels[ $channel_id ] ) ) {
            return [];
        }

        return $channels[ $channel_id ];
    }

    public static function get_email_recipients( $settings = null ) {
        $settings   = is_array( $settings ) ? $settings : QS_Protection::get_settings();
        $raw_value  = isset( $settings['security_alert_email_recipients'] ) ? (string) $settings['security_alert_email_recipients'] : '';
        $raw_items  = preg_split( '/[\r\n,;]+/', $raw_value );
        $recipients = [];

        foreach ( (array) $raw_items as $item ) {
            $email = sanitize_email( trim( (string) $item ) );

            if ( '' !== $email && is_email( $email ) ) {
                $recipients[] = $email;
            }
        }

        $recipients = array_values( array_unique( $recipients ) );

        if ( empty( $recipients ) ) {
            $admin_email = sanitize_email( (string) get_option( 'admin_email', '' ) );

            if ( '' !== $admin_email && is_email( $admin_email ) ) {
                $recipients[] = $admin_email;
            }
        }

        return $recipients;
    }

    public static function trigger_event( $event_key, $title, $detail_lines = [], $context = [], $force = false ) {
        $settings  = QS_Protection::get_settings();
        $event_key = sanitize_key( (string) $event_key );
        $title     = sanitize_text_field( (string) $title );
        $context   = is_array( $context ) ? $context : [];

        if ( ! $force && ! self::is_enabled( $settings ) ) {
            return [
                'skipped' => true,
                'reason'  => 'alert_center_disabled',
            ];
        }

        if ( ! $force && ! self::is_event_enabled( $event_key, $settings ) ) {
            return [
                'skipped' => true,
                'reason'  => 'event_not_enabled',
            ];
        }

        if ( ! $force && self::is_in_cooldown( $event_key, $context, $settings ) ) {
            return [
                'skipped' => true,
                'reason'  => 'cooldown',
            ];
        }

        if ( ! $force ) {
            self::set_cooldown( $event_key, $context, $settings );
        }

        $subject = self::build_subject( $title, $settings );
        $message = self::build_message( $event_key, $title, $detail_lines, $context );

        return self::dispatch_message(
            $subject,
            $message,
            $settings,
            [
                'source'   => self::SOURCE_PREFIX . '-' . $event_key,
                'event'    => $event_key,
                'title'    => $title,
                'context'  => $context,
                'force'    => $force,
            ]
        );
    }

    public static function send_test_alert( $settings = null ) {
        $settings = is_array( $settings ) ? $settings : QS_Protection::get_settings();
        $title    = '安全告警测试消息';
        $details  = [
            '启灵安全防护测试告警，用于验证邮件与飞书/钉钉通道连通性。',
            '当前配置的告警发送链路已完成一次测试投递。',
        ];
        $context  = [
            'event_key'    => 'test',
            'fingerprint'  => 'manual-test',
            'request_path' => QS_Audit::get_request_path(),
        ];

        $subject = self::build_subject( $title, $settings );
        $message = self::build_message( 'test', $title, $details, $context );

        return self::dispatch_message(
            $subject,
            $message,
            $settings,
            [
                'source' => self::SOURCE_PREFIX . '-test',
                'event'  => 'test',
                'title'  => $title,
                'force'  => true,
            ]
        );
    }

    public static function summarize_dispatch_result( $result ) {
        $result   = is_array( $result ) ? $result : [];
        $messages = [];

        if ( ! empty( $result['email']['enabled'] ) ) {
            if ( ! empty( $result['email']['success'] ) ) {
                $messages[] = '邮件已发送至 ' . implode( '、', (array) $result['email']['recipients'] );
            } else {
                $messages[] = '邮件发送失败：' . ( ! empty( $result['email']['message'] ) ? $result['email']['message'] : '未知错误' );
            }
        }

        if ( ! empty( $result['push']['enabled'] ) ) {
            if ( ! empty( $result['push']['success'] ) ) {
                $channel_name = ! empty( $result['push']['channel_name'] ) ? $result['push']['channel_name'] : '推送通道';
                $messages[]   = '推送通道 [' . $channel_name . '] 已发送';
            } else {
                $messages[] = '飞书/钉钉推送失败：' . ( ! empty( $result['push']['message'] ) ? $result['push']['message'] : '未知错误' );
            }
        }

        if ( empty( $messages ) ) {
            $messages[] = '当前没有可用的告警发送方式，请先配置邮件或启灵推送通道。';
        }

        return implode( '；', $messages ) . '。';
    }

    public static function filter_qilinghook_request_args( $request_args, $channel, $message, $args ) {
        $request_args = is_array( $request_args ) ? $request_args : [];
        $args         = is_array( $args ) ? $args : [];
        $source       = isset( $args['source'] ) ? (string) $args['source'] : '';

        if ( 0 !== strpos( $source, self::SOURCE_PREFIX ) ) {
            return $request_args;
        }

        $timeout                = isset( $request_args['timeout'] ) ? absint( $request_args['timeout'] ) : 10;
        $request_args['timeout'] = max( 3, min( 5, $timeout ) );

        return $request_args;
    }

    private static function dispatch_message( $subject, $message, $settings, $meta = [] ) {
        $settings      = is_array( $settings ) ? $settings : QS_Protection::get_settings();
        $meta          = is_array( $meta ) ? $meta : [];
        $email_enabled = ! empty( $settings['security_alert_email_enabled'] );
        $push_enabled  = ! empty( $settings['security_alert_push_enabled'] );
        $result        = [
            'email' => [
                'enabled'    => $email_enabled,
                'success'    => false,
                'recipients' => [],
                'message'    => '',
            ],
            'push'  => [
                'enabled'      => $push_enabled,
                'success'      => false,
                'channel_id'   => '',
                'channel_name' => '',
                'message'      => '',
            ],
        ];

        if ( $email_enabled ) {
            $recipients = self::get_email_recipients( $settings );

            $result['email']['recipients'] = $recipients;

            if ( empty( $recipients ) ) {
                $result['email']['message'] = '没有可用的邮箱收件人。';
            } else {
                $headers = [ 'Content-Type: text/plain; charset=UTF-8' ];
                $sent    = wp_mail( $recipients, $subject, $message, $headers );

                if ( $sent ) {
                    $result['email']['success'] = true;
                    $result['email']['message'] = '邮件发送成功。';
                } else {
                    $result['email']['message'] = 'wp_mail 返回失败。';
                }
            }
        }

        if ( $push_enabled ) {
            $channel = self::get_selected_push_channel( $settings );

            if ( empty( $channel ) ) {
                $result['push']['message'] = self::has_push_plugin() ? '当前未选择有效的启灵推送通道。' : '未检测到启灵消息推送插件。';
            } elseif ( ! function_exists( 'qilinghook_send' ) ) {
                $result['push']['message'] = 'qilinghook_send 不可用。';
            } else {
                $result['push']['channel_id']   = $channel['id'];
                $result['push']['channel_name'] = $channel['name'];

                $push_result = qilinghook_send(
                    $channel['id'],
                    $message,
                    [
                        'source' => isset( $meta['source'] ) ? $meta['source'] : self::SOURCE_PREFIX,
                    ]
                );

                if ( is_wp_error( $push_result ) ) {
                    $result['push']['message'] = $push_result->get_error_message();
                } else {
                    $result['push']['success'] = true;
                    $result['push']['message'] = '推送发送成功。';
                }
            }
        }

        $result['success'] = ( ! empty( $result['email']['success'] ) || ! empty( $result['push']['success'] ) );

        return $result;
    }

    private static function is_event_enabled( $event_key, $settings ) {
        if ( 'test' === $event_key ) {
            return true;
        }

        $settings = is_array( $settings ) ? $settings : QS_Protection::get_settings();
        $enabled  = QS_Protection::parse_list_setting( isset( $settings['security_alert_events'] ) ? $settings['security_alert_events'] : '' );

        return in_array( $event_key, $enabled, true );
    }

    private static function get_cooldown_seconds( $settings ) {
        $settings = is_array( $settings ) ? $settings : QS_Protection::get_settings();
        $minutes  = isset( $settings['security_alert_cooldown_minutes'] ) ? absint( $settings['security_alert_cooldown_minutes'] ) : 10;

        return max( 0, $minutes * MINUTE_IN_SECONDS );
    }

    private static function is_in_cooldown( $event_key, $context, $settings ) {
        $ttl = self::get_cooldown_seconds( $settings );

        if ( $ttl <= 0 ) {
            return false;
        }

        return (bool) get_transient( self::build_cooldown_key( $event_key, $context ) );
    }

    private static function set_cooldown( $event_key, $context, $settings ) {
        $ttl = self::get_cooldown_seconds( $settings );

        if ( $ttl <= 0 ) {
            return;
        }

        set_transient( self::build_cooldown_key( $event_key, $context ), 1, $ttl );
    }

    private static function build_cooldown_key( $event_key, $context ) {
        $context     = is_array( $context ) ? $context : [];
        $fingerprint = isset( $context['fingerprint'] ) ? (string) $context['fingerprint'] : '';

        if ( '' === $fingerprint ) {
            $parts = [
                $event_key,
                isset( $context['ip'] ) ? (string) $context['ip'] : '',
                isset( $context['route'] ) ? (string) $context['route'] : '',
                isset( $context['needle'] ) ? (string) $context['needle'] : '',
                isset( $context['username'] ) ? (string) $context['username'] : '',
            ];

            $fingerprint = implode( '|', $parts );
        }

        return 'qs_security_alert_' . md5( $event_key . '|' . $fingerprint );
    }

    private static function build_subject( $title, $settings ) {
        $settings = is_array( $settings ) ? $settings : QS_Protection::get_settings();
        $prefix   = isset( $settings['security_alert_subject_prefix'] ) ? sanitize_text_field( (string) $settings['security_alert_subject_prefix'] ) : '';
        $prefix   = '' !== $prefix ? $prefix : '[启灵安全告警]';
        $title    = sanitize_text_field( (string) $title );

        return trim( $prefix . ' ' . $title );
    }

    private static function build_message( $event_key, $title, $detail_lines, $context ) {
        $context      = is_array( $context ) ? $context : [];
        $detail_lines = is_array( $detail_lines ) ? $detail_lines : [ $detail_lines ];
        $site_name    = wp_specialchars_decode( get_bloginfo( 'name' ), ENT_QUOTES );
        $site_url     = home_url( '/' );
        $event_label  = 'test' === $event_key ? '测试消息' : self::get_event_label( $event_key );
        $lines        = [
            '启灵安全防护告警',
            '站点：' . sanitize_text_field( (string) $site_name ),
            '地址：' . esc_url_raw( $site_url ),
            '时间：' . date_i18n( get_option( 'date_format' ) . ' ' . get_option( 'time_format' ), current_time( 'timestamp' ) ),
            '事件：' . sanitize_text_field( (string) $event_label ),
            '标题：' . sanitize_text_field( (string) $title ),
        ];

        if ( ! empty( $context['ip'] ) ) {
            $lines[] = '来源 IP：' . sanitize_text_field( (string) $context['ip'] );
        }

        if ( ! empty( $context['username'] ) ) {
            $lines[] = '用户：' . sanitize_text_field( (string) $context['username'] );
        }

        if ( ! empty( $context['route'] ) ) {
            $lines[] = '路由：' . sanitize_text_field( (string) $context['route'] );
        }

        if ( ! empty( $context['request_path'] ) ) {
            $lines[] = '入口：' . sanitize_text_field( (string) $context['request_path'] );
        }

        if ( ! empty( $context['risk_level'] ) ) {
            $lines[] = '风险等级：' . sanitize_text_field( (string) $context['risk_level'] );
        }

        if ( isset( $context['risk_score'] ) && '' !== (string) $context['risk_score'] ) {
            $lines[] = '风险分数：' . absint( $context['risk_score'] );
        }

        if ( isset( $context['issue_count'] ) && '' !== (string) $context['issue_count'] ) {
            $lines[] = '风险数量：' . absint( $context['issue_count'] );
        }

        $detail_lines = array_values(
            array_filter(
                array_map(
                    static function( $line ) {
                        return sanitize_text_field( (string) $line );
                    },
                    $detail_lines
                ),
                static function( $line ) {
                    return '' !== $line;
                }
            )
        );

        if ( ! empty( $detail_lines ) ) {
            $lines[] = '';
            $lines[] = '详情：';

            foreach ( $detail_lines as $line ) {
                $lines[] = '- ' . $line;
            }
        }

        return implode( "\n", $lines );
    }
}
