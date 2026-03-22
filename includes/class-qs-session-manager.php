<?php
/**
 * 安全防护插件 - 用户会话管理
 */
if ( ! defined( 'ABSPATH' ) ) {
    exit;
}

class QS_Session_Manager {

    public static function get_active_sessions( $limit = 200 ) {
        global $wpdb;

        $limit           = max( 1, absint( $limit ) );
        $row_limit       = (int) apply_filters( 'qs_session_overview_row_limit', min( 5000, max( $limit, $limit * 8 ) ), $limit );
        $row_limit       = max( $limit, $row_limit );
        $current_time    = current_time( 'timestamp' );
        $current_user    = get_current_user_id();
        $current_token   = function_exists( 'wp_get_session_token' ) ? wp_get_session_token() : '';
        $current_verify  = '' !== $current_token ? hash( 'sha256', $current_token ) : '';
        $meta_table      = $wpdb->usermeta;
        $rows            = $wpdb->get_results(
            $wpdb->prepare(
                "SELECT user_id, meta_value FROM $meta_table WHERE meta_key = %s ORDER BY umeta_id DESC LIMIT %d",
                'session_tokens',
                $row_limit
            )
        );
        $sessions        = [];

        foreach ( (array) $rows as $row ) {
            $user_id         = isset( $row->user_id ) ? absint( $row->user_id ) : 0;
            $stored_sessions = isset( $row->meta_value ) ? maybe_unserialize( $row->meta_value ) : [];

            if ( ! $user_id || ! is_array( $stored_sessions ) || empty( $stored_sessions ) ) {
                continue;
            }

            $user = get_userdata( $user_id );

            if ( ! $user ) {
                continue;
            }

            foreach ( $stored_sessions as $verifier => $session ) {
                $session    = is_array( $session ) ? $session : [];
                $expiration = isset( $session['expiration'] ) ? absint( $session['expiration'] ) : 0;

                if ( $expiration <= $current_time ) {
                    continue;
                }

                $sessions[] = [
                    'user_id'        => $user_id,
                    'user_login'     => $user->user_login,
                    'display_name'   => $user->display_name,
                    'user_email'     => $user->user_email,
                    'roles'          => self::get_readable_roles( $user ),
                    'verifier'       => sanitize_text_field( (string) $verifier ),
                    'login'          => isset( $session['login'] ) ? absint( $session['login'] ) : 0,
                    'expiration'     => $expiration,
                    'ip'             => isset( $session['ip'] ) ? sanitize_text_field( (string) $session['ip'] ) : '',
                    'ua'             => isset( $session['ua'] ) ? sanitize_text_field( (string) $session['ua'] ) : '',
                    'ua_summary'     => self::summarize_user_agent( isset( $session['ua'] ) ? (string) $session['ua'] : '' ),
                    'is_current'     => $user_id === $current_user && '' !== $current_verify && hash_equals( $current_verify, (string) $verifier ),
                ];
            }
        }

        usort(
            $sessions,
            static function( $a, $b ) {
                $a_login = isset( $a['login'] ) ? absint( $a['login'] ) : 0;
                $b_login = isset( $b['login'] ) ? absint( $b['login'] ) : 0;

                if ( $a_login === $b_login ) {
                    return ( isset( $b['expiration'] ) ? absint( $b['expiration'] ) : 0 ) <=> ( isset( $a['expiration'] ) ? absint( $a['expiration'] ) : 0 );
                }

                return $b_login <=> $a_login;
            }
        );

        if ( count( $sessions ) > $limit ) {
            $sessions = array_slice( $sessions, 0, $limit );
        }

        return $sessions;
    }

    public static function get_active_session_summary( $sessions = [] ) {
        $sessions   = is_array( $sessions ) ? $sessions : [];
        $user_ids   = [];
        $current    = 0;

        foreach ( $sessions as $session ) {
            if ( empty( $session['user_id'] ) ) {
                continue;
            }

            $user_ids[ absint( $session['user_id'] ) ] = true;

            if ( ! empty( $session['is_current'] ) ) {
                $current++;
            }
        }

        return [
            'sessions'         => count( $sessions ),
            'users'            => count( $user_ids ),
            'current_sessions' => $current,
        ];
    }

    public static function enforce_max_sessions( $user_id, $max_sessions, $preserve_current = true ) {
        $user_id         = absint( $user_id );
        $max_sessions    = max( 1, absint( $max_sessions ) );
        $preserve_current = (bool) $preserve_current;

        if ( ! $user_id ) {
            return 0;
        }

        $sessions      = self::get_user_session_tokens( $user_id );
        $active        = self::normalize_active_sessions( $sessions );
        $before_count  = count( $active );

        if ( $before_count <= $max_sessions ) {
            if ( $before_count !== count( (array) $sessions ) ) {
                self::store_user_session_tokens( $user_id, $active );
            }

            return 0;
        }

        $preserve_verifier = '';
        if ( $preserve_current && get_current_user_id() === $user_id ) {
            $preserve_verifier = self::get_current_session_verifier();
        }

        uasort(
            $active,
            static function( $a, $b ) {
                $a_login = isset( $a['login'] ) ? absint( $a['login'] ) : 0;
                $b_login = isset( $b['login'] ) ? absint( $b['login'] ) : 0;

                if ( $a_login === $b_login ) {
                    $a_expiration = isset( $a['expiration'] ) ? absint( $a['expiration'] ) : 0;
                    $b_expiration = isset( $b['expiration'] ) ? absint( $b['expiration'] ) : 0;

                    return $a_expiration <=> $b_expiration;
                }

                return $a_login <=> $b_login;
            }
        );

        foreach ( array_keys( $active ) as $verifier ) {
            if ( count( $active ) <= $max_sessions ) {
                break;
            }

            if ( '' !== $preserve_verifier && hash_equals( (string) $preserve_verifier, (string) $verifier ) ) {
                continue;
            }

            unset( $active[ $verifier ] );
        }

        if ( count( $active ) > $max_sessions ) {
            foreach ( array_keys( $active ) as $verifier ) {
                if ( count( $active ) <= $max_sessions ) {
                    break;
                }

                unset( $active[ $verifier ] );
            }
        }

        self::store_user_session_tokens( $user_id, $active );

        return max( 0, $before_count - count( $active ) );
    }

    public static function destroy_session( $user_id, $verifier ) {
        $user_id  = absint( $user_id );
        $verifier = sanitize_text_field( (string) $verifier );

        if ( ! $user_id || '' === $verifier ) {
            return false;
        }

        $sessions = self::get_user_session_tokens( $user_id );

        if ( ! isset( $sessions[ $verifier ] ) ) {
            return false;
        }

        unset( $sessions[ $verifier ] );

        self::store_user_session_tokens( $user_id, $sessions );

        return true;
    }

    public static function destroy_user_sessions( $user_id, $preserve_current = false ) {
        $user_id          = absint( $user_id );
        $preserve_current = (bool) $preserve_current;

        if ( ! $user_id ) {
            return 0;
        }

        $sessions        = self::get_user_session_tokens( $user_id );
        $current_verify  = self::get_current_session_verifier();
        $preserved       = [];
        $deleted_count   = count( $sessions );

        if ( $preserve_current && get_current_user_id() === $user_id && '' !== $current_verify && isset( $sessions[ $current_verify ] ) ) {
            $preserved     = [ $current_verify => $sessions[ $current_verify ] ];
            $deleted_count = max( 0, $deleted_count - 1 );
        }

        self::store_user_session_tokens( $user_id, $preserved );

        return $deleted_count;
    }

    public static function destroy_all_sessions_except_current() {
        global $wpdb;

        $meta_table      = $wpdb->usermeta;
        $rows            = $wpdb->get_results(
            $wpdb->prepare(
                "SELECT user_id, meta_value FROM $meta_table WHERE meta_key = %s",
                'session_tokens'
            )
        );
        $current_user    = get_current_user_id();
        $current_verify  = self::get_current_session_verifier();
        $affected_users  = 0;
        $deleted_sessions = 0;

        foreach ( (array) $rows as $row ) {
            $user_id  = isset( $row->user_id ) ? absint( $row->user_id ) : 0;
            $sessions = isset( $row->meta_value ) ? maybe_unserialize( $row->meta_value ) : [];

            if ( ! $user_id || ! is_array( $sessions ) || empty( $sessions ) ) {
                continue;
            }

            $preserved = [];

            if ( $user_id === $current_user && '' !== $current_verify && isset( $sessions[ $current_verify ] ) ) {
                $preserved = [ $current_verify => $sessions[ $current_verify ] ];
            }

            $removed = count( $sessions ) - count( $preserved );

            if ( $removed <= 0 ) {
                continue;
            }

            self::store_user_session_tokens( $user_id, $preserved );
            $affected_users++;
            $deleted_sessions += $removed;
        }

        return [
            'users'    => $affected_users,
            'sessions' => $deleted_sessions,
        ];
    }

    public static function format_session_time( $timestamp ) {
        $timestamp = absint( $timestamp );

        if ( $timestamp <= 0 ) {
            return '未知';
        }

        return wp_date( 'Y-m-d H:i:s', $timestamp );
    }

    private static function get_user_session_tokens( $user_id ) {
        $sessions = get_user_meta( absint( $user_id ), 'session_tokens', true );

        return is_array( $sessions ) ? $sessions : [];
    }

    private static function store_user_session_tokens( $user_id, $sessions ) {
        $user_id  = absint( $user_id );
        $sessions = is_array( $sessions ) ? $sessions : [];

        if ( empty( $sessions ) ) {
            delete_user_meta( $user_id, 'session_tokens' );
            return;
        }

        update_user_meta( $user_id, 'session_tokens', $sessions );
    }

    private static function get_current_session_verifier() {
        $token = function_exists( 'wp_get_session_token' ) ? wp_get_session_token() : '';

        return '' !== $token ? hash( 'sha256', $token ) : '';
    }

    private static function normalize_active_sessions( $sessions ) {
        $sessions      = is_array( $sessions ) ? $sessions : [];
        $current_time  = current_time( 'timestamp' );
        $normalized    = [];

        foreach ( $sessions as $verifier => $session ) {
            $session = is_array( $session ) ? $session : [];

            if ( '' === (string) $verifier ) {
                continue;
            }

            $expiration = isset( $session['expiration'] ) ? absint( $session['expiration'] ) : 0;

            if ( $expiration <= $current_time ) {
                continue;
            }

            $normalized[ (string) $verifier ] = $session;
        }

        return $normalized;
    }

    private static function get_readable_roles( $user ) {
        $roles = [];
        $wp_roles = function_exists( 'wp_roles' ) ? wp_roles() : null;

        foreach ( (array) $user->roles as $role ) {
            if ( function_exists( 'translate_user_role' ) ) {
                $role_name = $role;

                if ( $wp_roles && isset( $wp_roles->roles[ $role ]['name'] ) ) {
                    $role_name = $wp_roles->roles[ $role ]['name'];
                }

                $roles[] = translate_user_role( $role_name );
            } else {
                $roles[] = $role;
            }
        }

        return empty( $roles ) ? [ '未分配角色' ] : $roles;
    }

    private static function summarize_user_agent( $user_agent ) {
        $user_agent = trim( sanitize_text_field( (string) $user_agent ) );

        if ( '' === $user_agent ) {
            return '未知设备';
        }

        $summary = [];

        foreach ( [
            'Chrome'  => 'Chrome',
            'Firefox' => 'Firefox',
            'Safari'  => 'Safari',
            'Edg/'    => 'Edge',
            'Opera'   => 'Opera',
            'MSIE'    => 'IE',
        ] as $needle => $label ) {
            if ( false !== strpos( $user_agent, $needle ) ) {
                $summary[] = $label;
                break;
            }
        }

        foreach ( [
            'Windows' => 'Windows',
            'Mac OS X' => 'macOS',
            'iPhone'  => 'iPhone',
            'iPad'    => 'iPad',
            'Android' => 'Android',
            'Linux'   => 'Linux',
        ] as $needle => $label ) {
            if ( false !== strpos( $user_agent, $needle ) ) {
                $summary[] = $label;
                break;
            }
        }

        if ( empty( $summary ) ) {
            return function_exists( 'mb_substr' ) ? mb_substr( $user_agent, 0, 80 ) : substr( $user_agent, 0, 80 );
        }

        return implode( ' / ', array_unique( $summary ) );
    }
}
