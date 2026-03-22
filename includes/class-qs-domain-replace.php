<?php
/**
 * 安全防护插件 - 域名安全替换（序列化安全）
 */
if ( ! defined( 'ABSPATH' ) ) {
    exit;
}

class QS_Domain_Replace {

    public static function get_targets() {
        global $wpdb;

        $targets = [
            'options' => [
                'label'   => 'wp_options（站点与插件设置）',
                'desc'    => '站点配置、主题/插件设置等（option_value）',
                'table'   => $wpdb->options,
                'primary' => 'option_id',
                'columns' => [ 'option_value' ],
                'default' => true,
            ],
            'postmeta' => [
                'label'   => 'wp_postmeta（文章/页面元数据）',
                'desc'    => '页面模块、SEO、自定义字段（meta_value）',
                'table'   => $wpdb->postmeta,
                'primary' => 'meta_id',
                'columns' => [ 'meta_value' ],
                'default' => true,
            ],
            'usermeta' => [
                'label'   => 'wp_usermeta（用户元数据）',
                'desc'    => '用户资料、偏好设置（meta_value）',
                'table'   => $wpdb->usermeta,
                'primary' => 'umeta_id',
                'columns' => [ 'meta_value' ],
                'default' => true,
            ],
            'posts' => [
                'label'   => 'wp_posts（正文与摘要）',
                'desc'    => '文章/页面正文与摘要（post_content/post_excerpt）',
                'table'   => $wpdb->posts,
                'primary' => 'ID',
                'columns' => [ 'post_content', 'post_excerpt' ],
                'default' => true,
            ],
            'attachments' => [
                'label'   => 'wp_posts（媒体库附件链接）',
                'desc'    => '媒体库图片/文件的附件地址（guid，仅限 attachment）',
                'table'   => $wpdb->posts,
                'primary' => 'ID',
                'columns' => [ 'guid' ],
                'where'   => [
                    [
                        'column' => 'post_type',
                        'value'  => 'attachment',
                        'format' => '%s',
                    ],
                ],
                'default' => true,
            ],
            'attachmentmeta' => [
                'label'   => 'wp_postmeta（媒体附件元数据）',
                'desc'    => '媒体附件路径与元数据（_wp_attached_file / _wp_attachment_metadata / _wp_attachment_backup_sizes）',
                'table'   => $wpdb->postmeta,
                'primary' => 'meta_id',
                'columns' => [ 'meta_value' ],
                'where'   => [
                    [
                        'column'   => 'meta_key',
                        'operator' => 'IN',
                        'value'    => [ '_wp_attached_file', '_wp_attachment_metadata', '_wp_attachment_backup_sizes' ],
                        'format'   => '%s',
                    ],
                ],
                'default' => true,
            ],
            'comments' => [
                'label'   => 'wp_comments（评论内容）',
                'desc'    => '评论正文与作者网址（comment_content/comment_author_url）',
                'table'   => $wpdb->comments,
                'primary' => 'comment_ID',
                'columns' => [ 'comment_content', 'comment_author_url' ],
                'default' => false,
            ],
            'commentmeta' => [
                'label'   => 'wp_commentmeta（评论元数据）',
                'desc'    => '评论附加信息（meta_value）',
                'table'   => isset( $wpdb->commentmeta ) ? $wpdb->commentmeta : '',
                'primary' => 'meta_id',
                'columns' => [ 'meta_value' ],
                'default' => false,
            ],
            'termmeta' => [
                'label'   => 'wp_termmeta（分类/标签元数据）',
                'desc'    => '分类/标签附加信息（meta_value）',
                'table'   => isset( $wpdb->termmeta ) ? $wpdb->termmeta : '',
                'primary' => 'meta_id',
                'columns' => [ 'meta_value' ],
                'default' => false,
            ],
            'links' => [
                'label'   => 'wp_links（链接管理）',
                'desc'    => '老的友链链接表（link_url）',
                'table'   => isset( $wpdb->links ) ? $wpdb->links : '',
                'primary' => 'link_id',
                'columns' => [ 'link_url', 'link_image', 'link_rss' ],
                'default' => false,
            ],
        ];

        self::append_qilingshop_targets( $targets );
        self::append_qibbs_targets( $targets );

        foreach ( $targets as $key => $target ) {
            if ( empty( $target['table'] ) ) {
                unset( $targets[ $key ] );
            }
        }

        return apply_filters( 'qs_domain_replace_targets', $targets );
    }

    public static function get_target( $key ) {
        $targets = self::get_targets();
        return isset( $targets[ $key ] ) ? $targets[ $key ] : null;
    }

    public static function build_search_pairs( $old, $new, $include_protocols = true ) {
        $old = trim( (string) $old );
        $new = trim( (string) $new );

        $pairs = [];
        $add_pair = static function( $search, $replace ) use ( &$pairs ) {
            $search  = (string) $search;
            $replace = (string) $replace;
            if ( $search === '' || $search === $replace ) {
                return;
            }
            $pairs[ $search ] = $replace;
        };

        $add_pair( $old, $new );

        $old_host = self::extract_host( $old );
        $new_host = self::extract_host( $new );

        if ( $old_host && $new_host ) {
            $add_pair( $old_host, $new_host );

            if ( $include_protocols ) {
                $add_pair( 'http://' . $old_host, 'http://' . $new_host );
                $add_pair( 'https://' . $old_host, 'https://' . $new_host );
                $add_pair( '//' . $old_host, '//' . $new_host );
                $add_pair( 'http:\\/\\/' . $old_host, 'http:\\/\\/' . $new_host );
                $add_pair( 'https:\\/\\/' . $old_host, 'https:\\/\\/' . $new_host );
            }
        }

        return [
            'search'  => array_keys( $pairs ),
            'replace' => array_values( $pairs ),
            'needle'  => $old_host ? $old_host : $old,
        ];
    }

    public static function replace_in_target( $target, $search, $replace, $last_id = 0, $limit = 200, $dry_run = true, $needle = '' ) {
        global $wpdb;

        $table   = isset( $target['table'] ) ? $target['table'] : '';
        $primary = isset( $target['primary'] ) ? $target['primary'] : '';
        $columns = isset( $target['columns'] ) ? (array) $target['columns'] : [];

        if ( $table === '' || $primary === '' || empty( $columns ) ) {
            return [
                'error' => '目标配置无效',
            ];
        }

        $primary_sql = self::esc_identifier( $primary );
        $column_sqls = array_map( [ __CLASS__, 'esc_identifier' ], $columns );
        $select_sql  = implode( ', ', array_merge( [ $primary_sql ], $column_sqls ) );

        $where_sqls  = [ $primary_sql . ' > %d' ];
        $params      = [ (int) $last_id ];

        $extra_wheres = isset( $target['where'] ) && is_array( $target['where'] ) ? $target['where'] : [];
        foreach ( $extra_wheres as $condition ) {
            if ( ! is_array( $condition ) || empty( $condition['column'] ) || ! array_key_exists( 'value', $condition ) ) {
                continue;
            }

            $column_sql = self::esc_identifier( $condition['column'] );
            $operator   = isset( $condition['operator'] ) ? strtoupper( (string) $condition['operator'] ) : '=';
            $format     = isset( $condition['format'] ) && in_array( $condition['format'], [ '%s', '%d', '%f' ], true )
                ? (string) $condition['format']
                : '%s';
            $value      = $condition['value'];

            if ( in_array( $operator, [ 'IN', 'NOT IN' ], true ) ) {
                if ( ! is_array( $value ) || empty( $value ) ) {
                    continue;
                }

                $placeholders = [];
                foreach ( array_values( $value ) as $item ) {
                    $placeholders[] = $format;
                    $params[]       = $item;
                }

                $where_sqls[] = $column_sql . ' ' . $operator . ' (' . implode( ', ', $placeholders ) . ')';
                continue;
            }

            if ( ! in_array( $operator, [ '=', '!=', '<>', 'LIKE', 'NOT LIKE' ], true ) ) {
                $operator = '=';
            }

            $where_sqls[] = $column_sql . ' ' . $operator . ' ' . $format;
            $params[]     = $value;
        }

        $needle = (string) $needle;
        if ( $needle !== '' ) {
            $like = '%' . $wpdb->esc_like( $needle ) . '%';
            $like_sql = [];
            foreach ( $column_sqls as $column_sql ) {
                $like_sql[] = $column_sql . ' LIKE %s';
                $params[] = $like;
            }
            $where_sqls[] = '(' . implode( ' OR ', $like_sql ) . ')';
        }

        $where_sql = implode( ' AND ', $where_sqls );
        $limit = max( 20, min( 1000, (int) $limit ) );

        $sql = "SELECT {$select_sql} FROM {$table} WHERE {$where_sql} ORDER BY {$primary_sql} ASC LIMIT %d";
        $params[] = $limit;

        $rows = $wpdb->get_results( $wpdb->prepare( $sql, $params ), ARRAY_A );

        $stats = [
            'scanned'      => 0,
            'updated'      => 0,
            'replacements' => 0,
            'next_id'      => (int) $last_id,
            'done'         => true,
        ];

        if ( empty( $rows ) ) {
            return $stats;
        }

        foreach ( $rows as $row ) {
            $stats['scanned']++;
            $row_id = isset( $row[ $primary ] ) ? (int) $row[ $primary ] : 0;
            if ( $row_id > $stats['next_id'] ) {
                $stats['next_id'] = $row_id;
            }

            $update_data = [];
            $update_fmt  = [];
            $row_replaced = 0;

            foreach ( $columns as $column ) {
                $original = isset( $row[ $column ] ) ? $row[ $column ] : '';
                $changed = false;
                $replaced = 0;
                $updated_value = self::safe_replace_value( $original, $search, $replace, $changed, $replaced );

                if ( $changed ) {
                    $update_data[ $column ] = $updated_value;
                    $update_fmt[] = '%s';
                    $row_replaced += $replaced;
                }
            }

            if ( ! empty( $update_data ) ) {
                $stats['replacements'] += $row_replaced;
                if ( ! $dry_run ) {
                    $wpdb->update(
                        $table,
                        $update_data,
                        [ $primary => $row_id ],
                        $update_fmt,
                        [ '%d' ]
                    );
                }
                $stats['updated']++;
            }
        }

        $stats['done'] = count( $rows ) < $limit;
        return $stats;
    }

    private static function safe_replace_value( $value, $search, $replace, &$changed, &$replaced ) {
        $changed  = false;
        $replaced = 0;

        if ( is_string( $value ) ) {
            if ( function_exists( 'is_serialized' ) && is_serialized( $value ) ) {
                $unserialized = self::try_unserialize_no_classes( $value );
                if ( $unserialized === null ) {
                    $fixed = self::fix_serialized_string_lengths( $value );
                    if ( $fixed !== $value ) {
                        $unserialized = self::try_unserialize_no_classes( $fixed );
                    }
                }

                if ( is_array( $unserialized ) ) {
                    $new_data = self::recursive_replace( $unserialized, $search, $replace, $changed, $replaced, 0 );
                    if ( $changed ) {
                        return maybe_serialize( $new_data );
                    }
                    return $value;
                }

                // 如果是对象或无法解析，保持原值
                return $value;
            }

            $new_value = str_replace( $search, $replace, $value, $count );
            if ( $count > 0 ) {
                $changed  = true;
                $replaced = $count;
                return $new_value;
            }
        }

        return $value;
    }

    private static function recursive_replace( $data, $search, $replace, &$changed, &$replaced, $depth ) {
        if ( $depth > 50 ) {
            return $data;
        }

        if ( is_string( $data ) ) {
            $new_value = str_replace( $search, $replace, $data, $count );
            if ( $count > 0 ) {
                $changed  = true;
                $replaced += $count;
                return $new_value;
            }
            return $data;
        }

        if ( is_array( $data ) ) {
            foreach ( $data as $key => $value ) {
                $data[ $key ] = self::recursive_replace( $value, $search, $replace, $changed, $replaced, $depth + 1 );
            }
            return $data;
        }

        return $data;
    }

    private static function try_unserialize_no_classes( $value ) {
        if ( ! is_string( $value ) || $value === '' ) {
            return null;
        }

        if ( $value === 'b:0;' ) {
            return false;
        }

        $result = @unserialize( $value, [ 'allowed_classes' => false ] );
        if ( $result === false ) {
            return null;
        }

        return $result;
    }

    private static function fix_serialized_string_lengths( $value ) {
        if ( ! is_string( $value ) || $value === '' ) {
            return $value;
        }

        $fixed = preg_replace_callback(
            '/s:(\\d+):\"(.*?)\";/s',
            static function ( $matches ) {
                return 's:' . strlen( $matches[2] ) . ':"' . $matches[2] . '";';
            },
            $value
        );

        return is_string( $fixed ) ? $fixed : $value;
    }

    private static function extract_host( $value ) {
        $value = trim( (string) $value );
        if ( $value === '' ) {
            return '';
        }

        $value = preg_replace( '#^https?://#i', '', $value );
        $value = preg_replace( '#^//#', '', $value );
        $value = preg_replace( '#/.*$#', '', $value );

        return trim( $value );
    }

    private static function append_qilingshop_targets( &$targets ) {
        global $wpdb;

        $shop_prefix = $wpdb->prefix . 'qls_shop_';
        $shop_targets = [
            'qilingshop_products' => [
                'label'   => '启灵积分商城（商品图片/详情）',
                'desc'    => '实物商城商品主图、相册与详情内容（products.main_image / gallery / content）',
                'table'   => $shop_prefix . 'products',
                'primary' => 'id',
                'columns' => [ 'main_image', 'gallery', 'content' ],
                'default' => false,
            ],
            'qilingshop_skus' => [
                'label'   => '启灵积分商城（SKU 图片）',
                'desc'    => '商品 SKU 图（product_skus.image）',
                'table'   => $shop_prefix . 'product_skus',
                'primary' => 'id',
                'columns' => [ 'image' ],
                'default' => false,
            ],
            'qilingshop_attribute_values' => [
                'label'   => '启灵积分商城（规格值图片）',
                'desc'    => '颜色/规格值图片（product_attribute_values.image）',
                'table'   => $shop_prefix . 'product_attribute_values',
                'primary' => 'id',
                'columns' => [ 'image' ],
                'default' => false,
            ],
            'qilingshop_categories' => [
                'label'   => '启灵积分商城（商品分类图）',
                'desc'    => '实物商城分类图片（categories.image）',
                'table'   => $shop_prefix . 'categories',
                'primary' => 'id',
                'columns' => [ 'image' ],
                'default' => false,
            ],
            'qilingshop_order_items' => [
                'label'   => '启灵积分商城（订单商品快照图）',
                'desc'    => '订单里保存的商品图片快照（order_items.image）',
                'table'   => $shop_prefix . 'order_items',
                'primary' => 'id',
                'columns' => [ 'image' ],
                'default' => false,
            ],
            'qilingshop_reviews' => [
                'label'   => '启灵积分商城（评价晒图）',
                'desc'    => '商品评价/晒单图片（reviews.images）',
                'table'   => $shop_prefix . 'reviews',
                'primary' => 'id',
                'columns' => [ 'images' ],
                'default' => false,
            ],
        ];

        foreach ( $shop_targets as $key => $target ) {
            if ( empty( $target['table'] ) || ! self::table_exists( $target['table'] ) ) {
                continue;
            }

            $targets[ $key ] = $target;
        }
    }

    private static function append_qibbs_targets( &$targets ) {
        global $wpdb;

        $community_prefix = $wpdb->prefix . 'qibbs_';
        $community_targets = [
            'qibbs_posts' => [
                'label'   => '启灵社区（动态内容）',
                'desc'    => '社区动态正文（qibbs_posts.content）',
                'table'   => $community_prefix . 'posts',
                'primary' => 'id',
                'columns' => [ 'content' ],
                'default' => false,
            ],
            'qibbs_comments' => [
                'label'   => '启灵社区（评论内容）',
                'desc'    => '社区评论正文（qibbs_comments.content）',
                'table'   => $community_prefix . 'comments',
                'primary' => 'id',
                'columns' => [ 'content' ],
                'default' => false,
            ],
            'qibbs_messages' => [
                'label'   => '启灵社区（私信内容）',
                'desc'    => '社区私信内容（qibbs_messages.content）',
                'table'   => $community_prefix . 'messages',
                'primary' => 'id',
                'columns' => [ 'content' ],
                'default' => false,
            ],
            'qibbs_notifications' => [
                'label'   => '启灵社区（通知内容）',
                'desc'    => '社区通知内容（qibbs_notifications.content）',
                'table'   => $community_prefix . 'notifications',
                'primary' => 'id',
                'columns' => [ 'content' ],
                'default' => false,
            ],
            'qibbs_forums' => [
                'label'   => '启灵社区（圈子封面图）',
                'desc'    => '社区圈子图标与封面图片（qibbs_forums.icon / cover_image）',
                'table'   => $community_prefix . 'forums',
                'primary' => 'id',
                'columns' => [ 'icon', 'cover_image' ],
                'default' => false,
            ],
            'qibbs_media' => [
                'label'   => '启灵社区（媒体附件链接）',
                'desc'    => '社区上传的图片/视频地址（qibbs_media.file_url）',
                'table'   => $community_prefix . 'media',
                'primary' => 'id',
                'columns' => [ 'file_url' ],
                'default' => false,
            ],
            'qibbs_tickets' => [
                'label'   => '启灵社区（工单内容）',
                'desc'    => '社区工单正文（qibbs_tickets.content）',
                'table'   => $community_prefix . 'tickets',
                'primary' => 'id',
                'columns' => [ 'content' ],
                'default' => false,
            ],
            'qibbs_ticket_replies' => [
                'label'   => '启灵社区（工单回复）',
                'desc'    => '社区工单回复正文（qibbs_ticket_replies.content）',
                'table'   => $community_prefix . 'ticket_replies',
                'primary' => 'id',
                'columns' => [ 'content' ],
                'default' => false,
            ],
            'qibbs_user_meta' => [
                'label'   => '启灵社区（用户扩展资料）',
                'desc'    => '社区用户扩展资料（qibbs_user_meta.meta_value）',
                'table'   => $community_prefix . 'user_meta',
                'primary' => 'id',
                'columns' => [ 'meta_value' ],
                'default' => false,
            ],
            'qibbs_risk_logs' => [
                'label'   => '启灵社区（风控日志元数据）',
                'desc'    => '社区风控日志附加元数据（qibbs_risk_logs.meta）',
                'table'   => $community_prefix . 'risk_logs',
                'primary' => 'id',
                'columns' => [ 'meta' ],
                'default' => false,
            ],
        ];

        foreach ( $community_targets as $key => $target ) {
            if ( empty( $target['table'] ) || ! self::table_exists( $target['table'] ) ) {
                continue;
            }

            $targets[ $key ] = $target;
        }
    }

    private static function table_exists( $table_name ) {
        global $wpdb;

        static $cache = [];

        $table_name = (string) $table_name;
        if ( $table_name === '' ) {
            return false;
        }

        if ( array_key_exists( $table_name, $cache ) ) {
            return $cache[ $table_name ];
        }

        $result = $wpdb->get_var(
            $wpdb->prepare(
                'SHOW TABLES LIKE %s',
                $wpdb->esc_like( $table_name )
            )
        );

        $cache[ $table_name ] = is_string( $result ) && $result !== '';

        return $cache[ $table_name ];
    }

    private static function esc_identifier( $value ) {
        return '`' . str_replace( '`', '', (string) $value ) . '`';
    }
}
