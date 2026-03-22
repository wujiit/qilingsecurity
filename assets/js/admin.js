jQuery(document).ready(function ($) {
    const payload = (typeof window !== 'undefined' && window.qsData && typeof window.qsData === 'object') ? window.qsData : {};
    const $startBtn = $('#qs-start-scan');
    const $progressArea = $('#qs-progress-area');
    const $currentTask = $('#qs-current-task');
    const $progressFill = $('#qs-progress-fill');
    const $progressText = $('#qs-progress-text');
    const $resultsPanel = $('#qs-results-panel');
    const $resultsBody = $('#qs-results-body');
    const $lastScanStatus = $('#qs-last-scan-status');
    const scanSteps = Array.isArray(payload.scanSteps) ? payload.scanSteps : [];
    const proxyPresets = payload.proxyPresets && typeof payload.proxyPresets === 'object' ? payload.proxyPresets : {};
    const defaultProxyHeaders = Array.isArray(payload.defaultProxyHeaders) ? payload.defaultProxyHeaders : [];
    const ajaxurl = typeof payload.ajaxurl === 'string' ? payload.ajaxurl : '';
    const nonce = typeof payload.nonce === 'string' ? payload.nonce : '';
    const resultStatusMeta = {
        open: { label: '待处理', className: 'warning' },
        resolved: { label: '已处理', className: 'success' },
        ignored: { label: '已忽略', className: 'neutral' }
    };

    let currentScanId = 0;

    try {
        initProxyPresetHelper();
    } catch (err) {
        console.error('Qiling Security proxy preset init failed:', err);
    }
    try {
        initDomainReplace();
    } catch (err) {
        console.error('Qiling Security domain replace init failed:', err);
    }
    activateInitialTab();

    $startBtn.on('click', function () {
        startFullScan();
    });

    function startFullScan() {
        if ($startBtn.prop('disabled')) {
            return;
        }

        if (!scanSteps.length) {
            handleError('没有可执行的扫描步骤，请检查插件配置。');
            return;
        }

        $startBtn.prop('disabled', true).text('正在体检中...');
        $progressArea.show();
        $resultsPanel.show();
        $resultsBody.empty();
        $progressFill.css({ width: '5%', background: '' });
        $currentTask.text('正在初始化扫描任务...');
        $lastScanStatus.text('扫描中...').css('color', '#f59e0b');

        $.post(ajaxurl, {
            action: 'qs_run_scan',
            nonce: nonce,
            step: 'start'
        }, function (response) {
            if (response.success && response.data.scan_id) {
                currentScanId = response.data.scan_id;
                runStep(0);
            } else {
                handleError('初始化任务失败：' + (response.data || '未知原因'));
            }
        }).fail(function (xhr) {
            handleError('网络错误：' + xhr.statusText);
        });
    }

    function runStep(index, stepStats) {
        if (index >= scanSteps.length) {
            finishScan();
            return;
        }

        const step = scanSteps[index];
        const totalSteps = scanSteps.length;
        const progressPercent = 5 + ((index / totalSteps) * 90);
        const stats = stepStats && typeof stepStats === 'object'
            ? stepStats
            : { issues: 0, scanned: 0, truncated: false };

        const stepHint = stats.scanned > 0
            ? ` 已扫描 ${stats.scanned} 项，命中 ${stats.issues} 项。`
            : '';

        $currentTask.text(`[${index + 1}/${totalSteps}] 正在执行：${step.name}...这可能需要一些时间，请勿关闭页面。${stepHint}`);
        $progressFill.css('width', progressPercent + '%');
        $progressText.text(`已完成 ${index}/${totalSteps} 阶段`);

        $.post(ajaxurl, {
            action: 'qs_run_scan',
            nonce: nonce,
            scan_id: currentScanId,
            step: step.id
        }, function (response) {
            if (!response.success) {
                handleError(`执行步骤 [${step.name}] 时报错：` + (response.data || '未知错误'));
                return;
            }

            const payload = response.data || {};
            const progress = payload.progress && typeof payload.progress === 'object' ? payload.progress : {};
            const nextStats = {
                issues: Number(progress.matches || 0),
                scanned: Number(progress.scanned || 0),
                truncated: Boolean(progress.truncated)
            };

            if (!payload.done) {
                const progressLabel = progress.label ? ` ${progress.label}` : '';
                $currentTask.text(`[${index + 1}/${totalSteps}] 正在执行：${step.name}...${progressLabel}`);
                runStep(index, nextStats);
                return;
            }

            if (nextStats.issues > 0) {
                const suffix = nextStats.truncated ? ' 已达到扫描上限，结果可能并非全量。' : '';
                appendResultRow('warning', step.id, `发现在 ${step.name} 中存在 ${nextStats.issues} 个风险项！刷新后可查看完整报告。${suffix}`, '查看报告');
            } else if (nextStats.truncated) {
                appendResultRow('info', step.id, `${step.name} 已达到扫描上限，当前未发现异常，但本轮只完成了部分扫描。建议调大扫描上限后重试。`, '部分完成');
            } else {
                appendResultRow('success', step.id, `${step.name} 未发现异常风险。`, '-');
            }

            runStep(index + 1);
        }).fail(function (xhr) {
            if (xhr.status === 504) {
                appendResultRow('info', step.id, `${step.name} 执行超时，已跳过并继续下一项。建议调大扫描上限或缩小排除路径。`, '已跳过');
                runStep(index + 1);
                return;
            }

            handleError(`网络错误：${xhr.statusText}`);
        });
    }

    function finishScan() {
        const totalSteps = scanSteps.length;

        $currentTask.text('体检完成！');
        $progressFill.css({ width: '100%', background: '#10b981' });
        $progressText.text(`${totalSteps} / ${totalSteps} 阶段`);
        $startBtn.prop('disabled', false).text('🚀 重新体检');

        $.post(ajaxurl, {
            action: 'qs_run_scan',
            nonce: nonce,
            scan_id: currentScanId,
            step: 'finish'
        }, function () {
            $lastScanStatus.text('体检完毕，正在生成报表...').css('color', '#10b981');
            reloadCurrentTab(800);
        }).fail(function () {
            $lastScanStatus.text('体检完成，但报告刷新失败，请手动刷新页面。').css('color', '#ef4444');
        });
    }

    function handleError(msg) {
        $currentTask.text('体检中断或发生错误！');
        $progressFill.css('background', '#ef4444');
        $startBtn.prop('disabled', false).text('🚀 重新体检');
        appendResultRow('critical', 'ERROR', msg, '查看日志');
    }

    function appendResultRow(severity, type, desc, actionText) {
        let badgeClass = 'qs-badge';
        let severityText = '';
        let actionHtml = actionText && actionText !== '-' ? actionText : '-';

        if (severity === 'critical') {
            badgeClass += ' critical';
            severityText = '高危';
            actionHtml = `<button class="button button-small" type="button" disabled>${actionHtml}</button>`;
        } else if (severity === 'warning') {
            badgeClass += ' warning';
            severityText = '警告';
            actionHtml = `<button class="button button-small" type="button" disabled>${actionHtml}</button>`;
        } else if (severity === 'success') {
            severityText = '安全';
            $resultsBody.append(`
                <tr>
                    <td><span class="qs-badge" style="background:#10b981;">${severityText}</span></td>
                    <td>${type}</td>
                    <td>-</td>
                    <td style="color:#10b981;">${desc}</td>
                    <td>-</td>
                </tr>
            `);
            return;
        } else {
            severityText = '提示';
            $resultsBody.append(`
                <tr>
                    <td><span class="qs-badge" style="background:#3b82f6;">${severityText}</span></td>
                    <td>${type}</td>
                    <td>-</td>
                    <td>${desc}</td>
                    <td>${actionHtml}</td>
                </tr>
            `);
            return;
        }

        $resultsBody.prepend(`
            <tr>
                <td><span class="${badgeClass}">${severityText}</span></td>
                <td><strong>${type}</strong></td>
                <td>-</td>
                <td style="color:#b91c1c; font-weight:500;">${desc}</td>
                <td>${actionHtml}</td>
            </tr>
        `);
    }

    $('.nav-tab').on('click', function (e) {
        e.preventDefault();
        activateTab(String($(this).attr('href') || '#tab-scanner'), true);
    });

    $(document).on('click', '.qs-toggle-advice', function () {
        const $adviceBox = $(this).closest('tr').find('.qs-advice-box');
        $adviceBox.slideToggle(200);
        $(this).text($(this).text() === '查看建议' ? '收起建议' : '查看建议');
    });

    $(document).on('click', '.qs-iprisk-detail-btn', function () {
        const $btn = $(this);
        const ipAddress = String($btn.data('ipAddress') || $btn.attr('data-ip-address') || '').trim();
        if (!ipAddress) {
            return;
        }

        loadIpRiskDetail(ipAddress, $btn);
    });

    $('#qs-iprisk-clear-profiles, #qs-iprisk-clear-events, #qs-iprisk-clear-all').on('click', function () {
        const $btn = $(this);
        const target = String($btn.attr('id') || '')
            .replace('qs-iprisk-clear-', '')
            .replace('profiles', 'profiles')
            .replace('events', 'events')
            .replace('all', 'all');

        if (!['profiles', 'events', 'all'].includes(target)) {
            return;
        }

        const labelMap = {
            profiles: '画像缓存',
            events: '画像事件',
            all: '画像缓存 + 画像事件'
        };
        const label = labelMap[target] || target;
        if (!confirm(`确定要清空 ${label} 吗？此操作不可恢复。`)) {
            return;
        }

        const $allButtons = $('#qs-iprisk-clear-profiles, #qs-iprisk-clear-events, #qs-iprisk-clear-all');
        const $spinner = $('.qs-iprisk-action-spinner');
        const $msg = $('#qs-iprisk-action-message');
        $allButtons.prop('disabled', true);
        $spinner.addClass('is-active');
        $msg.text('');

        $.post(ajaxurl, {
            action: 'qs_clear_ip_risk_data',
            nonce: nonce,
            target: target
        }, function (response) {
            $allButtons.prop('disabled', false);
            $spinner.removeClass('is-active');

            if (!response || !response.success) {
                $msg.css('color', '#ef4444').text('清理失败：' + ((response && response.data) ? response.data : '未知错误'));
                return;
            }

            const summary = response.data.summary || {};
            $msg.css('color', '#10b981').text(`清理完成：画像缓存 ${summary.profiles || 0} 条，画像事件 ${summary.events || 0} 条。`);
            reloadCurrentTab(700);
        }).fail(function () {
            $allButtons.prop('disabled', false);
            $spinner.removeClass('is-active');
            $msg.css('color', '#ef4444').text('网络错误，请稍后再试。');
        });
    });

    $('#qs-iprisk-delete-current').on('click', function () {
        const $btn = $(this);
        const ipAddress = String($btn.data('ipAddress') || '').trim();
        if (!ipAddress) {
            return;
        }

        if (!confirm(`确定删除 IP ${ipAddress} 的画像记录吗？`)) {
            return;
        }

        $btn.prop('disabled', true);
        $.post(ajaxurl, {
            action: 'qs_delete_ip_risk_profile',
            nonce: nonce,
            ip_address: ipAddress,
            delete_events: 1
        }, function (response) {
            if (!response || !response.success) {
                alert('删除失败：' + ((response && response.data) ? response.data : '未知错误'));
                $btn.prop('disabled', false);
                return;
            }

            alert(`已删除该 IP 记录：画像缓存 ${response.data.summary && response.data.summary.profiles ? response.data.summary.profiles : 0}，画像事件 ${response.data.summary && response.data.summary.events ? response.data.summary.events : 0}`);
            reloadCurrentTab(500);
        }).fail(function () {
            alert('网络错误，请稍后再试');
            $btn.prop('disabled', false);
        });
    });

    bindProtectionSaveButton('#qs-save-protection', '.qs-save-spinner', '#qs-save-message');
    bindProtectionSaveButton('#qs-save-security-optimize', '.qs-security-optimize-save-spinner', '#qs-save-security-optimize-message');
    bindProtectionSaveButton('#qs-save-route-isolation', '.qs-route-isolation-save-spinner', '#qs-save-route-isolation-message');

    function bindProtectionSaveButton(buttonSelector, spinnerSelector, messageSelector) {
        $(buttonSelector).on('click', function () {
            const $btn = $(this);
            const $spinner = $(spinnerSelector);
            const $msg = $(messageSelector);

            if (!$btn.length) {
                return;
            }

            $btn.prop('disabled', true);
            $spinner.addClass('is-active');
            $msg.text('');

            $.post(ajaxurl, {
                action: 'qs_save_protection',
                nonce: nonce,
                settings: collectSettingsPayload()
            }, function (response) {
                $btn.prop('disabled', false);
                $spinner.removeClass('is-active');

                if (response.success) {
                    $msg.css('color', '#10b981').text(response.data.msg);
                    setTimeout(function () {
                        $msg.text('');
                    }, 3000);
                } else {
                    $msg.css('color', '#ef4444').text('保存失败：' + (response.data || '未知错误'));
                }
            }).fail(function () {
                $btn.prop('disabled', false);
                $spinner.removeClass('is-active');
                $msg.css('color', '#ef4444').text('网络错误，请稍后再试');
            });
        });
    }

    $('#qs-clear-route-isolation-logs').on('click', function () {
        const $btn = $(this);
        const $spinner = $('.qs-route-isolation-clear-spinner');
        const $msg = $('#qs-route-isolation-clear-message');

        if (!confirm('确定清空路由隔离监控日志吗？此操作不可恢复。')) {
            return;
        }

        $btn.prop('disabled', true);
        $spinner.addClass('is-active');
        $msg.text('');

        $.post(ajaxurl, {
            action: 'qs_clear_route_isolation_logs',
            nonce: nonce
        }, function (response) {
            $btn.prop('disabled', false);
            $spinner.removeClass('is-active');

            if (!response || !response.success) {
                $msg.css('color', '#ef4444').text('清空失败：' + ((response && response.data) ? response.data : '未知错误'));
                return;
            }

            $msg.css('color', '#10b981').text(response.data.msg || '路由隔离监控日志已清空。');
            reloadCurrentTab(600);
        }).fail(function () {
            $btn.prop('disabled', false);
            $spinner.removeClass('is-active');
            $msg.css('color', '#ef4444').text('网络错误，请稍后再试');
        });
    });

    $(document).on('click', '.qs-result-status-btn', function () {
        const $btn = $(this);
        const resultId = $btn.data('resultId');
        const nextStatus = $btn.data('status');
        const $row = $btn.closest('.qs-result-row');
        const hasAdvice = $row.data('hasAdvice') === 1 || $row.data('hasAdvice') === '1';
        const $actionCell = $row.find('.qs-result-actions-cell');
        const $statusCell = $row.find('.qs-result-status-cell');

        $actionCell.find('button').prop('disabled', true);

        $.post(ajaxurl, {
            action: 'qs_update_result_status',
            nonce: nonce,
            result_id: resultId,
            status: nextStatus
        }, function (response) {
            if (!response.success) {
                alert('状态更新失败：' + (response.data || '未知错误'));
                $actionCell.find('button').prop('disabled', false);
                return;
            }

            $row.attr('data-status', response.data.status)
                .removeClass('is-status-open is-status-resolved is-status-ignored')
                .addClass(`is-status-${response.data.status}`);

            $statusCell.html(buildResultStatusBadge(response.data.status));
            $actionCell.html(buildResultActionButtons(resultId, response.data.status, hasAdvice));
        }).fail(function () {
            alert('网络错误，请稍后再试');
            $actionCell.find('button').prop('disabled', false);
        });
    });

    $('#qs-cleanup-data').on('click', function () {
        const $btn = $(this);
        const $clearAllBtn = $('#qs-clear-all-history');
        const $spinner = $('.qs-cleanup-spinner');
        const $msg = $('#qs-cleanup-message');

        if (!confirm('确定要按当前保留策略清理过期历史数据吗？此操作只会删除超过保留天数的旧扫描、旧审计以及已过期封禁记录，不会把当前数据全部清空。')) {
            return;
        }

        $btn.prop('disabled', true);
        $clearAllBtn.prop('disabled', true);
        $spinner.addClass('is-active');
        $msg.text('');

        $.post(ajaxurl, {
            action: 'qs_cleanup_data',
            nonce: nonce
        }, function (response) {
            $btn.prop('disabled', false);
            $clearAllBtn.prop('disabled', false);
            $spinner.removeClass('is-active');

            if (!response.success) {
                $msg.css('color', '#ef4444').text('清理失败：' + (response.data || '未知错误'));
                return;
            }

            const summary = response.data.summary || {};
            $msg.css('color', '#10b981').text(`过期数据清理完成：删除扫描 ${summary.scans || 0}，结果 ${summary.results || 0}，审计 ${summary.audit || 0}，过期封禁 ${summary.bans || 0}，IP风险事件 ${summary.ip_risk_events || 0}，IP风险缓存 ${summary.ip_risk_profiles || 0}。面板数字显示的是当前剩余总量。`);

            reloadCurrentTab(1000);
        }).fail(function () {
            $btn.prop('disabled', false);
            $clearAllBtn.prop('disabled', false);
            $spinner.removeClass('is-active');
            $msg.css('color', '#ef4444').text('网络错误，请稍后再试');
        });
    });

    $('#qs-clear-all-history').on('click', function () {
        const $btn = $(this);
        const $cleanupBtn = $('#qs-cleanup-data');
        const $spinner = $('.qs-cleanup-spinner');
        const $msg = $('#qs-cleanup-message');

        if (!confirm('确定要清空全部历史数据吗？这会删除扫描任务、扫描结果、审计日志、封禁记录、文件基线、手机号归属地缓存、IP风险画像缓存和IP风险登录事件，但不会删除防护设置和官方规则包。此操作不可恢复。')) {
            return;
        }

        $btn.prop('disabled', true);
        $cleanupBtn.prop('disabled', true);
        $spinner.addClass('is-active');
        $msg.text('');

        $.post(ajaxurl, {
            action: 'qs_clear_all_history',
            nonce: nonce
        }, function (response) {
            $btn.prop('disabled', false);
            $cleanupBtn.prop('disabled', false);
            $spinner.removeClass('is-active');

            if (!response.success) {
                $msg.css('color', '#ef4444').text('清空失败：' + (response.data || '未知错误'));
                return;
            }

            const summary = response.data.summary || {};
            $msg.css('color', '#10b981').text(`全部历史数据已清空：扫描 ${summary.scans || 0}，结果 ${summary.results || 0}，审计 ${summary.audit || 0}，封禁 ${summary.bans || 0}，基线 ${summary.baseline || 0}，手机号缓存 ${summary.phone_cache || 0}，IP风险缓存 ${summary.ip_risk_profiles || 0}，IP风险事件 ${summary.ip_risk_events || 0}`);

            reloadCurrentTab(1000);
        }).fail(function () {
            $btn.prop('disabled', false);
            $cleanupBtn.prop('disabled', false);
            $spinner.removeClass('is-active');
            $msg.css('color', '#ef4444').text('网络错误，请稍后再试');
        });
    });

    $('#qs-clear-audit-logs').on('click', function () {
        const $btn = $(this);
        const $spinner = $('.qs-clear-audit-spinner');
        const $msg = $('#qs-clear-audit-message');

        if (!confirm('确定要单独清空审计日志吗？此操作只会删除操作审计表，不会影响扫描结果和封禁记录。')) {
            return;
        }

        $btn.prop('disabled', true);
        $spinner.addClass('is-active');
        $msg.text('');

        $.post(ajaxurl, {
            action: 'qs_clear_audit_logs',
            nonce: nonce
        }, function (response) {
            $btn.prop('disabled', false);
            $spinner.removeClass('is-active');

            if (!response.success) {
                $msg.css('color', '#ef4444').text('清空失败：' + (response.data || '未知错误'));
                return;
            }

            $msg.css('color', '#10b981').text(response.data.msg || '审计日志已清空。');

            reloadCurrentTab(800);
        }).fail(function () {
            $btn.prop('disabled', false);
            $spinner.removeClass('is-active');
            $msg.css('color', '#ef4444').text('网络错误，请稍后再试');
        });
    });

    $('#qs-rebuild-file-baseline').on('click', function () {
        const $btn = $(this);
        const $spinner = $('.qs-baseline-spinner');
        const $msg = $('#qs-baseline-message');

        if (!confirm('确定要重建文件完整性基线吗？只有在你确认当前站点文件状态可信时，才应该这样做。重建后，后续扫描会以当前文件状态作为新的对照标准。')) {
            return;
        }

        $btn.prop('disabled', true);
        $spinner.addClass('is-active');
        $msg.text('');

        $.post(ajaxurl, {
            action: 'qs_rebuild_file_baseline',
            nonce: nonce
        }, function (response) {
            $btn.prop('disabled', false);
            $spinner.removeClass('is-active');

            if (!response.success) {
                $msg.css('color', '#ef4444').text('重建失败：' + (response.data || '未知错误'));
                return;
            }

            const suffix = response.data.truncated ? ' 当前达到扫描上限，基线可能不完整，建议调大“文件基线扫描上限”后再次重建。' : '';
            $msg.css('color', '#10b981').text((response.data.msg || '文件基线已重建。') + suffix);

            reloadCurrentTab(900);
        }).fail(function () {
            $btn.prop('disabled', false);
            $spinner.removeClass('is-active');
            $msg.css('color', '#ef4444').text('网络错误，请稍后再试');
        });
    });

    $('#qs-import-rules-package').on('click', function () {
        const $btn = $(this);
        const $rollbackBtn = $('#qs-rollback-rules-package');
        const $spinner = $('.qs-rules-spinner');
        const $msg = $('#qs-rules-message');
        const $file = $('#qs-rules-package-file');
        const fileInput = $file.length ? $file.get(0) : null;
        const selectedFile = fileInput && fileInput.files ? fileInput.files[0] : null;
        const rollbackWasDisabled = $rollbackBtn.prop('disabled');

        if (!selectedFile) {
            $msg.css('color', '#ef4444').text('请先选择作者提供的官方规则包文件。');
            return;
        }

        if (!confirm('确定要导入并启用这个官方规则包吗？新规则会影响后续扫描判断，但不会自动修改网站文件和数据库。')) {
            return;
        }

        const formData = new FormData();
        formData.append('action', 'qs_import_rules_package');
        formData.append('nonce', nonce);
        formData.append('package', selectedFile);

        $btn.prop('disabled', true);
        $rollbackBtn.prop('disabled', true);
        $spinner.addClass('is-active');
        $msg.text('');

        $.ajax({
            url: ajaxurl,
            method: 'POST',
            data: formData,
            processData: false,
            contentType: false
        }).done(function (response) {
            $btn.prop('disabled', false);
            $rollbackBtn.prop('disabled', rollbackWasDisabled);
            $spinner.removeClass('is-active');

            if (!response.success) {
                $msg.css('color', '#ef4444').text('导入失败：' + (response.data || '未知错误'));
                return;
            }

            $msg.css('color', '#10b981').text(response.data.msg || '官方规则已启用。');
            reloadCurrentTab(900);
        }).fail(function () {
            $btn.prop('disabled', false);
            $rollbackBtn.prop('disabled', rollbackWasDisabled);
            $spinner.removeClass('is-active');
            $msg.css('color', '#ef4444').text('网络错误，请稍后再试');
        });
    });

    $('#qs-rollback-rules-package').on('click', function () {
        const $btn = $(this);
        const $importBtn = $('#qs-import-rules-package');
        const $spinner = $('.qs-rules-spinner');
        const $msg = $('#qs-rules-message');

        if (!confirm('确定要回滚到上一版官方规则吗？该操作只会影响后续扫描判定标准。')) {
            return;
        }

        $btn.prop('disabled', true);
        $importBtn.prop('disabled', true);
        $spinner.addClass('is-active');
        $msg.text('');

        $.post(ajaxurl, {
            action: 'qs_rollback_rules_package',
            nonce: nonce
        }, function (response) {
            $importBtn.prop('disabled', false);
            $spinner.removeClass('is-active');

            if (!response.success) {
                $btn.prop('disabled', false);
                $msg.css('color', '#ef4444').text('回滚失败：' + (response.data || '未知错误'));
                return;
            }

            $msg.css('color', '#10b981').text(response.data.msg || '规则包回滚成功。');
            reloadCurrentTab(900);
        }).fail(function () {
            $btn.prop('disabled', false);
            $importBtn.prop('disabled', false);
            $spinner.removeClass('is-active');
            $msg.css('color', '#ef4444').text('网络错误，请稍后再试');
        });
    });

    $(document).on('click', '.qs-unban-btn', function () {
        const $btn = $(this);
        const ip = $btn.data('ip');
        const rowId = $btn.data('row');

        if (!confirm(`确定要提前解封此恶意 IP: ${ip} 吗？`)) {
            return;
        }

        $btn.prop('disabled', true).text('处理中...');

        $.post(ajaxurl, {
            action: 'qs_unban_ip',
            nonce: nonce,
            ip: ip
        }, function (response) {
            if (response.success) {
                $(`#${rowId}`).fadeOut(300, function () {
                    $(this).remove();
                });
            } else {
                alert('解封失败：' + (response.data || '未知错误'));
                $btn.prop('disabled', false).text('立即解封');
            }
        }).fail(function () {
            alert('网络错误，请稍后再试');
            $btn.prop('disabled', false).text('立即解封');
        });
    });

    $(document).on('click', '.qs-destroy-session-btn', function () {
        const $btn = $(this);
        const userId = $btn.data('userId');
        const verifier = $btn.data('verifier');
        const $spinner = $('.qs-sessions-spinner');
        const $msg = $('#qs-sessions-message');

        if (!confirm('确定要强制下线这个登录设备吗？被踢下线后，对方需要重新登录。')) {
            return;
        }

        $btn.prop('disabled', true);
        $spinner.addClass('is-active');
        $msg.text('');

        $.post(ajaxurl, {
            action: 'qs_destroy_session',
            nonce: nonce,
            user_id: userId,
            verifier: verifier
        }, function (response) {
            if (!response.success) {
                $btn.prop('disabled', false);
                $spinner.removeClass('is-active');
                $msg.css('color', '#ef4444').text('操作失败：' + (response.data || '未知错误'));
                return;
            }

            $msg.css('color', '#10b981').text(response.data.msg || '会话已下线。');
            reloadCurrentTab(700);
        }).fail(function () {
            $btn.prop('disabled', false);
            $spinner.removeClass('is-active');
            $msg.css('color', '#ef4444').text('网络错误，请稍后再试');
        });
    });

    $(document).on('click', '.qs-destroy-user-sessions-btn', function () {
        const $btn = $(this);
        const userId = $btn.data('userId');
        const preserveCurrent = $btn.data('preserveCurrent') ? '1' : '';
        const $spinner = $('.qs-sessions-spinner');
        const $msg = $('#qs-sessions-message');
        const confirmText = preserveCurrent
            ? '确定要强制下线该用户的其他活跃会话吗？当前这个后台会话会被保留。'
            : '确定要强制下线该用户的全部活跃会话吗？';

        if (!confirm(confirmText)) {
            return;
        }

        $btn.prop('disabled', true);
        $spinner.addClass('is-active');
        $msg.text('');

        $.post(ajaxurl, {
            action: 'qs_destroy_user_sessions',
            nonce: nonce,
            user_id: userId,
            preserve_current: preserveCurrent
        }, function (response) {
            if (!response.success) {
                $btn.prop('disabled', false);
                $spinner.removeClass('is-active');
                $msg.css('color', '#ef4444').text('操作失败：' + (response.data || '未知错误'));
                return;
            }

            $msg.css('color', '#10b981').text(response.data.msg || '用户会话已清理。');
            reloadCurrentTab(700);
        }).fail(function () {
            $btn.prop('disabled', false);
            $spinner.removeClass('is-active');
            $msg.css('color', '#ef4444').text('网络错误，请稍后再试');
        });
    });

    $('#qs-destroy-all-sessions').on('click', function () {
        const $btn = $(this);
        const $spinner = $('.qs-sessions-spinner');
        const $msg = $('#qs-sessions-message');

        if (!confirm('确定要强制全部其他用户重新登录吗？系统会尽量保留当前这个管理员会话。')) {
            return;
        }

        $btn.prop('disabled', true);
        $spinner.addClass('is-active');
        $msg.text('');

        $.post(ajaxurl, {
            action: 'qs_destroy_all_sessions',
            nonce: nonce
        }, function (response) {
            $btn.prop('disabled', false);
            $spinner.removeClass('is-active');

            if (!response.success) {
                $msg.css('color', '#ef4444').text('操作失败：' + (response.data || '未知错误'));
                return;
            }

            const users = response.data.users || 0;
            const sessions = response.data.sessions || 0;
            $msg.css('color', '#10b981').text(`已让 ${users} 个用户的 ${sessions} 个会话失效。`);

            reloadCurrentTab(800);
        }).fail(function () {
            $btn.prop('disabled', false);
            $spinner.removeClass('is-active');
            $msg.css('color', '#ef4444').text('网络错误，请稍后再试');
        });
    });

    function collectSettingsPayload() {
        const settings = {};

        $('.qs-setting-field').each(function () {
            const $field = $(this);
            const key = $field.data('settingKey');

            if (!key) {
                return;
            }

            if ($field.hasClass('qs-setting-multi-checkbox')) {
                if ($field.is(':checked')) {
                    const currentVal = settings[key] || '';
                    const val = ($field.val() || '').trim();
                    if (val) {
                        settings[key] = currentVal ? currentVal + '\n' + val : val;
                    }
                } else if (!settings.hasOwnProperty(key)) {
                    // Ensure the key exists even if nothing is checked, so it can be cleared
                    settings[key] = '';
                }
                return;
            }

            if ($field.is(':checkbox')) {
                settings[key] = $field.is(':checked') ? '1' : '';
                return;
            }

            settings[key] = ($field.val() || '').trim();
        });

        return settings;
    }

    function findTabByHash(tabHash) {
        return $('.nav-tab').filter(function () {
            return String($(this).attr('href') || '') === String(tabHash || '');
        }).first();
    }

    function activateInitialTab() {
        const rawHash = String(window.location.hash || '');
        const tabHash = rawHash && findTabByHash(rawHash).length ? rawHash : '#tab-scanner';
        activateTab(tabHash, false);
    }

    function activateTab(tabHash, updateHash) {
        let safeHash = typeof tabHash === 'string' && tabHash.indexOf('#tab-') === 0 ? tabHash : '#tab-scanner';
        let $tab = findTabByHash(safeHash);

        if (!$tab.length) {
            $tab = $('.nav-tab').first();
            if (!$tab.length) {
                return;
            }

            safeHash = String($tab.attr('href') || '#tab-scanner');
        }

        $('.nav-tab').removeClass('nav-tab-active');
        $tab.addClass('nav-tab-active');

        $('.qs-tab-content').hide();
        const $content = $(safeHash.replace('#tab-', '#tab-content-'));
        if ($content.length) {
            $content.show();
        }

        if (updateHash) {
            if (window.history && typeof window.history.replaceState === 'function') {
                window.history.replaceState(null, '', safeHash);
            } else {
                window.location.hash = safeHash;
            }
        }
    }

    function reloadCurrentTab(delay) {
        const $activeTab = $('.nav-tab.nav-tab-active').first();
        const activeHash = $activeTab.length ? String($activeTab.attr('href') || '#tab-scanner') : '#tab-scanner';

        activateTab(activeHash, true);

        setTimeout(function () {
            location.reload();
        }, Math.max(0, Number(delay) || 0));
    }

    function initDomainReplace() {
        const $old = $('#qs-domain-old');
        const $new = $('#qs-domain-new');
        const $targets = $('.qs-domain-target');
        const $includeSchemes = $('#qs-domain-include-schemes');
        const $previewBtn = $('#qs-domain-preview');
        const $executeBtn = $('#qs-domain-execute');
        const $spinner = $('#qs-domain-spinner');
        const $message = $('#qs-domain-message');
        const $progress = $('#qs-domain-progress');
        const $result = $('#qs-domain-result');

        if (!$old.length || !$new.length || !$previewBtn.length || !$executeBtn.length) {
            return;
        }

        let running = false;

        function collectTargets() {
            const list = [];
            $targets.each(function () {
                const $item = $(this);
                if ($item.is(':checked')) {
                    list.push({
                        key: String($item.data('target') || ''),
                        label: String($item.data('label') || '')
                    });
                }
            });
            return list.filter(item => item.key);
        }

        function setBusy(state) {
            running = state;
            $previewBtn.prop('disabled', state);
            $executeBtn.prop('disabled', state);
            if (state) {
                $spinner.addClass('is-active');
            } else {
                $spinner.removeClass('is-active');
            }
        }

        function showMessage(text, tone) {
            const color = tone === 'error' ? '#ef4444' : (tone === 'success' ? '#10b981' : '#374151');
            $message.css('color', color).text(text || '');
        }

        function runReplace(dryRun) {
            if (running) {
                return;
            }

            const oldVal = String($old.val() || '').trim();
            const newVal = String($new.val() || '').trim();
            const targets = collectTargets();

            if (!oldVal || !newVal) {
                showMessage('请先填写旧域名和新域名。', 'error');
                return;
            }

            if (oldVal === newVal) {
                showMessage('旧域名与新域名相同，无需替换。', 'error');
                return;
            }

            if (!targets.length) {
                showMessage('请至少选择一个替换范围。', 'error');
                return;
            }

            setBusy(true);
            showMessage(dryRun ? '正在预览影响范围...' : '正在执行替换...', '');
            $result.text('');

            const totals = {
                scanned: 0,
                updated: 0,
                replacements: 0
            };

            let index = 0;
            let lastId = 0;

            function step() {
                if (index >= targets.length) {
                    setBusy(false);
                    const summary = dryRun
                        ? `预览完成：扫描 ${totals.scanned} 行，预计影响 ${totals.updated} 行，替换次数 ${totals.replacements}。`
                        : `替换完成：扫描 ${totals.scanned} 行，更新 ${totals.updated} 行，替换次数 ${totals.replacements}。`;
                    showMessage(summary, 'success');
                    $result.text(summary);
                    return;
                }

                const target = targets[index];
                $progress.text(`正在处理 ${target.label || target.key}...（已扫描 ${totals.scanned} 行，更新 ${totals.updated} 行）`);

                $.post(ajaxurl, {
                    action: 'qs_domain_replace',
                    nonce: nonce,
                    old_domain: oldVal,
                    new_domain: newVal,
                    target: target.key,
                    last_id: lastId,
                    limit: 200,
                    dry_run: dryRun ? 1 : 0,
                    include_protocols: $includeSchemes.is(':checked') ? 1 : 0
                }, function (response) {
                    if (!response || !response.success) {
                        setBusy(false);
                        showMessage('执行失败：' + (response && response.data ? response.data : '未知错误'), 'error');
                        return;
                    }

                    const data = response.data || {};
                    totals.scanned += Number(data.scanned || 0);
                    totals.updated += Number(data.updated || 0);
                    totals.replacements += Number(data.replacements || 0);

                    if (data.done) {
                        index += 1;
                        lastId = 0;
                    } else {
                        lastId = Number(data.next_id || lastId);
                    }

                    step();
                }).fail(function () {
                    setBusy(false);
                    showMessage('网络错误，请稍后重试。', 'error');
                });
            }

            step();
        }

        $previewBtn.on('click', function () {
            runReplace(true);
        });

        $executeBtn.on('click', function () {
            if (!window.confirm('确定要执行替换吗？建议先备份数据库。')) {
                return;
            }
            runReplace(false);
        });
    }

    function initProxyPresetHelper() {
        const $preset = $('#qs_proxy_preset');
        const $headers = $('#qs_trusted_proxy_headers');
        const $ips = $('#qs_trusted_proxy_ips');

        if (!$preset.length || !$headers.length || !$ips.length) {
            return;
        }

        const knownHeaderProfiles = {};
        const knownIpProfiles = {};

        if (defaultProxyHeaders.length) {
            knownHeaderProfiles[defaultProxyHeaders.join('\n')] = true;
        }

        Object.keys(proxyPresets).forEach(function (presetId) {
            const preset = proxyPresets[presetId];
            if (!preset || typeof preset !== 'object') {
                return;
            }

            const headerText = Array.isArray(preset.headers) ? preset.headers.join('\n') : '';
            const ipText = Array.isArray(preset.proxyIps) ? preset.proxyIps.join('\n') : '';

            if (headerText) {
                knownHeaderProfiles[headerText] = true;
            }

            if (ipText) {
                knownIpProfiles[ipText] = true;
            }
        });

        function applyPreset(isInitial) {
            const presetId = String($preset.val() || 'manual');
            const preset = proxyPresets[presetId] || {};
            const presetHeaders = Array.isArray(preset.headers) ? preset.headers.join('\n') : '';
            const presetIps = Array.isArray(preset.proxyIps) ? preset.proxyIps.join('\n') : '';
            const currentHeaders = String($headers.val() || '').trim();
            const currentIps = String($ips.val() || '').trim();

            if (presetHeaders) {
                $headers.attr('placeholder', presetHeaders);

                if (!currentHeaders || knownHeaderProfiles[currentHeaders]) {
                    $headers.val(presetHeaders);
                }
            } else if (!isInitial) {
                $headers.attr('placeholder', defaultProxyHeaders.join('\n'));
            }

            if (presetIps) {
                $ips.attr('placeholder', presetIps);

                if (!currentIps || knownIpProfiles[currentIps]) {
                    $ips.val(presetIps);
                }
            } else {
                $ips.attr('placeholder', '');
            }
        }

        applyPreset(true);
        $preset.on('change', function () {
            applyPreset(false);
        });
    }

    function loadIpRiskDetail(ipAddress, $triggerBtn) {
        const $panel = $('#qs-iprisk-detail-panel');
        const $ip = $('#qs-iprisk-detail-ip');
        const $meta = $('#qs-iprisk-detail-meta');
        const $signals = $('#qs-iprisk-detail-signals');
        const $plan = $('#qs-iprisk-detail-provider-plan');
        const $providers = $('#qs-iprisk-detail-providers');
        const $eventsBody = $('#qs-iprisk-detail-events-body');
        const $deleteCurrent = $('#qs-iprisk-delete-current');

        if (!$panel.length || !$ip.length || !$meta.length || !$signals.length || !$plan.length || !$providers.length || !$eventsBody.length || !$deleteCurrent.length) {
            return;
        }

        if ($triggerBtn && $triggerBtn.length) {
            $triggerBtn.prop('disabled', true);
        }

        $ip.text(ipAddress);
        $meta.text('正在加载详细画像数据...');
        $signals.html('');
        $plan.html('');
        $providers.html('');
        $eventsBody.html('<tr><td colspan="6" style="text-align:center; padding:20px;">正在加载该 IP 的画像详情...</td></tr>');
        $deleteCurrent.prop('disabled', true).data('ipAddress', '');
        $panel.show();

        $.post(ajaxurl, {
            action: 'qs_get_ip_risk_profile_detail',
            nonce: nonce,
            ip_address: ipAddress
        }, function (response) {
            if (!response || !response.success || !response.data || !response.data.profile) {
                $meta.text('加载失败：' + ((response && response.data) ? response.data : '未知错误'));
                $eventsBody.html('<tr><td colspan="6" style="text-align:center; padding:20px;">没有拿到详细数据。</td></tr>');
                return;
            }

            const data = response.data;
            const profile = data.profile || {};
            const providers = Array.isArray(data.providers) ? data.providers : [];
            const events = Array.isArray(data.events) ? data.events : [];

            const hitCount = Number(profile.hit_count || 0);
            const statusText = String(profile.query_status || 'unknown');
            const statusLabel = getProfileStatusLabel(statusText);
            const updatedAt = String(profile.updated_at || profile.last_seen || '');
            const lastEventType = String(profile.last_event_type || '');
            const level = String(profile.risk_level || 'unknown');
            const levelLabel = getRiskLevelLabel(level);
            const eventOnly = !!profile.event_only;

            $meta.text(`等级 ${levelLabel} / 命中 ${hitCount} / 状态 ${statusLabel}${updatedAt ? ' / 更新时间 ' + updatedAt : ''}${lastEventType ? ' / 最近事件 ' + getEventTypeLabel(lastEventType) : ''}${eventOnly ? ' / 当前为事件回退数据（缓存画像尚未写入）' : ''}`);
            $deleteCurrent.prop('disabled', false).data('ipAddress', ipAddress);

            const signalList = Array.isArray(profile.signals) ? profile.signals : [];
            if (!signalList.length) {
                $signals.html('<span class="qs-iprisk-tag">暂无信号</span>');
            } else {
                $signals.html(signalList.map(signal => `<span class="qs-iprisk-tag qs-iprisk-tag-signal">${escapeHtml(String(signal || ''))}</span>`).join(''));
            }

            const providerPlan = profile.provider_plan && typeof profile.provider_plan === 'object' ? profile.provider_plan : {};
            const selected = Array.isArray(providerPlan.selected) ? providerPlan.selected : [];
            const missingKey = Array.isArray(providerPlan.missing_key) ? providerPlan.missing_key : [];
            const usedFallback = !!providerPlan.used_public_fallback;
            const planItems = [];
            if (selected.length) {
                planItems.push(`<span class="qs-iprisk-tag qs-iprisk-tag-key">本次调用: ${escapeHtml(formatProviderList(selected))}</span>`);
            }
            if (missingKey.length) {
                planItems.push(`<span class="qs-iprisk-tag qs-iprisk-tag-fallback">缺 Key: ${escapeHtml(formatProviderList(missingKey))}</span>`);
            }
            if (usedFallback) {
                planItems.push('<span class="qs-iprisk-tag qs-iprisk-tag-public">已启用公共回退来源</span>');
            }
            if (!planItems.length) {
                planItems.push('<span class="qs-iprisk-tag">暂无来源计划数据</span>');
            }
            $plan.html(planItems.join(''));

            if (!providers.length) {
                $providers.html(`<div class="qs-iprisk-provider-card">${eventOnly ? '当前没有来源查询明细，系统先回退显示事件数据。请稍后重试详情，或把查询模式切到“同步即时查询”。' : '暂无来源查询明细。'}</div>`);
            } else {
                $providers.html(providers.map(item => {
                    const provider = String(item.provider || 'unknown');
                    const providerLabel = String(item.provider_label || provider);
                    const providerStatus = String(item.status || 'unknown');
                    const providerStatusLabel = getProviderStatusLabel(providerStatus);
                    const reason = String(item.reason || '');
                    const signals = Array.isArray(item.signals) ? item.signals : [];
                    const highlights = Array.isArray(item.highlights) ? item.highlights : [];
                    const sections = Array.isArray(item.sections) ? item.sections : [];
                    const statusClass = providerStatus === 'ok'
                        ? 'qs-iprisk-provider-status-ok'
                        : (providerStatus === 'error' ? 'qs-iprisk-provider-status-error' : 'qs-iprisk-provider-status-skipped');
                    const cardClass = providerStatus === 'ok'
                        ? 'qs-iprisk-provider-card-ok'
                        : (providerStatus === 'error' ? 'qs-iprisk-provider-card-error' : 'qs-iprisk-provider-card-skipped');
                    const reasonLabel = getProviderReasonText(reason);
                    const metaParts = [
                        signals.length ? `信号: ${escapeHtml(signals.join(', '))}` : '',
                        reasonLabel ? `说明: ${escapeHtml(reasonLabel)}` : ''
                    ].filter(Boolean);

                    return `<div class="qs-iprisk-provider-card ${cardClass}">
                        <div class="qs-iprisk-provider-head">
                            <strong>${escapeHtml(providerLabel)}</strong>
                            <span class="qs-iprisk-provider-status ${statusClass}">${escapeHtml(providerStatusLabel)}</span>
                        </div>
                        <div class="qs-iprisk-provider-meta">${metaParts.map(part => `<span>${part}</span>`).join('')}</div>
                        ${renderProviderHighlights(highlights)}
                        ${renderProviderSections(sections)}
                    </div>`;
                }).join(''));
            }

            if (!events.length) {
                $eventsBody.html('<tr><td colspan="6" style="text-align:center; padding:20px;">该 IP 暂无历史画像事件。</td></tr>');
            } else {
                const rows = events.map(event => {
                    const eventTime = String(event.time || '');
                    const eventType = getEventTypeLabel(String(event.event_type || ''));
                    const username = String(event.username || '-');
                    const eventLevel = String(event.risk_level || 'unknown');
                    const profileStatus = String(event.profile_status || 'unknown');
                    const profileStatusLabel = getProfileStatusLabel(profileStatus);
                    const actionLabel = getActionLabel(String(event.action || 'observe'));

                    return `<tr>
                        <td>${escapeHtml(eventTime)}</td>
                        <td>${escapeHtml(eventType)}</td>
                        <td>${escapeHtml(username)}</td>
                        <td>${renderRiskBadge(eventLevel)}</td>
                        <td><code>${escapeHtml(profileStatusLabel)}</code></td>
                        <td>${escapeHtml(actionLabel)}</td>
                    </tr>`;
                });
                $eventsBody.html(rows.join(''));
            }

            const panelTop = $panel.offset() ? $panel.offset().top : 0;
            if (panelTop > 0) {
                $('html, body').animate({ scrollTop: Math.max(0, panelTop - 80) }, 200);
            }
        }).fail(function () {
            $meta.text('网络错误，获取 IP 详情失败。');
            $eventsBody.html('<tr><td colspan="6" style="text-align:center; padding:20px;">网络错误，请稍后重试。</td></tr>');
        }).always(function () {
            if ($triggerBtn && $triggerBtn.length) {
                $triggerBtn.prop('disabled', false);
            }
        });
    }

    function getRiskLevelLabel(level) {
        switch (String(level || 'unknown')) {
            case 'safe': return '安全';
            case 'low': return '低风险';
            case 'medium': return '中风险';
            case 'high': return '高风险';
            case 'critical': return '严重';
            default: return '未知';
        }
    }

    function renderProviderSections(sections) {
        if (!Array.isArray(sections) || !sections.length) {
            return '<div class="qs-iprisk-provider-empty">暂无结构化字段</div>';
        }

        const sectionHtml = sections.map(section => {
            const title = String(section && section.title ? section.title : '');
            const items = Array.isArray(section && section.items) ? section.items : [];
            if (!items.length) {
                return '';
            }

            const rows = items.map(row => {
                const label = String(row && row.label ? row.label : '');
                const value = String(row && row.value ? row.value : '');
                if (!label || !value) {
                    return '';
                }
                return `<div class="qs-iprisk-provider-field">
                    <span class="qs-iprisk-provider-field-label">${escapeHtml(label)}</span>
                    <span class="qs-iprisk-provider-field-value">${escapeHtml(value)}</span>
                </div>`;
            }).filter(Boolean).join('');

            if (!rows) {
                return '';
            }

            return `<div class="qs-iprisk-provider-section">
                ${title ? `<div class="qs-iprisk-provider-section-title">${escapeHtml(title)}</div>` : ''}
                <div class="qs-iprisk-provider-fields">${rows}</div>
            </div>`;
        }).filter(Boolean).join('');

        return sectionHtml || '<div class="qs-iprisk-provider-empty">暂无结构化字段</div>';
    }

    function renderProviderHighlights(highlights) {
        if (!Array.isArray(highlights) || !highlights.length) {
            return '';
        }

        const html = highlights.map(item => {
            const label = String(item && item.label ? item.label : '');
            const value = String(item && item.value ? item.value : '');
            let state = String(item && item.state ? item.state : 'neutral');
            if (!label || !value) {
                return '';
            }

            if (!['danger', 'ok', 'info', 'neutral'].includes(state)) {
                state = 'neutral';
            }

            return `<span class="qs-iprisk-pill qs-iprisk-pill-${state}">
                <span class="qs-iprisk-pill-label">${escapeHtml(label)}</span>
                <span class="qs-iprisk-pill-value">${escapeHtml(value)}</span>
            </span>`;
        }).filter(Boolean).join('');

        if (!html) {
            return '';
        }

        return `<div class="qs-iprisk-provider-highlights">${html}</div>`;
    }

    function formatProviderList(providerIds) {
        if (!Array.isArray(providerIds)) {
            return '';
        }
        return providerIds.map(id => getProviderLabel(String(id || ''))).filter(Boolean).join(', ');
    }

    function getProviderLabel(providerId) {
        switch (String(providerId || '')) {
            case 'ipregistry': return 'IPRegistry';
            case 'ipdata': return 'IPData';
            case 'ip_api': return 'IP-API';
            case 'ipinfo': return 'IPinfo';
            case 'ip_sb': return 'IP.SB';
            default: return providerId || 'Unknown';
        }
    }

    function getProviderStatusLabel(status) {
        switch (String(status || '')) {
            case 'ok': return '成功';
            case 'error': return '失败';
            case 'skipped': return '跳过';
            default: return status || '未知';
        }
    }

    function getProfileStatusLabel(status) {
        switch (String(status || 'unknown')) {
            case 'ready': return '已完成';
            case 'stale': return '缓存过期';
            case 'failed': return '查询失败';
            case 'skipped': return '已跳过';
            case 'pending': return '等待查询';
            case 'pending_async': return '异步处理中';
            case 'pending_external': return '等待外部任务';
            case 'private_ip': return '内网IP';
            case 'missing': return '无画像';
            default: return status || '未知';
        }
    }

    function getProviderReasonText(reason) {
        switch (String(reason || '').trim()) {
            case 'missing_api_key': return '未配置 API Key';
            case 'unsupported_provider': return '来源不受支持';
            case 'invalid_json': return '返回数据格式异常';
            case 'query_failed': return '来源查询失败';
            case 'private_ip': return '内网 IP 不进行外部查询';
            case 'http_429': return '来源请求过于频繁（429）';
            case 'http_403': return '来源拒绝访问（403）';
            case 'http_401': return '来源鉴权失败（401）';
            default: return reason || '';
        }
    }

    function getEventTypeLabel(eventType) {
        switch (String(eventType || '')) {
            case 'login_success': return '登录成功';
            case 'login_failed': return '登录失败';
            default: return eventType || '未知事件';
        }
    }

    function getActionLabel(action) {
        switch (String(action || 'observe')) {
            case 'alert': return '告警';
            case 'block': return '拦截';
            default: return '观察';
        }
    }

    function renderRiskBadge(level) {
        const normalized = String(level || 'unknown');
        let cls = 'neutral';
        if (normalized === 'safe') cls = 'success';
        else if (normalized === 'low') cls = 'info';
        else if (normalized === 'medium') cls = 'warning';
        else if (normalized === 'high' || normalized === 'critical') cls = 'critical';
        return `<span class="qs-badge ${cls}">${escapeHtml(getRiskLevelLabel(normalized))}</span>`;
    }

    function escapeHtml(value) {
        return String(value || '')
            .replace(/&/g, '&amp;')
            .replace(/</g, '&lt;')
            .replace(/>/g, '&gt;')
            .replace(/"/g, '&quot;')
            .replace(/'/g, '&#39;');
    }

    function buildResultStatusBadge(status) {
        const meta = resultStatusMeta[status] || resultStatusMeta.open;
        return `<span class="qs-badge ${meta.className}">${meta.label}</span>`;
    }

    function buildResultActionButtons(resultId, status, hasAdvice) {
        const actions = [];

        if (hasAdvice) {
            actions.push('<button type="button" class="button button-small qs-toggle-advice">查看建议</button>');
        }

        if (status === 'open') {
            actions.push(`<button type="button" class="button button-small qs-result-status-btn" data-result-id="${resultId}" data-status="resolved">标记已处理</button>`);
            actions.push(`<button type="button" class="button button-small qs-result-status-btn" data-result-id="${resultId}" data-status="ignored">忽略</button>`);
        } else {
            actions.push(`<button type="button" class="button button-small qs-result-status-btn" data-result-id="${resultId}" data-status="open">恢复待处理</button>`);
        }

        return `<div class="qs-result-actions">${actions.join('')}</div>`;
    }
});
