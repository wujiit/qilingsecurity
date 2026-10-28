(function () {
    if (typeof window === 'undefined' || typeof document === 'undefined') {
        return;
    }

    const config = window.qsRedisUiData && typeof window.qsRedisUiData === 'object'
        ? window.qsRedisUiData
        : {};

    let modalState = null;
    let requestInFlight = false;
    let toastRoot = null;
    let modalRoot = null;

    function ensureToastRoot() {
        if (toastRoot && document.body.contains(toastRoot)) {
            return toastRoot;
        }

        toastRoot = document.createElement('div');
        toastRoot.className = 'qs-redis-toast-stack';
        toastRoot.setAttribute('aria-live', 'polite');
        toastRoot.setAttribute('aria-atomic', 'true');
        document.body.appendChild(toastRoot);
        return toastRoot;
    }

    function ensureModal() {
        if (modalRoot && document.body.contains(modalRoot)) {
            return modalRoot;
        }

        modalRoot = document.createElement('div');
        modalRoot.className = 'qs-redis-modal';
        modalRoot.hidden = true;
        modalRoot.innerHTML = [
            '<div class="qs-redis-modal__backdrop" data-qs-modal-close="1"></div>',
            '<div class="qs-redis-modal__dialog" role="dialog" aria-modal="true" aria-labelledby="qs-redis-modal-title" aria-describedby="qs-redis-modal-body">',
            '<div class="qs-redis-modal__glow" aria-hidden="true"></div>',
            '<div class="qs-redis-modal__header">',
            '<div>',
            '<span class="qs-redis-modal__eyebrow">启灵缓存操作确认</span>',
            '<h3 id="qs-redis-modal-title" class="qs-redis-modal__title"></h3>',
            '</div>',
            '<button type="button" class="qs-redis-modal__close" data-qs-modal-close="1" aria-label="关闭">×</button>',
            '</div>',
            '<div id="qs-redis-modal-body" class="qs-redis-modal__body"></div>',
            '<div class="qs-redis-modal__footer">',
            '<button type="button" class="button qs-redis-modal__cancel" data-qs-modal-close="1">取消</button>',
            '<button type="button" class="button button-primary qs-redis-modal__confirm">确认</button>',
            '</div>',
            '</div>'
        ].join('');

        document.body.appendChild(modalRoot);

        modalRoot.addEventListener('click', function (event) {
            const closeTrigger = event.target.closest('[data-qs-modal-close="1"]');
            if (closeTrigger) {
                event.preventDefault();
                closeConfirm(false);
                return;
            }

            const confirmButton = event.target.closest('.qs-redis-modal__confirm');
            if (confirmButton) {
                event.preventDefault();
                closeConfirm(true);
            }
        });

        document.addEventListener('keydown', function (event) {
            if (!modalState) {
                return;
            }

            if (event.key === 'Escape') {
                event.preventDefault();
                closeConfirm(false);
            }
        });

        return modalRoot;
    }

    function showToast(message, tone, duration) {
        if (!message) {
            return;
        }

        const root = ensureToastRoot();
        const toast = document.createElement('div');
        const safeTone = ['success', 'error', 'warning', 'info'].includes(tone) ? tone : 'info';
        toast.className = 'qs-redis-toast qs-redis-toast-' + safeTone;
        toast.setAttribute('role', 'status');
        toast.innerHTML = [
            '<div class="qs-redis-toast__badge"></div>',
            '<div class="qs-redis-toast__content">',
            '<strong class="qs-redis-toast__title"></strong>',
            '<div class="qs-redis-toast__message"></div>',
            '</div>'
        ].join('');

        const titleMap = {
            success: '刷新成功',
            error: '刷新失败',
            warning: '需要留意',
            info: '启灵缓存'
        };

        const title = toast.querySelector('.qs-redis-toast__title');
        const content = toast.querySelector('.qs-redis-toast__message');

        if (title) {
            title.textContent = titleMap[safeTone] || titleMap.info;
        }

        if (content) {
            content.textContent = message;
        }

        root.appendChild(toast);

        window.setTimeout(function () {
            toast.classList.add('is-visible');
        }, 16);

        const lifetime = Math.max(1800, Number(duration) || 3600);
        window.setTimeout(function () {
            toast.classList.remove('is-visible');
            toast.classList.add('is-leaving');
            window.setTimeout(function () {
                if (toast.parentNode) {
                    toast.parentNode.removeChild(toast);
                }
            }, 220);
        }, lifetime);
    }

    function openConfirm(options) {
        const modal = ensureModal();
        const settings = options && typeof options === 'object' ? options : {};
        const title = modal.querySelector('.qs-redis-modal__title');
        const body = modal.querySelector('.qs-redis-modal__body');
        const confirmButton = modal.querySelector('.qs-redis-modal__confirm');

        if (title) {
            title.textContent = settings.title || '刷新 Redis 对象缓存';
        }

        if (body) {
            body.innerHTML = [
                '<p class="qs-redis-modal__lead">',
                escapeHtml(settings.message || '这会清空当前 Redis 对象缓存中的持久对象与 transient，并同步启灵生态相关缓存版本。'),
                '</p>',
                '<p class="qs-redis-modal__note">这是立即生效的缓存操作，不会修改数据库结构，但会让站点随后按需重新回源构建对象缓存。</p>'
            ].join('');
        }

        if (confirmButton) {
            confirmButton.textContent = settings.confirmLabel || '确认刷新';
        }

        modal.hidden = false;
        document.body.classList.add('qs-redis-ui-lock');
        modal.classList.add('is-open');

        modalState = {
            resolve: settings.resolve,
            previousFocus: document.activeElement instanceof HTMLElement ? document.activeElement : null
        };

        window.setTimeout(function () {
            if (confirmButton) {
                confirmButton.focus();
            }
        }, 24);
    }

    function closeConfirm(result) {
        if (!modalState) {
            return;
        }

        const currentState = modalState;
        const modal = ensureModal();

        modal.classList.remove('is-open');
        modal.hidden = true;
        document.body.classList.remove('qs-redis-ui-lock');
        modalState = null;

        if (currentState.previousFocus && typeof currentState.previousFocus.focus === 'function') {
            currentState.previousFocus.focus();
        }

        if (typeof currentState.resolve === 'function') {
            currentState.resolve(!!result);
        }
    }

    function confirmAction(options) {
        return new Promise(function (resolve) {
            openConfirm(Object.assign({}, options || {}, { resolve: resolve }));
        });
    }

    function escapeHtml(text) {
        return String(text || '')
            .replace(/&/g, '&amp;')
            .replace(/</g, '&lt;')
            .replace(/>/g, '&gt;')
            .replace(/"/g, '&quot;')
            .replace(/'/g, '&#039;');
    }

    function resolveElement(target) {
        if (!target) {
            return null;
        }

        if (typeof target === 'string') {
            return document.querySelector(target);
        }

        return target instanceof HTMLElement ? target : null;
    }

    function setInlineMessage(target, message, tone) {
        const element = resolveElement(target);
        if (!element) {
            return;
        }

        const colorMap = {
            success: '#10b981',
            error: '#ef4444',
            warning: '#d97706',
            info: '#334155'
        };

        element.textContent = message || '';
        element.style.color = colorMap[tone] || colorMap.info;
    }

    function setBusyState(target, state) {
        const element = resolveElement(target);
        if (!element) {
            return;
        }

        element.classList.toggle('is-active', !!state);
    }

    function setDisabled(target, state) {
        const element = resolveElement(target);
        if (!element || !('disabled' in element)) {
            return;
        }

        element.disabled = !!state;
    }

    function extractErrorMessage(response) {
        if (!response || typeof response !== 'object') {
            return '未知错误';
        }

        if (typeof response.data === 'string') {
            return response.data;
        }

        if (response.data && typeof response.data === 'object' && typeof response.data.message === 'string') {
            return response.data.message;
        }

        return '未知错误';
    }

    function postFlushRequest() {
        if (!config.ajaxurl || !config.nonce) {
            return Promise.reject(new Error('启灵缓存前端配置未加载完整。'));
        }

        const body = new URLSearchParams();
        body.append('action', 'qs_flush_redis_cache');
        body.append('nonce', config.nonce);

        return window.fetch(config.ajaxurl, {
            method: 'POST',
            credentials: 'same-origin',
            headers: {
                'Content-Type': 'application/x-www-form-urlencoded; charset=UTF-8'
            },
            body: body.toString()
        }).then(function (response) {
            return response.text().then(function (text) {
                let payload = null;

                try {
                    payload = text ? JSON.parse(text) : null;
                } catch (error) {
                    payload = null;
                }

                if (!response.ok) {
                    if (payload && typeof payload === 'object') {
                        return payload;
                    }

                    throw new Error('网络请求失败，请稍后再试。');
                }

                if (payload && typeof payload === 'object') {
                    return payload;
                }

                throw new Error('服务器返回了无法识别的响应。');
            });
        });
    }

    function flushRedisCache(options) {
        const settings = options && typeof options === 'object' ? options : {};
        const button = resolveElement(settings.button);
        const spinner = settings.spinner;
        const message = settings.message;

        if (requestInFlight || (button && button.disabled)) {
            return Promise.resolve(false);
        }

        return confirmAction({
            title: settings.title || '刷新 Redis 对象缓存',
            message: settings.confirmMessage || '这会清空当前 Redis 对象缓存中的持久对象与 transient，并同步启灵生态相关缓存版本。',
            confirmLabel: settings.confirmLabel || '确认刷新'
        }).then(function (confirmed) {
            if (!confirmed) {
                return false;
            }

            requestInFlight = true;
            setDisabled(button, true);
            setBusyState(spinner, true);
            setInlineMessage(message, '', 'info');

            return postFlushRequest()
                .then(function (response) {
                    if (!response || !response.success) {
                        const errorMessage = '刷新失败：' + extractErrorMessage(response);
                        setInlineMessage(message, errorMessage, 'error');
                        showToast(errorMessage, 'error', 4200);
                        return false;
                    }

                    const responseData = response.data && typeof response.data === 'object' ? response.data : {};
                    const successMessage = typeof responseData.msg === 'string' && responseData.msg
                        ? responseData.msg
                        : 'Redis 对象缓存已刷新。';

                    setInlineMessage(message, successMessage, 'success');
                    showToast(successMessage, 'success', 3600);

                    if (settings.reloadAfterSuccess) {
                        window.setTimeout(function () {
                            window.location.reload();
                        }, Math.max(0, Number(settings.reloadDelay) || 700));
                    }

                    return true;
                })
                .catch(function (error) {
                    const errorMessage = normalizeRuntimeErrorMessage(error);
                    setInlineMessage(message, errorMessage, 'error');
                    showToast(errorMessage, 'error', 4200);
                    return false;
                })
                .finally(function () {
                    requestInFlight = false;
                    setDisabled(button, false);
                    setBusyState(spinner, false);
                });
        });
    }

    function bindTriggers() {
        document.addEventListener('click', function (event) {
            const trigger = event.target.closest('#qs-flush-redis-cache, #wp-admin-bar-qs-redis-cache-flush > a');
            if (!trigger) {
                return;
            }

            event.preventDefault();

            const panelButton = document.getElementById('qs-flush-redis-cache');
            const isPanelButton = trigger === panelButton;

            flushRedisCache({
                button: isPanelButton ? panelButton : null,
                spinner: document.querySelector('.qs-redis-cache-action-spinner'),
                message: document.querySelector('#qs-redis-cache-action-message'),
                reloadAfterSuccess: true,
                reloadDelay: 700
            });
        });
    }

    window.QSRedisUi = {
        confirm: confirmAction,
        notify: showToast,
        flushRedisCache: flushRedisCache
    };

    function normalizeRuntimeErrorMessage(error) {
        if (!error || !error.message) {
            return '网络错误，请稍后再试';
        }

        if (
            error.message === '启灵缓存前端配置未加载完整。' ||
            error.message === '网络请求失败，请稍后再试。' ||
            error.message === '服务器返回了无法识别的响应。'
        ) {
            return error.message;
        }

        return '网络错误，请稍后再试';
    }

    if (document.readyState === 'loading') {
        document.addEventListener('DOMContentLoaded', bindTriggers);
    } else {
        bindTriggers();
    }
})();
