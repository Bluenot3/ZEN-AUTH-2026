// === ZENX CONFIGURATION ===
const ZENX_CONFIG = {
    ENABLE_WEBAUTHN: true,
    ENABLE_MAGIC_LINK: true,
    ENABLE_TOTP: true,
    ENABLE_SESSION_PANEL: true,
    ENABLE_SECURITY_HUD: true,
    ENABLE_AUDIT_LOG: true,
    ENABLE_PWA: true,
    ENABLE_ACCESSIBILITY: true,
    ENABLE_WEB3: true,
    ENABLE_OFFLINE_MODE: true,
    ENABLE_TOKEN_VAULT: true,
    ENABLE_API_KEYS: true,
    ENABLE_WEBHOOKS: true,
    ENABLE_TEAM_SHARING: true
};

// === ZENX STORAGE PROVIDER ===
const ZENXStorage = {
    prefix: 'zenx_',
    get: (key) => { try { return JSON.parse(localStorage.getItem(ZENXStorage.prefix + key)); } catch { return null; } },
    set: (key, value) => localStorage.setItem(ZENXStorage.prefix + key, JSON.stringify(value)),
    delete: (key) => localStorage.removeItem(ZENXStorage.prefix + key),
    getAll: (pattern) => {
        const results = {};
        for (let i = 0; i < localStorage.length; i++) {
            const key = localStorage.key(i);
            if (key.startsWith(ZENXStorage.prefix + pattern)) {
                results[key.replace(ZENXStorage.prefix, '')] = ZENXStorage.get(key.replace(ZENXStorage.prefix, ''));
            }
        }
        return results;
    }
};

// === ZENX MAIN MODULE ===
window.ZENX = {
    version: '2.0.0',
    config: ZENX_CONFIG,
    storage: ZENXStorage,

    // Utility functions
    utils: {
        generateId: () => crypto.randomUUID ? crypto.randomUUID() : 'xxxx-xxxx-xxxx'.replace(/x/g, () => Math.floor(Math.random() * 16).toString(16)),
        formatDate: (date) => new Intl.DateTimeFormat('en-US', { dateStyle: 'medium', timeStyle: 'short' }).format(new Date(date)),
        truncateAddress: (addr) => addr ? `${addr.slice(0, 6)}...${addr.slice(-4)}` : '',
        copyToClipboard: async (text) => { await navigator.clipboard.writeText(text); ZENX.ui.toast('Copied to clipboard!'); },
        fingerprint: () => {
            const canvas = document.createElement('canvas');
            const ctx = canvas.getContext('2d');
            ctx.textBaseline = 'top';
            ctx.font = '14px Arial';
            ctx.fillText('ZENAuth', 2, 2);
            return canvas.toDataURL().slice(-32);
        }
    },

    // UI Module
    ui: {
        currentModal: null,
        showModal: (id) => {
            const modal = document.getElementById(id);
            if (modal) { modal.classList.add('active'); ZENX.ui.currentModal = id; }
        },
        hideModal: (id) => {
            const modal = document.getElementById(id || ZENX.ui.currentModal);
            if (modal) { modal.classList.remove('active'); ZENX.ui.currentModal = null; }
        },
        togglePanel: (id) => document.getElementById(id)?.classList.toggle('active'),
        toggleHUD: () => document.getElementById('zenx-security-hud')?.classList.toggle('active'),
        toast: (message, type = 'info') => {
            const toast = document.createElement('div');
            toast.className = 'zenx-badge active zenx-animate-in';
            toast.style.cssText = 'bottom:80px;left:50%;transform:translateX(-50%);background:var(--zenx-primary)';
            toast.textContent = message;
            document.body.appendChild(toast);
            setTimeout(() => toast.remove(), 3000);
        }
    },

    // Audit Log Module
    auditLog: {
        events: [],
        init: () => { ZENX.auditLog.events = ZENXStorage.get('audit_log') || []; },
        log: (action, details = {}) => {
            const event = { id: ZENX.utils.generateId(), action, details, timestamp: Date.now(), device: ZENX.utils.fingerprint() };
            ZENX.auditLog.events.unshift(event);
            if (ZENX.auditLog.events.length > 100) ZENX.auditLog.events.pop();
            ZENXStorage.set('audit_log', ZENX.auditLog.events);
            ZENX.auditLog.render();
            return event;
        },
        render: () => {
            const container = document.getElementById('zenx-audit-timeline');
            if (!container) return;
            container.innerHTML = ZENX.auditLog.events.slice(0, 20).map(e => `
        <div class="zenx-timeline-item zenx-animate-in">
          <div class="time">${ZENX.utils.formatDate(e.timestamp)}</div>
          <strong>${e.action}</strong>
          ${e.details.info ? `<div style="opacity:0.7;font-size:0.9rem">${e.details.info}</div>` : ''}
        </div>
      `).join('') || '<p style="opacity:0.5">No events yet</p>';
        },
        export: () => {
            const blob = new Blob([JSON.stringify(ZENX.auditLog.events, null, 2)], { type: 'application/json' });
            const a = document.createElement('a'); a.href = URL.createObjectURL(blob); a.download = 'zenauth-audit-log.json'; a.click();
        }
    },

    // Session Management
    session: {
        current: null,
        devices: [],
        init: () => {
            ZENX.session.devices = ZENXStorage.get('devices') || [];
            const fp = ZENX.utils.fingerprint();
            let device = ZENX.session.devices.find(d => d.fingerprint === fp);
            if (!device) {
                device = { id: ZENX.utils.generateId(), fingerprint: fp, name: navigator.userAgent.includes('Mobile') ? '📱 Mobile Device' : '💻 Desktop', created: Date.now(), lastActive: Date.now(), trusted: false };
                ZENX.session.devices.push(device);
            }
            device.lastActive = Date.now();
            ZENX.session.current = device;
            ZENXStorage.set('devices', ZENX.session.devices);
        },
        trustDevice: (id) => {
            const device = ZENX.session.devices.find(d => d.id === id);
            if (device) { device.trusted = true; ZENXStorage.set('devices', ZENX.session.devices); ZENX.auditLog.log('device_trusted', { info: device.name }); }
        },
        revokeDevice: (id) => {
            ZENX.session.devices = ZENX.session.devices.filter(d => d.id !== id);
            ZENXStorage.set('devices', ZENX.session.devices);
            ZENX.auditLog.log('device_revoked');
        },
        render: () => {
            const container = document.getElementById('zenx-devices-list');
            if (!container) return;
            container.innerHTML = ZENX.session.devices.map(d => `
        <div class="zenx-device ${d.id === ZENX.session.current?.id ? 'current' : ''}">
          <div class="zenx-device-icon">${d.name.split(' ')[0]}</div>
          <div class="zenx-device-info">
            <div class="zenx-device-name">${d.name.split(' ').slice(1).join(' ') || 'Device'} ${d.trusted ? '✓' : ''}</div>
            <div class="zenx-device-meta">Last active: ${ZENX.utils.formatDate(d.lastActive)}</div>
          </div>
          ${d.id !== ZENX.session.current?.id ? `<button class="zenx-btn zenx-btn-secondary" onclick="ZENX.session.revokeDevice('${d.id}');ZENX.session.render()">Revoke</button>` : '<span style="color:var(--zenx-success)">Current</span>'}
        </div>
      `).join('');
        }
    },

    // Telemetry/Security HUD
    telemetry: {
        data: { lastLogin: null, failedAttempts: 0, riskScore: 0, tokensGenerated: 0 },
        init: () => { ZENX.telemetry.data = ZENXStorage.get('telemetry') || ZENX.telemetry.data; },
        update: (key, value) => { ZENX.telemetry.data[key] = value; ZENXStorage.set('telemetry', ZENX.telemetry.data); ZENX.telemetry.render(); },
        increment: (key) => { ZENX.telemetry.data[key] = (ZENX.telemetry.data[key] || 0) + 1; ZENXStorage.set('telemetry', ZENX.telemetry.data); ZENX.telemetry.render(); },
        render: () => {
            const hud = document.getElementById('zenx-security-hud');
            if (!hud) return;
            const d = ZENX.telemetry.data;
            hud.querySelector('.zenx-hud-content').innerHTML = `
        <div class="zenx-hud-item"><span>Last Login</span><span>${d.lastLogin ? ZENX.utils.formatDate(d.lastLogin) : 'Never'}</span></div>
        <div class="zenx-hud-item"><span>Tokens Generated</span><span>${d.tokensGenerated || 0}</span></div>
        <div class="zenx-hud-item"><span>Failed Attempts</span><span>${d.failedAttempts || 0}</span></div>
        <div class="zenx-hud-item"><span>Risk Score</span><span style="color:${d.riskScore > 50 ? 'var(--zenx-danger)' : 'var(--zenx-success)'}">${d.riskScore || 0}%</span></div>
      `;
        }
    },

    // Token Vault
    vault: {
        tokens: [],
        init: () => { ZENX.vault.tokens = ZENXStorage.get('token_vault') || []; },
        save: (token) => {
            if (ZENX.vault.tokens.find(t => t.value === token)) return;
            ZENX.vault.tokens.unshift({ id: ZENX.utils.generateId(), value: token, created: Date.now(), tags: [], verified: false });
            if (ZENX.vault.tokens.length > 50) ZENX.vault.tokens.pop();
            ZENXStorage.set('token_vault', ZENX.vault.tokens);
            ZENX.auditLog.log('token_saved', { info: token.slice(0, 8) + '...' });
            ZENX.vault.render();
        },
        delete: (id) => {
            ZENX.vault.tokens = ZENX.vault.tokens.filter(t => t.id !== id);
            ZENXStorage.set('token_vault', ZENX.vault.tokens);
            ZENX.vault.render();
        },
        render: () => {
            const container = document.getElementById('zenx-vault-list');
            if (!container) return;
            container.innerHTML = ZENX.vault.tokens.slice(0, 10).map(t => `
        <div class="zenx-device">
          <div class="zenx-device-icon">🔑</div>
          <div class="zenx-device-info">
            <div class="zenx-code-display" style="padding:5px;font-size:0.8rem">${t.value}</div>
            <div class="zenx-device-meta">${ZENX.utils.formatDate(t.created)} ${t.verified ? '✓ Verified' : ''}</div>
          </div>
          <button class="zenx-btn zenx-btn-secondary" onclick="ZENX.utils.copyToClipboard('${t.value}')">📋</button>
        </div>
      `).join('') || '<p style="opacity:0.5">No saved tokens</p>';
        }
    },

    // Offline Mode
    offline: {
        isOnline: navigator.onLine,
        init: () => {
            window.addEventListener('online', () => { ZENX.offline.isOnline = true; ZENX.offline.updateBadge(); });
            window.addEventListener('offline', () => { ZENX.offline.isOnline = false; ZENX.offline.updateBadge(); });
            ZENX.offline.updateBadge();
        },
        updateBadge: () => {
            const badge = document.getElementById('zenx-offline-badge');
            if (badge) badge.classList.toggle('active', !ZENX.offline.isOnline);
        }
    },

    // PWA
    pwa: {
        deferredPrompt: null,
        init: () => {
            if ('serviceWorker' in navigator && ZENX_CONFIG.ENABLE_PWA) {
                navigator.serviceWorker.register('/sw.js').catch(() => { });
            }
            window.addEventListener('beforeinstallprompt', (e) => { e.preventDefault(); ZENX.pwa.deferredPrompt = e; });
        },
        install: async () => {
            if (ZENX.pwa.deferredPrompt) {
                ZENX.pwa.deferredPrompt.prompt();
                await ZENX.pwa.deferredPrompt.userChoice;
                ZENX.pwa.deferredPrompt = null;
            }
        }
    },

    // Initialize all modules
    init: () => {
        console.log('🚀 ZENX v' + ZENX.version + ' initializing...');
        ZENX.auditLog.init();
        ZENX.session.init();
        ZENX.telemetry.init();
        ZENX.vault.init();
        ZENX.offline.init();
        ZENX.pwa.init();
        ZENX.telemetry.update('lastLogin', Date.now());
        ZENX.auditLog.log('session_start', { info: 'App loaded' });
        console.log('✅ ZENX initialized with config:', ZENX_CONFIG);
    }
};
