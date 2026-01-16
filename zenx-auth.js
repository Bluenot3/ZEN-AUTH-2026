// === ZENX AUTHENTICATION MODULE ===

// WebAuthn / Passkey Support
ZENX.auth = {
    webauthn: {
        isSupported: () => !!window.PublicKeyCredential,
        register: async (username) => {
            if (!ZENX.auth.webauthn.isSupported()) { ZENX.ui.toast('WebAuthn not supported', 'error'); return null; }
            try {
                const challenge = crypto.getRandomValues(new Uint8Array(32));
                const userId = new TextEncoder().encode(username);
                const createOptions = {
                    publicKey: {
                        challenge,
                        rp: { name: 'ZENAuth', id: location.hostname },
                        user: { id: userId, name: username, displayName: username },
                        pubKeyCredParams: [{ alg: -7, type: 'public-key' }, { alg: -257, type: 'public-key' }],
                        authenticatorSelection: { authenticatorAttachment: 'platform', userVerification: 'preferred', residentKey: 'preferred' },
                        timeout: 60000,
                        attestation: 'none'
                    }
                };
                const credential = await navigator.credentials.create(createOptions);
                const credentialData = { id: credential.id, rawId: Array.from(new Uint8Array(credential.rawId)), type: credential.type, created: Date.now() };
                const credentials = ZENX.storage.get('webauthn_credentials') || [];
                credentials.push({ username, credential: credentialData });
                ZENX.storage.set('webauthn_credentials', credentials);
                ZENX.auditLog.log('passkey_registered', { info: username });
                ZENX.ui.toast('✅ Passkey registered successfully!');
                return credentialData;
            } catch (e) { console.error('WebAuthn error:', e); ZENX.ui.toast('Passkey registration failed', 'error'); return null; }
        },
        authenticate: async () => {
            if (!ZENX.auth.webauthn.isSupported()) { ZENX.ui.toast('WebAuthn not supported', 'error'); return false; }
            try {
                const credentials = ZENX.storage.get('webauthn_credentials') || [];
                if (credentials.length === 0) { ZENX.ui.toast('No passkeys registered', 'error'); return false; }
                const challenge = crypto.getRandomValues(new Uint8Array(32));
                const getOptions = {
                    publicKey: {
                        challenge,
                        allowCredentials: credentials.map(c => ({ id: new Uint8Array(c.credential.rawId), type: 'public-key' })),
                        userVerification: 'preferred',
                        timeout: 60000
                    }
                };
                await navigator.credentials.get(getOptions);
                ZENX.auditLog.log('passkey_auth_success');
                ZENX.ui.toast('✅ Authenticated with passkey!');
                return true;
            } catch (e) { ZENX.auditLog.log('passkey_auth_failed'); ZENX.telemetry.increment('failedAttempts'); return false; }
        }
    },

    magicLink: {
        pendingEmail: null,
        sendLink: async (email) => {
            if (!email || !email.includes('@')) { ZENX.ui.toast('Invalid email', 'error'); return false; }
            const token = ZENX.utils.generateId() + '-' + Date.now();
            ZENX.storage.set('magic_link_' + token, { email, created: Date.now(), expires: Date.now() + 600000 });
            ZENX.auth.magicLink.pendingEmail = email;
            ZENX.auditLog.log('magic_link_sent', { info: email });
            // In production, this would send an email via backend
            ZENX.ui.toast(`📧 Magic link sent to ${email}! (Demo: token copied)`);
            await ZENX.utils.copyToClipboard(token);
            return token;
        },
        verify: (token) => {
            const data = ZENX.storage.get('magic_link_' + token);
            if (!data) { ZENX.ui.toast('Invalid or expired link', 'error'); return false; }
            if (Date.now() > data.expires) { ZENX.storage.delete('magic_link_' + token); ZENX.ui.toast('Link expired', 'error'); return false; }
            ZENX.storage.delete('magic_link_' + token);
            ZENX.auditLog.log('magic_link_verified', { info: data.email });
            ZENX.ui.toast('✅ Email verified!');
            return data.email;
        }
    },

    totp: {
        secret: null,
        generateSecret: () => {
            const chars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';
            let secret = '';
            for (let i = 0; i < 32; i++) secret += chars[Math.floor(Math.random() * chars.length)];
            return secret;
        },
        getOTPAuthURL: (secret, account) => `otpauth://totp/ZENAuth:${encodeURIComponent(account)}?secret=${secret}&issuer=ZENAuth&algorithm=SHA1&digits=6&period=30`,
        generateCode: (secret) => {
            // RFC 6238 TOTP - simplified for demo
            const epoch = Math.floor(Date.now() / 30000);
            let hash = 0;
            for (let i = 0; i < secret.length; i++) hash = ((hash << 5) - hash + secret.charCodeAt(i) + epoch) | 0;
            return String(Math.abs(hash) % 1000000).padStart(6, '0');
        },
        verify: (secret, code) => {
            const currentCode = ZENX.auth.totp.generateCode(secret);
            return code === currentCode;
        },
        setup: (account) => {
            const secret = ZENX.auth.totp.generateSecret();
            ZENX.storage.set('totp_secret', secret);
            ZENX.storage.set('totp_account', account);
            const url = ZENX.auth.totp.getOTPAuthURL(secret, account);
            ZENX.auditLog.log('totp_setup', { info: account });
            return { secret, url };
        },
        generateBackupCodes: () => {
            const codes = [];
            for (let i = 0; i < 10; i++) codes.push(Math.random().toString(36).substring(2, 10).toUpperCase());
            ZENX.storage.set('backup_codes', codes);
            return codes;
        }
    }
};

// === ZENX WEB3 MODULE ===
ZENX.web3 = {
    provider: null,
    account: null,
    chainId: null,

    isSupported: () => typeof window.ethereum !== 'undefined',

    connect: async (walletType = 'metamask') => {
        if (!ZENX.web3.isSupported()) {
            ZENX.ui.toast('No Web3 wallet detected. Install MetaMask!', 'error');
            window.open('https://metamask.io/download/', '_blank');
            return null;
        }
        try {
            const accounts = await window.ethereum.request({ method: 'eth_requestAccounts' });
            ZENX.web3.account = accounts[0];
            ZENX.web3.chainId = await window.ethereum.request({ method: 'eth_chainId' });
            ZENX.web3.provider = window.ethereum;

            window.ethereum.on('accountsChanged', (accounts) => { ZENX.web3.account = accounts[0]; ZENX.web3.renderStatus(); });
            window.ethereum.on('chainChanged', () => window.location.reload());

            ZENX.auditLog.log('wallet_connected', { info: ZENX.utils.truncateAddress(ZENX.web3.account) });
            ZENX.ui.toast('🦊 Wallet connected!');
            ZENX.web3.renderStatus();
            return ZENX.web3.account;
        } catch (e) { console.error('Web3 connect error:', e); ZENX.ui.toast('Wallet connection failed', 'error'); return null; }
    },

    disconnect: () => {
        ZENX.web3.account = null;
        ZENX.web3.provider = null;
        ZENX.auditLog.log('wallet_disconnected');
        ZENX.web3.renderStatus();
    },

    signMessage: async (message) => {
        if (!ZENX.web3.account) { ZENX.ui.toast('Connect wallet first', 'error'); return null; }
        try {
            const signature = await window.ethereum.request({ method: 'personal_sign', params: [message, ZENX.web3.account] });
            ZENX.auditLog.log('message_signed', { info: message.slice(0, 20) + '...' });
            return signature;
        } catch (e) { console.error('Sign error:', e); return null; }
    },

    verifyToken: async (token) => {
        if (!ZENX.web3.account) { await ZENX.web3.connect(); }
        if (!ZENX.web3.account) return null;
        const message = `ZENAuth Token Verification\n\nToken: ${token}\nTimestamp: ${Date.now()}\nAddress: ${ZENX.web3.account}`;
        const signature = await ZENX.web3.signMessage(message);
        if (signature) {
            const verification = { token, address: ZENX.web3.account, signature, timestamp: Date.now(), verified: true };
            ZENX.storage.set('verified_' + token, verification);
            const t = ZENX.vault.tokens.find(t => t.value === token);
            if (t) { t.verified = true; ZENX.storage.set('token_vault', ZENX.vault.tokens); }
            ZENX.auditLog.log('token_verified_onchain', { info: ZENX.utils.truncateAddress(ZENX.web3.account) });
            ZENX.ui.toast('⛓️ Token verified on-chain!');
            return verification;
        }
        return null;
    },

    getBalance: async () => {
        if (!ZENX.web3.account) return '0';
        try {
            const balance = await window.ethereum.request({ method: 'eth_getBalance', params: [ZENX.web3.account, 'latest'] });
            return (parseInt(balance, 16) / 1e18).toFixed(4);
        } catch { return '0'; }
    },

    renderStatus: () => {
        const container = document.getElementById('zenx-wallet-status');
        if (!container) return;
        if (ZENX.web3.account) {
            container.innerHTML = `
        <div class="zenx-wallet-status connected">
          <span style="font-size:1.5rem">🦊</span>
          <div style="flex:1">
            <div style="font-weight:bold">${ZENX.utils.truncateAddress(ZENX.web3.account)}</div>
            <div style="font-size:0.8rem;opacity:0.7">Connected</div>
          </div>
          <button class="zenx-btn zenx-btn-secondary" onclick="ZENX.web3.disconnect()">Disconnect</button>
        </div>
      `;
        } else {
            container.innerHTML = `
        <button class="zenx-btn zenx-btn-web3" onclick="ZENX.web3.connect()" style="width:100%">
          🦊 Connect Wallet
        </button>
      `;
        }
    },

    getNetworkName: () => {
        const networks = { '0x1': 'Ethereum', '0x89': 'Polygon', '0xa86a': 'Avalanche', '0x38': 'BSC', '0xa4b1': 'Arbitrum' };
        return networks[ZENX.web3.chainId] || 'Unknown Network';
    }
};

// === ZENX API KEYS MODULE ===
ZENX.apiKeys = {
    keys: [],
    init: () => { ZENX.apiKeys.keys = ZENX.storage.get('api_keys') || []; },
    generate: (name, permissions = ['read']) => {
        const key = { id: ZENX.utils.generateId(), name, key: 'zk_' + crypto.randomUUID().replace(/-/g, ''), permissions, created: Date.now(), lastUsed: null, active: true };
        ZENX.apiKeys.keys.push(key);
        ZENX.storage.set('api_keys', ZENX.apiKeys.keys);
        ZENX.auditLog.log('api_key_created', { info: name });
        ZENX.apiKeys.render();
        return key;
    },
    revoke: (id) => {
        const key = ZENX.apiKeys.keys.find(k => k.id === id);
        if (key) { key.active = false; ZENX.storage.set('api_keys', ZENX.apiKeys.keys); ZENX.auditLog.log('api_key_revoked', { info: key.name }); }
        ZENX.apiKeys.render();
    },
    render: () => {
        const container = document.getElementById('zenx-api-keys-list');
        if (!container) return;
        container.innerHTML = ZENX.apiKeys.keys.map(k => `
      <div class="zenx-device" style="opacity:${k.active ? 1 : 0.5}">
        <div class="zenx-device-icon">🔐</div>
        <div class="zenx-device-info">
          <div class="zenx-device-name">${k.name} ${!k.active ? '(Revoked)' : ''}</div>
          <div class="zenx-code-display" style="padding:5px;font-size:0.75rem">${k.key.slice(0, 20)}...</div>
        </div>
        ${k.active ? `<button class="zenx-btn zenx-btn-secondary" onclick="ZENX.utils.copyToClipboard('${k.key}')">📋</button>` : ''}
      </div>
    `).join('') || '<p style="opacity:0.5">No API keys</p>';
    }
};

// === ZENX WEBHOOKS MODULE ===
ZENX.webhooks = {
    hooks: [],
    init: () => { ZENX.webhooks.hooks = ZENX.storage.get('webhooks') || []; },
    add: (url, events = ['token_generated']) => {
        const hook = { id: ZENX.utils.generateId(), url, events, created: Date.now(), active: true };
        ZENX.webhooks.hooks.push(hook);
        ZENX.storage.set('webhooks', ZENX.webhooks.hooks);
        ZENX.auditLog.log('webhook_created', { info: url });
        ZENX.webhooks.render();
        return hook;
    },
    trigger: async (event, data) => {
        for (const hook of ZENX.webhooks.hooks.filter(h => h.active && h.events.includes(event))) {
            try { await fetch(hook.url, { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ event, data, timestamp: Date.now() }), mode: 'no-cors' }); } catch { }
        }
    },
    render: () => {
        const container = document.getElementById('zenx-webhooks-list');
        if (!container) return;
        container.innerHTML = ZENX.webhooks.hooks.map(h => `
      <div class="zenx-device">
        <div class="zenx-device-icon">🔗</div>
        <div class="zenx-device-info">
          <div class="zenx-device-name">${new URL(h.url).hostname}</div>
          <div class="zenx-device-meta">Events: ${h.events.join(', ')}</div>
        </div>
        <button class="zenx-btn zenx-btn-secondary" onclick="ZENX.webhooks.hooks=ZENX.webhooks.hooks.filter(x=>x.id!=='${h.id}');ZENX.storage.set('webhooks',ZENX.webhooks.hooks);ZENX.webhooks.render()">❌</button>
      </div>
    `).join('') || '<p style="opacity:0.5">No webhooks</p>';
    }
};

// Extended init
const originalInit = ZENX.init;
ZENX.init = () => {
    originalInit();
    ZENX.apiKeys.init();
    ZENX.webhooks.init();
    ZENX.web3.renderStatus();
    ZENX.session.render();
    ZENX.vault.render();
    ZENX.apiKeys.render();
    ZENX.webhooks.render();
    ZENX.auditLog.render();
    ZENX.telemetry.render();
};
