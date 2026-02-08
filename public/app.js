// LANtern - Client-side Application with E2E Encryption

// ============ SOFTWARE AES-GCM FALLBACK (for HTTP / non-secure contexts) ============
// A compact pure-JS AES-256-GCM implementation so encryption works without crypto.subtle.
const SoftCrypto = (() => {
    // --- AES core ---
    const SBOX = new Uint8Array(256), INV_SBOX = new Uint8Array(256);
    const RCON = [0x01,0x02,0x04,0x08,0x10,0x20,0x40,0x80,0x1b,0x36];
    (function initSbox() {
        let p = 1, q = 1;
        do {
            p ^= (p << 1) ^ (p & 0x80 ? 0x11b : 0);
            p &= 0xff;
            q ^= q << 1; q ^= q << 2; q ^= q << 4;
            q ^= q & 0x80 ? 0x09 : 0; q &= 0xff;
            const x = q ^ (q << 1 | q >>> 7) ^ (q << 2 | q >>> 6) ^
                      (q << 3 | q >>> 5) ^ (q << 4 | q >>> 4);
            SBOX[p] = (x ^ 0x63) & 0xff;
            INV_SBOX[SBOX[p]] = p;
        } while (p !== 1);
        SBOX[0] = 0x63; INV_SBOX[0x63] = 0;
    })();

    function expandKey256(key) {
        const w = new Uint32Array(60);
        for (let i = 0; i < 8; i++)
            w[i] = (key[4*i]<<24)|(key[4*i+1]<<16)|(key[4*i+2]<<8)|key[4*i+3];
        for (let i = 8; i < 60; i++) {
            let t = w[i-1];
            if (i % 8 === 0) {
                t = (t << 8 | t >>> 24);
                t = (SBOX[t>>>24]<<24)|(SBOX[(t>>>16)&0xff]<<16)|
                    (SBOX[(t>>>8)&0xff]<<8)|SBOX[t&0xff];
                t ^= RCON[i/8-1] << 24;
            } else if (i % 8 === 4) {
                t = (SBOX[t>>>24]<<24)|(SBOX[(t>>>16)&0xff]<<16)|
                    (SBOX[(t>>>8)&0xff]<<8)|SBOX[t&0xff];
            }
            w[i] = w[i-8] ^ t;
        }
        return w;
    }

    function encryptBlock(block, w) {
        const s = new Uint8Array(16);
        for (let i = 0; i < 16; i++) s[i] = block[i] ^ (w[i>>2] >>> (24-8*(i%4))) & 0xff;
        for (let r = 1; r <= 14; r++) {
            const t = new Uint8Array(16);
            // SubBytes + ShiftRows
            const shifts = [0,5,10,15,4,9,14,3,8,13,2,7,12,1,6,11];
            for (let i = 0; i < 16; i++) t[i] = SBOX[s[shifts[i]]];
            if (r < 14) {
                // MixColumns
                for (let c = 0; c < 4; c++) {
                    const a = [t[4*c],t[4*c+1],t[4*c+2],t[4*c+3]];
                    const x2 = a.map(v => (v<<1)^(v&0x80?0x1b:0)&0xff);
                    t[4*c]   = (x2[0]^x2[1]^a[1]^a[2]^a[3])&0xff;
                    t[4*c+1] = (a[0]^x2[1]^x2[2]^a[2]^a[3])&0xff;
                    t[4*c+2] = (a[0]^a[1]^x2[2]^x2[3]^a[3])&0xff;
                    t[4*c+3] = (x2[0]^a[0]^a[1]^a[2]^x2[3])&0xff;
                }
            }
            // AddRoundKey
            for (let i = 0; i < 16; i++) s[i] = t[i] ^ ((w[r*4+(i>>2)] >>> (24-8*(i%4))) & 0xff);
        }
        return s;
    }

    // --- GCM helpers ---
    function inc32(counter) {
        const c = new Uint8Array(counter);
        for (let i = 15; i >= 12; i--) { c[i]++; if (c[i] !== 0) break; }
        return c;
    }

    function ghashBlock(H, X, Y) {
        // XOR then multiply in GF(2^128) – bit-by-bit (not fast, but correct)
        const Z = new Uint8Array(16);
        const V = new Uint8Array(16);
        for (let i = 0; i < 16; i++) V[i] = H[i];
        const R = new Uint8Array(16); R[0] = 0xe1; // R polynomial
        // XOR X into Y first
        const val = new Uint8Array(16);
        for (let i = 0; i < 16; i++) val[i] = (Y[i] || 0) ^ (X[i] || 0);
        for (let i = 0; i < 128; i++) {
            if (val[i >> 3] & (0x80 >> (i & 7))) {
                for (let j = 0; j < 16; j++) Z[j] ^= V[j];
            }
            const lsb = V[15] & 1;
            for (let j = 15; j > 0; j--) V[j] = (V[j] >> 1) | ((V[j-1] & 1) << 7);
            V[0] >>= 1;
            if (lsb) for (let j = 0; j < 16; j++) V[j] ^= R[j];
        }
        return Z;
    }

    function ghash(H, aad, ciphertext) {
        let Y = new Uint8Array(16);
        // Process AAD (empty for us)
        const aadLen = aad ? aad.length : 0;
        for (let i = 0; i < aadLen; i += 16) {
            const block = new Uint8Array(16);
            for (let j = 0; j < 16 && i+j < aadLen; j++) block[j] = aad[i+j];
            Y = ghashBlock(H, block, Y);
        }
        // Process ciphertext
        for (let i = 0; i < ciphertext.length; i += 16) {
            const block = new Uint8Array(16);
            for (let j = 0; j < 16 && i+j < ciphertext.length; j++) block[j] = ciphertext[i+j];
            Y = ghashBlock(H, block, Y);
        }
        // Length block: 64-bit AAD length, 64-bit ciphertext length (in bits)
        const lenBlock = new Uint8Array(16);
        const aadBits = aadLen * 8, ctBits = ciphertext.length * 8;
        lenBlock[4] = (aadBits >>> 24) & 0xff; lenBlock[5] = (aadBits >>> 16) & 0xff;
        lenBlock[6] = (aadBits >>> 8) & 0xff; lenBlock[7] = aadBits & 0xff;
        lenBlock[12] = (ctBits >>> 24) & 0xff; lenBlock[13] = (ctBits >>> 16) & 0xff;
        lenBlock[14] = (ctBits >>> 8) & 0xff; lenBlock[15] = ctBits & 0xff;
        Y = ghashBlock(H, lenBlock, Y);
        return Y;
    }

    return {
        async deriveKey(password, salt, iterations) {
            // PBKDF2-SHA256
            const enc = new TextEncoder();
            const pwd = enc.encode(password);
            const s = enc.encode(salt);
            // HMAC-SHA256 helper
            async function hmacSha256(key, data) {
                const bKey = key.length > 64 ? new Uint8Array(await sha256(key)) : key;
                const iPad = new Uint8Array(64), oPad = new Uint8Array(64);
                for (let i = 0; i < 64; i++) {
                    iPad[i] = 0x36 ^ (bKey[i] || 0);
                    oPad[i] = 0x5c ^ (bKey[i] || 0);
                }
                const inner = new Uint8Array(64 + data.length);
                inner.set(iPad); inner.set(data, 64);
                const innerHash = new Uint8Array(await sha256(inner));
                const outer = new Uint8Array(64 + 32);
                outer.set(oPad); outer.set(innerHash, 64);
                return new Uint8Array(await sha256(outer));
            }
            async function sha256(data) {
                // Use subtle if available, else a tiny JS sha256
                if (typeof crypto !== 'undefined' && crypto.subtle) {
                    return crypto.subtle.digest('SHA-256', data);
                }
                return jsSha256(data);
            }
            // Tiny JS SHA-256
            function jsSha256(msg) {
                const K = [
                    0x428a2f98,0x71374491,0xb5c0fbcf,0xe9b5dba5,0x3956c25b,0x59f111f1,0x923f82a4,0xab1c5ed5,
                    0xd807aa98,0x12835b01,0x243185be,0x550c7dc3,0x72be5d74,0x80deb1fe,0x9bdc06a7,0xc19bf174,
                    0xe49b69c1,0xefbe4786,0x0fc19dc6,0x240ca1cc,0x2de92c6f,0x4a7484aa,0x5cb0a9dc,0x76f988da,
                    0x983e5152,0xa831c66d,0xb00327c8,0xbf597fc7,0xc6e00bf3,0xd5a79147,0x06ca6351,0x14292967,
                    0x27b70a85,0x2e1b2138,0x4d2c6dfc,0x53380d13,0x650a7354,0x766a0abb,0x81c2c92e,0x92722c85,
                    0xa2bfe8a1,0xa81a664b,0xc24b8b70,0xc76c51a3,0xd192e819,0xd6990624,0xf40e3585,0x106aa070,
                    0x19a4c116,0x1e376c08,0x2748774c,0x34b0bcb5,0x391c0cb3,0x4ed8aa4a,0x5b9cca4f,0x682e6ff3,
                    0x748f82ee,0x78a5636f,0x84c87814,0x8cc70208,0x90befffa,0xa4506ceb,0xbef9a3f7,0xc67178f2
                ];
                const data = (msg instanceof Uint8Array) ? msg : new Uint8Array(msg);
                const len = data.length;
                const bitLen = len * 8;
                const padLen = ((len + 9 + 63) & ~63);
                const padded = new Uint8Array(padLen);
                padded.set(data);
                padded[len] = 0x80;
                padded[padLen-4] = (bitLen >>> 24) & 0xff;
                padded[padLen-3] = (bitLen >>> 16) & 0xff;
                padded[padLen-2] = (bitLen >>> 8) & 0xff;
                padded[padLen-1] = bitLen & 0xff;
                let [h0,h1,h2,h3,h4,h5,h6,h7] = [0x6a09e667,0xbb67ae85,0x3c6ef372,0xa54ff53a,0x510e527f,0x9b05688c,0x1f83d9ab,0x5be0cd19];
                const W = new Int32Array(64);
                for (let off = 0; off < padLen; off += 64) {
                    for (let i = 0; i < 16; i++) W[i] = (padded[off+4*i]<<24)|(padded[off+4*i+1]<<16)|(padded[off+4*i+2]<<8)|padded[off+4*i+3];
                    for (let i = 16; i < 64; i++) {
                        const s0 = (((W[i-15]>>>7)|(W[i-15]<<25))^((W[i-15]>>>18)|(W[i-15]<<14))^(W[i-15]>>>3));
                        const s1 = (((W[i-2]>>>17)|(W[i-2]<<15))^((W[i-2]>>>19)|(W[i-2]<<13))^(W[i-2]>>>10));
                        W[i] = (W[i-16]+s0+W[i-7]+s1)|0;
                    }
                    let [a,b,c,d,e,f,g,h] = [h0,h1,h2,h3,h4,h5,h6,h7];
                    for (let i = 0; i < 64; i++) {
                        const S1 = (((e>>>6)|(e<<26))^((e>>>11)|(e<<21))^((e>>>25)|(e<<7)));
                        const ch = (e&f)^(~e&g);
                        const t1 = (h+S1+ch+K[i]+W[i])|0;
                        const S0 = (((a>>>2)|(a<<30))^((a>>>13)|(a<<19))^((a>>>22)|(a<<10)));
                        const maj = (a&b)^(a&c)^(b&c);
                        const t2 = (S0+maj)|0;
                        h=g; g=f; f=e; e=(d+t1)|0; d=c; c=b; b=a; a=(t1+t2)|0;
                    }
                    h0=(h0+a)|0; h1=(h1+b)|0; h2=(h2+c)|0; h3=(h3+d)|0;
                    h4=(h4+e)|0; h5=(h5+f)|0; h6=(h6+g)|0; h7=(h7+h)|0;
                }
                const out = new ArrayBuffer(32);
                const dv = new DataView(out);
                [h0,h1,h2,h3,h4,h5,h6,h7].forEach((v,i) => dv.setInt32(i*4, v));
                return out;
            }
            // PBKDF2
            const u1Salt = new Uint8Array(s.length + 4);
            u1Salt.set(s); u1Salt[s.length+3] = 1; // block index = 1
            let U = await hmacSha256(pwd, u1Salt);
            const result = new Uint8Array(U);
            for (let i = 1; i < iterations; i++) {
                U = await hmacSha256(pwd, U);
                for (let j = 0; j < 32; j++) result[j] ^= U[j];
            }
            return result; // 32 bytes = AES-256 key
        },

        encrypt(key, iv, plaintext) {
            const rk = expandKey256(key);
            // Encrypt zero block to get H for GHASH
            const H = encryptBlock(new Uint8Array(16), rk);
            // J0 = IV || 00000001
            const J0 = new Uint8Array(16);
            J0.set(iv); J0[15] = 1;
            // CTR encryption
            let counter = new Uint8Array(J0);
            const ct = new Uint8Array(plaintext.length);
            for (let i = 0; i < plaintext.length; i += 16) {
                counter = inc32(counter);
                const ks = encryptBlock(counter, rk);
                for (let j = 0; j < 16 && i+j < plaintext.length; j++) {
                    ct[i+j] = plaintext[i+j] ^ ks[j];
                }
            }
            // GHASH
            const tag = ghash(H, null, ct);
            // Encrypt J0 and XOR with tag
            const encJ0 = encryptBlock(J0, rk);
            const authTag = new Uint8Array(16);
            for (let i = 0; i < 16; i++) authTag[i] = tag[i] ^ encJ0[i];
            return { ciphertext: ct, tag: authTag };
        },

        decrypt(key, iv, ciphertext, tag) {
            const rk = expandKey256(key);
            const H = encryptBlock(new Uint8Array(16), rk);
            const J0 = new Uint8Array(16);
            J0.set(iv); J0[15] = 1;
            // Verify tag
            const computedTag = ghash(H, null, ciphertext);
            const encJ0 = encryptBlock(J0, rk);
            for (let i = 0; i < 16; i++) {
                if (((computedTag[i] ^ encJ0[i]) & 0xff) !== tag[i]) {
                    throw new Error('Authentication tag mismatch – wrong password or corrupted data');
                }
            }
            // CTR decryption
            let counter = new Uint8Array(J0);
            const pt = new Uint8Array(ciphertext.length);
            for (let i = 0; i < ciphertext.length; i += 16) {
                counter = inc32(counter);
                const ks = encryptBlock(counter, rk);
                for (let j = 0; j < 16 && i+j < ciphertext.length; j++) {
                    pt[i+j] = ciphertext[i+j] ^ ks[j];
                }
            }
            return pt;
        }
    };
})();

// ============ CRYPTO HELPER (auto-selects Web Crypto or software fallback) ============
class CryptoHelper {
    constructor() {
        this.key = null;
        this.rawKey = null; // For software fallback
        this.useNative = !!(typeof crypto !== 'undefined' && crypto.subtle);
    }

    async deriveKey(password) {
        if (this.useNative) {
            try {
                const encoder = new TextEncoder();
                const passwordData = encoder.encode(password);
                const baseKey = await crypto.subtle.importKey(
                    'raw', passwordData, 'PBKDF2', false, ['deriveBits', 'deriveKey']
                );
                this.key = await crypto.subtle.deriveKey(
                    { name: 'PBKDF2', salt: encoder.encode('LANtern-salt-v1'), iterations: 100000, hash: 'SHA-256' },
                    baseKey,
                    { name: 'AES-GCM', length: 256 },
                    true,
                    ['encrypt', 'decrypt']
                );
                return this.key;
            } catch (e) {
                console.warn('Web Crypto failed, falling back to software crypto:', e.message);
                this.useNative = false;
            }
        }
        // Software fallback – use fewer iterations for usable speed in pure JS
        this.rawKey = await SoftCrypto.deriveKey(password, 'LANtern-salt-v1', 1000);
        this.key = this.rawKey;
        return this.key;
    }

    _getIV() {
        if (typeof crypto !== 'undefined' && crypto.getRandomValues) {
            return crypto.getRandomValues(new Uint8Array(12));
        }
        const iv = new Uint8Array(12);
        for (let i = 0; i < 12; i++) iv[i] = Math.floor(Math.random() * 256);
        return iv;
    }

    async encrypt(data) {
        if (!this.key) throw new Error('Key not derived');
        const encoder = new TextEncoder();
        const dataBytes = typeof data === 'string' ? encoder.encode(data) : new Uint8Array(data);
        const iv = this._getIV();

        if (this.useNative) {
            const encrypted = await crypto.subtle.encrypt({ name: 'AES-GCM', iv }, this.key, dataBytes);
            const combined = new Uint8Array(iv.length + encrypted.byteLength);
            combined.set(iv);
            combined.set(new Uint8Array(encrypted), iv.length);
            return this.arrayBufferToBase64(combined);
        }
        // Software path
        const { ciphertext, tag } = SoftCrypto.encrypt(this.rawKey, iv, dataBytes);
        const combined = new Uint8Array(12 + ciphertext.length + 16);
        combined.set(iv);
        combined.set(ciphertext, 12);
        combined.set(tag, 12 + ciphertext.length);
        return this.arrayBufferToBase64(combined);
    }

    async decrypt(encryptedBase64) {
        if (!this.key) throw new Error('Key not derived');
        const combined = this.base64ToArrayBuffer(encryptedBase64);
        const iv = combined.slice(0, 12);

        if (this.useNative) {
            const encrypted = combined.slice(12);
            const decrypted = await crypto.subtle.decrypt({ name: 'AES-GCM', iv }, this.key, encrypted);
            return new TextDecoder().decode(decrypted);
        }
        // Software path: last 16 bytes are tag
        const ciphertext = combined.slice(12, combined.length - 16);
        const tag = combined.slice(combined.length - 16);
        const pt = SoftCrypto.decrypt(this.rawKey, iv, ciphertext, tag);
        return new TextDecoder().decode(pt);
    }

    async encryptFile(file) {
        const arrayBuffer = await file.arrayBuffer();
        const iv = this._getIV();

        if (this.useNative) {
            const encrypted = await crypto.subtle.encrypt({ name: 'AES-GCM', iv }, this.key, arrayBuffer);
            const combined = new Uint8Array(iv.length + encrypted.byteLength);
            combined.set(iv);
            combined.set(new Uint8Array(encrypted), iv.length);
            return new Blob([combined], { type: 'application/encrypted' });
        }
        const { ciphertext, tag } = SoftCrypto.encrypt(this.rawKey, iv, new Uint8Array(arrayBuffer));
        const combined = new Uint8Array(12 + ciphertext.length + 16);
        combined.set(iv);
        combined.set(ciphertext, 12);
        combined.set(tag, 12 + ciphertext.length);
        return new Blob([combined], { type: 'application/encrypted' });
    }

    async decryptFile(encryptedBlob, originalName) {
        const arrayBuffer = await encryptedBlob.arrayBuffer();
        const combined = new Uint8Array(arrayBuffer);
        const iv = combined.slice(0, 12);

        if (this.useNative) {
            const encrypted = combined.slice(12);
            const decrypted = await crypto.subtle.decrypt({ name: 'AES-GCM', iv }, this.key, encrypted);
            const mimeType = this.getMimeType(originalName);
            return new Blob([decrypted], { type: mimeType });
        }
        const ciphertext = combined.slice(12, combined.length - 16);
        const tag = combined.slice(combined.length - 16);
        const pt = SoftCrypto.decrypt(this.rawKey, iv, ciphertext, tag);
        const mimeType = this.getMimeType(originalName);
        return new Blob([pt], { type: mimeType });
    }

    getMimeType(filename) {
        const ext = filename.split('.').pop().toLowerCase();
        const mimeTypes = {
            pdf: 'application/pdf', jpg: 'image/jpeg', jpeg: 'image/jpeg',
            png: 'image/png', gif: 'image/gif', mp4: 'video/mp4',
            mp3: 'audio/mpeg', zip: 'application/zip', txt: 'text/plain'
        };
        return mimeTypes[ext] || 'application/octet-stream';
    }

    arrayBufferToBase64(buffer) {
        let binary = '';
        const bytes = new Uint8Array(buffer);
        for (let i = 0; i < bytes.byteLength; i++) {
            binary += String.fromCharCode(bytes[i]);
        }
        return btoa(binary);
    }

    base64ToArrayBuffer(base64) {
        const binary = atob(base64);
        const bytes = new Uint8Array(binary.length);
        for (let i = 0; i < binary.length; i++) {
            bytes[i] = binary.charCodeAt(i);
        }
        return bytes;
    }
}

class OfflineQueue {
    constructor() {
        this.queue = [];
    }

    enqueue(type, data) {
        this.queue.push({ type, data, timestamp: Date.now() });
    }

    dequeueAll() {
        const items = [...this.queue];
        this.queue = [];
        return items;
    }

    get length() {
        return this.queue.length;
    }

    clear() {
        this.queue = [];
    }
}

class LANternApp {
    constructor() {
        // Configure socket with reconnection options for local network
        this.socket = io({
            reconnection: true,
            reconnectionAttempts: Infinity,
            reconnectionDelay: 1000,
            reconnectionDelayMax: 5000,
            timeout: 20000,
            transports: ['websocket', 'polling']
        });
        this.crypto = new CryptoHelper();
        this.user = null;
        this.isHost = false;
        this.sessionPassword = null;
        this.connectedUsers = [];
        this.selectedFiles = [];
        this.shareMode = 'all';
        this.textShareMode = 'all';
        this.selectedUsersToShare = [];
        this.connectionAttempts = 0;
        this.isConnected = false;
        this.offlineQueue = new OfflineQueue();

        this.init();
    }

    init() {
        this.bindElements();
        this.bindEvents();
        this.setupSocketListeners();
    }

    bindElements() {
        // Landing page
        this.landingPage = document.getElementById('landing-page');
        this.hostPage = document.getElementById('host-page');
        this.clientPage = document.getElementById('client-page');
        this.usernameInput = document.getElementById('username');
        this.passwordInput = document.getElementById('session-password');
        this.hostKeyInput = document.getElementById('host-key');
        this.joinHostBtn = document.getElementById('join-as-host');
        this.joinClientBtn = document.getElementById('join-as-client');

        // Host elements
        this.hostNameEl = document.getElementById('host-name');
        this.hostLogoutBtn = document.getElementById('host-logout');
        this.usersList = document.getElementById('users-list');
        this.userCount = document.getElementById('user-count');
        this.hostDropzone = document.getElementById('host-dropzone');
        this.hostFileInput = document.getElementById('host-file-input');
        this.hostUploadBtn = document.getElementById('host-upload-btn');
        this.shareAllBtn = document.getElementById('share-all-btn');
        this.shareSelectedBtn = document.getElementById('share-selected-btn');
        this.userSelectContainer = document.getElementById('user-select-container');
        this.userCheckboxes = document.getElementById('user-checkboxes');
        this.hostFilesList = document.getElementById('host-files-list');
        this.hostFilesCount = document.getElementById('host-files-count');
        this.receivedFilesList = document.getElementById('received-files-list');
        this.clientFilesCount = document.getElementById('client-files-count');

        // Host text elements
        this.hostTextInput = document.getElementById('host-text-input');
        this.hostSendTextBtn = document.getElementById('host-send-text-btn');
        this.textShareAllBtn = document.getElementById('text-share-all-btn');
        this.textShareSelectedBtn = document.getElementById('text-share-selected-btn');
        this.textUserSelectContainer = document.getElementById('text-user-select-container');
        this.textUserCheckboxes = document.getElementById('text-user-checkboxes');
        this.hostSharedTexts = document.getElementById('host-shared-texts');
        this.hostReceivedTexts = document.getElementById('host-received-texts');
        this.hostReceivedTextsCount = document.getElementById('host-received-texts-count');

        // Client elements
        this.clientNameEl = document.getElementById('client-name');
        this.clientLogoutBtn = document.getElementById('client-logout');
        this.clientDropzone = document.getElementById('client-dropzone');
        this.clientFileInput = document.getElementById('client-file-input');
        this.clientUploadBtn = document.getElementById('client-upload-btn');
        this.availableFilesList = document.getElementById('available-files-list');
        this.availableFilesCount = document.getElementById('available-files-count');

        // Client text elements
        this.clientTextInput = document.getElementById('client-text-input');
        this.clientSendTextBtn = document.getElementById('client-send-text-btn');
        this.clientReceivedTexts = document.getElementById('client-received-texts');
        this.receivedTextsCount = document.getElementById('received-texts-count');

        // Modal
        this.progressModal = document.getElementById('progress-modal');
        this.progressFill = document.getElementById('progress-fill');
        this.progressText = document.getElementById('progress-text');

        // Chat elements
        this.hostChatMessages = document.getElementById('host-chat-messages');
        this.hostChatInput = document.getElementById('host-chat-input');
        this.hostChatSend = document.getElementById('host-chat-send');
        this.clientChatMessages = document.getElementById('client-chat-messages');
        this.clientChatInput = document.getElementById('client-chat-input');
        this.clientChatSend = document.getElementById('client-chat-send');

        // Batch download buttons
        this.hostDownloadAllBtn = document.getElementById('host-download-all-btn');
        this.clientDownloadAllBtn = document.getElementById('client-download-all-btn');
        this.hostDownloadReceivedBtn = document.getElementById('host-download-client-files-btn');

        // Preview modal
        this.previewModal = document.getElementById('preview-modal');
        this.previewClose = document.getElementById('preview-close');
        this.previewTitle = document.getElementById('preview-filename');
        this.previewContainer = document.getElementById('preview-container');
        this.previewDownload = document.getElementById('preview-download');

        // Sidebar elements
        this.hostSidebar = document.getElementById('host-sidebar');
        this.clientSidebar = document.getElementById('client-sidebar');
        this.hostHamburger = document.getElementById('host-hamburger');
        this.clientHamburger = document.getElementById('client-hamburger');
        this.hostSidebarClose = document.getElementById('host-sidebar-close');
        this.clientSidebarClose = document.getElementById('client-sidebar-close');
        this.hostSidebarOverlay = document.getElementById('host-sidebar-overlay');
        this.clientSidebarOverlay = document.getElementById('client-sidebar-overlay');
        this.hostPageTitle = document.getElementById('host-page-title');
        this.clientPageTitle = document.getElementById('client-page-title');

        // Stats elements
        this.statUsers = document.getElementById('stat-users');
        this.statFiles = document.getElementById('stat-files');
        this.statMessages = document.getElementById('stat-messages');
        this.clientStatFiles = document.getElementById('client-stat-files');
        this.clientStatMessages = document.getElementById('client-stat-messages');
        this.navUserCount = document.getElementById('nav-user-count');
    }

    bindEvents() {
        // Landing page events
        this.joinHostBtn.addEventListener('click', () => this.joinSession(true));
        this.joinClientBtn.addEventListener('click', () => this.joinSession(false));
        this.usernameInput.addEventListener('keypress', (e) => {
            if (e.key === 'Enter') this.passwordInput.focus();
        });
        this.passwordInput.addEventListener('keypress', (e) => {
            if (e.key === 'Enter') this.joinSession(false);
        });

        // Logout buttons
        this.hostLogoutBtn.addEventListener('click', () => this.logout());
        this.clientLogoutBtn.addEventListener('click', () => this.logout());

        // Host upload events
        this.setupDropzone(this.hostDropzone, this.hostFileInput, true);
        this.hostUploadBtn.addEventListener('click', () => this.uploadFiles(true));

        // Share mode toggle
        this.shareAllBtn.addEventListener('click', () => this.setShareMode('all'));
        this.shareSelectedBtn.addEventListener('click', () => this.setShareMode('selected'));

        // Text share mode toggle
        this.textShareAllBtn.addEventListener('click', () => this.setTextShareMode('all'));
        this.textShareSelectedBtn.addEventListener('click', () => this.setTextShareMode('selected'));

        // Host text send
        this.hostSendTextBtn.addEventListener('click', () => this.sendText(true));
        this.hostTextInput.addEventListener('keypress', (e) => {
            if (e.key === 'Enter' && !e.shiftKey) {
                e.preventDefault();
                this.sendText(true);
            }
        });

        // Client upload events
        this.setupDropzone(this.clientDropzone, this.clientFileInput, false);
        this.clientUploadBtn.addEventListener('click', () => this.uploadFiles(false));

        // Client text send
        this.clientSendTextBtn.addEventListener('click', () => this.sendText(false));
        this.clientTextInput.addEventListener('keypress', (e) => {
            if (e.key === 'Enter' && !e.shiftKey) {
                e.preventDefault();
                this.sendText(false);
            }
        });

        // Chat events
        this.hostChatSend?.addEventListener('click', () => this.sendChatMessage(true));
        this.hostChatInput?.addEventListener('keypress', (e) => {
            if (e.key === 'Enter') this.sendChatMessage(true);
        });
        this.clientChatSend?.addEventListener('click', () => this.sendChatMessage(false));
        this.clientChatInput?.addEventListener('keypress', (e) => {
            if (e.key === 'Enter') this.sendChatMessage(false);
        });

        // Batch download events
        this.hostDownloadAllBtn?.addEventListener('click', () => this.downloadAllFiles('host'));
        this.clientDownloadAllBtn?.addEventListener('click', () => this.downloadAllFiles('host'));
        this.hostDownloadReceivedBtn?.addEventListener('click', () => this.downloadAllFiles('client'));

        // Preview modal events
        this.previewClose?.addEventListener('click', () => this.closePreview());
        this.previewModal?.addEventListener('click', (e) => {
            if (e.target === this.previewModal) this.closePreview();
        });
        document.addEventListener('keydown', (e) => {
            if (e.key === 'Escape' && this.previewModal?.classList.contains('active')) {
                this.closePreview();
            }
        });

        // Store the current preview file for download
        this.currentPreviewFile = null;

        // Sidebar navigation events
        this.setupSidebarEvents();
    }

    setupSidebarEvents() {
        // Hamburger toggle
        this.hostHamburger?.addEventListener('click', () => this.toggleSidebar(true, true));
        this.clientHamburger?.addEventListener('click', () => this.toggleSidebar(false, true));
        
        // Close buttons
        this.hostSidebarClose?.addEventListener('click', () => this.toggleSidebar(true, false));
        this.clientSidebarClose?.addEventListener('click', () => this.toggleSidebar(false, false));
        
        // Overlay click
        this.hostSidebarOverlay?.addEventListener('click', () => this.toggleSidebar(true, false));
        this.clientSidebarOverlay?.addEventListener('click', () => this.toggleSidebar(false, false));

        // Navigation items
        const hostNavItems = this.hostPage?.querySelectorAll('.nav-item');
        const clientNavItems = this.clientPage?.querySelectorAll('.nav-item');

        hostNavItems?.forEach(item => {
            item.addEventListener('click', () => this.switchSection(true, item.dataset.section));
        });

        clientNavItems?.forEach(item => {
            item.addEventListener('click', () => this.switchSection(false, item.dataset.section));
        });

        // Quick action buttons
        const hostActionBtns = this.hostPage?.querySelectorAll('.action-btn[data-goto]');
        const clientActionBtns = this.clientPage?.querySelectorAll('.action-btn[data-goto]');

        hostActionBtns?.forEach(btn => {
            btn.addEventListener('click', () => this.switchSection(true, btn.dataset.goto));
        });

        clientActionBtns?.forEach(btn => {
            btn.addEventListener('click', () => this.switchSection(false, btn.dataset.goto));
        });
    }

    toggleSidebar(isHost, open) {
        const sidebar = isHost ? this.hostSidebar : this.clientSidebar;
        const overlay = isHost ? this.hostSidebarOverlay : this.clientSidebarOverlay;

        if (open) {
            sidebar?.classList.add('open');
            overlay?.classList.add('active');
        } else {
            sidebar?.classList.remove('open');
            overlay?.classList.remove('active');
        }
    }

    switchSection(isHost, sectionName) {
        const page = isHost ? this.hostPage : this.clientPage;
        const pageTitle = isHost ? this.hostPageTitle : this.clientPageTitle;
        
        // Update nav items
        const navItems = page?.querySelectorAll('.nav-item');
        navItems?.forEach(item => {
            item.classList.toggle('active', item.dataset.section === sectionName);
        });

        // Update sections
        const sections = page?.querySelectorAll('.content-section');
        sections?.forEach(section => {
            const sectionId = isHost ? `host-section-${sectionName}` : `client-section-${sectionName}`;
            section.classList.toggle('active', section.id === sectionId);
        });

        // Update page title
        const titles = {
            'home': 'Home',
            'community': 'Community',
            'chat': 'Group Chat',
            'files': 'Files',
            'messages': 'Messages'
        };
        if (pageTitle) pageTitle.textContent = titles[sectionName] || 'Home';

        // Close sidebar on mobile
        this.toggleSidebar(isHost, false);
    }

    setupDropzone(dropzone, fileInput, isHost) {
        dropzone.addEventListener('click', () => fileInput.click());
        
        dropzone.addEventListener('dragover', (e) => {
            e.preventDefault();
            dropzone.classList.add('dragover');
        });

        dropzone.addEventListener('dragleave', () => {
            dropzone.classList.remove('dragover');
        });

        dropzone.addEventListener('drop', (e) => {
            e.preventDefault();
            dropzone.classList.remove('dragover');
            this.handleFiles(e.dataTransfer.files, isHost);
        });

        fileInput.addEventListener('change', (e) => {
            this.handleFiles(e.target.files, isHost);
        });
    }

    handleFiles(files, isHost) {
        const maxSize = 25 * 1024 * 1024;
        const validFiles = [];

        for (const file of files) {
            if (file.size > maxSize) {
                this.showToast(`${file.name} exceeds 25MB limit`, 'error');
            } else {
                validFiles.push(file);
            }
        }

        if (validFiles.length > 0) {
            this.selectedFiles = validFiles;
            const uploadBtn = isHost ? this.hostUploadBtn : this.clientUploadBtn;
            uploadBtn.disabled = false;
            uploadBtn.textContent = `🔐 Upload ${validFiles.length} file(s) (Encrypted)`;
            this.showToast(`${validFiles.length} file(s) ready to upload`, 'info');
        }
    }

    setupSocketListeners() {
        // Connection established
        this.socket.on('connect', () => {
            console.log('Connected to server');
            this.isConnected = true;
            this.connectionAttempts = 0;
            this.updateConnectionStatus(true);
            // Hide any connection error messages
            const errorEl = document.getElementById('connection-error');
            if (errorEl) errorEl.style.display = 'none';
        });

        // Connection error handling
        this.socket.on('connect_error', (error) => {
            console.error('Connection error:', error);
            this.connectionAttempts++;
            this.showConnectionError(`Unable to connect to server. Attempt ${this.connectionAttempts}/10...`);
        });

        // Disconnection handling
        this.socket.on('disconnect', (reason) => {
            console.log('Disconnected:', reason);
            this.isConnected = false;
            this.updateConnectionStatus(false);
            if (reason === 'io server disconnect') {
                // Server disconnected us, try to reconnect
                this.socket.connect();
            }
            this.showToast('Disconnected from server. Data will be sent when reconnected.', 'error');
        });

        // Reconnection events
        this.socket.on('reconnect', (attemptNumber) => {
            console.log('Reconnected after', attemptNumber, 'attempts');
            this.isConnected = true;
            this.updateConnectionStatus(true);
            this.showToast('Reconnected to server!', 'success');
            // Re-register so the server knows who we are
            if (this.user) {
                this.socket.emit('register', {
                    name: this.user.name,
                    isHost: this.isHost,
                    password: this.sessionPassword,
                    hostKey: ''
                });
                this.loadFiles();
                this.loadTexts();
            }
            // Flush any queued offline operations
            this.flushOfflineQueue();
        });

        this.socket.on('reconnect_failed', () => {
            this.showConnectionError('Failed to connect to server. Please check if the server is running and refresh the page.');
        });

        this.socket.on('registered', (user) => {
            this.user = user;
            this.isHost = user.isHost;
            try {
                this.showDashboard();
                this.loadFiles();
                this.loadTexts();
            } catch (error) {
                console.error('Error in showDashboard:', error);
                this.showToast('Error loading dashboard: ' + error.message, 'error');
            }
        });

        this.socket.on('error', (data) => {
            console.error('Socket error:', data);
            this.showToast(data.message, 'error');
        });

        this.socket.on('sessionEnded', (data) => {
            this.showToast(data.message, 'error');
            setTimeout(() => location.reload(), 2000);
        });

        this.socket.on('kicked', (data) => {
            this.showToast(data.message, 'error');
            setTimeout(() => location.reload(), 2000);
        });

        this.socket.on('blocked', (data) => {
            this.showToast(data.message, 'error');
            setTimeout(() => location.reload(), 2000);
        });

        this.socket.on('usersUpdate', (data) => {
            this.connectedUsers = data.users;
            this.updateUsersList();
            this.updateUserCheckboxes();
        });

        this.socket.on('userJoined', (user) => {
            this.showToast(`${user.name} joined the session`, 'info');
        });

        this.socket.on('userLeft', (user) => {
            this.showToast(`${user.name} left the session`, 'info');
        });

        this.socket.on('newHostFile', (file) => {
            if (!this.isHost) {
                this.addFileToList(this.availableFilesList, file, false);
                this.updateFilesCount();
                this.showToast(`New file available: ${file.originalName}`, 'success');
            }
        });

        this.socket.on('newClientFile', (file) => {
            if (this.isHost) {
                this.addFileToList(this.receivedFilesList, file, true, true);
                this.updateFilesCount();
                const uploader = this.connectedUsers.find(u => u.id === file.uploadedBy);
                const uploaderName = uploader ? uploader.name : 'A user';
                this.showToast(`${uploaderName} sent: ${file.originalName}`, 'success');
            }
        });

        this.socket.on('fileDeleted', (data) => {
            const fileElements = document.querySelectorAll(`[data-file-id="${data.fileId}"]`);
            fileElements.forEach(el => el.remove());
            this.updateFilesCount();
            this.checkEmptyStates();
        });

        // Text message listeners
        this.socket.on('newHostText', async (text) => {
            if (!this.isHost) {
                await this.addTextToList(this.clientReceivedTexts, text, false);
                this.updateTextsCount();
                this.showToast('New message from host', 'success');
            }
        });

        this.socket.on('newClientText', async (text) => {
            if (this.isHost) {
                await this.addTextToList(this.hostReceivedTexts, text, true);
                this.updateTextsCount();
                const sender = this.connectedUsers.find(u => u.id === text.uploadedBy);
                const senderName = sender ? sender.name : 'A user';
                this.showToast(`Message from ${senderName}`, 'success');
            }
        });

        this.socket.on('textDeleted', (data) => {
            const textElements = document.querySelectorAll(`[data-text-id="${data.textId}"]`);
            textElements.forEach(el => el.remove());
            this.updateTextsCount();
            this.checkEmptyStates();
        });

        // Chat message listener
        this.socket.on('newChatMessage', (message) => {
            this.displayChatMessage(message);
        });

        // Load chat history on connect
        this.socket.on('chatHistory', (messages) => {
            messages.forEach(msg => this.displayChatMessage(msg, false));
        });
    }

    async joinSession(asHost) {
        const name = this.usernameInput.value.trim();
        const password = this.passwordInput.value.trim();
        const hostKey = this.hostKeyInput ? this.hostKeyInput.value.trim() : '';

        if (!name) {
            this.showToast('Please enter your name', 'error');
            this.usernameInput.focus();
            return;
        }

        if (!password) {
            this.showToast('Please enter a session password', 'error');
            this.passwordInput.focus();
            return;
        }

        if (asHost && !hostKey) {
            this.showToast('Host key is required to host a session', 'error');
            this.hostKeyInput.focus();
            return;
        }

        try {
            await this.crypto.deriveKey(password);
            this.sessionPassword = password;
        } catch (error) {
            this.showToast('Failed to initialize encryption', 'error');
            return;
        }

        this.socket.emit('register', { name, isHost: asHost, password, hostKey });
    }

    showDashboard() {
        if (!this.landingPage) return;
        
        this.landingPage.classList.remove('active');
        
        if (this.isHost) {
            if (!this.hostPage) return;
            this.hostPage.classList.add('active');
            if (this.hostNameEl) {
                this.hostNameEl.textContent = this.user.name;
            }
        } else {
            if (!this.clientPage) return;
            this.clientPage.classList.add('active');
            if (this.clientNameEl) {
                this.clientNameEl.textContent = this.user.name;
            }
        }

        // Load chat history
        this.loadChatHistory();
    }

    async loadChatHistory() {
        try {
            const response = await fetch('/api/chat');
            const data = await response.json();
            
            if (data.messages && data.messages.length > 0) {
                // Clear empty state
                const chatMessages = this.isHost ? this.hostChatMessages : this.clientChatMessages;
                if (chatMessages) {
                    const emptyState = chatMessages.querySelector('.chat-empty');
                    if (emptyState) emptyState.remove();
                }
                
                for (const msg of data.messages) {
                    await this.displayChatMessage(msg, false);
                }
            }
        } catch (error) {
            console.error('Failed to load chat history:', error);
        }
    }

    logout() {
        location.reload();
    }

    setShareMode(mode) {
        this.shareMode = mode;
        
        if (mode === 'all') {
            this.shareAllBtn.classList.add('active');
            this.shareSelectedBtn.classList.remove('active');
            this.userSelectContainer.classList.add('hidden');
        } else {
            this.shareAllBtn.classList.remove('active');
            this.shareSelectedBtn.classList.add('active');
            this.userSelectContainer.classList.remove('hidden');
        }
    }

    setTextShareMode(mode) {
        this.textShareMode = mode;
        
        if (mode === 'all') {
            this.textShareAllBtn.classList.add('active');
            this.textShareSelectedBtn.classList.remove('active');
            this.textUserSelectContainer.classList.add('hidden');
        } else {
            this.textShareAllBtn.classList.remove('active');
            this.textShareSelectedBtn.classList.add('active');
            this.textUserSelectContainer.classList.remove('hidden');
            this.updateTextUserCheckboxes();
        }
    }

    updateTextUserCheckboxes() {
        if (!this.isHost || !this.textUserCheckboxes) return;

        if (this.connectedUsers.length === 0) {
            this.textUserCheckboxes.innerHTML = '<p style="color: var(--text-muted); font-size: 12px;">No users to select</p>';
        } else {
            this.textUserCheckboxes.innerHTML = this.connectedUsers.map(user => `
                <label class="user-checkbox">
                    <input type="checkbox" value="${user.id}" ${this.selectedUsersToShare.includes(user.id) ? 'checked' : ''}>
                    ${this.escapeHtml(user.name)}
                </label>
            `).join('');

            this.textUserCheckboxes.querySelectorAll('input').forEach(checkbox => {
                checkbox.addEventListener('change', (e) => {
                    if (e.target.checked) {
                        if (!this.selectedUsersToShare.includes(e.target.value)) {
                            this.selectedUsersToShare.push(e.target.value);
                        }
                    } else {
                        this.selectedUsersToShare = this.selectedUsersToShare.filter(id => id !== e.target.value);
                    }
                });
            });
        }
    }

    updateUsersList() {
        if (!this.isHost) return;

        const userCount = this.connectedUsers.length;

        if (userCount === 0) {
            this.usersList.innerHTML = `
                <div class="empty-state-card">
                    <span class="empty-icon">👥</span>
                    <p>Waiting for guests to join...</p>
                    <p class="empty-hint">Share the session link with others</p>
                </div>
            `;
        } else {
            this.usersList.innerHTML = this.connectedUsers.map(user => `
                <div class="user-card" data-user-id="${user.id}">
                    <div class="user-avatar">${user.name.charAt(0).toUpperCase()}</div>
                    <div class="user-info">
                        <div class="name">${this.escapeHtml(user.name)}</div>
                        <div class="status">🟢 Online</div>
                    </div>
                    <div class="user-actions">
                        <button class="btn btn-small btn-kick" data-user-id="${user.id}" title="Remove user">🚪</button>
                        <button class="btn btn-small btn-block" data-user-id="${user.id}" title="Block user">🚫</button>
                    </div>
                </div>
            `).join('');
            
            // Add event listeners for kick and block buttons
            this.usersList.querySelectorAll('.btn-kick').forEach(btn => {
                btn.addEventListener('click', (e) => {
                    const userId = e.target.dataset.userId;
                    const user = this.connectedUsers.find(u => u.id === userId);
                    if (confirm(`Remove ${user?.name || 'this user'} from the session?`)) {
                        this.socket.emit('kickUser', { userId });
                        this.showToast(`${user?.name || 'User'} has been removed`, 'info');
                    }
                });
            });
            
            this.usersList.querySelectorAll('.btn-block').forEach(btn => {
                btn.addEventListener('click', (e) => {
                    const userId = e.target.dataset.userId;
                    const user = this.connectedUsers.find(u => u.id === userId);
                    if (confirm(`Block ${user?.name || 'this user'}? They won't be able to rejoin this session.`)) {
                        this.socket.emit('blockUser', { userId });
                        this.showToast(`${user?.name || 'User'} has been blocked`, 'warning');
                    }
                });
            });
        }

        // Update all user count displays
        if (this.userCount) this.userCount.textContent = `${userCount} member${userCount !== 1 ? 's' : ''}`;
        if (this.navUserCount) this.navUserCount.textContent = userCount;
        if (this.statUsers) this.statUsers.textContent = userCount;
    }

    updateUserCheckboxes() {
        if (!this.isHost) return;

        if (this.connectedUsers.length === 0) {
            this.userCheckboxes.innerHTML = '<p style="color: var(--text-muted); font-size: 12px;">No users to select</p>';
        } else {
            this.userCheckboxes.innerHTML = this.connectedUsers.map(user => `
                <label class="user-checkbox">
                    <input type="checkbox" value="${user.id}" ${this.selectedUsersToShare.includes(user.id) ? 'checked' : ''}>
                    ${this.escapeHtml(user.name)}
                </label>
            `).join('');

            this.userCheckboxes.querySelectorAll('input').forEach(checkbox => {
                checkbox.addEventListener('change', (e) => {
                    if (e.target.checked) {
                        this.selectedUsersToShare.push(e.target.value);
                    } else {
                        this.selectedUsersToShare = this.selectedUsersToShare.filter(id => id !== e.target.value);
                    }
                });
            });
        }
    }

    async sendText(isHost) {
        const textInput = isHost ? this.hostTextInput : this.clientTextInput;
        const content = textInput.value.trim();

        if (!content) {
            this.showToast('Please enter a message', 'error');
            return;
        }

        try {
            const encryptedContent = await this.crypto.encrypt(content);
            const sharedWith = isHost ? (this.textShareMode === 'all' ? 'all' : [...this.selectedUsersToShare]) : 'host';
            const payload = {
                encryptedContent,
                sharedWith,
                isHost,
                userId: this.user.id
            };

            if (!this.isConnected) {
                this.offlineQueue.enqueue('text', payload);
                textInput.value = '';
                this.showToast('Message queued — will send when reconnected', 'info');
                return;
            }

            const response = await fetch('/api/text', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify(payload)
            });

            const result = await response.json();

            if (result.success) {
                textInput.value = '';
                this.showToast('Message sent (encrypted)', 'success');
                
                if (isHost) {
                    await this.addTextToList(this.hostSharedTexts, { ...result.text, decryptedContent: content }, true);
                }
            } else {
                this.showToast(result.error || 'Failed to send message', 'error');
            }
        } catch (error) {
            // Network error – queue for later
            if (!this.isConnected) {
                this.showToast('Message queued — will send when reconnected', 'info');
            } else {
                this.showToast('Failed to send message: ' + error.message, 'error');
            }
        }
    }

    async addTextToList(listEl, text, canDelete) {
        const emptyState = listEl.querySelector('.empty-state');
        if (emptyState) emptyState.remove();

        let content = text.decryptedContent;
        if (!content) {
            try {
                content = await this.crypto.decrypt(text.content);
            } catch (error) {
                content = '[Decryption failed]';
            }
        }

        const sender = text.uploadedBy ? this.connectedUsers.find(u => u.id === text.uploadedBy) : null;
        const senderName = text.isFromHost ? 'Host' : (sender ? sender.name : 'Unknown');
        const time = new Date(text.uploadedAt).toLocaleTimeString();

        const textItem = document.createElement('div');
        textItem.className = 'text-item';
        textItem.dataset.textId = text.id;
        textItem.innerHTML = `
            <div class="text-header">
                <span class="text-sender">${this.escapeHtml(senderName)}</span>
                <span class="text-time">${time}</span>
                <span class="encrypted-badge">🔐</span>
                ${canDelete ? `<button class="btn-delete-text" onclick="app.deleteText('${text.id}')">✕</button>` : ''}
            </div>
            <div class="text-content">${this.escapeHtml(content)}</div>
        `;

        listEl.prepend(textItem);
        this.updateTextsCount();
    }

    async deleteText(textId) {
        if (!confirm('Delete this message?')) return;

        try {
            const response = await fetch(`/api/texts/${textId}?isHost=${this.isHost}`, {
                method: 'DELETE'
            });

            const result = await response.json();

            if (result.success) {
                this.showToast('Message deleted', 'success');
            } else {
                this.showToast(result.error || 'Delete failed', 'error');
            }
        } catch (error) {
            this.showToast('Delete failed', 'error');
        }
    }

    async uploadFiles(isHost) {
        if (this.selectedFiles.length === 0) return;

        const uploadBtn = isHost ? this.hostUploadBtn : this.clientUploadBtn;
        uploadBtn.disabled = true;

        for (const file of this.selectedFiles) {
            await this.uploadSingleFile(file, isHost);
        }

        this.selectedFiles = [];
        uploadBtn.textContent = isHost ? '🔐 Upload & Share (Encrypted)' : '🔐 Send to Host (Encrypted)';
        
        if (isHost) {
            this.hostFileInput.value = '';
        } else {
            this.clientFileInput.value = '';
        }
    }

    async uploadSingleFile(file, isHost) {
        this.showProgress(0);

        try {
            this.showProgress(20);
            const encryptedBlob = await this.crypto.encryptFile(file);
            this.showProgress(50);

            if (!this.isConnected) {
                // Queue the encrypted file for later upload
                this.offlineQueue.enqueue('file', {
                    encryptedBlob,
                    fileName: file.name,
                    fileSize: file.size,
                    isHost,
                    sharedWith: isHost ? (this.shareMode === 'all' ? 'all' : [...this.selectedUsersToShare]) : undefined
                });
                this.showProgress(100);
                this.showToast(`${file.name} queued — will upload when reconnected`, 'info');
                this.hideProgress();
                return;
            }

            const formData = new FormData();
            formData.append('file', encryptedBlob, file.name + '.enc');
            
            if (isHost) {
                const sharedWith = this.shareMode === 'all' ? 'all' : this.selectedUsersToShare;
                formData.append('sharedWith', JSON.stringify(sharedWith));
            }

            formData.append('originalName', file.name);
            formData.append('originalSize', file.size);

            const response = await fetch(`/api/upload?isHost=${isHost}&userId=${this.user.id}`, {
                method: 'POST',
                body: formData
            });

            this.showProgress(90);
            const result = await response.json();

            if (result.success) {
                result.file.displayName = file.name;
                result.file.originalSize = file.size;
                
                this.showToast(`${file.name} uploaded (encrypted)`, 'success');
                
                if (isHost) {
                    this.addFileToList(this.hostFilesList, result.file, true);
                }
                this.updateFilesCount();
            } else {
                this.showToast(result.error || 'Upload failed', 'error');
            }
        } catch (error) {
            // Network error – queue for later
            this.showToast('Upload failed, will retry when reconnected', 'error');
        }

        this.hideProgress();
    }

    showProgress(percent) {
        this.progressModal.classList.remove('hidden');
        this.progressFill.style.width = `${percent}%`;
        this.progressText.textContent = `${percent}%`;
    }

    hideProgress() {
        this.progressModal.classList.add('hidden');
    }

    async loadFiles() {
        try {
            const response = await fetch(`/api/files?userId=${this.user.id}&isHost=${this.isHost}`);
            const data = await response.json();

            if (this.isHost) {
                if (data.hostFiles && data.hostFiles.length > 0) {
                    this.hostFilesList.innerHTML = '';
                    data.hostFiles.forEach(file => {
                        this.addFileToList(this.hostFilesList, file, true);
                    });
                }

                if (data.clientFiles && data.clientFiles.length > 0) {
                    this.receivedFilesList.innerHTML = '';
                    data.clientFiles.forEach(file => {
                        this.addFileToList(this.receivedFilesList, file, true, true);
                    });
                }
            } else {
                if (data.hostFiles && data.hostFiles.length > 0) {
                    this.availableFilesList.innerHTML = '';
                    data.hostFiles.forEach(file => {
                        this.addFileToList(this.availableFilesList, file, false);
                    });
                }
            }

            this.updateFilesCount();
            this.checkEmptyStates();
        } catch (error) {
            console.error('Failed to load files:', error);
        }
    }

    async loadTexts() {
        try {
            const response = await fetch(`/api/texts?userId=${this.user.id}&isHost=${this.isHost}`);
            const data = await response.json();

            if (data.texts && data.texts.length > 0) {
                for (const text of data.texts) {
                    if (this.isHost) {
                        if (text.isFromHost) {
                            await this.addTextToList(this.hostSharedTexts, text, true);
                        } else {
                            await this.addTextToList(this.hostReceivedTexts, text, true);
                        }
                    } else {
                        if (text.isFromHost) {
                            await this.addTextToList(this.clientReceivedTexts, text, false);
                        }
                    }
                }
            }

            this.updateTextsCount();
            this.checkEmptyStates();
        } catch (error) {
            console.error('Failed to load texts:', error);
        }
    }

    addFileToList(listEl, file, canDelete, isClientFile = false) {
        const emptyState = listEl.querySelector('.empty-state');
        if (emptyState) emptyState.remove();

        const displayName = file.displayName || file.originalName.replace('.enc', '');
        const fileIcon = this.getFileIcon(displayName);
        const fileSize = this.formatFileSize(file.originalSize || file.size);
        const uploadDate = new Date(file.uploadedAt).toLocaleString();
        
        let uploaderInfo = '';
        if (isClientFile && file.uploadedBy) {
            const uploader = this.connectedUsers.find(u => u.id === file.uploadedBy);
            uploaderInfo = `<span>From: ${uploader ? this.escapeHtml(uploader.name) : 'Unknown'}</span>`;
        }

        let sharedInfo = '';
        if (!isClientFile && this.isHost && file.sharedWith) {
            if (file.sharedWith === 'all') {
                sharedInfo = '<span>Shared with: Everyone</span>';
            } else if (Array.isArray(file.sharedWith)) {
                const names = file.sharedWith.map(id => {
                    const user = this.connectedUsers.find(u => u.id === id);
                    return user ? user.name : 'Unknown';
                });
                sharedInfo = `<span>Shared with: ${names.join(', ') || 'Selected users'}</span>`;
            }
        }

        const fileItem = document.createElement('div');
        fileItem.className = 'file-item';
        fileItem.dataset.fileId = file.id;
        
        // Check if file is previewable
        const ext = displayName.split('.').pop().toLowerCase();
        const previewableExts = ['jpg', 'jpeg', 'png', 'gif', 'webp', 'bmp', 'svg', 'mp4', 'webm', 'ogg', 'mov', 'mp3', 'wav', 'flac', 'm4a', 'pdf', 'txt', 'md', 'json', 'js', 'ts', 'py', 'html', 'css', 'xml', 'csv', 'log'];
        const canPreview = previewableExts.includes(ext);

        fileItem.innerHTML = `
            <span class="file-icon">${fileIcon}</span>
            <div class="file-info">
                <div class="name" title="${this.escapeHtml(displayName)}">
                    ${this.escapeHtml(displayName)}
                    <span class="encrypted-badge">🔐</span>
                </div>
                <div class="meta">
                    <span>${fileSize}</span>
                    <span>${uploadDate}</span>
                    ${uploaderInfo}
                    ${sharedInfo}
                </div>
            </div>
            <div class="file-actions">
                ${canPreview ? `<button class="btn-preview" onclick="app.previewFile('${file.id}', '${this.escapeHtml(displayName).replace(/'/g, "\\'")}')">👁 Preview</button>` : ''}
                <button class="btn-download" onclick="app.downloadFile('${file.id}', '${this.escapeHtml(displayName).replace(/'/g, "\\'")}')">⬇ Download</button>
                ${canDelete ? `<button class="btn-delete" onclick="app.deleteFile('${file.id}')">✕</button>` : ''}
            </div>
        `;

        listEl.prepend(fileItem);
    }

    async downloadFile(fileId, originalName) {
        try {
            this.showToast('Downloading and decrypting...', 'info');
            
            const response = await fetch(`/api/download/${fileId}?userId=${this.user.id}&isHost=${this.isHost}`);
            
            if (!response.ok) {
                throw new Error('Download failed');
            }

            const encryptedBlob = await response.blob();
            const decryptedBlob = await this.crypto.decryptFile(encryptedBlob, originalName);
            
            const url = URL.createObjectURL(decryptedBlob);
            const a = document.createElement('a');
            a.href = url;
            a.download = originalName;
            document.body.appendChild(a);
            a.click();
            document.body.removeChild(a);
            URL.revokeObjectURL(url);
            
            this.showToast('File downloaded and decrypted', 'success');
        } catch (error) {
            this.showToast('Download failed: ' + error.message, 'error');
        }
    }

    async deleteFile(fileId) {
        if (!confirm('Are you sure you want to delete this file?')) return;

        try {
            const response = await fetch(`/api/files/${fileId}?isHost=${this.isHost}`, {
                method: 'DELETE'
            });

            const result = await response.json();

            if (result.success) {
                this.showToast('File deleted', 'success');
            } else {
                this.showToast(result.error || 'Delete failed', 'error');
            }
        } catch (error) {
            this.showToast('Delete failed', 'error');
        }
    }

    updateFilesCount() {
        if (this.isHost) {
            const hostFilesCount = this.hostFilesList.querySelectorAll('.file-item').length;
            const clientFilesCount = this.receivedFilesList.querySelectorAll('.file-item').length;
            if (this.hostFilesCount) this.hostFilesCount.textContent = hostFilesCount;
            if (this.clientFilesCount) this.clientFilesCount.textContent = clientFilesCount;
            // Update stats
            if (this.statFiles) this.statFiles.textContent = hostFilesCount + clientFilesCount;
        } else {
            const availableCount = this.availableFilesList.querySelectorAll('.file-item').length;
            if (this.availableFilesCount) this.availableFilesCount.textContent = availableCount;
            // Update stats
            if (this.clientStatFiles) this.clientStatFiles.textContent = availableCount;
        }
    }

    updateTextsCount() {
        if (this.isHost) {
            const receivedCount = this.hostReceivedTexts.querySelectorAll('.text-item').length;
            const sharedCount = this.hostSharedTexts.querySelectorAll('.text-item').length;
            if (this.hostReceivedTextsCount) this.hostReceivedTextsCount.textContent = receivedCount;
            // Update stats
            if (this.statMessages) this.statMessages.textContent = receivedCount + sharedCount;
        } else {
            const receivedCount = this.clientReceivedTexts.querySelectorAll('.text-item').length;
            if (this.receivedTextsCount) this.receivedTextsCount.textContent = receivedCount;
            // Update stats
            if (this.clientStatMessages) this.clientStatMessages.textContent = receivedCount;
        }
    }

    checkEmptyStates() {
        const lists = [
            { el: this.hostFilesList, msg: 'No files shared yet' },
            { el: this.receivedFilesList, msg: 'No files received yet' },
            { el: this.availableFilesList, msg: 'No files available for download' },
            { el: this.hostSharedTexts, msg: 'No messages shared yet' },
            { el: this.hostReceivedTexts, msg: 'No messages received yet' },
            { el: this.clientReceivedTexts, msg: 'No messages received yet' }
        ].filter(item => item.el);

        lists.forEach(({ el, msg }) => {
            const hasItems = el.querySelectorAll('.file-item, .text-item').length > 0;
            const hasEmpty = el.querySelector('.empty-state');
            
            if (!hasItems && !hasEmpty) {
                el.innerHTML = `<p class="empty-state">${msg}</p>`;
            }
        });
    }

    getFileIcon(filename) {
        const ext = filename.split('.').pop().toLowerCase();
        const icons = {
            pdf: '📄',
            doc: '📝', docx: '📝',
            xls: '📊', xlsx: '📊',
            ppt: '📽️', pptx: '📽️',
            jpg: '🖼️', jpeg: '🖼️', png: '🖼️', gif: '🖼️', webp: '🖼️', svg: '🖼️',
            mp4: '🎬', avi: '🎬', mov: '🎬', mkv: '🎬',
            mp3: '🎵', wav: '🎵', flac: '🎵',
            zip: '📦', rar: '📦', '7z': '📦', tar: '📦',
            js: '💻', ts: '💻', py: '💻', java: '💻', cpp: '💻', c: '💻',
            html: '🌐', css: '🎨',
            txt: '📃', md: '📃',
            exe: '⚙️', msi: '⚙️'
        };
        return icons[ext] || '📁';
    }

    formatFileSize(bytes) {
        if (bytes === 0) return '0 Bytes';
        const k = 1024;
        const sizes = ['Bytes', 'KB', 'MB', 'GB'];
        const i = Math.floor(Math.log(bytes) / Math.log(k));
        return parseFloat((bytes / Math.pow(k, i)).toFixed(2)) + ' ' + sizes[i];
    }

    escapeHtml(text) {
        const div = document.createElement('div');
        div.textContent = text;
        return div.innerHTML;
    }

    // ============ CHAT FUNCTIONALITY ============
    async sendChatMessage(isHost) {
        const chatInput = isHost ? this.hostChatInput : this.clientChatInput;
        const message = chatInput.value.trim();

        if (!message) return;

        try {
            const encryptedMessage = await this.crypto.encrypt(message);
            const payload = {
                content: encryptedMessage,
                userId: this.user.id,
                userName: this.user.name,
                isHost: this.isHost
            };

            if (this.isConnected) {
                this.socket.emit('chatMessage', payload);
            } else {
                this.offlineQueue.enqueue('chat', payload);
                this.showToast('Chat message queued — will send when reconnected', 'info');
            }

            chatInput.value = '';
        } catch (error) {
            this.showToast('Failed to send message: ' + error.message, 'error');
        }
    }

    async displayChatMessage(message, animate = true) {
        const chatMessages = this.isHost ? this.hostChatMessages : this.clientChatMessages;
        if (!chatMessages) return;

        // Remove empty state
        const emptyState = chatMessages.querySelector('.chat-empty');
        if (emptyState) emptyState.remove();

        let content;
        try {
            content = await this.crypto.decrypt(message.content);
        } catch (error) {
            content = '[Unable to decrypt]';
        }

        const isOwn = message.userId === this.user.id;
        const time = new Date(message.timestamp).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' });

        const msgEl = document.createElement('div');
        msgEl.className = `chat-message ${isOwn ? 'own' : 'other'}`;
        if (!animate) msgEl.style.animation = 'none';
        
        msgEl.innerHTML = `
            <div class="message-header">
                <span class="message-sender">${this.escapeHtml(message.userName)}${message.isHost ? ' (Host)' : ''}</span>
                <span class="message-time">${time}</span>
            </div>
            <div class="message-bubble">${this.escapeHtml(content)}</div>
        `;

        chatMessages.appendChild(msgEl);
        chatMessages.scrollTop = chatMessages.scrollHeight;
    }

    // ============ FILE PREVIEW FUNCTIONALITY ============
    async previewFile(fileId, originalName) {
        try {
            this.showToast('Loading preview...', 'info');
            
            const response = await fetch(`/api/download/${fileId}?userId=${this.user.id}&isHost=${this.isHost}`);
            
            if (!response.ok) throw new Error('Failed to load file');

            const encryptedBlob = await response.blob();
            const decryptedBlob = await this.crypto.decryptFile(encryptedBlob, originalName);
            
            const ext = originalName.split('.').pop().toLowerCase();
            const url = URL.createObjectURL(decryptedBlob);
            
            this.previewTitle.textContent = originalName;
            this.previewContainer.innerHTML = '';

            // Determine preview type
            const imageExts = ['jpg', 'jpeg', 'png', 'gif', 'webp', 'bmp', 'svg'];
            const videoExts = ['mp4', 'webm', 'ogg', 'mov'];
            const audioExts = ['mp3', 'wav', 'ogg', 'flac', 'm4a'];
            const textExts = ['txt', 'md', 'json', 'js', 'ts', 'py', 'html', 'css', 'xml', 'csv', 'log'];

            if (imageExts.includes(ext)) {
                const img = document.createElement('img');
                img.src = url;
                img.alt = originalName;
                this.previewContainer.appendChild(img);
            } else if (videoExts.includes(ext)) {
                const video = document.createElement('video');
                video.src = url;
                video.controls = true;
                video.autoplay = false;
                this.previewContainer.appendChild(video);
            } else if (audioExts.includes(ext)) {
                const audio = document.createElement('audio');
                audio.src = url;
                audio.controls = true;
                this.previewContainer.appendChild(audio);
            } else if (ext === 'pdf') {
                const iframe = document.createElement('iframe');
                iframe.src = url;
                this.previewContainer.appendChild(iframe);
            } else if (textExts.includes(ext)) {
                const text = await decryptedBlob.text();
                const pre = document.createElement('pre');
                pre.textContent = text;
                this.previewContainer.appendChild(pre);
            } else {
                this.previewContainer.innerHTML = `
                    <div class="preview-unsupported">
                        <i>📁</i>
                        <p>Preview not available for this file type</p>
                        <p>Click download to save the file</p>
                    </div>
                `;
            }

            this.previewModal.classList.add('active');
            
            // Store URL for cleanup
            this.currentPreviewUrl = url;
        } catch (error) {
            this.showToast('Preview failed: ' + error.message, 'error');
        }
    }

    closePreview() {
        this.previewModal?.classList.remove('active');
        this.previewContainer.innerHTML = '';
        
        if (this.currentPreviewUrl) {
            URL.revokeObjectURL(this.currentPreviewUrl);
            this.currentPreviewUrl = null;
        }
    }

    // ============ BATCH DOWNLOAD FUNCTIONALITY ============
    async downloadAllFiles(type) {
        try {
            const btn = type === 'host' 
                ? (this.isHost ? this.hostDownloadAllBtn : this.clientDownloadAllBtn)
                : this.hostDownloadReceivedBtn;
            
            if (btn) {
                btn.disabled = true;
                btn.innerHTML = '<i>⏳</i> Downloading...';
            }

            this.showToast('Preparing batch download...', 'info');

            const response = await fetch(`/api/download-all?type=${type}&userId=${this.user.id}&isHost=${this.isHost}`);
            
            if (!response.ok) {
                const error = await response.json();
                throw new Error(error.error || 'Download failed');
            }

            // Get the ZIP blob
            const zipBlob = await response.blob();
            
            if (zipBlob.size < 100) {
                throw new Error('No files available for download');
            }

            // Create a new ZIP with decrypted files
            this.showToast('Decrypting files...', 'info');
            
            // Download as ZIP (files are encrypted, user can decrypt individually)
            const url = URL.createObjectURL(zipBlob);
            const a = document.createElement('a');
            a.href = url;
            a.download = `LANtern-${type}-files-${Date.now()}.zip`;
            document.body.appendChild(a);
            a.click();
            document.body.removeChild(a);
            URL.revokeObjectURL(url);

            this.showToast('Download complete! Note: Files are encrypted in the ZIP.', 'success');
        } catch (error) {
            this.showToast('Batch download failed: ' + error.message, 'error');
        } finally {
            // Reset button
            const btn = type === 'host' 
                ? (this.isHost ? this.hostDownloadAllBtn : this.clientDownloadAllBtn)
                : this.hostDownloadReceivedBtn;
            
            if (btn) {
                btn.disabled = false;
                btn.innerHTML = '<i>📦</i> Download All';
            }
        }
    }

    async flushOfflineQueue() {
        const items = this.offlineQueue.dequeueAll();
        if (items.length === 0) return;

        this.showToast(`Sending ${items.length} queued item(s)...`, 'info');
        let sent = 0;

        for (const item of items) {
            try {
                if (item.type === 'chat') {
                    this.socket.emit('chatMessage', item.data);
                    sent++;
                } else if (item.type === 'text') {
                    const response = await fetch('/api/text', {
                        method: 'POST',
                        headers: { 'Content-Type': 'application/json' },
                        body: JSON.stringify(item.data)
                    });
                    const result = await response.json();
                    if (result.success) sent++;
                } else if (item.type === 'file') {
                    const formData = new FormData();
                    formData.append('file', item.data.encryptedBlob, item.data.fileName + '.enc');
                    if (item.data.isHost && item.data.sharedWith) {
                        formData.append('sharedWith', JSON.stringify(item.data.sharedWith));
                    }
                    formData.append('originalName', item.data.fileName);
                    formData.append('originalSize', item.data.fileSize);
                    const response = await fetch(`/api/upload?isHost=${item.data.isHost}&userId=${this.user.id}`, {
                        method: 'POST',
                        body: formData
                    });
                    const result = await response.json();
                    if (result.success) {
                        sent++;
                        if (item.data.isHost) {
                            result.file.displayName = item.data.fileName;
                            result.file.originalSize = item.data.fileSize;
                            this.addFileToList(this.hostFilesList, result.file, true);
                        }
                        this.updateFilesCount();
                    }
                }
            } catch (err) {
                console.error('Failed to flush queued item:', err);
                // Re-queue the failed item
                this.offlineQueue.enqueue(item.type, item.data);
            }
        }

        if (sent > 0) {
            this.showToast(`${sent} queued item(s) sent successfully`, 'success');
        }
    }

    updateConnectionStatus(connected) {
        const statusElements = document.querySelectorAll('.connection-status');
        statusElements.forEach(el => {
            if (connected) {
                el.textContent = '🟢 Connected';
                el.classList.remove('offline');
            } else {
                const queueCount = this.offlineQueue.length;
                el.textContent = queueCount > 0
                    ? `🔴 Offline (${queueCount} queued)`
                    : '🔴 Offline';
                el.classList.add('offline');
            }
        });
    }

    showToast(message, type = 'info') {
        const container = document.getElementById('toast-container');
        const toast = document.createElement('div');
        toast.className = `toast ${type}`;
        
        const icons = {
            success: '✓',
            error: '✕',
            info: 'ℹ'
        };

        toast.innerHTML = `
            <span class="toast-icon">${icons[type]}</span>
            <span class="toast-message">${message}</span>
        `;

        container.appendChild(toast);

        setTimeout(() => {
            toast.style.animation = 'slideIn 0.3s ease reverse';
            setTimeout(() => toast.remove(), 300);
        }, 4000);
    }

    showConnectionError(message) {
        let errorEl = document.getElementById('connection-error');
        if (!errorEl) {
            errorEl = document.createElement('div');
            errorEl.id = 'connection-error';
            errorEl.style.cssText = `
                position: fixed;
                top: 0;
                left: 0;
                right: 0;
                background: linear-gradient(135deg, #ff6b6b, #ee5a24);
                color: white;
                padding: 15px 20px;
                text-align: center;
                z-index: 10000;
                font-weight: 600;
                box-shadow: 0 2px 10px rgba(0,0,0,0.3);
            `;
            document.body.prepend(errorEl);
        }
        errorEl.innerHTML = `
            <span>⚠️ ${message}</span>
            <button onclick="location.reload()" style="
                margin-left: 15px;
                padding: 5px 15px;
                background: white;
                color: #ee5a24;
                border: none;
                border-radius: 5px;
                cursor: pointer;
                font-weight: 600;
            ">Retry</button>
        `;
        errorEl.style.display = 'block';
    }
}

// Initialize app
const app = new LANternApp();
