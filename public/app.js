// LANtern - Client-side Application with E2E Encryption

class CryptoHelper {
    constructor() {
        this.key = null;
    }

    async deriveKey(password) {
        const encoder = new TextEncoder();
        const passwordData = encoder.encode(password);
        
        const baseKey = await crypto.subtle.importKey(
            'raw',
            passwordData,
            'PBKDF2',
            false,
            ['deriveBits', 'deriveKey']
        );

        this.key = await crypto.subtle.deriveKey(
            {
                name: 'PBKDF2',
                salt: encoder.encode('LANtern-salt-v1'),
                iterations: 100000,
                hash: 'SHA-256'
            },
            baseKey,
            { name: 'AES-GCM', length: 256 },
            true,
            ['encrypt', 'decrypt']
        );

        return this.key;
    }

    async encrypt(data) {
        if (!this.key) throw new Error('Key not derived');
        
        const encoder = new TextEncoder();
        const dataBytes = typeof data === 'string' ? encoder.encode(data) : data;
        const iv = crypto.getRandomValues(new Uint8Array(12));
        
        const encrypted = await crypto.subtle.encrypt(
            { name: 'AES-GCM', iv },
            this.key,
            dataBytes
        );

        const combined = new Uint8Array(iv.length + encrypted.byteLength);
        combined.set(iv);
        combined.set(new Uint8Array(encrypted), iv.length);

        return this.arrayBufferToBase64(combined);
    }

    async decrypt(encryptedBase64) {
        if (!this.key) throw new Error('Key not derived');
        
        const combined = this.base64ToArrayBuffer(encryptedBase64);
        const iv = combined.slice(0, 12);
        const encrypted = combined.slice(12);

        const decrypted = await crypto.subtle.decrypt(
            { name: 'AES-GCM', iv },
            this.key,
            encrypted
        );

        return new TextDecoder().decode(decrypted);
    }

    async encryptFile(file) {
        const arrayBuffer = await file.arrayBuffer();
        const iv = crypto.getRandomValues(new Uint8Array(12));
        
        const encrypted = await crypto.subtle.encrypt(
            { name: 'AES-GCM', iv },
            this.key,
            arrayBuffer
        );

        const combined = new Uint8Array(iv.length + encrypted.byteLength);
        combined.set(iv);
        combined.set(new Uint8Array(encrypted), iv.length);

        return new Blob([combined], { type: 'application/encrypted' });
    }

    async decryptFile(encryptedBlob, originalName) {
        const arrayBuffer = await encryptedBlob.arrayBuffer();
        const combined = new Uint8Array(arrayBuffer);
        
        const iv = combined.slice(0, 12);
        const encrypted = combined.slice(12);

        const decrypted = await crypto.subtle.decrypt(
            { name: 'AES-GCM', iv },
            this.key,
            encrypted
        );

        const mimeType = this.getMimeType(originalName);
        return new Blob([decrypted], { type: mimeType });
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

class LANternApp {
    constructor() {
        this.socket = io();
        this.crypto = new CryptoHelper();
        this.user = null;
        this.isHost = false;
        this.sessionPassword = null;
        this.connectedUsers = [];
        this.selectedFiles = [];
        this.shareMode = 'all';
        this.textShareMode = 'all';
        this.selectedUsersToShare = [];

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
        this.socket.on('registered', (user) => {
            this.user = user;
            this.isHost = user.isHost;
            this.showDashboard();
            this.loadFiles();
            this.loadTexts();
        });

        this.socket.on('error', (data) => {
            this.showToast(data.message, 'error');
        });

        this.socket.on('sessionEnded', (data) => {
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

        try {
            await this.crypto.deriveKey(password);
            this.sessionPassword = password;
        } catch (error) {
            this.showToast('Failed to initialize encryption', 'error');
            return;
        }

        this.socket.emit('register', { name, isHost: asHost, password });
    }

    showDashboard() {
        this.landingPage.classList.remove('active');
        
        if (this.isHost) {
            this.hostPage.classList.add('active');
            this.hostNameEl.textContent = this.user.name;
        } else {
            this.clientPage.classList.add('active');
            this.clientNameEl.textContent = this.user.name;
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

        if (this.connectedUsers.length === 0) {
            this.usersList.innerHTML = '<p class="empty-state">No users connected yet</p>';
        } else {
            this.usersList.innerHTML = this.connectedUsers.map(user => `
                <div class="user-item">
                    <div class="user-avatar">${user.name.charAt(0).toUpperCase()}</div>
                    <div class="user-info">
                        <div class="name">${this.escapeHtml(user.name)}</div>
                        <div class="status">● Online</div>
                    </div>
                </div>
            `).join('');
        }

        this.userCount.textContent = this.connectedUsers.length;
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
            const sharedWith = isHost ? (this.textShareMode === 'all' ? 'all' : this.selectedUsersToShare) : 'host';

            const response = await fetch('/api/text', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({
                    encryptedContent,
                    sharedWith,
                    isHost,
                    userId: this.user.id
                })
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
            this.showToast('Failed to send message: ' + error.message, 'error');
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
            this.showToast('Upload failed: ' + error.message, 'error');
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
            this.hostFilesCount.textContent = hostFilesCount;
            this.clientFilesCount.textContent = clientFilesCount;
        } else {
            const availableCount = this.availableFilesList.querySelectorAll('.file-item').length;
            this.availableFilesCount.textContent = availableCount;
        }
    }

    updateTextsCount() {
        if (this.isHost) {
            const receivedCount = this.hostReceivedTexts.querySelectorAll('.text-item').length;
            this.hostReceivedTextsCount.textContent = receivedCount;
        } else {
            const receivedCount = this.clientReceivedTexts.querySelectorAll('.text-item').length;
            this.receivedTextsCount.textContent = receivedCount;
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
            
            this.socket.emit('chatMessage', {
                content: encryptedMessage,
                userId: this.user.id,
                userName: this.user.name,
                isHost: this.isHost
            });

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
}

// Initialize app
const app = new LANternApp();
