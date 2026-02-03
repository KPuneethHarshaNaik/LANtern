const express = require('express');
const http = require('http');
const { Server } = require('socket.io');
const multer = require('multer');
const path = require('path');
const fs = require('fs');
const { v4: uuidv4 } = require('uuid');
const os = require('os');
const archiver = require('archiver');

const app = express();
const server = http.createServer(app);
const io = new Server(server);

const PORT = process.env.PORT || 3000;
const MAX_FILE_SIZE = 25 * 1024 * 1024; // 25MB limit

// Create directories if they don't exist
const uploadDirs = {
    hostFiles: path.join(__dirname, 'uploads', 'host-files'),
    clientFiles: path.join(__dirname, 'uploads', 'client-files')
};

Object.values(uploadDirs).forEach(dir => {
    if (!fs.existsSync(dir)) {
        fs.mkdirSync(dir, { recursive: true });
    }
});

// In-memory storage for connected users and files
const connectedUsers = new Map(); // socketId -> { id, name, isHost }
const hostFiles = new Map(); // fileId -> { filename, originalName, size, uploadedAt, sharedWith: [] | 'all' }
const clientFiles = new Map(); // fileId -> { filename, originalName, size, uploadedAt, uploadedBy }
const sharedTexts = new Map(); // textId -> { content, sharedWith, uploadedBy, uploadedAt }
const chatMessages = []; // Array of chat messages
let hostSocketId = null;
let sessionPassword = null; // Password for the session

// Middleware
app.use(express.static(path.join(__dirname, 'public')));
app.use(express.json());

// Multer configuration for file uploads
const storage = multer.diskStorage({
    destination: (req, file, cb) => {
        const isHost = req.query.isHost === 'true';
        cb(null, isHost ? uploadDirs.hostFiles : uploadDirs.clientFiles);
    },
    filename: (req, file, cb) => {
        // Sanitize filename: use UUID + extension only to avoid path issues
        const ext = path.extname(file.originalname) || '';
        const uniqueName = `${uuidv4()}${ext}`;
        cb(null, uniqueName);
    }
});

const upload = multer({
    storage,
    limits: { fileSize: MAX_FILE_SIZE },
    fileFilter: (req, file, cb) => {
        cb(null, true); // Accept all file types
    }
});

// Get local IP addresses
function getLocalIPs() {
    const interfaces = os.networkInterfaces();
    const addresses = [];
    for (const name of Object.keys(interfaces)) {
        for (const iface of interfaces[name]) {
            if (iface.family === 'IPv4' && !iface.internal) {
                addresses.push(iface.address);
            }
        }
    }
    return addresses;
}

// API Routes

// Upload file (host or client)
app.post('/api/upload', upload.single('file'), (req, res) => {
    try {
        if (!req.file) {
            return res.status(400).json({ error: 'No file uploaded' });
        }

        const isHost = req.query.isHost === 'true';
        const uploaderId = req.query.userId;
        const sharedWith = req.body.sharedWith ? JSON.parse(req.body.sharedWith) : 'all';

        const fileId = uuidv4();
        const fileInfo = {
            id: fileId,
            filename: req.file.filename,
            originalName: req.file.originalname,
            size: req.file.size,
            uploadedAt: new Date().toISOString(),
            uploadedBy: uploaderId
        };

        if (isHost) {
            fileInfo.sharedWith = sharedWith;
            hostFiles.set(fileId, fileInfo);
            
            // Notify relevant clients
            if (sharedWith === 'all') {
                io.emit('newHostFile', fileInfo);
            } else {
                sharedWith.forEach(userId => {
                    const user = Array.from(connectedUsers.entries()).find(([_, u]) => u.id === userId);
                    if (user) {
                        io.to(user[0]).emit('newHostFile', fileInfo);
                    }
                });
            }
        } else {
            clientFiles.set(fileId, fileInfo);
            // Notify host about new client file
            if (hostSocketId) {
                io.to(hostSocketId).emit('newClientFile', fileInfo);
            }
        }

        res.json({ success: true, file: fileInfo });
    } catch (error) {
        console.error('Upload error:', error.message);
        res.status(500).json({ error: 'Upload failed' });
    }
});

// Get files for a user
app.get('/api/files', (req, res) => {
    try {
        const userId = req.query.userId;
        const isHost = req.query.isHost === 'true';

        if (isHost) {
            // Host gets all files
            res.json({
                hostFiles: Array.from(hostFiles.values()),
                clientFiles: Array.from(clientFiles.values())
            });
        } else {
            // Client gets only files shared with them
            const availableFiles = Array.from(hostFiles.values()).filter(file => {
                return file.sharedWith === 'all' || file.sharedWith.includes(userId);
            });
            res.json({ hostFiles: availableFiles });
        }
    } catch (error) {
        console.error('Get files error:', error.message);
        res.status(500).json({ error: 'Failed to get files' });
    }
});

// Download file
app.get('/api/download/:fileId', (req, res) => {
    try {
        const { fileId } = req.params;
        const userId = req.query.userId;
        const isHost = req.query.isHost === 'true';

        let fileInfo = hostFiles.get(fileId) || clientFiles.get(fileId);
        
        if (!fileInfo) {
            return res.status(404).json({ error: 'File not found' });
        }

        // Check access permissions
        if (!isHost && hostFiles.has(fileId)) {
            const file = hostFiles.get(fileId);
            if (file.sharedWith !== 'all' && !file.sharedWith.includes(userId)) {
                return res.status(403).json({ error: 'Access denied' });
            }
        }

        // Only host can download client files
        if (!isHost && clientFiles.has(fileId)) {
            return res.status(403).json({ error: 'Only host can access client uploads' });
        }

        const filePath = hostFiles.has(fileId) 
            ? path.join(uploadDirs.hostFiles, fileInfo.filename)
            : path.join(uploadDirs.clientFiles, fileInfo.filename);

        if (!fs.existsSync(filePath)) {
            // File doesn't exist on disk, remove from memory
            hostFiles.delete(fileId);
            clientFiles.delete(fileId);
            return res.status(404).json({ error: 'File not found on disk' });
        }

        res.download(filePath, fileInfo.originalName, (err) => {
            if (err) {
                console.error('Download error:', err.message);
                if (!res.headersSent) {
                    res.status(500).json({ error: 'Download failed' });
                }
            }
        });
    } catch (error) {
        console.error('Download route error:', error.message);
        if (!res.headersSent) {
            res.status(500).json({ error: 'Server error during download' });
        }
    }
});

// Delete file (host only for host files, host can delete client files too)
app.delete('/api/files/:fileId', (req, res) => {
    const { fileId } = req.params;
    const isHost = req.query.isHost === 'true';

    if (!isHost) {
        return res.status(403).json({ error: 'Only host can delete files' });
    }

    let fileInfo = hostFiles.get(fileId) || clientFiles.get(fileId);
    
    if (!fileInfo) {
        return res.status(404).json({ error: 'File not found' });
    }

    const filePath = hostFiles.has(fileId) 
        ? path.join(uploadDirs.hostFiles, fileInfo.filename)
        : path.join(uploadDirs.clientFiles, fileInfo.filename);

    // Delete from disk
    if (fs.existsSync(filePath)) {
        fs.unlinkSync(filePath);
    }

    // Remove from memory
    hostFiles.delete(fileId);
    clientFiles.delete(fileId);

    // Notify all users
    io.emit('fileDeleted', { fileId });

    res.json({ success: true });
});

// Share text message
app.post('/api/text', express.json(), (req, res) => {
    const { content, sharedWith, isHost, userId, encryptedContent } = req.body;
    
    if (!encryptedContent) {
        return res.status(400).json({ error: 'No content provided' });
    }

    const textId = uuidv4();
    const textInfo = {
        id: textId,
        content: encryptedContent, // Store encrypted content
        sharedWith: sharedWith || 'all',
        uploadedBy: userId,
        uploadedAt: new Date().toISOString(),
        isFromHost: isHost
    };

    sharedTexts.set(textId, textInfo);

    if (isHost) {
        // Host sharing text with clients
        if (sharedWith === 'all') {
            io.emit('newHostText', textInfo);
        } else {
            sharedWith.forEach(targetUserId => {
                const user = Array.from(connectedUsers.entries()).find(([_, u]) => u.id === targetUserId);
                if (user) {
                    io.to(user[0]).emit('newHostText', textInfo);
                }
            });
        }
    } else {
        // Client sharing text with host
        if (hostSocketId) {
            io.to(hostSocketId).emit('newClientText', textInfo);
        }
    }

    res.json({ success: true, text: textInfo });
});

// Get texts
app.get('/api/texts', (req, res) => {
    const userId = req.query.userId;
    const isHost = req.query.isHost === 'true';

    const texts = Array.from(sharedTexts.values());
    
    if (isHost) {
        res.json({ texts });
    } else {
        // Client only sees texts shared with them
        const availableTexts = texts.filter(t => {
            if (!t.isFromHost) return false;
            return t.sharedWith === 'all' || t.sharedWith.includes(userId);
        });
        res.json({ texts: availableTexts });
    }
});

// Delete text (host only)
app.delete('/api/texts/:textId', (req, res) => {
    const { textId } = req.params;
    const isHost = req.query.isHost === 'true';

    if (!isHost) {
        return res.status(403).json({ error: 'Only host can delete texts' });
    }

    if (!sharedTexts.has(textId)) {
        return res.status(404).json({ error: 'Text not found' });
    }

    sharedTexts.delete(textId);
    io.emit('textDeleted', { textId });

    res.json({ success: true });
});

// Batch download - Download all files as ZIP
app.get('/api/download-all', (req, res) => {
    try {
        const userId = req.query.userId;
        const isHost = req.query.isHost === 'true';
        const fileType = req.query.type || 'host'; // 'host' or 'client'

        let files = [];
        let baseDir = '';

        if (fileType === 'host') {
            baseDir = uploadDirs.hostFiles;
            if (isHost) {
                files = Array.from(hostFiles.values());
            } else {
                files = Array.from(hostFiles.values()).filter(file => {
                    return file.sharedWith === 'all' || file.sharedWith.includes(userId);
                });
            }
        } else if (fileType === 'client' && isHost) {
            baseDir = uploadDirs.clientFiles;
            files = Array.from(clientFiles.values());
        }

        if (files.length === 0) {
            return res.status(404).json({ error: 'No files to download' });
        }

        res.setHeader('Content-Type', 'application/zip');
        res.setHeader('Content-Disposition', `attachment; filename=LANtern-files-${Date.now()}.zip`);

        const archive = archiver('zip', { zlib: { level: 5 } });
        
        archive.on('error', (err) => {
            console.error('Archive error:', err);
            if (!res.headersSent) {
                res.status(500).json({ error: 'Failed to create archive' });
            }
        });

        archive.pipe(res);

        files.forEach(file => {
            const filePath = path.join(baseDir, file.filename);
            if (fs.existsSync(filePath)) {
                archive.file(filePath, { name: file.originalName });
            }
        });

        archive.finalize();
    } catch (error) {
        console.error('Batch download error:', error);
        if (!res.headersSent) {
            res.status(500).json({ error: 'Batch download failed' });
        }
    }
});

// Get chat messages
app.get('/api/chat', (req, res) => {
    res.json({ messages: chatMessages.slice(-100) }); // Return last 100 messages
});

// Get connected users (for host)
app.get('/api/users', (req, res) => {
    const users = Array.from(connectedUsers.values()).filter(u => !u.isHost);
    res.json({ users });
});

// Socket.IO connection handling
io.on('connection', (socket) => {
    console.log('User connected:', socket.id);

    // User registration
    socket.on('register', (data) => {
        const { name, isHost, password } = data;
        
        // Password validation
        if (isHost) {
            // Host sets the session password
            sessionPassword = password;
            console.log('Session password set by host');
        } else {
            // Client must provide correct password
            if (!sessionPassword) {
                socket.emit('error', { message: 'No active session. Ask the host to start first.' });
                return;
            }
            if (password !== sessionPassword) {
                socket.emit('error', { message: 'Incorrect session password' });
                return;
            }
        }
        
        const userId = uuidv4();
        
        const userInfo = {
            id: userId,
            name: name,
            isHost: isHost,
            connectedAt: new Date().toISOString()
        };

        connectedUsers.set(socket.id, userInfo);

        if (isHost) {
            hostSocketId = socket.id;
        }

        // Send back user info
        socket.emit('registered', userInfo);

        // Notify host about new user
        if (!isHost && hostSocketId) {
            io.to(hostSocketId).emit('userJoined', userInfo);
        }

        // Broadcast updated user list
        const users = Array.from(connectedUsers.values()).filter(u => !u.isHost);
        io.emit('usersUpdate', { users });

        console.log(`User registered: ${name} (${isHost ? 'HOST' : 'CLIENT'})`);
    });

    // Handle disconnection
    socket.on('disconnect', () => {
        const user = connectedUsers.get(socket.id);
        if (user) {
            console.log(`User disconnected: ${user.name}`);
            
            if (user.isHost) {
                hostSocketId = null;
                sessionPassword = null; // Clear session password when host leaves
                // Clear all data when host disconnects
                hostFiles.clear();
                clientFiles.clear();
                sharedTexts.clear();
                chatMessages.length = 0; // Clear chat
                // Notify all clients that session ended
                io.emit('sessionEnded', { message: 'Host has ended the session' });
            }

            connectedUsers.delete(socket.id);

            // Notify remaining users
            const users = Array.from(connectedUsers.values()).filter(u => !u.isHost);
            io.emit('usersUpdate', { users });

            if (hostSocketId) {
                io.to(hostSocketId).emit('userLeft', user);
            }
        }
    });

    // Handle chat messages
    socket.on('chatMessage', (data) => {
        const user = connectedUsers.get(socket.id);
        if (!user) return;

        const message = {
            id: uuidv4(),
            userId: user.id,
            userName: user.name,
            isHost: user.isHost,
            content: data.content, // Already encrypted
            timestamp: new Date().toISOString()
        };

        chatMessages.push(message);
        
        // Keep only last 100 messages
        if (chatMessages.length > 100) {
            chatMessages.shift();
        }

        // Broadcast to all connected users
        io.emit('newChatMessage', message);
    });
});

// Error handling for multer
app.use((err, req, res, next) => {
    if (err instanceof multer.MulterError) {
        if (err.code === 'LIMIT_FILE_SIZE') {
            return res.status(400).json({ error: 'File size exceeds 25MB limit' });
        }
    }
    console.error('Express error:', err.message);
    if (!res.headersSent) {
        res.status(500).json({ error: 'Server error' });
    }
});

// Global uncaught exception handler - prevents server crashes
process.on('uncaughtException', (err) => {
    console.error('Uncaught Exception:', err.message);
});

process.on('unhandledRejection', (reason, promise) => {
    console.error('Unhandled Rejection at:', promise, 'reason:', reason);
});

// Start server
server.listen(PORT, '0.0.0.0', () => {
    const ips = getLocalIPs();
    console.log('\n========================================');
    console.log('   🏮 LANtern - LAN File Sharing');
    console.log('========================================\n');
    console.log(`Server running on port ${PORT}\n`);
    console.log('Access the application at:');
    console.log(`  Local:    http://localhost:${PORT}`);
    ips.forEach(ip => {
        console.log(`  Network:  http://${ip}:${PORT}`);
    });
    console.log('\nShare the Network URL with others on the same WiFi!');
    console.log('========================================\n');
});
