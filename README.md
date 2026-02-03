# 🏮 LANtern - LAN File Sharing Application

A web-based file sharing application designed for offline/local networks. Perfect for college WiFi environments where internet access is restricted but local network communication is available.

## ✨ Features

- **Host-Client Architecture**: One host can manage and share files with multiple clients
- **Selective Sharing**: Host can share files with everyone or selected users
- **Client Uploads**: Clients can send files to the host (not to other clients)
- **Real-time Updates**: Instant notifications using Socket.IO
- **25MB File Limit**: Built-in file size restriction
- **No Internet Required**: Works entirely on local network
- **Modern UI**: Clean, responsive dark-themed interface

## 🚀 Quick Start

### Prerequisites

- [Node.js](https://nodejs.org/) (v14 or higher)
- npm (comes with Node.js)

### Installation

1. **Navigate to the project folder**
   ```bash
   cd LANtern
   ```

2. **Install dependencies**
   ```bash
   npm install
   ```

3. **Start the server**
   ```bash
   npm start
   ```

4. **Access the application**
   - Open your browser and go to `http://localhost:3000`
   - The server will display the network IP address that others can use to connect

### For Development (with auto-reload)

```bash
npm run dev
```

## 📖 How to Use

### As Host

1. Open the application in your browser
2. Enter your name and click **"Host a Session"**
3. Share the network URL (shown in terminal) with others
4. Upload files and choose to share with:
   - **Everyone**: All connected users can download
   - **Selected Users**: Only chosen users can download
5. View files received from clients in the "Received Files" section

### As Guest (Client)

1. Open the network URL shared by the host
2. Enter your name and click **"Join as Guest"**
3. Download files shared by the host
4. Upload files to send to the host (max 25MB)

## 🌐 Network Setup

When you start the server, it will display:
- Local URL: `http://localhost:3000`
- Network URL: `http://<your-ip>:3000`

Share the **Network URL** with others on the same WiFi/LAN to let them connect.

## 📁 Project Structure

```
LANtern/
├── server.js           # Express server with Socket.IO
├── package.json        # Project dependencies
├── public/
│   ├── index.html      # Main HTML file
│   ├── styles.css      # Styling
│   └── app.js          # Client-side JavaScript
├── uploads/
│   ├── host-files/     # Files uploaded by host
│   └── client-files/   # Files uploaded by clients
└── README.md
```

## 🔒 Security Notes

- This application is designed for **trusted local networks only**
- Files are stored on the server's filesystem
- No authentication system (relies on network trust)
- For production use, consider adding authentication

## 🛠️ Configuration

You can modify the following in `server.js`:

```javascript
const PORT = process.env.PORT || 3000;  // Change port
const MAX_FILE_SIZE = 25 * 1024 * 1024; // Change file size limit (in bytes)
```

## 📝 API Endpoints

| Method | Endpoint | Description |
|--------|----------|-------------|
| POST | `/api/upload` | Upload a file |
| GET | `/api/files` | Get available files |
| GET | `/api/download/:fileId` | Download a file |
| DELETE | `/api/files/:fileId` | Delete a file (host only) |
| GET | `/api/users` | Get connected users |

## 🔧 Troubleshooting

### Others can't connect?
- Make sure everyone is on the same WiFi network
- Check if firewall is blocking port 3000
- Try using the IP address instead of hostname

### File upload fails?
- Check if file size is under 25MB
- Ensure the uploads folder has write permissions

### Server won't start?
- Make sure port 3000 is not in use
- Run `npm install` to ensure all dependencies are installed

## 📄 License

MIT License - Feel free to use and modify!

---

Made with ❤️ for offline file sharing
