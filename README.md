# NesaraQFS Lab — Backend Server

**Contact:** info@nesaraqfslab.com | +1 (206) 251-7105

## Requirements
- Node.js 16+
- No external dependencies (uses built-in Node.js modules only)

## Quick Start

```bash
# 1. Install (no npm install needed — zero dependencies!)
# 2. Run
node server.js

# Or with auto-restart on file changes (Node 18+)
npm run dev
```

Server starts at: **http://localhost:3000**

## Project Structure

```
backend/
├── server.js        # Main server file
├── package.json
└── data/
    └── users.json   # Auto-created on first run
```

## API Endpoints

| Method | Path | Description |
|--------|------|-------------|
| POST | /api/register | Create new account |
| POST | /api/login | Authenticate user |
| GET | /api/me | Get current user (auth required) |
| POST | /api/logout | End session |
| POST | /api/wallet/sync | Sync wallet balance |
| POST | /api/kyc/submit | Submit KYC documents |
| PUT | /api/profile | Update profile |
| GET | /api/health | Server health check |

## Deployment

### Production with PM2
```bash
npm install -g pm2
pm2 start server.js --name nesaraqfs
pm2 save
pm2 startup
```

### Environment Variables
```bash
PORT=3000              # Server port (default: 3000)
ALLOWED_ORIGIN=https://nesaraqfslab.com  # CORS origin
```

### Nginx Reverse Proxy
```nginx
server {
    listen 80;
    server_name nesaraqfslab.com;

    location / {
        proxy_pass http://localhost:3000;
        proxy_http_version 1.1;
        proxy_set_header Upgrade $http_upgrade;
        proxy_set_header Connection 'upgrade';
        proxy_set_header Host $host;
        proxy_cache_bypass $http_upgrade;
    }
}
```

## Security Notes

- Passwords are hashed with SHA-256 + salt
- Sessions expire after 24 hours
- Rate limiting: 20 requests/minute per IP on API routes
- Path traversal protection on static file serving
- CORS headers configurable via env
