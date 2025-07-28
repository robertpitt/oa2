# OAuth 2.0 Express Server Example (TypeScript)

A complete **OAuth 2.0 Authorization Server** implementation with **Express.js**, **Handlebars templates**, and **enterprise-grade authentication flows**.

## 🚀 Features

### **OAuth 2.0 Grant Types**

- ✅ **Authorization Code** (with PKCE)
- ✅ **Client Credentials**
- ✅ **Password Grant**
- ✅ **Refresh Token**

### **Security Features**

- ✅ **PKCE (S256)** for public clients
- ✅ **Session Management** (cookie-based)
- ✅ **Client Authentication** (Basic Auth)
- ✅ **Token Introspection & Revocation**

### **UI/UX Features**

- ✅ **Handlebars Template Engine**
- ✅ **Responsive Design** with gradients
- ✅ **Modular Partials** (head, header, footer, scripts)
- ✅ **Login & Consent Screens**
- ✅ **Interactive Dashboard**

## 🏃‍♂️ Quick Start

### **1. Start the Server**

```bash
PORT=3001 npx ts-node examples/express/index.ts
```

### **2. Open Browser**

Visit: **http://localhost:3001**

### **3. Test Flows**

- **Client Credentials**: Click "🔧 Client Credentials" button
- **Password Flow**: Click "🔑 Password Flow" button
- **Authorization Code**: Click "🌐 Authorization Code Flow" button

## 📋 Demo Credentials

### **OAuth Clients**

| Client ID        | Secret               | Grant Types                       | Scopes             |
| ---------------- | -------------------- | --------------------------------- | ------------------ |
| `webapp-client`  | `webapp-secret-123`  | authorization_code, refresh_token | read, write, admin |
| `service-client` | `service-secret-456` | client_credentials                | read, write        |
| `mobile-client`  | `mobile-secret-789`  | password, refresh_token           | read, profile      |

### **Demo Users**

| Username   | Password   | Scopes                      |
| ---------- | ---------- | --------------------------- |
| `testuser` | `password` | read, write, profile        |
| `admin`    | `admin123` | read, write, profile, admin |

## 🔗 OAuth 2.0 Endpoints

| Method | Endpoint            | Description                                 |
| ------ | ------------------- | ------------------------------------------- |
| `GET`  | `/oauth/authorize`  | Authorization endpoint (with login/consent) |
| `POST` | `/oauth/token`      | Token endpoint for all grant types          |
| `POST` | `/oauth/revoke`     | Token revocation endpoint                   |
| `POST` | `/oauth/introspect` | Token introspection endpoint                |

## 🧪 Manual Testing

### **Authorization Code Flow (PKCE)**

```bash
# Step 1: Authorization (redirects to login if needed)
open "http://localhost:3001/oauth/authorize?response_type=code&client_id=webapp-client&redirect_uri=http://localhost:3001/callback&scope=read%20write&state=xyz123&code_challenge=E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM&code_challenge_method=S256"

# Step 2: Login with testuser/password
# Step 3: Consent screen - click "Approve"
# Step 4: Callback page shows token exchange result
```

### **Client Credentials**

```bash
curl -X POST http://localhost:3001/oauth/token \
  -H "Authorization: Basic $(echo -n 'service-client:service-secret-456' | base64)" \
  -d "grant_type=client_credentials&scope=read"
```

### **Password Flow**

```bash
curl -X POST http://localhost:3001/oauth/token \
  -H "Authorization: Basic $(echo -n 'mobile-client:mobile-secret-789' | base64)" \
  -d "grant_type=password&username=testuser&password=password&scope=read%20profile"
```

### **Token Introspection**

```bash
# Get token first, then introspect
curl -X POST http://localhost:3001/oauth/introspect \
  -H "Authorization: Basic $(echo -n 'service-client:service-secret-456' | base64)" \
  -d "token=YOUR_ACCESS_TOKEN"
```

## 🔧 PKCE Configuration

**Correct PKCE Implementation:**

- **Code Verifier**: `dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk`
- **Code Challenge**: `E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM` (SHA256 hash)
- **Method**: `S256`

## 📁 Project Structure

```
examples/express/
├── index.ts              # Main server file
├── middleware/
│   └── session.ts        # Session management
├── routes/
│   └── auth.ts          # Login & consent routes
├── views/
│   ├── home.hbs         # Dashboard page
│   ├── login.hbs        # Authentication form
│   ├── consent.hbs      # OAuth consent screen
│   ├── callback.hbs     # Authorization results
│   └── partials/        # Reusable components
│       ├── head.hbs     # CSS styles
│       ├── header.hbs   # Navigation
│       ├── footer.hbs   # Footer
│       └── scripts.hbs  # JavaScript
└── README.md            # This file
```

## 🎨 Template Engine

Uses **Handlebars** with modular partials:

- **Layout**: Self-contained HTML with embedded partials
- **Styling**: Professional gradients and responsive design
- **JavaScript**: Interactive OAuth flow testing
- **Error Handling**: Proper success/error states

## 🔐 Security Notes

- **Session cookies**: HTTP-only, 24-hour expiration
- **PKCE**: Required for authorization code flow
- **Client secrets**: Hashed using bcrypt
- **Authorization codes**: Single-use, 10-minute expiration
- **Access tokens**: 1-hour lifetime
- **Refresh tokens**: 7-day lifetime

## 🚨 Production Considerations

❌ **This is a DEMO server - DO NOT use in production without:**

- Database persistence (replace `InMemoryStorageAdapter`)
- Redis session store
- HTTPS/TLS termination
- Rate limiting
- Input validation
- Audit logging
- Secret management
- Multi-factor authentication
