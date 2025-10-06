# OAuth 2.0 vs OpenID Connect (OIDC)

OAuth 2.0 and OpenID Connect (OIDC) are both protocols used in modern authentication and authorization systems. Here's how they differ and when to use each:

## 🔍 Key Differences

|Feature |OAuth 2.0 |OpenID Connect (OIDC) |
|--------|----------|----------------------|
|Purpose |Authorization |Authentication + Authorization| 
|Identity Info| Not provided| Provided via ID Token|
| Token Types | Access Token| Access Token + ID Token|
| Protocol Layer| Base protocol| Built on top of OAuth 2.0|
| Use Case| API access| Login + API access|

## ✅ When to Use

- **Use OAuth 2.0** if you only need to access APIs on behalf of a user (authorization).
- **Use OIDC** if you need to authenticate users and also access APIs (authentication + authorization).

---

# OAuth2

OAuth 2.0 is a secure way to allow applications to access a user's data on another service without sharing passwords. Here's a simple breakdown of how it works:

## 1. The Players in OAuth 2.0

- `User` – The person using the application.
- `Client (App)` – The application that wants access to the user’s data.
- `Authorization Server` – The system that verifies the user and gives access tokens.
- `Resource Server` – The API that holds the user’s data.

## 2. Supported Grant Types

> Spring Authorization Server supports: `authorization_code`, `client_credentials`, `refresh_token`

---

### Authorization Code Grant (Most Secure & Common)

📌 Best for: Web & mobile apps needing secure user authentication.  
🔒 Security: Uses a temporary authorization code and exchanges it for an access token.  
👤 User Involvement: ✅ Yes

**Flow:**
- App redirects user to Authorization Server.
- User logs in and approves access.
- Authorization Server sends an Authorization Code to the app.
- App exchanges the code for an Access Token.
- App uses the token to access user data from the API.

💡 Commonly used with: PKCE (Proof Key for Code Exchange)

---

### Client Credentials Grant (Machine-to-Machine)

📌 Best for: Backend services, microservices, or automated scripts.  
🔒 Security: Uses client ID and client secret.  
👤 User Involvement: ❌ No

**Flow:**
- App requests an Access Token using client ID & secret.
- Authorization Server returns the Access Token.
- App accesses the API.

💡 Commonly used for: Server-to-server communication.

---

### Implicit Grant (Deprecated)

📌 Best for: SPAs (but no longer recommended).  
🔒 Security: Less secure (tokens exposed in URLs).  
👤 User Involvement: ✅ Yes

**Flow:**
- App redirects user to Authorization Server.
- User logs in and approves access.
- Access Token is sent directly in the URL.

🚨 Deprecated due to security risks.  
> Use Authorization Code Flow with PKCE instead.

---

### Resource Owner Password Credentials Grant (ROPC)

📌 Best for: Trusted apps (e.g., first-party mobile apps).  
🔒 Security: Less secure (app handles user credentials).  
👤 User Involvement: ✅ Yes

**Flow:**
- User enters credentials in the app.
- App sends them to Authorization Server.
- Access Token is returned.

🚨 Discouraged due to security risks.  
> Use Authorization Code Flow instead.

---

### Device Authorization Grant (Device Flow)

📌 Best for: Devices without browsers (e.g., smart TVs).  
🔒 Security: Uses a unique code + user authentication via another device.  
👤 User Involvement: ✅ Yes

**Flow:**
- Device shows a code & URL.
- User visits URL on another device.
- User logs in and approves access.
- Device polls Authorization Server.
- Access Token is returned.

💡 Commonly used for: TVs, IoT devices, gaming consoles.

---

### Refresh Token Flow

📌 Best for: Getting a new access token without user login.  
🔒 Security: Requires a valid refresh token.  
👤 User Involvement: ❌ No

**Flow:**
- App sends refresh token to Authorization Server.
- New Access Token is returned.

💡 Commonly used for: Long-lived sessions in web & mobile apps.

---

## 🔄 Comparison Table

|Grant Type| Best For |User Logs In? |Security Level|
|----------|----------|--------------|--------------|
|Authorization Code|Web & mobile apps|✅ Yes|🔒🔒🔒 High| 
|Client Credentials         | Machine-to-machine         | ❌ No          | 🔒🔒 Medium     |
| Implicit (Deprecated)      | SPAs (Old method)          | ✅ Yes         | 🔒 Low          |
| Password (ROPC)            | First-party apps           | ✅ Yes         | 🔒 Low          |
| Device Flow                | TVs, consoles, IoT         | ✅ Yes         | 🔒🔒 Medium     |
| Refresh Token              | Long-lived sessions        | ❌ No          | 🔒🔒 High       |

---

# spring-oauth2-authorization-server

[Getting started guide](https://docs.spring.io/spring-authorization-server/reference/getting-started.html).

- The JWK-Set Endpoint is available at `http://localhost:9000/oauth2/jwks` when the application is running.
- The OAuth2 Authorization Server Metadata Endpoint is available at `http://localhost:9000/.well-known/oauth-authorization-server` when the application is running.
- The OpenID Connect Provider Configuration Endpoint is available at `http://localhost:9000/.well-known/openid-configuration` when the application is running.

### client_credentials example

```shell
http -f POST :9000/oauth2/token grant_type=client_credentials scope='message.read' -a messaging-client:secret
```

- To introspect a token
```shell
TOKEN= http -f POST :9000/oauth2/token grant_type=client_credentials scope='message.read' -a messaging-client:secret | jq -r .access_token
http -f POST :9000/oauth2/introspect token=$TOKEN -a messaging-client:secret
```

> **Note**: The `http` command is part of the `httpie` package.
> The host and port might vary depending on the configuration in the `application.yml` file.
