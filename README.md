# Oauth2

OAuth 2.0 is a secure way to allow applications to access a user's data on another service without sharing passwords. Here's a simple breakdown of how it works:

1.) The Players involve in OAuth 2.0 are:
- `User` – The person using the application.
- `Client (App)` – The application that wants access to the user’s data.
- `Authorization Server` – The system that verifies the user and gives access tokens.
- `Resource Server` – The API that holds the user’s data.

2.) Different available grant types in OAuth 2.0 are:

> Spring authorization server supports the following grant types: `authorization_code`, `client_credentials`, `refresh_token`

### Authorization Code Grant (Most Secure & Common)
📌 Best for: Web & mobile apps needing secure user authentication.

🔒 Security: Uses a temporary authorization code and exchanges it for an access token (keeps credentials secure).

👤 User Involvement: Yes (user logs in and consents).

**Flow:**
- App redirects user to Authorization Server.
- User logs in and approves access.
- Authorization Server sends an Authorization Code to the app.
- App exchanges the code for an Access Token (secure because it happens server-to-server).
- App uses the token to access user data from the API (Resource Server).

💡 Commonly used with:

PKCE (Proof Key for Code Exchange) → Adds extra security for mobile & SPA apps (prevents interception).


### Client Credentials Grant (Machine-to-Machine)

📌 Best for: Backend services, microservices, or automated scripts.

🔒 Security: Uses client ID and client secret (no user interaction).

👤 User Involvement: No.

**Flow:**

- App directly requests an Access Token from the Authorization Server using its client ID & secret.
- If valid, Authorization Server returns the Access Token.
- App uses the token to access the API (Resource Server).

💡 Commonly used for:

Server-to-server communication (e.g., fetching data from APIs).

Internal applications or services where users don’t need to log in.


### Implicit Grant (Deprecated)

📌 Best for: SPAs (but no longer recommended due to security risks).

🔒 Security: Less secure because access tokens are exposed in URLs.

👤 User Involvement: Yes.

**Flow:**

- App redirects user to Authorization Server.
- User logs in and approves access.
- Instead of an Authorization Code, the Access Token is sent directly in the URL.
- App uses the token to access APIs.

🚨 Why is it deprecated?

The access token is exposed in the URL (prone to theft).

It lacks a way to securely refresh the token.

> PKCE + Authorization Code Flow is the recommended alternative.


### Resource Owner Password Credentials Grant (ROPC)

📌 Best for: Trusted apps (e.g., first-party mobile apps).

🔒 Security: Less secure because the user provides their username & password directly to the app.

👤 User Involvement: Yes (user enters credentials).

**Flow:**

User enters their username & password directly into the app.

The app sends credentials to the Authorization Server.

If valid, Authorization Server returns an Access Token.

App uses the token to access APIs.

🚨 Why is it discouraged?

The app directly handles user passwords (potential security risk).

> Authorization Code Flow is recommended instead.

### Device Authorization Grant (Device Flow)

📌 Best for: Devices without browsers (e.g., smart TVs, gaming consoles).

🔒 Security: Uses a unique code + user authentication via another device.

👤 User Involvement: Yes (user must authorize on a separate device).

**Flow:**

Device shows a unique code & URL to the user.

User visits the URL on a different device (phone/laptop).

User logs in and approves access.

Device polls the Authorization Server until approval is granted.

Device receives an Access Token and starts using the API.

💡 Commonly used for:

Smart TVs (e.g., logging into Netflix on your TV using a code).

IoT devices and gaming consoles.

### Refresh Token Flow

📌 Best for: Getting a new access token without asking the user to log in again.

🔒 Security: Requires a valid refresh token.

👤 User Involvement: No (silent refresh).

**Flow:**

App sends the refresh token to the Authorization Server.

If valid, Authorization Server returns a new Access Token.

App continues using the new token without asking the user to log in again.

💡 Commonly used for:

Keeping users logged in without re-entering credentials.

Long-lived sessions in web & mobile apps.


### Comparison Table

| Grant Type| Best For	| User Logs In?	 | Security Level (as per LLM) |
|-----------|----------|----------------|-----------------------------|
| Authorization Code|Web & mobile apps | 	✅ Yes| 	🔒🔒🔒 High                |
| Client Credentials| Machine-to-machine| ❌ No| 🔒🔒 Medium                 |
| Implicit (Deprecated)| SPAs (Old method)| 	✅ Yes| 🔒 Low                      |
| Password (ROPC)	| First-party apps| 	✅ Yes| 🔒 Low                      |
| Device Flow	| TVs, consoles, IoT	| ✅ Yes| 🔒🔒 Medium                 |
| Refresh Token| Long-lived sessions	| ❌ No| 🔒🔒 High                   |


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
