browser               nginx               app               OIDC Provider         Jitsi
───┬───               ──┬──               ──┬──                ──┬──              ──┬──
   │                    │                   │                    │                  │
   │                    │                   │                    │                  │
   │    join request    │                   │                    │                  │
   │(no-token + no-flag)│                   │                    │                  │
   ├───────────────────▶│                   │                    │                  │
   │                    │                   │                    │                  │
   │                    │                   │                    │                  │
   │                    │      forward      │                    │                  │
   │                    │  (OIDC callback)  │                    │                  │
   ├───────────────────▶│──────────────────▶│                    │                  │
   │                    │                   │                    │                  │
   │                    │                   │   exchange code    │                  │
   │                    │                   ├───────────────────▶│                  │
   │                    │                   │                    │                  │
   │                    │                   │  (receive tokens)  │                  │
   │                    │                   │◀───────────────────┤                  │
   │                    │                   │                    │                  │
   │                    │                   │  parse ID token    │                  │
   │                    │                   ├───────────────────▶│                  │
   │                    │                   │                    │                  │
   │                    │                   │  store user info   │                  │
   │                    │                   │    (session)       │                  │
   │                    │                   │                    │                  │
   │                    │                   │                    │                  │
   │                    │                   │ redirect to        │                  │
   │                    │                   │  /oidc/tokenize    │                  │
   │                    │                   │◀───────────────────┤                  │
   │                    │                   │                    │                  │
   │                    │                   │ generate JWT       │                  │
   │                    │                   │   (session info)   │                  │
   │                    │                   │                    │                  │
   │                    │                   │ redirect to Jitsi  │                  │
   │                    │                   │  (with JWT)        │                  │
   │                    │                   │──────────────────────────────────────▶│
   │                    │                   │                    │                  │
   │                    │                   │                    │                  │
   │                    │                   │                    │                  │


Detailed Flow Description
User Initiates OAuth Flow

User accesses your application and starts the OAuth process.
User is redirected to the IdP login page.
User Authenticates with IdP

User logs in at the IdP.
IdP authenticates and redirects user back to your application with an authorization code.
OAuth Callback Endpoint (/oidc/redirect)

Your app receives the authorization code.
The oauth_callback function processes this code.
Exchange Authorization Code for Tokens

exchange_code_for_token function sends a request to the IdP's token endpoint.
The request includes the authorization code, client credentials, and redirect URI.
IdP responds with access and ID tokens.
Parse ID Token

The ID token is parsed using the parse_id_token function.
Validate the token's signature with the IdP's JWKS URI.
Check for nonce to prevent replay attacks.
Extract user info (name, email) from the ID token.
Store User Info in Session

Store user info in the session, including Gravatar URL if email is available.
If no email, use default avatar URL.
Generate JWT for Application Use (/oidc/tokenize)

User is redirected to the /oidc/tokenize route.
The tokenize function retrieves user info from the session.
Create JWT payload with user info and other claims.
Sign JWT with your application's secret key.
Redirect user to application URL with JWT as a query parameter.
Application Access

User uses JWT to access protected resources.
Your application validates JWT to authorize the user.
This architecture ensures secure handling of user authentication and authorization using OAuth and JWT, while also incorporating Gravatar for user avatars.