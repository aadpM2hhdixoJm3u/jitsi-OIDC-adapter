![image](https://github.com/aadpM2hhdixoJm3u/jitsi-OIDC-adapter/assets/56654306/6db06f53-0982-4cf1-917f-eced304a3ae3)


# Application Architecture and Communication Flow

## Components
- **Browser**: User interface where the join request is initiated.
- **Nginx**: Acts as a reverse proxy, forwarding requests to the application.
- **App**: Your application that handles authentication and generates JWT tokens.
- **OIDC Provider**: The OpenID Connect provider for authentication.
- **Jitsi**: The video conferencing service.

## Communication Flow

### 1. Join Request (Browser to Nginx)
- **Action**: User initiates a join request from the browser.
- **Destination**: Nginx server.
- **Condition**: No token and no flag present in the request.


### 2. Forward to Application (Nginx to App)
- **Action**: Nginx forwards the request to the application's OIDC callback route (`/oidc/redirect`).


### 3. Exchange Code for Tokens (App to OIDC Provider)
- **Action**: The app exchanges the authorization code for tokens by sending a request to the OIDC provider.
- **Response**: OIDC provider returns access and ID tokens.


### 4. Parse ID Token and Store User Info (App)
- **Action**: The app parses the ID token and extracts user information (name, email).
- **Session**: User information is stored in the session.


### 5. Redirect to `/oidc/tokenize` (App to Browser)
- **Action**: The app redirects the browser to the `/oidc/tokenize` route.


### 6. Generate JWT (App)
- **Action**: The app retrieves user info from the session and generates a JWT containing user details.


### 7. Redirect to Jitsi (App to Browser to Jitsi)
- **Action**: The app redirects the browser to the Jitsi URL, appending the generated JWT as a query parameter.
- **Final Destination**: User is authenticated and redirected to the Jitsi conference room.


## Summary
This flow ensures that user authentication and authorization are handled securely, integrating with the OIDC provider for authentication and using JWT tokens to facilitate secure communication with the Jitsi server.

