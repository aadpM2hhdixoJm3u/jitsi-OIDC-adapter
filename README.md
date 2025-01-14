# jitsi-OIDC-adapter

This project aims to add support for OpenID Connect (OIDC) since Jitsi decided to discontinue support for Shibboleth. It is inspired by [@nordeck's](https://github.com/nordeck/jitsi-keycloak-adapter) OIDC connector for Keycloak. However, due to my limited experience with TypeScript, I have developed this project using Python and some JavaScript.

The primary function of this project is to integrate authentication capabilities into Jitsi Meet through any OIDC-compliant Identity Provider (IDP). In my case, the objective is to authenticate the meeting host, allowing guests to join the meeting without requiring authentication.

**Note:** This app has been tested on **Ubuntu 22.04** with **Python 3** and the latest Jitsi installation. The Identity Provider (IDP) tested with this app is **Nexus DA**. But it should work with any IDP that follows the OIDC standard for authorization code flow.<br><br>

# Installation Guide

This guide expects a working Jitsi Meet installation with JWT and an anonymous domain activated. I recommend using @emrah's [Jitsi-Token Installer](https://github.com/jitsi-contrib/installers), which is brilliant, by the way. Once that is up and running, you can follow this guide.

You can also install Jitsi Meet with an anonymous domain and JWT support by following the standard Jitsi install guide [here](https://jitsi.github.io/handbook/docs/devops-guide/devops-guide-quickstart).

### Step 1: Install Python
```sh
sudo apt update && sudo apt upgrade -y
sudo apt install python3 python3-pip -y
```


### Step 2: Clone the Repository
```bash
sudo apt install git -y
apt install python3-pip
git clone https://github.com/aadpM2hhdixoJm3u/jitsi-OIDC-adapter.git
cd jitsi-OIDC-adapter
```


### Step 3: Install Python Dependencies

You can install the Python dependencies globally or within a virtual environment. In this guide, we will install them globally as root, making them accessible system-wide. However, using a virtual environment is generally recommended to avoid conflicts between different projects.

Globally:
```sh
sudo su
pip install -r requirements.txt
exit
```
Using a virtual environment:
```sh
python3 -m venv myenv
source myenv/bin/activate
pip install -r requirements.txt
```

### Step 4: Copy the File
```sh
sudo cp body.html /etc/jitsi/meet/
```
This ensures that we don't overwrite the original body.html when upgrading Jitsi. We chose this location over the root Jitsi folder to keep our customizations separate

### Step 5: Update Nginx

Add the following lines as the first ```location``` blocks:
```sh
sudo nano /etc/nginx/sites-available/meet.yourdomain.com.conf
```
```nginx
    set $body_html_location /etc/jitsi/meet/body.html;
    
    location = /body.html {
        alias $body_html_location;
    }
    
    # /oidc/redirect
    location = /oidc/redirect {
        proxy_pass http://127.0.0.1:8000;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
    }
    
    # /oidc/tokenize
    location = /oidc/tokenize {
        proxy_pass http://127.0.0.1:8000;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
    }
    
    # /oidc/auth
    location = /oidc/auth {
        proxy_pass http://127.0.0.1:8000;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
    }

```

### Step 6: Create a Gunicorn Service
Ceate ``/gunicorn/`` directory if needed:
```sh
sudo mkdir -p /etc/gunicorn
sudo nano /etc/gunicorn/config.py
```
Example content:
```python
bind = '0.0.0.0:8000'
workers = 1
```
Create the systemd service file:
```sh
sudo nano /etc/systemd/system/gunicorn.service
```
Example content:

```ini
[Unit]
Description=Gunicorn instance to serve myapp
After=network.target

[Service]
User=ubuntu # Adjust based on your environment
Group=ubuntu # Adjust based on your environment
WorkingDirectory=/home/ubuntu/jitsi-OIDC-adapter/ # Adjust based on your environment
ExecStart=/usr/local/bin/gunicorn --config /etc/gunicorn/config.py app:app # Adjust based on your environment
[Install]
WantedBy=multi-user.target
```
Depending on where you want to run the jitsi-OIDC-adapter from and which user you want to use, this may impact the service configuration. In this example, we are running the jitsi-OIDC-adapter from /home/ubuntu/jitsi-OIDC-adapter. However, this may change depending on your setup.

### Step 7: configure jitsi-OIDC-adapter ``app.conf``

The `app.conf` file is used to configure the OAuth, URLs, JWT, and logging settings for jitsi-OIDC-adapter. Each section is explained below:

#### [oauth]
- **client_id**:
  - **Description**: The client ID provided by your OIDC (OpenID Connect) provider.
  - **Example**: `client_id = your_client_id`
- **client_secret**:
  - **Description**: The client secret provided by your OIDC provider.
  - **Example**: `client_secret = your_client_secret`
- **issuer**:
  - **Description**: The issuer URL for your OIDC provider. This is used to verify the authenticity of the tokens.
  - **Example**: `issuer = https://your-oidc-provider.com`
- **authorize_url**:
  - **Description**: The URL used to authorize users with your OIDC provider.
  - **Example**: `authorize_url = https://your-oidc-provider.com/authorize`
- **access_token_url**:
  - **Description**: The URL used to obtain access tokens from your OIDC provider.
  - **Example**: `access_token_url = https://your-oidc-provider.com/token`
- **jwks_uri**:
  - **Description**: The URL where the JSON Web Key Set (JWKS) can be retrieved from your OIDC provider.
  - **Example**: `jwks_uri = https://your-oidc-provider.com/.well-known/jwks.json`
- **scope**:
  - **Description**: The scope of the access request. `openid` is typically required for OIDC.
  - **Default Value**: `scope = openid`

**Note**: If you fill out `oidc_discovery` in the `[urls]` section, you do not need to fill out `issuer`, `authorize_url`, `access_token_url`, and `jwks_uri` as these will be automatically discovered. However, leave the default values for these fields if they are not being filled out, as the application may not handle empty values correctly.

#### [urls]
- **jitsi_base**:
  - **Description**: The base URL for your Jitsi instance.
  - **Example**: `jitsi_base = https://meet.yourdomain.com`
- **oidc_discovery**:
  - **Description**: The OIDC discovery URL. If provided, it will automatically discover `issuer`, `authorize_url`, `access_token_url`, and `jwks_uri`.
  - **Example**: `oidc_discovery = https://your-oidc-provider.com/.well-known/openid-configuration`

#### [jwt]
- **audience**:
  - **Description**: The audience claim (`aud`) that the JWT should contain. This typically identifies the intended recipient(s) of the token.
  - **Example**: `audience = your_audience`
- **issuer**:
  - **Description**: The issuer claim (`iss`) that the JWT should contain. This identifies the principal that issued the token. **This must match the issuer configured in your Jitsi JWT setup.**
  - **Example**: `issuer = your_jitsi_jwt_issuer`
- **subject**:
  - **Description**: The subject claim (`sub`) that the JWT should contain. This identifies the principal that is the subject of the token.
  - **Example**: `subject = your_subject`
- **secret_key**:
  - **Description**: The secret key used to sign the JWT. **This must match the secret key configured in your Jitsi JWT setup.**
  - **Example**: `secret_key = your_jitsi_jwt_secret_key`

#### [logging]
- **level**:
  - **Description**: The logging level. Common levels are `DEBUG`, `INFO`, `WARNING`, `ERROR`, and `CRITICAL`.
  - **Default Value**: `level = DEBUG`
- **filename**:
  - **Description**: The name of the log file where logs will be written.
  - **Default Value**: `filename = app.log`
- **filemode**:
  - **Description**: The mode in which the log file is opened. `a` for append, `w` for write.
  - **Default Value**: `filemode = a`

#### Example `app.conf`

```ini
[oauth]
client_id = your_client_id
client_secret = your_client_secret
issuer = https://your-oidc-provider.com
authorize_url = https://your-oidc-provider.com/authorize
access_token_url = https://your-oidc-provider.com/token
jwks_uri = https://your-oidc-provider.com/.well-known/jwks.json
scope = openid email profile # Change depending on your IDP's scope configuration

[urls]
jitsi_base = https://meet.yourdomain.com
oidc_discovery = https://your-oidc-provider.com/.well-known/openid-configuration

[jwt]
audience = your_audience
issuer = your_jitsi_jwt_issuer  # Must match your Jitsi
subject = your_subject # eg meet.yourdomain.com
secret_key = your_jitsi_jwt_secret_key  # Must match your Jitsi JWT configuration

[logging]
level = INFO
filename = app.log
filemode = a
```
**Note:** If you provide the oidc_discovery URL, you can omit the ``issuer``, ``authorize_url``, ``access_token_url``, and ``jwks_uri`` fields, and they will be automatically discovered.

Reload systemd, start and enable the service:
```sh
sudo systemctl daemon-reload
sudo systemctl start gunicorn.service
sudo systemctl enable gunicorn.service
```
Check the status:
```sh
sudo systemctl status gunicorn.service
```
### Step 8: configure your IDP
Make sure that you send attributes ``displayName`` and ``email`` or change this code to match your claims. See the note below regarding ``email`` and Gravatar.
```python
        email = id_token.get('email')
        avatar_url = get_gravatar_url(email) if email else 'http://example.com/default-avatar.png'

        session['user_info'] = {
            'name': id_token.get('displayName', 'Change me'),
            'email': id_token.get('email', 'no-email@example.com'),
            'avatar': avatar_url
        }
```

**Note:** Turn on DEBUG logging if you experience any problems in `app.conf`. 
```ìni
[logging]
level = DEBUG
```
I added extensive logging when `DEBUG` is on so you can easily find any issues. Make sure your Jitsi installation works with JWT and an anonymous domain before running this app. If you don't need features like Gravatar, avoid sending email in your ID token.






