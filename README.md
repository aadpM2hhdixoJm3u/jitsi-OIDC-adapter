# jitsi-OIDC-adapter

This project aims to add support for OpenID Connect (OIDC) since Jitsi decided to discontinue support for Shibboleth. It is inspired by [@nordeck's](https://github.com/nordeck/jitsi-keycloak-adapter) OIDC connector for Keycloak. However, due to my limited experience with TypeScript, I have developed this project using Python and some JavaScript.

The primary function of this project is to integrate authentication capabilities into Jitsi Meet through any OIDC-compliant Identity Provider (IDP). In my use case, the objective is to authenticate the meeting host, allowing guests to join the meeting without requiring authentication.

# Installation Guide

This guide expects a working Jitsi Meet installation with JWT and an anonymous domain activated. I recommend using @emrah's [Jitsi-Token Installer](https://github.com/jitsi-contrib/installers), which is brilliant, by the way. Once that is up and running, you can follow this guide.

1. Install dependencies:
```sh
sudo apt update && sudo apt upgrade -y
sudo apt install python3 python3-pip -y
```


2. Clone the repository:
```bash
sudo apt install git -y
git clone https://github.com/aadpM2hhdixoJm3u/jitsi-OIDC-adapter.git
cd jitsi-OIDC-adapter
```


3. Install Python dependencies:

You can install the Python dependencies globally or within a virtual environment. In this guide, we will install them globally as root, making them accessible system-wide. However, using a virtual environment is generally recommended to avoid conflicts between different projects.
```sh
sudo su
pip install -r requirements.txt
exit
```
To use a virtual environment instead, you can do the following:
```sh
python3 -m venv myenv
source myenv/bin/activate
pip install -r requirements.txt
```

4. Copy the file:
```sh
sudo cp body.html /usr/share/jitsi-meet/
```

5. Update Nginx

Add the following lines as the first ```location``` blocks
```sh
sudo nano /etc/nginx/sites-available/meet.yourdomain.com.conf
```
```sh
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
6. Create a Gunicorn service
Ceate ``/gunicorn/`` directory if needed:
```sh
sudo mkdir -p /etc/gunicorn
sudo nano /etc/gunicorn/config.py
```
Example content:
```sh
bind = '0.0.0.0:8000'
workers = 3
```
Create the systemd service file:
```sh
sudo nano /etc/systemd/system/gunicorn.service
```
Example content:

```sh
[Unit]
Description=Gunicorn instance to serve myapp
After=network.target

[Service]
User=ubuntu # Adjust based on your environment
Group=ubuntu # Adjust based on your environment
WorkingDirectory=/home/ubuntu/jitsi_OIDC_adapter/ # Adjust based on your environment
ExecStart=/usr/local/bin/gunicorn --config /etc/gunicorn/config.py app:app # Adjust based on your environment
[Install]
WantedBy=multi-user.target
```
Depending on where you want to run the jitsi-OIDC-adapter from and which user you want to use, this may impact the service configuration. In this example, we are running the jitsi-OIDC-adapter from /home/ubuntu/jitsi-OIDC-adapter. However, this may change depending on your setup.

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








