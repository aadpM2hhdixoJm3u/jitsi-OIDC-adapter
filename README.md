# jitsi-OIDC-adapter

This project aims to add support for OpenID Connect (OIDC) since Jitsi decided to discontinue support for Shibboleth. It is inspired by @emrahcom's OIDC connector for Keycloak. However, due to my limited experience with TypeScript, I have developed this project using Python and some JavaScript.

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
Depending on your security concerns, you can install the Python dependencies in different ways. In this guide, we will install them as root, making them accessible globally. However, feel free to use a virtual environment if you prefer.
```sh
sudo su
pip install -r requirements.txt
exit
```


4. Copy the file:
```sh
sudo cp body.html /usr/share/jitsi-meet/
```












