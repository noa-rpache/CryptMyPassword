<!--
SPDX-FileCopyrightText: 2026 Noa Rodríguez noa.rpache@gmail.com  Pablo Diz pablo.diz@gmailcom  Hugo Freire hugo.freire@udc.es  Eloy Sastre elhoyyy@gmail.com

SPDX-License-Identifier: Apache-2.0
-->

# CryptMyPassword 🔐

A secure, open-source password manager browser extension that generates and stores strong passwords with quantum-enhanced entropy, protecting your digital identity with modern cryptography.

## Table of Contents

- [Purpose](#purpose)
- [Features](#features)
- [Installation](#installation)
- [Usage](#usage)
- [Configuration](#configuration)
- [Architecture](#architecture)
- [Contributing](#contributing)
- [License](#license)
- [Support](#support)

## Purpose

CryptMyPassword solves the problem of password management and secure generation. It provides:

- **Automatic Password Generation**: Create cryptographically secure passwords using quantum-enhanced entropy
- **Transparent Storage**: Securely store passwords for websites you visit without manual intervention
- **HIBP Integration**: Check if your passwords have been compromised in known data breaches
- **Device Synchronization**: Sync passwords across multiple devices safely
- **Zero-Knowledge Architecture**: Your passwords are encrypted and stored securely; the extension never transmits unencrypted credentials

## Features

✨ **Core Features**
- **Secure Password Generation**: Quantum-enhanced entropy for maximum security
- **Auto-Save**: Automatically save passwords when you register/login on websites
- **Breach Detection**: Check passwords against HIBP (Have I Been Pwned) database
- **Multi-Device Sync**: Synchronize passwords securely across your devices
- **Smart Detection**: Automatically detects password fields and registration forms
- **Show/Hide Toggle**: Easily view or hide passwords when needed
- **One-Click Copy**: Quickly copy passwords to clipboard
- **Easy Management**: Delete passwords you no longer need

🔧 **Technical Features**
- FastAPI backend with MongoDB storage
- Docker containerization for easy deployment and development
- Quantum randomness integration for enhanced entropy

## Installation

### For Users

> Available in upcoming releases 

### For Developers

**Prerequisites**
- Docker
- Android Studio (for mobile development)
- python3

**Mobile setup**

- Clone the repository
- Open the project in Android Studio
- Launch the app on a connected device or emulator

**Backend Setup**
```bash
# Clone repository
git clone https://github.com/noa-rpache/CryptMyPassword.git

cd server

cp .env.example .env # Modify the values as needed

# Create a virtual environment
python3 -m venv <nombre-env>

source <nombre-env>/bin/activate  # Linux
<nombre-env>\Scripts\activate     # Windows

pip install -r requirements.txt   # Install dependencies

# Launch FastAPI server
python -m fastapi dev main.py --host 0.0.0.0 --port 8000
# Launch MongoDB
docker-compose up
```

**Extension Setup**
```bash
# Load in Firefox
# 1. Navigate to about:debugging#/runtime/this-firefox
# 2. Click "Load Temporary Add-on"
# 3. Select manifest.json in the browser/ folder

# Load in Chrome
# 1. Navigate to chrome://extensions/
# 2. Enable "Developer mode"
# 3. Click "Load unpacked"
# 4. Select the browser/ folder
```

## Usage

### For End Users

#### Generate a Secure Password
1. Visit any website with a registration form
3. Click the "Generar contraseña segura" button in the extension popup
4. Complete the registration and submit the form
5. Your password is automatically saved

#### Use a Saved Password
1. Visit a website you've registered on before
3. Click "Usar contraseña guardada" if available
4. Your saved password is filled in automatically

#### Manage Your Passwords
1. Click the extension icon in your browser toolbar
2. View all saved passwords with domain, username, and encrypted password
3. Check for breaches with the "Verificar contraseñas" button
4. Delete passwords with the 🗑️ button
5. Copy passwords with the 📋 button
6. Toggle visibility with the 👁️ button

#### Verify Password Security
1. Click the "Verificar contraseñas" button in the dashboard
2. The extension checks each password against HIBP
3. Breached passwords are highlighted in red with breach count

### API Endpoints

```
POST   /password                 # Generate a new password
GET    /password                 # Get all stored passwords
GET    /password/{domain}        # Get password for specific domain
POST   /password/save            # Save a password
DELETE /password/{domain}        # Delete a password
GET    /audit                    # Check all passwords against HIBP
GET    /synchronise              # Get linked devices
POST   /synchronise              # Link a new device
```

## Configuration

Add an `API_KEY` to both server and browser `.env` files.

## Architecture

```
CryptMyPassword/
├── browser/                     # WebExtension and dashboard
├── server/                      # FastAPI Backend
│   ├── main.py                  # API routes
│   ├── requirements.txt         # Python dependencies
│   ├── dockerfile               # Docker configuration
│   ├── docker-compose.yml       # Docker composition
│   └── ...                      # Initialization scripts
├── mobile_app/                  # Mobile app
└── docs/                        # Documentation
```

**Communication Flow**
1. **Content Script** detects password fields on web pages
2. **Browser Extension** shows UI for password generation/saving
3. **Background Worker** communicates with FastAPI backend
4. **Backend API** manages MongoDB storage and HIBP checks
5. **Database** securely stores encrypted credentials

## Contributing

We welcome contributions! See [CONTRIBUTING.md](CONTRIBUTING.md) for detailed guidelines on:
- Setting up your development environment
- Code standards and style guide
- Running tests
- Submitting pull requests
- Commit message conventions

### Quick Contribution Guide

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/amazing-feature`)
3. Make your changes
4. Test your changes
5. Commit with conventional commits
6. Push to your branch
7. Open a Pull Request

## License

This project is licensed under the **MIT License** - see [LICENSE](LICENSE) file for details.

## Support

### Getting Help

- 📖 **Documentation**: See the [docs/](docs/) folder for detailed explanations about how it works.
- 🐛 **Bug Reports**: [GitHub Issues](https://github.com/noa-rpache/CryptMyPassword/issues)
- 💬 **Discussions**: [GitHub Discussions](https://github.com/noa-rpache/CryptMyPassword/discussions)

### Roadmap

- [ ] User installation
- [ ] Internationalization (i18n)
- [ ] Improve form fields detection

### Community

- Follow development on [GitHub](https://github.com/noa-rpache/CryptMyPassword)
- Join discussions and share feedback
- Report bugs and request features
- Contribute code, docs, or translations

### Attrbution
- For the extension icon: https://www.flaticon.com/free-icon/password_4543404
