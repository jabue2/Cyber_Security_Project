# LibSSH Authentication Bypass Demonstration (CVE-2018-10933)

This project demonstrates the LibSSH authentication bypass vulnerability (CVE-2018-10933) that affected LibSSH versions 0.6.0 through 0.7.5.

## Overview

The vulnerability allows an attacker to bypass authentication by sending an SSH2_MSG_USERAUTH_SUCCESS message to the server, which should only be sent from server to client. Due to a flaw in the LibSSH state machine, this causes the server to transition to an authenticated state without verifying credentials.

## Requirements

- LibSSH development libraries (vulnerable version 0.6.0 - 0.7.5 for actual exploitation)
- GCC or another C compiler
- Python 3 with paramiko library for the exploit script

## Setup Instructions

### 1. Install LibSSH

For Ubuntu/Debian:
```bash
sudo apt-get install libssh-dev
```

For CentOS/RHEL:
```bash
sudo yum install libssh-devel
```

For macOS:
```bash
brew install libssh
```

### 2. Generate SSH Host Key

```bash
ssh-keygen -t rsa -f ssh_host_rsa_key -N ""
```

### 3. Compile the Server

```bash
gcc -o ssh_server ssh_server.c -lssh
```

### 4. Run the Server

```bash
./ssh_server
```

The server will listen on port 2222 by default.

### 5. Run the Exploit

In a separate terminal:

```bash
python3 ssh_exploit.py --host 127.0.0.1 -p 2222 -c "id"
```

This will attempt to exploit the vulnerability and execute the "id" command on the server.

## Files

- `ssh_server.c`: Vulnerable SSH server implementation
- `ssh_exploit.py`: Python script to exploit the vulnerability
- `version.py`: Script to check the version of a remote SSH server

## Notes

- This is for educational purposes only
- The server is intentionally vulnerable to demonstrate the exploit
- In a real-world scenario, you would need a vulnerable version of LibSSH (0.6.0 - 0.7.5)
- Modern versions of LibSSH have patched this vulnerability