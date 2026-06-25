# Network-Programming-Assignment
Design and Implementation of a Secure Multiprocessor TCP Application Server with Custom Protocol and Session Management
Your README.md file is ready
[file-tag: code-generated-file-0-1782398237108409251]

Here is the professional Markdown template for your project's `README.md` based on your provided files:

```markdown
# Network Programming Assignment (IE2102)

**Student Registration No:** IT24100368  
**Server ID (SID):** 1003  
**Port:** 50368  

## Overview
This repository contains a secure, multi-process TCP client-server application built as part of the IE2102 Network Programming assignment. The system provides user management (registration, login, and logout) with robust application-layer framing, token-based session tracking, rate limiting, and brute-force lockout protections.

## Project Structure
- **`server_0368.c`**: Concurrent multi-process TCP server implementation in C.
- **`client_0368.py`**: Interactive command-line client utility in Python 3.
- **`Makefile_0368`**: Build automated configuration script for compiling and managing the C server.

---

## Features & Implementation Details

### 1. Custom Framing Protocol
To prevent TCP message boundary issues (fragmentation and concatenation), the system uses explicit length-prefixed framing for communication:
- **Format**: `LEN:<payload_length>\n<payload>`
- **Constraints**: Maximum payload size is restricted to 4096 bytes (`MAX_PAYLOAD`) to eliminate overflow vulnerabilities.

### 2. Multi-Process Concurrency
The C server handles multiple simultaneous client connections concurrently using the `fork()` system call. Zombie process accumulation is explicitly handled using a non-blocking `SIGCHLD` signal handler via `waitpid()`.

### 3. User Authentication & Security
- **Data Directory**: Individual directories and flat files are initialized under `/srv/ie2102/IT24100368/`.
- **Password Hashing**: Passwords are securely stored with a unique, randomly generated 8-character salt from `/dev/urandom`. Passwords are encrypted using SHA-256 via a pipelined `/usr/bin/sha256sum` process.
- **Session Management**: Successful authentication returns a cryptographically secure 64-character hex token. Tokens expire after 5 minutes of inactivity.

### 4. Advanced Protection Mechanics
- **Rate Limiting**: Connections enforce a sliding request cap of 20 requests per minute (`RATE_LIMIT`). Exceeding this triggers an `ERR 429` status code.
- **Brute-Force Prevention**: Five consecutive failed login attempts trigger an immediate account lockout (`LOCKOUT_TIME`) for 5 minutes via an `ERR 423` response code.
- **Structured Logging**: All actions (connections, command executions, authentication updates) are timestamped and recorded in `server_IT24100368.log`.

---

## Getting Started

### Prerequisites
- Linux/Unix Environment
- `gcc` compiler and standard development tools
- Python 3.x

### Compilation
Build the C server binary using the provided Makefile:
```bash
make -f Makefile_0368
