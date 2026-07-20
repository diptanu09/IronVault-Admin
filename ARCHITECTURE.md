# IronVault Admin - Architecture & System Reference

![IronVault](https://img.shields.io/badge/Security-Enterprise%20Grade-red?style=for-the-badge)
![Rust](https://img.shields.io/badge/Language-Rust%202021-ce422b?style=for-the-badge)
![Slint](https://img.shields.io/badge/UI-Slint%20Native-ff6b6b?style=for-the-badge)

IronVault Admin is a multi-tier, security-hardened desktop management system written in **Rust** and **Slint GUI**. It connects enterprise security runtime controls with high-concurrency database storage engines.

---

## 🏗️ Monorepo Workspace Topology


ironvault-admin/
├── Cargo.toml                       # Workspace manifest (lto="fat", opt-level=3, debug=true)
├── .gitignore                       # Target, .env, and local storage exclusion
├── ARCHITECTURE.md                  # Comprehensive System & Technical Architecture
├── PRD.md                           # Product Requirement Document
├── rules.md                         # Engineering & Security Guidelines
├── passcs.md                        # Security & Protection Analysis
├── Degine.md                        # Design System & UI Architecture
├── memory.md                        # System Memory & State Management Reference
├── Roadmap.md                       # Enterprise Completion Roadmap
│
├── ironvault-core/                  # Security, Licensing & Cryptographic Layer
│   ├── Cargo.toml
│   └── src/
│       ├── lib.rs                   # Core module definitions & re-exports
│       ├── auth.rs                  # RBAC models (SuperAdmin, Admin, Operator, Viewer)
│       ├── crypto.rs                # AES-256-GCM, Bcrypt (Cost 12), SHA-256 Token Hashes
│       ├── security.rs              # Anti-Debug & VM Detection via VMProtect FFI
│       ├── licensing.rs             # OS-Native Machine GUID / DMI Product UUID HWID Engine
│       ├── audit.rs                 # File-based immutable Audit Logger (Fallback Engine)
│       ├── network.rs               # Secure TLS network utilities
│       └── bin/
│           └── node_client.rs       # Node client testing executable
│
├── ironvault-db/                    # Dual-Engine Data Access Layer
│   ├── Cargo.toml
│   └── src/
│       ├── lib.rs                   # Database crate exports
│       ├── postgres.rs              # PostgreSQL ORM with SQLx (Pool max 5 conn)
│       ├── oracle.rs                # Oracle Multi-Pool Matrix Hub (7 TNS Pools)
│       ├── gpf.rs                   # GPFFP schema queries & cascade mutations
│       ├── pendak.rs                # Outward Pension DAK records & recipient handlers
│       ├── sai_agartala.rs          # Pension biographical details & tracking queries
│       :: vlcs.rs                   # VLCS legacy ledger operations
│
└── ironvault-ui/                    # Slint Native GUI & Main Orchestrator
├── Cargo.toml
├── build.rs                     # Slint build script compiler
├── src/
│   ├── main.rs                  # Application Bootstrapper & Async UI State Handler
│   ├── context.rs               # Context wrappers
│   ├── controllers.rs           # Event routing & controller adapters
│   └── handlers/                # Business logic handlers
│       ├── mod.rs
│       ├── auth.rs              # Authentication handlers
│       ├── users.rs             # Operator administration handlers
│       └── audit_log.rs         # Audit stream handlers
└── ui/                          # Declarative Slint Layout Templates
├── main.slint               # Master AppWindow Component
├── theme.slint              # Cyberpunk / Neon Glassmorphism Color Palette
├── components/              # Reusable UI Controls (Sidebar, Topbar, Toast, Logo)
└── views/                   # Operational Views (Login, Dashboard, GPF, DAK, Pension)


## 🔐 Core Component Architecture

+-----------------------------------+
                   |         Slint UI Front-End        |
                   | (main.slint / Neon Design System) |
                   +-----------------------------------+
                                     |
                        invoke_from_event_loop
                                     v
+----------------------------------------------------------------------------------+
|                              ironvault-ui (main.rs)                              |
|                          Tokio Async Runtime Engine                              |
+----------------------------------------------------------------------------------+
|                                   |                                  |
v                                   v                                  v
+-----------------------+     +--------------------------+      +--------------------------+
|    ironvault-core     |     |   ironvault-db (PgPool)  |      | ironvault-db (Oracle)    |
| - VMProtect / Themida |     | - PostgreSQL (SQLx)      |      | - 7 Discrete TNS Pools   |
| - Bcrypt / AES-GCM    |     | - Auth & Operator Store  |      | - GPFFP, PENDAK, P-SAI   |
| - OS-native HWID      |     | - Primary Audit Logs     |      | - Legacy DB11g / ORCL    |
+-----------------------+     +--------------------------+      +--------------------------+


---

## 📊 Database Schema Details

### PostgreSQL Schema (`ironvault.users`)
```sql
CREATE TABLE ironvault.users (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    username VARCHAR(255) UNIQUE NOT NULL,
    password VARCHAR(255) NOT NULL, -- Self-describing Bcrypt Hash ($2b$12$...)
    role VARCHAR(50) NOT NULL,     -- SuperAdmin, Admin, Operator, Viewer
    status VARCHAR(50) NOT NULL,   -- ACTIVE, PENDING, EXPIRED, BANNED
    hardware_fingerprint VARCHAR(255) NOT NULL,
    first_name VARCHAR(100),
    middle_name VARCHAR(100),
    last_name VARCHAR(100),
    full_name VARCHAR(255),
    designation VARCHAR(100),
    section VARCHAR(255),          -- Comma-separated schema access tokens (e.g. "gpffp,pendak,")
    temp_token VARCHAR(255),       -- SHA-256 hash of single-use reset code
    approved_by VARCHAR(255),
    expires_at TIMESTAMP WITH TIME ZONE,
    last_login_at TIMESTAMP WITH TIME ZONE,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);
PostgreSQL Audit Schema (ironvault.db_audit_logs)
SQL
CREATE TABLE ironvault.db_audit_logs (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    operator_id VARCHAR(255) NOT NULL,
    operation_action TEXT NOT NULL,
    impact_level VARCHAR(50) NOT NULL, -- CRITICAL, WARNING, NOMINAL
    target_schema VARCHAR(100) NOT NULL,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

---

# 3. `rules.md` (Engineering & Security Standards)

```markdown
# IronVault Admin Engineering & Security Rules

To maintain high security, stability, and code clarity, all developers contributing to IronVault Admin must strictly adhere to these rules.

---

## 1. Cryptography & Credentials
1. **Never Hardcode Secrets:** API tokens, database passwords, and private keys must be fetched from environment variables via `dotenvy`.
2. **Password Hashing Standard:** Always use `ironvault_core::crypto::hash_password` (Bcrypt, Cost 12) for user login credentials. Never use simple SHA-256 or MD5 for passwords.
3. **One-Time Token Hashes:** Use `ironvault_core::crypto::hash_token` (SHA-256) for high-entropy machine-generated reset tokens.
4. **No Plaintext Logging:** Never write passwords, raw encryption keys, or unhashed reset tokens to console output or audit logs.

---

## 2. Concurrency & Slint UI Isolation
1. **Non-Blocking UI Thread:** Never execute blocking I/O, network requests, or long computations directly on the main UI thread.
2. **Asynchronous Spawning:** Use `tokio::spawn` for all database calls and background procedures.
3. **Safe UI Updates:** All state mutations originating from async worker threads back to Slint components must be wrapped in `slint::invoke_from_event_loop(move || { ... })`.
4. **Weak Pointer Safety:** Always clone `Slint::as_weak()` handles before passing them across thread boundaries. Call `.upgrade()` safely inside the event loop closure.

---

## 3. Database Operations
1. **SQL Injection Prevention:** Never concatenate user input directly into SQL strings. Use parameterized queries with `.bind()` in `sqlx`.
2. **Audit Requirement:** Any mutation altering user state, granting access, or purging records must emit a corresponding audit entry via `record_audit()`.
3. **Graceful Outage Fallback:** If PostgreSQL audit log insertion fails, automatically divert the record to the file-backed `AuditLogger`.

---

## 4. Binary Protection & FFI
1. **Keep Symbols Intact:** Maintain `debug = true` and `strip = false` in release profile definitions in `Cargo.toml` to preserve SDK scanner markers for Themida/VMProtect.
2. **Wrap Critical Blocks:** Enclose critical cryptographic and authentication routines within `VMStart()` / `VMEnd()` and `VMProtectBeginUltra()` / `VMProtectEnd()` gates.
4. passcs.md (Security & Protection Analysis)
Markdown
# IronVault Protection & Attack Surface Analysis (PASSCS)

## 1. Security Architecture Matrix

| Protection Layer | Mechanism | Implementation Detail | Threat Mitigated |
| :--- | :--- | :--- | :--- |
| **Executable Protection** | Oreans Themida SDK | `VMStart()` / `VMEnd()` wrappers around authentication routines | Reverse engineering, code injection |
| **Virtualization & Anti-Debug**| VMProtect SDK64 | `VMProtectIsDebuggerPresent()`, `VMProtectIsVirtualMachinePresent()` | x64dbg/GDB attachment, Memory dumping |
| **Hardware Binding** | HWID Licensing | OS-specific MachineGuid / DMI UUID hashing (`Sha256`) | Credential cloning & unauthorized machine access |
| **Credential Security** | Bcrypt Algorithm | Adaptive work factor 12 with cryptographically random salts | Offline rainbow table attacks, GPU cracking |
| **Symmetric Encryption** | AES-256-GCM | Authenticated payload envelopes with time-bound TTLs | Replay attacks, transport tampering |
| **Integrity Logging** | Dual-Layer Audit | PostgreSQL primary storage + File-based hash chain fallback | Forensic evasion, log tampering |

---

## 2. Threat Vector Evaluation & Countermeasures

### 2.1 Dynamic Debugger Attachment
- **Threat:** An attacker attaches `x64dbg` or `Cheat Engine` to analyze process memory and extract user session tokens.
- **Countermeasure:** `SecurityValidator::enforce_anti_debug()` queries Win32 `IsDebuggerPresent()` and kernel handles via `CheckRemoteDebuggerPresent()`. It runs in a background thread every 4 seconds and self-terminates the process on violation (`std::process::exit(1)`).

### 2.2 Virtual Machine / Sandbox Analysis
- **Threat:** Automated malware analysis sandboxes (e.g., Cuckoo) run the application to inspect network traffic and behavior.
- **Countermeasure:** Hardware-level CPUID leaf checking (`__cpuid(1)` ECX bit 31 check & leaf `0x40000000` hypervisor signature parsing) detects virtualized runtime environments and blocks execution immediately.

### 2.3 Sql Injection / Parameter Tampering
- **Threat:** Malicious inputs placed into search bars or application fields attempt SQL injection attacks.
- **Countermeasure:** SQL queries use parameterized bindings via `sqlx` (PostgreSQL) an