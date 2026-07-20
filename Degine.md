# IronVault UI Design System & Component Architecture (`Degine.md`)

## 1. Visual Theme & Styling Guidelines

IronVault Admin utilizes a **Cyberpunk / Glassmorphism** design system rendered natively via Slint.

### 1.1 Color Palette (`ironvault-ui/ui/theme.slint`)
- **Primary Accent:** `#00D4FF` (Neon Cyan)
- **Secondary Accent:** `#FF00FF` (Neon Magenta)
- **Background Primary:** `#0A0E27` (Deep Space Dark Navy)
- **Background Secondary:** `#12183B` (Translucent Card Navy)
- **Border / Glass Effect:** `rgba(0, 212, 255, 0.2)`
- **Status Colors:**
  - Success / Active: `#00FF87` (Neon Emerald)
  - Warning / Expired: `#FFB800` (Amber Gold)
  - Critical / Error: `#FF3366` (Crimson Red)

---

## 2. UI View Hierarchy (`ironvault-ui/ui/views/`)
AppWindow (main.slint)
├── Navigation (sidebar.slint)
├── Top Status Panel (topbar.slint)
├── Notification Banner / Toast Overlay (toast.slint)
└── Dynamic Content View Container
├── Login View (login.slint)
├── Registration View (register.slint)
├── Overview / Dashboard View (dashboard.slint)
├── GPFFP Final Payment Module View (gpf.slint)
├── Pension DAK Correspondence View (pendak.slint)
├── P-SAI Pension Status Tracking View (sai_agartala.slint)
└── VLCS View (vlcs.slint)


---

## 3. Dynamic UI Property Bindings

Slint communicates bidirectionally with Rust via callback events and global window properties:

```slint
export component AppWindow inherits Window {
    in-out property <string> current_user_name: "GUEST";
    in-out property <string> current_user_role: "UNAUTHORIZED";
    in-out property <bool> is_logged_in: false;
    in-out property <SchemaAccessState> schema_access;

    callback request_authentication(string, string);
    callback request_logout();
    callback commit_user_settings_pass(string, string, string, bool, bool, bool, bool);
}

---

# 6. `memory.md` (System Memory & State Reference)

```markdown
# IronVault Memory & State Management Reference

## 1. Operational State Map

### 1.1 Application Lifecycle States
- **BOOTSTRAP:** `main.rs` initializes `.env`, computes hardware HWID, enforces security checks, establishes PostgreSQL connection pools (`PgPool`), and initializes 7 Oracle TNS connection pools.
- **UNAUTHENTICATED:** Displays `login.slint` or `register.slint`. UI state flags: `is_logged_in = false`.
- **FORCED_RESET:** Triggered when an operator logs in using an OTA reset token. Blocks full dashboard navigation until new credentials are set.
- **AUTHENTICATED:** Active operator session. UI dynamically renders views based on `schema_access` permissions.

---

## 2. In-Memory Data Structures

### 2.1 Authenticated Session (`DbUser` & `ActiveUser`)
```rust
pub struct DbUser {
    pub username: String,
    pub role: String,
    pub last_login: String,
}

pub struct ActiveUser {
    pub username: String,
    pub role: String,
    pub last_login: String,
    pub full_name: String,
    pub designation: String,
    pub expires_at: String,
}