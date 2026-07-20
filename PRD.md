# Product Requirement Document (PRD): IronVault Admin

## 1. Executive Summary & Vision
IronVault Admin is an enterprise-grade desktop administrative console engineered for high-security environments. It acts as an operational control plane connecting a modern, hardened PostgreSQL authentication/authorization database with multi-cluster legacy Oracle databases (`gpffp`, `vlcs`, `agtall`, `agdak`, `sai_agartala`, `pendak`, `penindex`). The system enforces strict Role-Based Access Control (RBAC), multi-factor machine binding via OS-level Hardware IDs (HWID), cryptographic envelope protection, and native binary virtualization (Themida & VMProtect SDKs).

---

## 2. Target Audience & Roles

### 2.1 SuperAdmin
- **Description:** System Administrator / Chief Security Officer.
- **Permissions:** Unrestricted access across all operational modules and database schemas. Can approve, deny, ban, extend leases, override hardware fingerprints, and issue One-Time Passcode (OTA) reset tokens for operators.

### 2.2 Admin
- **Description:** Department Manager.
- **Permissions:** Manages operator accounts within their assigned sections, oversees lease expirations, and views system telemetry.

### 2.3 Operator
- **Description:** Day-to-day administrative officer.
- **Permissions:** Executes CRUD operations within permitted schemas (e.g., GPF case deletions, Pension DAK entries, P-SAI inquiries). Constrained by explicit schema assignments (`section` field).

### 2.4 Viewer
- **Description:** Auditor / Compliance Officer.
- **Permissions:** Read-only access to audit logs and schema metadata. All mutation handlers are blocked.

---

## 3. Core Functional Requirements

### 3.1 Authentication & Operator Onboarding
- **User Enrollment:** Plaintext registration capturing username, secret, full name (First, Middle, Last), designation, and section. Automatically acquires machine HWID.
- **Approval Workflow:** Newly registered accounts enter `PENDING` state with no assigned expiration (`expires_at = NULL`). SuperAdmin reviews and approves pending requests, assigning roles and setting a default 30-day lease.
- **Hardware Binding (HWID):** Enforces strict machine matching on login. Prevents credential sharing across unauthorized physical hosts.
- **One-Time Access (OTA) Token Authentication:** Allows account recovery or emergency access via temporary single-use CSPRNG tokens hashed with SHA-256 (`temp_token`). Triggers mandatory password updates upon initial entry.

### 3.2 Schema Access & Granular Permissions
- Multi-schema entitlement flags (`gpffp`, `vlcs`, `agtall`, `agdak`, `sai_agartala`, `pendak`, `penindex`).
- SuperAdmins bypass all schema restriction checks.
- Section toggles dynamically update UI action capabilities based on operator permissions.

### 3.3 Domain Operational Modules
1. **GPFFP (General Provident Fund Final Payment):**
   - Case Lookup by Registration Number (`regd_no`).
   - Cascade Case Clearing (`gpffp_delete_full_case`).
   - Isolated record purges from Application, Pre-Calculation, and Signed Authority/Upload Report tables.
2. **PENDAK (Pension Outward DAK & Correspondence):**
   - Auto-fetching PPO, FPPO, GPO, and CPO metadata.
   - Outward DAK entry creation with multi-copy recipient handling (Address, Barcode, Sender).
   - Dynamic Outward case query and modification pipeline.
3. **P-SAI (Pension Status & Biographical Tracking):**
   - Pensioner biographical details retrieval by query term.
   - Live settlement status tracking (PPO, GPO, CPO, SpeedPost Tracking, Treasury Dispatch).

### 3.4 Audit Trail & Compliance
- Primary logging written asynchronously to PostgreSQL (`ironvault.db_audit_logs`).
- Automatic fallback to file-based ledger (`ironvault.audit.log`) during database network outages.
- Immutable hash structure containing Event ID, Timestamp, Operator ID, Action String, and Impact Level (`CRITICAL`, `WARNING`, `NOMINAL`).

---

## 4. Non-Functional & Security Requirements
- **Password Security:** Mandatory bcrypt hashing (Work Factor 12) with unique per-hash random salts.
- **Runtime Integrity:** Anti-debug loops (ring-0 kernel debugger checks via `VMProtectSDK64.lib`) and hardware CPUID hypervisor detection (`__cpuid` leaf checks).
- **Native Binary Protection:** FFI links to Oreans Themida (`VMStart` / `VMEnd`) and VMProtect (`VMProtectBeginUltra` / `VMProtectBeginMutation`).
- **Performance & Concurrency:** Async I/O powered by Tokio runtime; Slint UI thread-isolation with event-loop dispatching (`slint::invoke_from_event_loop`).