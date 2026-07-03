# IronVault Admin - Enterprise Security Management System

![IronVault](https://img.shields.io/badge/Security-Enterprise%20Grade-red?style=for-the-badge)
![Rust](https://img.shields.io/badge/Language-Rust-ce422b?style=for-the-badge)
![Slint](https://img.shields.io/badge/UI-Slint-ff6b6b?style=for-the-badge)

A powerful, security-focused administrative platform built with **Rust** and **Slint** that provides enterprise-grade access control, cryptographic operations, and comprehensive audit logging.

## 🏗️ Architecture Overview

```
ironvault-admin/
├── ironvault-core/         # Security & Core Logic Layer
│   ├── auth.rs             # Role-Based Access Control (RBAC)
│   ├── crypto.rs           # AES-256-GCM Encryption
│   ├── security.rs         # Anti-debug, Anti-dump, VM Detection
│   ├── licensing.rs        # HWID Generation & License Management
│   └── audit.rs            # Immutable Audit Logging
│
├── ironvault-db/           # Data Access Layer
│   ├── postgres.rs         # PostgreSQL ORM (Primary)
│   └── oracle.rs           # Oracle 11g/12c Support (Legacy)
│
└── ironvault-ui/           # Presentation Layer
    ├── src/
    │   ├── main.rs         # Slint Bootstrapper
    │   └── controllers.rs   # Event Handlers & Business Logic
    └── ui/
        ├── main.slint      # Master Window
        ├── theme.slint     # Futuristic Design System
        ├── components/
        │   ├── sidebar.slint    # Navigation
        │   └── topbar.slint     # User Info
        └── views/
            ├── login.slint      # Authentication
            ├── register.slint   # User Onboarding
            └── dashboard.slint  # Metrics & Analytics
```

## 🔐 Core Features

### 1. **Security Layer** (ironvault-core)

#### Authentication & Authorization
- **Four-tier RBAC**: SuperAdmin, Admin, Operator, Viewer
- Role-based permission validation
- Session management with JWT tokens

#### Cryptography
- **AES-256-GCM** authenticated encryption
- Payload encryption/decryption with AAD support
- Secure key management

#### Advanced Security
- **Anti-debug Detection**: Prevents debugger attachment
- **Anti-dump Protection**: Guards against memory dumps
- **VM Detection**: Identifies virtualized environments
- **Integrity Verification**: Binary hash validation

#### Licensing & Hardware Binding
- **HWID Generation**: SHA-256 based hardware identification
- **MAC Address Binding**: Device-specific licensing
- **License Validation**: Expiration and authenticity checks
- **Support for multiple OS**: Windows, Linux, macOS

#### Audit Logging
- **Immutable Logs**: Hash-chained entries for integrity
- **Comprehensive Tracking**: All user actions logged
- **Compliance Export**: CSV, JSON, PDF formats
- **Forensics Ready**: IP address, timestamps, status tracking

### 2. **Database Layer** (ironvault-db)

#### PostgreSQL (Primary)
- Modern async/await with SQLx
- Connection pooling (max 5 connections)
- User management with roles
- Audit log persistence
- Full transaction support

#### Oracle Legacy Support
- 11g/12c compatibility
- Data migration pipeline
- Backward compatibility for existing deployments

### 3. **User Interface** (ironvault-ui)

#### Futuristic Design
- **Neon Cyan/Magenta** color scheme
- Glassmorphic components
- Smooth animations & transitions
- Dark mode by default

#### Views
- **Login**: Secure authentication form
- **Register**: New user onboarding
- **Dashboard**: Real-time metrics
- **User Management**: CRUD operations
- **Audit Logs**: Activity history

## 🚀 Getting Started

### Prerequisites
- **Rust 1.70+**: [Install Rust](https://rustup.rs/)
- **PostgreSQL 12+**: [Download PostgreSQL](https://www.postgresql.org/)
- **Platform-specific requirements**:
  - **macOS**: `brew install cmake pkg-config`
  - **Linux**: `sudo apt install libssl-dev pkg-config cmake`
  - **Windows**: Visual Studio Build Tools

### Installation

1. **Clone the repository**
```bash
cd ironvault-admin
```

2. **Setup PostgreSQL**
```bash
# Create database
createdb ironvault

# Create tables (run migrations)
psql -d ironvault -f migrations/001_initial_schema.sql
```

3. **Configure environment**
```bash
cp .env.example .env

# Edit .env with your database credentials
DATABASE_URL=postgresql://admin:password@localhost/ironvault
```

4. **Build the project**
```bash
cargo build --release
```

5. **Run the application**
```bash
cargo run --release
```

## 🛠️ Development

### Project Structure Guide

#### Adding New Security Features
1. Add module to `ironvault-core/src/`
2. Export in `ironvault-core/src/lib.rs`
3. Use in UI controllers

#### Database Schema Changes
1. Create migration in `ironvault-db/migrations/`
2. Update models in `postgres.rs` or `oracle.rs`
3. Run migrations: `sqlx migrate run`

#### UI Component Development
1. Create `.slint` file in appropriate directory
2. Import in parent component or `main.slint`
3. Update corresponding controller in `controllers.rs`

### Running Tests
```bash
# Run all tests
cargo test

# Run specific crate tests
cargo test -p ironvault-core
cargo test -p ironvault-db
cargo test -p ironvault-ui

# Run with logging
RUST_LOG=debug cargo test -- --nocapture
```

### Building for Production
```bash
# Build optimized release
cargo build --release

# Binary located at: target/release/ironvault-ui
```

## 📊 Database Schema

### Users Table
```sql
CREATE TABLE users (
    id UUID PRIMARY KEY,
    username VARCHAR(255) UNIQUE NOT NULL,
    email VARCHAR(255) UNIQUE NOT NULL,
    password_hash VARCHAR(255) NOT NULL,
    role VARCHAR(50) NOT NULL,
    is_active BOOLEAN DEFAULT true,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);
```

### Audit Logs Table
```sql
CREATE TABLE audit_logs (
    id UUID PRIMARY KEY,
    user_id UUID NOT NULL REFERENCES users(id),
    action VARCHAR(100) NOT NULL,
    resource VARCHAR(255) NOT NULL,
    timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    details TEXT,
    hash VARCHAR(255) NOT NULL
);
```

## 🔑 Key Configuration

### Theme Customization
Edit `ironvault-ui/ui/theme.slint`:
```slint
in-out property <color> primary: #00d4ff;        // Cyan
in-out property <color> secondary: #ff00ff;      // Magenta
in-out property <color> bg_primary: #0a0e27;     // Dark blue
```

### Role Permissions
Modify `ironvault-core/src/auth.rs`:
```rust
pub enum Role {
    SuperAdmin,  // Full access
    Admin,       // Manage users & config
    Operator,    // Execute actions
    Viewer,      // Read-only
}
```

## 📝 Audit Log Entry Structure

```json
{
    "id": "550e8400-e29b-41d4-a716-446655440000",
    "timestamp": "2024-01-15T10:30:45Z",
    "user_id": "550e8400-e29b-41d4-a716-446655440001",
    "username": "admin",
    "action": "USER_CREATION",
    "resource": "user:550e8400-e29b-41d4-a716-446655440002",
    "description": "New user onboarded",
    "details": "{\"email\": \"user@example.com\"}",
    "ip_address": "192.168.1.100",
    "status": "SUCCESS",
    "hash": "abc123def456..."
}
```

## 🔒 Security Best Practices

1. **Never commit secrets** to version control
2. **Use environment variables** for sensitive data
3. **Enable database backups** and test restore procedures
4. **Rotate encryption keys** regularly
5. **Review audit logs** weekly for suspicious activity
6. **Keep dependencies updated**: `cargo update`
7. **Run security audits**: `cargo audit`

## 🚨 Debugging

### Enable detailed logging
```bash
RUST_LOG=debug cargo run
```

### Check security validation
```rust
use ironvault_core::SecurityValidator;

if SecurityValidator::is_debugged() {
    eprintln!("Debugger detected!");
}

if SecurityValidator::is_virtualized() {
    eprintln!("Running in VM");
}
```

### Database diagnostics
```bash
# Test database connection
psql -c "SELECT version();"

# Check active connections
psql -c "SELECT datname, count(*) FROM pg_stat_activity GROUP BY datname;"
```

## 📦 Dependencies

### Core
- **tokio**: Async runtime
- **serde**: Serialization
- **uuid**: Unique identifiers
- **chrono**: DateTime handling

### Security
- **aes-gcm**: Authenticated encryption
- **sha2**: Hashing
- **rand**: Cryptographic randomness

### Database
- **sqlx**: SQL query builder
- **postgres**: PostgreSQL driver

### UI
- **slint**: Modern UI framework

## 🤝 Contributing

1. Create a feature branch: `git checkout -b feature/my-feature`
2. Commit changes: `git commit -am 'Add new feature'`
3. Push to branch: `git push origin feature/my-feature`
4. Submit a pull request

## 📄 License

MIT License - See LICENSE file for details

## 📞 Support

For issues, questions, or suggestions:
- GitHub Issues: [Create an issue](https://github.com/diptanu09/IronVault-Admin/issues)
- Documentation: [Wiki](https://github.com/diptanu09/IronVault-Admin/wiki)

## 🎯 Roadmap

- [ ] Database encryption at rest
- [ ] Multi-factor authentication (MFA)
- [ ] SSO integration (SAML/OAuth2)
- [ ] Advanced analytics dashboard
- [ ] Real-time security alerts
- [ ] API rate limiting
- [ ] Webhook support
- [ ] Mobile companion app
- [ ] Cloud deployment guides

---

**Built with security-first principles for enterprise environments** 🛡️
