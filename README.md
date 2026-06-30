# IronVault Admin

A secure Rust desktop administration suite with a shared core backend and a high-fidelity UI shell.

## Workspace Structure

- `ironvault-core/` — Secure core backend library.
- `ironvault-ui/` — Desktop user interface application.

Setup & Execution Guide: IronVault Secure Admin Suite

Welcome to your step-by-step guide to assembling, building, and running IronVault Admin! Follow these instructions sequentially to launch your secure, hardware-accelerated desktop application.

Part 1: Install the Rust Compiler

First, you need to install Rust on your computer.

Go to https://rustup.rs/ and download the official installer matching your operating system:

Windows: Download and run rustup-init.exe. (If prompted, agree to install the C++ build tools for Microsoft Visual Studio, which are required for native UI compilation).

macOS / Linux: Open your terminal and run:

curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh


Restart your terminal or command prompt and run the following command to verify the installation succeeded:

rustc --version


Part 2: File Layout & Assembly

Ensure all of your project files are placed in their correct locations. On your computer, create a folder named ironvault-admin. Inside it, copy and paste the contents of your files into the exact file path structure below:

ironvault-admin/
├── Cargo.toml                      <-- [Master Configuration]
├── SETUP_GUIDE.md                  <-- [This Guide]
├── ironvault-core/
│   ├── Cargo.toml                  <-- [Core Cargo Settings]
│   └── src/
│       ├── lib.rs                  <-- [Core Lib Integration]
│       ├── crypto.rs               <-- [Cryptographic Verification Engine]
│       └── models.rs               <-- [Data Models & Auditing Profiles]
└── ironvault-ui/
    ├── Cargo.toml                  <-- [UI Cargo Settings]
    ├── build.rs                    <-- [UI Compiling Script]
    ├── ui/
    │   └── appwindow.slint         <-- [Slint UI File]
    └── src/
        └── main.rs                 <-- [Rust Execution Entry]


Note: Double-check that your directory structure is exactly as displayed above. Missing folders or incorrect names will cause the compiler to fail.

Part 3: Compiling & Running the App

Once you have arranged all your files, open your terminal, navigate into the root directory of your project, and run the compilation commands.

Navigate to the root directory:

cd ironvault-admin


Build and execute the desktop application:

cargo run -p ironvault-ui


Note: The first time you run this command, Rust will download the required UI frameworks, compilers, and cryptographic drivers. This may take a few minutes. Subsquent compiles will run instantly in under two seconds.

Part 4: Testing the Secure Signature Features

Once the beautiful dark-themed interface loads:

Click on the Operations Console tab in the sidebar.

Click Initialize Export on the "Oracle 19c Data Pump" card.

The Supervisor Dual-Authorization Gate overlay will block the interface and ask for a private key.

Paste the following Test Cryptographic Private Key into the input field:

0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef


Click Verify & Approve.

The status banner at the top of the application will instantly change to a bright green success banner:
"TRANSACTION AUTHORIZED // SIGNATURE CHAIN SECURELY COMMITTED"

If you enter an invalid or short key, the dashboard will display a red error message indicating validation failed, safeguarding the execution path.