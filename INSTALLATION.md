# PasswordOut Windows Development Installation

This guide prepares a new 64-bit Windows development machine to build and run PasswordOut using the **MSYS2 UCRT64** environment and Rust's **GNU Windows toolchain**.

## 1. Install MSYS2

Install MSYS2 in its default location:

```text
C:\msys64
```

After installation, open **MSYS2 UCRT64** from the Windows Start menu.

Do not use the plain **MSYS**, **MINGW32**, **MINGW64**, **CLANG64**, or **CLANGARM64** shell for these instructions. The prompt should contain:

```text
UCRT64
```

## 2. Update MSYS2

In the UCRT64 terminal, update the package database and installed packages:

```bash
pacman -Syu
```

If MSYS2 tells you to close the terminal, close it, reopen **MSYS2 UCRT64**, and run:

```bash
pacman -Syu
```

Repeat until no additional core update or terminal restart is requested.

## 3. Install the build dependencies

Install Git, GNU Make, Perl, the UCRT64 compiler toolchain, OpenSSL, pkg-config support, and common build utilities:

```bash
pacman -S --needed \
  git \
  make \
  perl \
  base-devel \
  mingw-w64-ucrt-x86_64-toolchain \
  mingw-w64-ucrt-x86_64-openssl \
  mingw-w64-ucrt-x86_64-pkgconf
```

When `pacman` asks which members of the UCRT64 toolchain group to install, press **Enter** to install all of them.

The separate MSYS `make` package is required because Rust's vendored OpenSSL build invokes a command named `make`. The UCRT64 package `mingw-w64-ucrt-x86_64-make` normally provides `mingw32-make`, which does not satisfy that command by itself.

Verify the tools:

```bash
git --version
make --version
perl --version
gcc --version
pkg-config --version
```

The expected compiler path should begin with `/ucrt64/bin`:

```bash
which gcc
```

Expected:

```text
/ucrt64/bin/gcc
```

GNU Make normally resolves from:

```bash
which make
```

Expected:

```text
/usr/bin/make
```

## 4. Install Rust with rustup

PasswordOut is built for:

```text
x86_64-pc-windows-gnu
```

Download and run the official Windows rustup installer:

```bash
curl.exe --proto '=https' --tlsv1.2 -sSf \
  https://win.rustup.rs/x86_64 \
  -o /tmp/rustup-init.exe

/tmp/rustup-init.exe -y \
  --default-host x86_64-pc-windows-gnu \
  --default-toolchain stable \
  --profile default
```

Close and reopen the **MSYS2 UCRT64** terminal after installation.

Make Cargo available in the current shell:

```bash
export PATH="$HOME/.cargo/bin:$PATH"
```

To make that permanent:

```bash
printf '\nexport PATH="$HOME/.cargo/bin:$PATH"\n' \
   ~/.bashrc

source ~/.bashrc
```

Verify the installation:

```bash
rustup show
rustc --version
cargo --version
rustdoc --version
```

Confirm the active host toolchain:

```bash
rustc -vV
```

The output should include:

```text
host: x86_64-pc-windows-gnu
```

If another Rust host is active, install and select the GNU host explicitly:

```bash
rustup toolchain install stable-x86_64-pc-windows-gnu

rustup default stable-x86_64-pc-windows-gnu
```

## 5. Configure Git

Set the developer identity used for commits:

```bash
git config --global user.name "Your Name"

git config --global user.email "your.email@example.com"
```

Use Unix-style line endings in the repository:

```bash
git config --global core.autocrlf input
```

Optional defaults:

```bash
git config --global init.defaultBranch main
git config --global pull.ff only
```

## 6. Clone PasswordOut

Choose a workspace under the MSYS2 home directory:

```bash
mkdir -p ~/work

cd ~/work
```

Clone the repository:

```bash
git clone https://github.com/tobymoreno/password-out.git

cd password-out
```

For SSH access:

```bash
git clone git@github.com:tobymoreno/password-out.git

cd password-out
```

Verify the repository and branch:

```bash
git remote -v
git branch --show-current
```

To work on an existing feature branch:

```bash
git fetch origin

git switch vault-timeout

git pull --ff-only
```

## 7. Verify the Windows GNU build environment

Run:

```bash
printf 'MSYSTEM=%s\n' "$MSYSTEM"
printf 'PATH=%s\n' "$PATH"

which cargo
which rustc
which gcc
which make
which perl
```

Expected values include:

```text
MSYSTEM=UCRT64
```

Typical paths:

```text
/home/<user/.cargo/bin/cargo
/home/<user/.cargo/bin/rustc
/ucrt64/bin/gcc
/usr/bin/make
/usr/bin/perl
```

Confirm that Cargo is using the GNU Windows toolchain:

```bash
rustc -vV | grep '^host:'
```

Expected:

```text
host: x86_64-pc-windows-gnu
```

## 8. Build PasswordOut

From the repository root:

```bash
cargo build
```

 **First Windows build:** PasswordOut uses a vendored OpenSSL build for software-certificate and PFX support. The first `cargo build` may spend several minutes compiling native OpenSSL code and can appear paused at `openssl-sys`.

 This is normal as long as `make`, `gcc.exe`, `cc1.exe`, or `cargo.exe` remains active. Later builds are much faster because Cargo caches the compiled OpenSSL artifacts.

 To monitor the native build from another MSYS2 UCRT64 terminal:

 ```bash
 watch -n 2 \
   "ps -ef | grep -E '[m]ake build_libs|[m]ake _build_libs|[g]cc.exe|[c]c1.exe|[c]argo.exe'"
 ```

 Install `watch` when needed:

 ```bash
 pacman -S --needed procps-ng
 ```

Avoid running `cargo clean` unless necessary because it removes the cached OpenSSL build and forces it to compile again.

Build an optimized executable:

```bash
cargo build --release
```

The debug executable is created at:

```text
target/x86_64-pc-windows-gnu/debug/password-out.exe
```

Depending on the active Cargo target configuration, it may instead be located at:

```text
target/debug/password-out.exe
```

The release executable is created at:

```text
target/x86_64-pc-windows-gnu/release/password-out.exe
```

or:

```text
target/release/password-out.exe
```

Locate it with:

```bash
find target \
  -type f \
  -name 'password-out.exe' \
  -print
```

## 9. Run the test suite

Format and test the project:

```bash
cargo fmt --check
cargo test
```

Apply formatting automatically when needed:

```bash
cargo fmt
```

Run Clippy when the component is installed:

```bash
rustup component add clippy

cargo clippy --all-targets --all-features -- \
  -D warnings
```

## 10. Run PasswordOut

Display command help:

```bash
cargo run -- --help
```

Initialize a vault:

```bash
cargo run -- vault init
```

Display vault metadata:

```bash
cargo run -- vault info
```

Configure the encrypted clipboard timeout:

```bash
cargo run -- vault timeout
```

Add an entry:

```bash
cargo run -- entry add
```

List entries:

```bash
cargo run -- entry list
```

Start the global hotkey listener:

```bash
cargo run -- --listen
```

Override the vault timeout for one listener session:

```bash
cargo run -- --listen --clear-seconds 5
```

Test the internal countdown overlay directly:

```bash
cargo run -- --countdown 5
```

Stop the listener with:

```text
Ctrl+C
```

## 11. Smart-card requirements

PasswordOut uses the native Windows Smart Card API through `winscard.dll`. No MSYS2 PC/SC package is normally required on Windows.

For CAC/PIV testing:

1. Connect a Windows-compatible USB smart-card reader.
2. Confirm the reader appears in **Device Manager**.
3. Ensure the Windows **Smart Card** service is running.
4. Insert the CAC/PIV card before running a CAC-backed vault command.

Check the Smart Card service from PowerShell:

```powershell
Get-Service SCardSvr
```

Start it when necessary:

```powershell
Start-Service SCardSvr
```

Starting a Windows service may require administrator privileges.

## 12. Runtime DLL inspection

Inspect the release executable's imported Windows DLLs:

```bash
x86_64-w64-mingw32-objdump -p \
  target/x86_64-pc-windows-gnu/release/password-out.exe |
grep 'DLL Name'
```

Most dependencies should be Windows system DLLs. If a UCRT64 runtime DLL is required, locate it with:

```bash
find /ucrt64/bin \
  -maxdepth 1 \
  -type f \
  -name '*.dll' \
  -print
```

Do not copy every UCRT64 DLL beside the executable. Copy only DLLs that the executable actually imports and that are not supplied by Windows.

## 13. Common build failures

### `Command 'make' not found`

Install the MSYS GNU Make package:

```bash
pacman -S --needed make
```

Verify:

```bash
which make
make --version
```

Then remove the incomplete dependency build and retry:

```bash
cargo clean
cargo build
```

### `linker 'cc' not found` or `gcc: command not found`

Confirm that the UCRT64 compiler toolchain is installed:

```bash
pacman -S --needed \
  mingw-w64-ucrt-x86_64-toolchain
```

Confirm that the terminal is **MSYS2 UCRT64**:

```bash
echo "$MSYSTEM"
which gcc
```

Expected:

```text
UCRT64
/ucrt64/bin/gcc
```

### Rust is using the MSVC host

Check:

```bash
rustc -vV | grep '^host:'
```

Switch to the GNU host:

```bash
rustup toolchain install stable-x86_64-pc-windows-gnu

rustup default stable-x86_64-pc-windows-gnu
```

Then clean and rebuild:

```bash
cargo clean
cargo build
```

### OpenSSL cannot be found

PasswordOut currently supports a vendored OpenSSL build, which needs Perl, Make, and the compiler toolchain:

```bash
pacman -S --needed \
  make \
  perl \
  mingw-w64-ucrt-x86_64-toolchain
```

The UCRT64 OpenSSL and pkg-config packages are also recommended:

```bash
pacman -S --needed \
  mingw-w64-ucrt-x86_64-openssl \
  mingw-w64-ucrt-x86_64-pkgconf
```

Verify:

```bash
pkg-config --modversion openssl
```

If an incomplete vendored build is cached:

```bash
cargo clean
cargo build
```

### `cargo`, `rustc`, or `rustup` is not found

Add Cargo's bin directory to the shell:

```bash
export PATH="$HOME/.cargo/bin:$PATH"
```

Persist it:

```bash
printf '\nexport PATH="$HOME/.cargo/bin:$PATH"\n' \
   ~/.bashrc

source ~/.bashrc
```

### The wrong repository is being built

Check:

```bash
pwd
git remote -v
git branch --show-current
```

The repository directory should be `password-out`, not `credchord`, unless intentionally building the separate CredChord project.

### Rebuild from a clean state

Use:

```bash
cargo clean
cargo build
cargo test
```

## 14. One-command dependency installation

After opening **MSYS2 UCRT64** and completing the initial `pacman -Syu` update cycle:

```bash
pacman -S --needed \
  git \
  make \
  perl \
  base-devel \
  mingw-w64-ucrt-x86_64-toolchain \
  mingw-w64-ucrt-x86_64-openssl \
  mingw-w64-ucrt-x86_64-pkgconf
```

Then install Rust:

```bash
curl.exe --proto '=https' --tlsv1.2 -sSf \
  https://win.rustup.rs/x86_64 \
  -o /tmp/rustup-init.exe

/tmp/rustup-init.exe -y \
  --default-host x86_64-pc-windows-gnu \
  --default-toolchain stable \
  --profile default
```

Reopen **MSYS2 UCRT64**, clone the project, and build:

```bash
export PATH="$HOME/.cargo/bin:$PATH"

mkdir -p ~/work
cd ~/work

git clone https://github.com/tobymoreno/password-out.git
cd password-out

cargo build
cargo test
```
