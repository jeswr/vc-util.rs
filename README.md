# vc-utils

A Rust library for cryptographic utilities, focusing on Ed25519 signature validation and verification.

## Features

- Ed25519 signature validation
- Ed25519 signature verification
- Support for various cryptographic operations

## Installation

Add this to your `Cargo.toml`:

```toml
[dependencies]
vc-utils = "0.1.0"
```

## Usage

```rust
use vc_utils::ed25519_verify;

// Example usage will be added as the library matures
```

## Dependencies

- ecdsa = "0.16.9"
- serde = { version = "1.0", features = ["derive"] }
- serde_json = "1.0"
- sha2 = "0.10"
- bs58 = "0.5"
- ed25519-dalek = "2.1"
- hex = "0.4"

## Development

### Prerequisites

- Rust 2021 edition or later
- Cargo

### Building

```bash
cargo build
```

### Testing

```bash
cargo test
```

### Linting

```bash
cargo clippy
```

## License

This project is licensed under the MIT License - see the LICENSE file for details.
