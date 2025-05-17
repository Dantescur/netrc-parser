# netrc-rs

A Rust library for parsing and manipulating `.netrc` files.

`netrc-rs` provides a modern, idiomatic parser for `.netrc` files, supporting machine entries, login credentials, accounts, and macro definitions (`macdef`). It includes serialization to JSON and TOML, file I/O, and comprehensive error handling.

## Installation

Add to your `Cargo.toml`:

```toml
[dependencies]
netrc-rs = "0.1.0"
```

## Usage

Parse a `.netrc` file and retrieve credentials:

```rust
use netrc_rs::{Netrc, NetrcError};

fn main() -> Result<(), NetrcError> {
    let path = dirs::home_dir()
        .ok_or_else(|| NetrcError::FileNotFound("Home directory not found".to_string()))?
        .join(".netrc");
    let netrc = Netrc::parse_from_path(&path)?;
    if let Some(creds) = netrc.get("surge.surge.sh") {
        println!("Login: {}, Password: {}", creds.login, creds.password);
    }
    Ok(())
}
```

### Run the example

```sh
cargo run --example simple
```

## Documentation

Run `cargo doc --open` to view the API documentation.

## Development

### Format code with rustfmt nightly

```sh
rustup toolchain install nightly
rustup component add rustfmt --toolchain nightly
cargo +nightly fmt
```

## License

Licensed under the MIT. See [LICENSE](./LICENSE) for details.

## Contributing

Contributions are welcome! Please open a issue or pull request on [Github](https://github.com/dantescur/netrc-rs)
