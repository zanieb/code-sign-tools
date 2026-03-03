# code-sign-tools

A collection of Rust crates for code signing

- [`cargo-code-sign`](crates/cargo-code-sign/): A Cargo subcommand that automatically signs binaries after building
- [`native-code-sign`](crates/native-code-sign/): Code signing wrappers using platform-native signing tools

## Acknowledgements

The `cargo` wrapper approach was inspired by [`cargo-auditable`](https://github.com/rust-secure-code/cargo-auditable).

The signing implementation was informed by patterns in
[`cargo-dist`](https://github.com/axodotdev/cargo-dist),
[`tauri-macos-sign`](https://github.com/tauri-apps/tauri/tree/dev/crates/tauri-macos-sign), and
[`tauri-bundler`](https://github.com/tauri-apps/tauri/tree/dev/crates/tauri-bundler).

## License

code-sign-tools is licensed under either of

- Apache License, Version 2.0, ([LICENSE-APACHE](LICENSE-APACHE) or
  <https://www.apache.org/licenses/LICENSE-2.0>)
- MIT license ([LICENSE-MIT](LICENSE-MIT) or <https://opensource.org/licenses/MIT>)

at your option.

Unless you explicitly state otherwise, any contribution intentionally submitted for inclusion in
code-sign-tools by you, as defined in the Apache-2.0 license, shall be dually licensed as above,
without any additional terms or conditions.
