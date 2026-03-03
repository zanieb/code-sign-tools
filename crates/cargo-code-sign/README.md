# cargo-code-sign

A Cargo subcommand that automatically signs binaries after building.

## Usage

```sh
cargo install cargo-code-sign
cargo code-sign build --release
```

Or, wrap Cargo:

```sh
CARGO=cargo-code-sign
cargo build --release
```

## Signing identities

See the [`native-code-sign`](../native-code-sign/) configuration for [macOS](../native-code-sign/README.md#macos) and [Windows](../native-code-sign/README.md#windows).

No signing is performed on Linux — using `cargo code-sign` is a no-op.

### Configuration

- `CARGO_CODE_SIGN_TEST_BINARIES`: Set to `1` to also sign test binaries (default: disabled)
- `CARGO_CODE_SIGN_CARGO`: Path to the inner `cargo` command (see [Nested cargo wrappers](#nested-cargo-wrappers); default: `CARGO` env var, then `cargo`)

## Cross-compiles

Code signing is not supported during cross-compiles, as we require native tools to perform code
signing.

## Target files

Executable and library artifacts are signed by default. This does not include internal artifacts like
proc macros or build scripts.

Test binaries are not signed by default, but can be enabled with `CARGO_CODE_SIGN_TEST_BINARIES=1`.

## Nested cargo wrappers

When nesting multiple cargo wrappers, the `CARGO_CODE_SIGN_CARGO` variable can be used to configure
the inner `cargo` command invoked by `cargo-code-sign` as `cargo` will update the `CARGO` variable.
