# native-code-sign

Code signing wrappers using platform-native signing tools.

## macOS

Uses Apple's `codesign` tool.

Set the following environment variables:

- `CODESIGN_IDENTITY`: signing identity (e.g. "Developer ID Application: ...")
- `CODESIGN_CERTIFICATE`: base64-encoded .p12 certificate
- `CODESIGN_CERTIFICATE_PASSWORD`: password for the .p12
- `CODESIGN_OPTIONS`: (optional) extra `--options` value (e.g. `runtime` for hardened runtime / notarization)

An ephemeral keychain is used to store the certificate, temporarily modifying the keychain search
list. This modification is robust to concurrent `cargo-code-sign` invocations, but not to other
programs modifying the keychain search list.

## Windows

Uses Microsoft `signtool.exe`.

Set the following environment variables:

- `SIGNTOOL_CERTIFICATE_PATH`: path to a .pfx certificate file
- `SIGNTOOL_CERTIFICATE_PASSWORD`: password for the .pfx
- `SIGNTOOL_TIMESTAMP_URL`: (optional) RFC 3161 timestamp server URL
- `SIGNTOOL_DESCRIPTION`: (optional) description shown in UAC prompts (signtool `/d` flag)
- `SIGNTOOL_PATH`: (optional) path to signtool.exe (defaults to `signtool.exe` from `PATH`)
