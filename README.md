# OTP Toolbox

Store your TOTP secrete and generate the code with one command.

Like Google Authenticator or other Apps, but within VS Code.

## Features

First, store the OTP key, e.g. `othauth://...`, with `OTP Toolbox: Add Key` command.
The OTP key are usually given as a QR Code, find a QR Code scanner if necessary.

Once some OTP key is stored, we can get the one time password with `OTP Toolbox: Get Token` command.
The token will be send the the clipboard automatically and be shown through a information box.

For removing stored secrets, use `OTP Toolbox: Clear Keys`.

## Security Details

On first launch of this extension, a random master key is generated.

All stored OTP secrets is encrypted with this master key before saving into the disks.

The master key is protected in a OS-dependent way. And for remote VS Code session,
the secrete is stored in local OS.

- [Secrets API · Issue #112249 · microsoft/vscode](https://github.com/microsoft/vscode/issues/112249)
- [Supporting Remote Development and GitHub Codespaces | Visual Studio Code Extension API](https://code.visualstudio.com/api/advanced-topics/remote-extensions#persisting-secrets)

## Extension Settings

Currently no setting available to this extension.

## Release Notes

### 0.1.0

User can add TOTP key and generate token from key.

