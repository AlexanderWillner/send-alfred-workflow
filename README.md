# Send via ffsend - Alfred Workflow

Alfred workflow to upload files to any [ffsend](https://github.com/timvisee/send)/[send](https://github.com/mozilla/send) server with end-to-end encryption.

## Features

- E2E encrypted file uploads via the Firefox Send protocol
- Works with any compatible send server (timvisee/send, mozilla/send, etc.)
- Configurable server URL, download limits
- File Action and Universal Action support
- Copies shareable link to clipboard
- Shows notification on completion

## Requirements

- macOS with Alfred 4+
- [uv](https://docs.astral.sh/uv/) (Python package manager)
- Python 3.11+
- A running send/ffsend server

## Configuration

Environment variables (set in workflow's script or system):

| Variable | Default | Description |
|----------|---------|-------------|
| `SEND_SERVER` | `https://send.willner.ws` | Send server URL |
| `SEND_DLIMIT` | `3` | Max download count |

## Installation

```bash
just install
```

Or manually:
1. Build: `just build`
2. Double-click `Send via ffsend.alfredworkflow` to import into Alfred

## Usage

- Right-click any file in Finder → **Send via ffsend**
- Or use Alfred's Universal Action on a file
- The encrypted share link is copied to your clipboard

## Encryption

Uses the send-v1 protocol (RFC 8188 ECE with AES-128-GCM):

1. Random 128-bit secret key generated per upload
2. File encrypted with ECE (Encrypted Content-Encoding)
3. Metadata encrypted with AES-GCM
4. Authentication via HMAC-SHA256 (HKDF-derived keys)
5. Secret encoded as URL fragment (never sent to server)

## Architecture

```
upload.py
  ├── hkdf_derive()          HKDF-SHA256 key derivation
  ├── ece_encrypt()          RFC 8188 encrypted content encoding
  ├── encrypt_metadata()      AES-GCM metadata encryption
  └── upload_file()          HTTP upload + params
```

Key derivation matches the timvisee/send browser client:
- `meta_key`: HKDF(secret, salt=empty, info="metadata", length=16)
- `auth_key`: HKDF(secret, salt=empty, info="authentication", length=64)
- `ece_key/nonce`: HKDF(secret, salt=random, info="Content-Encoding: ...")

## License

MIT
