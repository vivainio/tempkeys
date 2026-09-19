# ziiring

Keep a **temporary keyset** on a Linux machine: send in a full set of secrets,
use them for a while, and have them become unrecoverable on their own.

Each secret is stored as its own encrypted file. The only thing the kernel holds
is the random encryption key, in the [Linux kernel keyring][keyrings], with a
timeout. When the key expires, is cleared, or the machine reboots, the files can
no longer be decrypted and are deleted.

```console
$ pass show myenv | ziiring load --ttl 8h
loaded 2 keys into "default", expires in 8h
$ ziiring list
default   2 keys   expires in 7h
$ ziiring get API_TOKEN
hunter2
$ ziiring run -e GH_TOKEN=github_token -- gh pr list
ziiring: populating GH_TOKEN=github_token
$ ziiring clear                 # or just wait
```

[keyrings]: https://man7.org/linux/man-pages/man7/keyrings.7.html

## Install

Linux only, with kernel keyring support (`CONFIG_KEYS`, on in mainstream
distributions). No `keyctl` or `libkeyutils` needed: ziiring calls the syscalls
directly.

```console
$ cargo install --git https://github.com/vivainio/ziiring
```

## Commands

| Command | What it does |
| --- | --- |
| `load [--set NAME] [--ttl 1h]` | Replace a keyset with the full set read from stdin |
| `get [--set NAME] KEY` | Decrypt and print one key's raw value |
| `list [--set NAME]` | List keysets, or key names in one (never values) |
| `run [--set NAME] [-e VAR=KEY]... -- CMD...` | Run a command with keys as environment variables |
| `clear [--set NAME \| --all]` | Delete a keyset and its encryption key now |
| `session [--set NAME] [--ttl 1h] [-- CMD...]` | Start a command in a private session keyring (see below) |

`load` reads dotenv lines (`KEY=VALUE`, `#` comments, optional `export`, one
pair of surrounding quotes stripped) or a JSON object of strings. Key names must
be valid environment variable names. Loading is all-or-nothing, and replaces the
whole keyset: keys missing from the new input are gone. Secrets are only ever
read from stdin, never from arguments. Empty values are rejected.

`run` lists the variables it populates on stderr (names only, never values):
`VAR=KEY` when a variable takes its value from a differently named key, or just
`VAR` when the names match. With `-e VAR=KEY` (repeatable; `-e VAR` means
`VAR=VAR`) only the variables you name are populated, so the command sees
nothing else from the keyset. Without `-e`, every key is injected under its own
name. A missing key fails before the command starts. `-q` silences the listing.

The default keyset name is `default`, and the default TTL is one hour (`90s`,
`15m`, `8h`, `2d`).

## How it works

```text
<dir>/user/default/API_TOKEN.enc     one XChaCha20-Poly1305 file per secret
<dir>/user/default/DB_PASS.enc

kernel @u:  ziiring:key:default:<generation>   32-byte key, with a timeout
```

`<dir>` is `$ZIIRING_DIR`, else `$XDG_RUNTIME_DIR/ziiring`, else
`~/.cache/ziiring`. Files are mode `0600` in `0700` directories.

**File format.** `"ZIR1" | generation (16) | expiry (8) | nonce (24) | ciphertext+tag`.
The header is cleartext so readers can find the right key and prune expired
files, but it is authenticated: the associated data is the header plus the
keyset and key names. A file can't be swapped with another key's file, moved to
another keyset, or have its expiry extended without decryption failing.

**Loading.** Each `load` generates a fresh random key, stores it in the kernel
keyring, writes the new files to a temporary directory, and swaps that directory
in, so readers never see a half-written keyset. Older keys for that keyset are
then revoked. Bad input leaves the current keyset untouched.

**Expiry.** The kernel enforces the key's timeout. Files whose expiry has passed,
whose key is gone, or that belong to a dead session are deleted by the next
`ziiring` command. Undecryptable files are useless in the meantime.

**Permissions.** The kernel key is owner-only (`0x003f0000`): possessor, group
and other get nothing.

## Session mode

By default the key lives in your user keyring (`@u`), which every process
running as your UID can use. For tighter scoping, `session` puts the key in a
private session keyring that only one process family can use:

```console
$ pass show myenv | ziiring session --ttl 8h -- ./myapp
$ ziiring session                       # a shell with an empty private session
$ ziiring --session load                #   ...load into it from inside
$ ziiring --session get API_TOKEN       #   ...and read it back
```

`session` joins a fresh anonymous session keyring, gives it possessor-only
permissions before any key goes in, and `exec`s the command, which inherits it.
If stdin is piped, the keyset is read from it and loaded with its key in the
session keyring; nothing touches `@u`, and a command is then required because
stdin is used up. Session members can add and remove keys but can't change
permissions. `--session` works only inside a session that ziiring created, so
secrets can't land in your login's shared session keyring by mistake.

The keyset lasts as long as the process family, or the TTL, whichever ends first.

## What this does and doesn't protect against

- **Protects:** the files at rest (disk, backups, other users, after reboot or
  expiry). Plaintext is never written to disk.
- **Session mode** additionally hides the key from unrelated processes running
  as you: a process outside the session that knows the key's numeric ID still
  gets `Permission denied`.
- **Default `@u` mode trusts every program running as your UID.** They can fetch
  the key and read the files. Use `session` when that isn't acceptable.
- **`run` puts secrets in environment variables**, which same-UID processes can
  read from `/proc/PID/environ` and which grandchildren inherit. Prefer `get`
  when the application can call it.
- **Root** can read anything, and ptrace-based inspection of a process that has
  decrypted a secret is out of scope. A revoked key can't erase copies already
  read into memory. Best-effort zeroing is done on ziiring's own buffers only.

## Limits

- Input is UTF-8 text (dotenv or JSON). The file format handles arbitrary bytes,
  but there is no way to load binary files (certificates, keys) yet.
- Non-root users have kernel key quotas (`/proc/sys/kernel/keys/maxkeys` and
  `maxbytes`). ziiring stores one 32-byte key per keyset, so this is rarely an
  issue.

## Background

Design notes on kernel keyrings, ownership vs. possession, session and user
keyrings: [Linux kernel keyrings](https://github.com/vivainio/sw-plumber-book/blob/main/docs/security/linux-keyrings.md).

## Development

```console
$ cargo test
```
