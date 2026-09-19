# tempkeys

Keep a **temporary keyset** on a Linux machine: send in a full set of secrets,
use them for a while, and have them become unrecoverable on their own.

Each secret is stored as its own encrypted file. The only thing the kernel holds
is the random encryption key, in the [Linux kernel keyring][keyrings]. When the
machine reboots or you `clear` the keyset, the files can no longer be decrypted
and are deleted. Keys don't expire by default; pass `--ttl` to have the kernel
expire the key on a timer too.

```console
$ pass show myenv | tempkeys load
loaded 2 keys into "default", no expiry
$ echo ghp_xxx | tempkeys set GH_TOKEN      # add or replace one key
set GH_TOKEN in "default"
$ tempkeys list
default   3 keys   no expiry
$ tempkeys get API_TOKEN
hunter2
$ tempkeys run -e GH_TOKEN=github_token -- gh pr list
tempkeys: populating GH_TOKEN=github_token
$ tempkeys clear
```

[keyrings]: https://man7.org/linux/man-pages/man7/keyrings.7.html

## What Linux provides, and what tempkeys adds

The hard part already exists in Linux: the [kernel key retention
service][kernel-keys]. It holds secrets in kernel memory rather than on disk,
checks per-key permissions and possession, expires keys on a timer, garbage
collects them, and lets a process family share a private session keyring across
`fork` and `exec`. `keyctl` exposes it. tempkeys doesn't reimplement any of that;
it calls the same syscalls (and the kernel's CSPRNG for keys and nonces).

What the raw keyring leaves to you, and what tempkeys does about it:

| With plain `keyctl` | With tempkeys |
| --- | --- |
| A `user` key holds at most 32 KB, and non-root users get about 200 keys and 20 KB in total (`/proc/sys/kernel/keys/`) | The kernel holds one 32-byte key per keyset. Secrets are encrypted files of any size and number |
| A key is a single opaque payload; there is no "set of secrets" | A keyset is loaded, replaced, merged into (`load --merge`) or edited (`set`) as a unit, and swapped in atomically, so readers never see half of it |
| Nothing ties stored data to the key's lifetime | When the key expires, is cleared, or the machine reboots, the files are unreadable and pruned, so nothing lingers on disk |
| Data is only as safe as the permissions on it | Files are XChaCha20-Poly1305 with the keyset and key names and the expiry authenticated: swapped, moved, edited or re-dated files fail to decrypt |
| A private per-process-family keyring is a manual recipe: join a session, set permissions, add keys, `exec` | `tempkeys session` does it in the safe order: permissions are set before any key goes in, members get no right to widen access, and `--session` can't fall into your login's shared keyring |
| You choose between `@u` and `@s` for every call | Inside a session, reads look in the session scope first and fall back to the user scope per keyset, and writes go to the session; `--user` and `--session` override |
| Getting a secret to a program means `keyctl search`, `keyctl pipe`, and your own plumbing | `get KEY`, or `run -e GH_TOKEN=github_token -- cmd`, which reports which variables it populated, names only |
| Needs `keyutils` installed | A single binary; no `keyctl` or `libkeyutils` |

tempkeys adds no new trust boundary. The kernel still decides who can fetch the
key (see [what this does and doesn't protect against](#what-this-does-and-doesnt-protect-against)),
so the protection is exactly the keyring's: same-UID processes in the user
scope, one process family in the session scope.

[kernel-keys]: https://docs.kernel.org/security/keys/core.html

## Install

Linux only, with kernel keyring support (`CONFIG_KEYS`, on in mainstream
distributions). No `keyctl` or `libkeyutils` needed: tempkeys calls the syscalls
directly.

```console
$ cargo install --git https://github.com/vivainio/tempkeys
```

## Platforms

Linux, including WSL2 (developed and tested on WSL2, whose kernel has keyring
support). There is no native Windows or macOS support: tempkeys depends on an
in-kernel keyring with timeouts and per-process-family sessions, which those
systems don't have. The keyring calls are isolated in `src/sys.rs`, so a port
would replace that layer rather than rewrite the rest.

## Commands

| Command | What it does |
| --- | --- |
| `load [--set NAME] [--ttl DUR] [--merge]` | Replace a keyset with the full set read from stdin, or add to it with `--merge` |
| `set [--set NAME] [--ttl DUR] [--raw] KEY` | Add or replace one key, value from stdin |
| `get [--set NAME] KEY` | Decrypt and print one key's raw value |
| `list [--set NAME]` | List keysets, or key names in one (never values) |
| `run [--set NAME] [-e VAR=KEY]... -- CMD...` | Run a command with keys as environment variables |
| `clear [--set NAME \| --all]` | Delete a keyset and its encryption key now |
| `session [--set NAME] [--ttl DUR] [-- CMD...]` | Start a command in a private session keyring (see below) |

`load` reads dotenv lines (`KEY=VALUE`, `#` comments, optional `export`, one
pair of surrounding quotes stripped) or a JSON object of strings. Key names must
be valid environment variable names. Loading is all-or-nothing, and replaces the
whole keyset: keys missing from the new input are gone. With `--merge` the input
is added to the existing keyset instead: keys in the input are added or
replaced, and every other key stays. A merge keeps the keyset's encryption key
and expiry, so `--ttl` is rejected for an existing keyset; if the keyset doesn't
exist yet, `--merge` behaves like a normal load. Secrets are only ever
read from stdin, never from arguments. Empty values are rejected.

`run` lists the variables it populates on stderr (names only, never values):
`VAR=KEY` when a variable takes its value from a differently named key, or just
`VAR` when the names match. With `-e VAR=KEY` (repeatable; `-e VAR` means
`VAR=VAR`) only the variables you name are populated, so the command sees
nothing else from the keyset. Without `-e`, every key is injected under its own
name. A missing key fails before the command starts. `-q` silences the listing.

`set` adds or replaces a single key without touching the rest. In an existing
keyset the new file is encrypted under the keyset's current key and keeps its
expiry. If the keyset doesn't exist it is created, and `--ttl` applies only then
(use `load` to change an existing keyset's expiry). The value comes from stdin,
or from a no-echo prompt on a terminal, never from arguments. One trailing
newline is dropped so `echo token | tempkeys set KEY` stores `token`; `--raw`
keeps the bytes exactly.

The default keyset name is `default`. There is no expiry unless you pass
`--ttl` (`90s`, `15m`, `8h`, `2d`): the kernel then expires the key on that
timer, and the files are deleted once it does. Without one, the keyset lasts
until you `clear` it, the machine reboots, or (in session mode) the process
family exits.

## How it works

```text
<dir>/user/default/API_TOKEN.enc     one XChaCha20-Poly1305 file per secret
<dir>/user/default/DB_PASS.enc

kernel @u:  tempkeys:key:default:<generation>   32-byte key (optional timeout)
```

`<dir>` follows the [XDG Base Directory spec][xdg]: `$XDG_RUNTIME_DIR/tempkeys`
(tmpfs, cleared at logout) when that directory is usable (absolute, owned by you,
mode `0700`), else `$XDG_CACHE_HOME/tempkeys`, else `~/.cache/tempkeys`. Files are
mode `0600` in `0700` directories. User keysets live in `<dir>/user/`, and each
session's in `<dir>/session-<keyring id>/`.

[xdg]: https://specifications.freedesktop.org/basedir-spec/latest/

**File format.** `"TKY1" | generation (16) | expiry (8) | nonce (24) | ciphertext+tag`.
The header is cleartext so readers can find the right key and prune expired
files, but it is authenticated: the associated data is the header plus the
keyset and key names. A file can't be swapped with another key's file, moved to
another keyset, or have its expiry extended without decryption failing.

**Loading.** Each `load` (without `--merge`) generates a fresh random key, stores it in the kernel
keyring, writes the new files to a temporary directory, and swaps that directory
in, so readers never see a half-written keyset. Older keys for that keyset are
then revoked. Bad input leaves the current keyset untouched.

**Expiry.** The kernel enforces the key's timeout. Files whose expiry has passed,
whose key is gone, or that belong to a dead session are deleted by the next
`tempkeys` command. Undecryptable files are useless in the meantime.

**Permissions.** The kernel key is owner-only (`0x003f0000`): possessor, group
and other get nothing.

## Session mode

By default the key lives in your user keyring (`@u`), which every process
running as your UID can use. For tighter scoping, `session` puts the key in a
private session keyring that only one process family can use:

```console
$ pass show myenv | tempkeys session --ttl 8h -- ./myapp
$ tempkeys session                       # a shell with an empty private session
$ tempkeys load                          #   ...load into the session, not @u
$ tempkeys get API_TOKEN                 #   ...and read it back
```

`session` joins a fresh anonymous session keyring, gives it possessor-only
permissions before any key goes in, and `exec`s the command, which inherits it.
If stdin is piped, the keyset is read from it and loaded with its key in the
session keyring; nothing touches `@u`, and a command is then required because
stdin is used up. Session members can add and remove keys but can't change
permissions. The session scope exists only inside a session that tempkeys
created, so secrets can't land in your login's shared session keyring by mistake.

The keyset lasts as long as the process family, or the TTL, whichever ends first.

### Which scope does a command use?

Outside a session everything uses the user scope. Inside one:

| Commands | Default | Override |
| --- | --- | --- |
| `get`, `run`, `list -s NAME` | the session scope first, then the user scope | `--session` or `--user` restricts to one |
| `load`, `set`, `clear` | the session scope only | `--user` writes to the user scope |
| `list` | both scopes, labelled | `--session` or `--user` restricts to one |

The fallback is **per keyset**: if the session scope has a keyset called
`default`, that keyset is used whole, and a key missing from it is an error
rather than being taken from the user scope's `default`. `run` says where its
values came from, for example `populating GH_TOKEN=github_token (from session
keyset "default")`, so a fallback can't go unnoticed. Files for the two scopes
live in separate directories and their keys in separate keyrings, so the same
keyset name in both never mixes.

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
  read into memory. Best-effort zeroing is done on tempkeys's own buffers only.

## Limits

- **Values are raw bytes**: files hold the exact payload, any size, and `get`
  returns it unchanged. `set --raw KEY < cert.der` stores binary data. `load`
  is text-only (UTF-8 dotenv or JSON), and `run` can't inject a value containing
  a NUL byte, since environment variables can't hold one.
- Non-root users have kernel key quotas (`/proc/sys/kernel/keys/maxkeys` and
  `maxbytes`). tempkeys stores one 32-byte key per keyset, so this is rarely an
  issue.

## Background

Design notes on kernel keyrings, ownership vs. possession, session and user
keyrings: [Linux kernel keyrings](https://github.com/vivainio/sw-plumber-book/blob/main/docs/security/linux-keyrings.md).

## Development

```console
$ cargo test
```
