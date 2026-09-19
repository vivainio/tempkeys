mod parse;
mod sys;
mod vault;

use std::ffi::OsStr;
use std::fs;
use std::io::{self, IsTerminal, Read, Write};
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::{DirBuilderExt, MetadataExt, OpenOptionsExt};
use std::os::unix::process::CommandExt;
use std::path::{Path, PathBuf};
use std::process::{Command, ExitCode};
use std::time::{SystemTime, UNIX_EPOCH};

use clap::{Args, Parser, Subcommand};

use sys::{KeyId, Secret};

const KEY_PREFIX: &str = "tempkeys:key:";
const SESSION_MARKER: &str = "tempkeys:session";
const EXT: &str = ".enc";

/// Keep a temporary keyset as encrypted files, with the key in the kernel keyring.
///
/// Each secret is its own XChaCha20-Poly1305 file. Only a random 256-bit key is
/// held by the kernel, optionally with a timeout (--ttl): when it expires, on
/// reboot, or on `clear`, the files can no longer be decrypted and are deleted.
///
/// There are two scopes. The user scope keeps the key in your user keyring (@u),
/// so every process running as your UID can use the keyset. The session scope
/// keeps it in a private session keyring created by `tempkeys session`, usable
/// only by that process family. Outside a session everything uses the user scope.
/// Inside one, reads (get, run, list) look in the session scope first and fall
/// back to the user scope per keyset, while writes (load, set, clear) go to the
/// session scope; --user and --session override this. Root can always read either. Files go in $XDG_RUNTIME_DIR/tempkeys, falling
/// back to $XDG_CACHE_HOME/tempkeys (default ~/.cache/tempkeys).
#[derive(Parser)]
#[command(version)]
struct Cli {
    /// Use only the session scope (an error outside `tempkeys session`)
    #[arg(long, global = true, conflicts_with = "user")]
    session: bool,

    /// Use only the user scope, even inside a session
    #[arg(long, global = true)]
    user: bool,

    #[command(subcommand)]
    command: Cmd,
}

#[derive(Args)]
struct SetArg {
    /// Name of the keyset
    #[arg(long, short, default_value = "default")]
    set: String,
}

#[derive(Args)]
struct TtlArg {
    /// Expire after this long, e.g. 90s, 15m, 8h, 2d (default: no expiry)
    #[arg(long, value_parser = parse_ttl)]
    ttl: Option<u32>,
}

#[derive(Subcommand)]
enum Cmd {
    /// Replace a keyset with the full set of keys read from stdin.
    ///
    /// Accepts dotenv lines (KEY=VALUE) or a JSON object of strings. The load is
    /// all-or-nothing: bad input leaves the current keyset untouched. Every load
    /// uses a new encryption key, unless --merge is given.
    Load {
        #[command(flatten)]
        set: SetArg,
        #[command(flatten)]
        ttl: TtlArg,
        /// Add or replace the given keys and keep the rest of an existing keyset
        ///
        /// The keyset keeps its encryption key and expiry (so --ttl is rejected for
        /// an existing keyset). If the keyset doesn't exist this is a normal load.
        #[arg(long)]
        merge: bool,
    },
    /// Add or replace one key, reading its value from stdin.
    ///
    /// In an existing keyset the key is encrypted under the keyset's current key
    /// and keeps its expiry; the other keys are untouched. If the keyset doesn't
    /// exist it is created (--ttl applies only then). One trailing newline is
    /// dropped from the value unless --raw is given. On a terminal the value is
    /// prompted for without echo.
    Set {
        #[command(flatten)]
        set: SetArg,
        #[command(flatten)]
        ttl: TtlArg,
        /// Keep the value's bytes exactly, including a trailing newline
        #[arg(long)]
        raw: bool,
        key: String,
    },
    /// Decrypt and print one key's raw value
    Get {
        #[command(flatten)]
        set: SetArg,
        key: String,
    },
    /// List keysets, or the key names in one keyset (never values)
    List {
        /// Show the key names in this keyset instead of listing keysets
        #[arg(long, short)]
        set: Option<String>,
    },
    /// Run a command with keys injected as environment variables.
    ///
    /// Without -e, every key in the keyset is injected under its own name. With
    /// -e, only the listed variables are populated. Either way the variables set
    /// are listed on stderr (names only, never values) as VAR=KEY, or just VAR
    /// when the variable has the key's name.
    ///
    /// Environment variables are visible to same-UID readers of /proc/PID/environ
    /// and are inherited by grandchildren, so this trades protection for
    /// convenience.
    Run {
        #[command(flatten)]
        set: SetArg,
        /// Populate VAR from key KEY (repeatable); VAR alone means KEY = VAR
        #[arg(short = 'e', long = "env", value_name = "VAR=KEY")]
        env: Vec<String>,
        /// Don't list the populated variables
        #[arg(short, long)]
        quiet: bool,
        #[arg(trailing_var_arg = true, required = true, num_args = 1.., allow_hyphen_values = true)]
        command: Vec<String>,
    },
    /// Serve a Git HTTPS credential from a key in the selected keyset.
    ///
    /// Configure as a Git credential helper for a specific host. Only `get`
    /// returns credentials; `store` and `erase` do not change the keyset.
    GitCredential {
        #[command(flatten)]
        set: SetArg,
        /// Name of the token key
        #[arg(long, default_value = "GH_TOKEN")]
        key: String,
        /// HTTPS host to answer for
        #[arg(long, default_value = "github.com")]
        host: String,
        /// Nonempty username sent with the token
        #[arg(long, default_value = "x-access-token")]
        username: String,
        /// Git credential helper operation
        operation: String,
    },
    /// Delete a keyset (or all of them) and its encryption key right now
    Clear {
        #[command(flatten)]
        set: SetArg,
        /// Remove every tempkeys keyset in the selected scope
        #[arg(long, conflicts_with = "set")]
        all: bool,
    },
    /// Start a command inside a fresh, private session keyring.
    ///
    /// Joins a new anonymous session keyring and execs COMMAND (default: $SHELL),
    /// which inherits it. If stdin is piped, the keyset is read from it and loaded
    /// with its key in the session keyring (nothing touches @u), and COMMAND is
    /// then required because stdin is used up. Inside, use
    /// `tempkeys --session get|list|load|run|clear`.
    Session {
        #[command(flatten)]
        set: SetArg,
        #[command(flatten)]
        ttl: TtlArg,
        #[arg(trailing_var_arg = true, num_args = 0.., allow_hyphen_values = true)]
        command: Vec<String>,
    },
}

type Res<T> = Result<T, String>;

/// Which scope(s) a command was asked to use.
#[derive(Clone, Copy)]
enum Target {
    /// Session scope first when inside a session, then user scope.
    Auto,
    User,
    Session,
}

/// Where a keyset's encryption key lives, and where its files live.
#[derive(Clone)]
struct Scope {
    label: &'static str,
    root: KeyId,
    perm: u32,
    dir: PathBuf,
}

impl Scope {
    fn user() -> Res<Scope> {
        // Owner-only: any process of this UID, no one else.
        Ok(Scope {
            label: "user",
            root: sys::USER_KEYRING,
            perm: sys::PERM_OWNER_ALL,
            dir: base_dir()?.join("user"),
        })
    }

    /// The session scope, if we are inside a session created by `tempkeys session`.
    /// Anywhere else it is refused, which avoids dropping keys into a login's
    /// shared session keyring.
    fn try_session() -> Res<Option<Scope>> {
        let marker = sys::search(sys::SESSION_KEYRING, "user", SESSION_MARKER)
            .map_err(|e| os_err("searching session keyring", e))?;
        if marker.is_none() {
            return Ok(None);
        }
        let serial = sys::serial(sys::SESSION_KEYRING)
            .map_err(|e| os_err("resolving session keyring", e))?;
        Ok(Some(Scope {
            label: "session",
            root: sys::SESSION_KEYRING,
            perm: sys::PERM_POSSESSOR_READ,
            dir: base_dir()?.join(format!("{SESSION_DIR_PREFIX}{serial}")),
        }))
    }

    fn session() -> Res<Scope> {
        Self::try_session()?.ok_or_else(|| {
            "not inside a tempkeys session (start one with `tempkeys session`)".into()
        })
    }

    /// The single scope a write (load, set, clear) goes to.
    fn for_write(target: Target) -> Res<Scope> {
        match target {
            Target::User => Scope::user(),
            Target::Session => Scope::session(),
            Target::Auto => match Scope::try_session()? {
                Some(session) => Ok(session),
                None => Scope::user(),
            },
        }
    }

    /// The scopes a read (get, run, list) may use, in lookup order.
    fn for_read(target: Target) -> Res<Vec<Scope>> {
        Ok(match target {
            Target::User => vec![Scope::user()?],
            Target::Session => vec![Scope::session()?],
            Target::Auto => Scope::try_session()?
                .into_iter()
                .chain([Scope::user()?])
                .collect(),
        })
    }
}

/// The first scope that has keyset `set`; if none does, the first scope, so the
/// caller reports "no such keyset". Fallback is per keyset: once a scope has the
/// keyset it is used whole, and a key missing from it is not taken from another.
fn pick(scopes: &[Scope], set: &str) -> Res<Scope> {
    check_set(set)?;
    let found = scopes
        .iter()
        .find(|s| s.dir.join(set).is_dir())
        .or(scopes.first());
    found
        .cloned()
        .ok_or_else(|| "no scope available".to_string())
}

const SESSION_DIR_PREFIX: &str = "session-";

/// `$XDG_RUNTIME_DIR` if it is usable as the XDG Base Directory spec requires:
/// absolute, a directory we own, and closed to everyone else.
fn runtime_dir() -> Option<PathBuf> {
    let dir = PathBuf::from(std::env::var_os("XDG_RUNTIME_DIR").filter(|v| !v.is_empty())?);
    let meta = fs::metadata(&dir).ok()?;
    // SAFETY: geteuid has no preconditions.
    let mine = meta.uid() == unsafe { libc::geteuid() };
    (dir.is_absolute() && meta.is_dir() && mine && meta.mode() & 0o077 == 0).then_some(dir)
}

/// Where tempkeys keeps its files, following the XDG Base Directory spec: the
/// runtime directory (tmpfs, per login), else `$XDG_CACHE_HOME`, else `~/.cache`.
fn base_dir() -> Res<PathBuf> {
    let env = |k: &str| {
        std::env::var_os(k)
            .map(PathBuf::from)
            .filter(|v| v.is_absolute())
    };
    let root = runtime_dir()
        .or_else(|| env("XDG_CACHE_HOME"))
        .or_else(|| env("HOME").map(|h| h.join(".cache")))
        .ok_or(
            "cannot locate a directory: XDG_RUNTIME_DIR, XDG_CACHE_HOME and HOME are all unusable",
        )?;
    Ok(root.join("tempkeys"))
}

fn mkdir_private(path: &Path) -> Res<()> {
    fs::DirBuilder::new()
        .recursive(true)
        .mode(0o700)
        .create(path)
        .map_err(|e| format!("creating {}: {e}", path.display()))
}

fn now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| d.as_secs())
}

fn parse_ttl(s: &str) -> Res<u32> {
    let (num, unit) = s.split_at(s.find(|c: char| !c.is_ascii_digit()).unwrap_or(s.len()));
    let n: u64 = num.parse().map_err(|_| format!("bad duration {s:?}"))?;
    let mult = match unit {
        "" | "s" => 1,
        "m" => 60,
        "h" => 3600,
        "d" => 86400,
        _ => return Err(format!("bad duration unit in {s:?} (use s, m, h, d)")),
    };
    let secs = n * mult;
    if secs == 0 {
        return Err("duration must be greater than zero".into());
    }
    u32::try_from(secs).map_err(|_| "duration too long".into())
}

/// Expiry recorded in files that never expire.
const NEVER: u64 = u64::MAX;

fn fmt_expiry(ttl: Option<u32>) -> String {
    ttl.map_or("no expiry".to_string(), |t| {
        format!("expires in {}", fmt_ttl(u64::from(t)))
    })
}

fn fmt_ttl(s: u64) -> String {
    match s {
        s if s >= 86400 && s % 86400 == 0 => format!("{}d", s / 86400),
        s if s >= 3600 && s % 3600 == 0 => format!("{}h", s / 3600),
        s if s >= 60 && s % 60 == 0 => format!("{}m", s / 60),
        s => format!("{s}s"),
    }
}

/// Time left, rounded down to its largest whole unit.
fn fmt_left(s: u64) -> String {
    match s {
        s if s >= 86400 => format!("{}d", s / 86400),
        s if s >= 3600 => format!("{}h", s / 3600),
        s if s >= 60 => format!("{}m", s / 60),
        s => format!("{s}s"),
    }
}

fn os_err(what: &str, e: io::Error) -> String {
    let hint = match e.raw_os_error() {
        Some(libc::ENOSYS) | Some(libc::EPERM) => {
            " (kernel keyrings unavailable: CONFIG_KEYS off or syscalls blocked by a sandbox)"
        }
        Some(libc::EDQUOT) => {
            " (key quota exceeded; see /proc/key-users and /proc/sys/kernel/keys/)"
        }
        Some(libc::EKEYEXPIRED) => " (key expired)",
        _ => "",
    };
    format!("{what}: {e}{hint}")
}

fn check_set(name: &str) -> Res<()> {
    if !name.is_empty()
        && !name.starts_with('.')
        && name
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || "-_.".contains(c))
    {
        Ok(())
    } else {
        Err(format!("invalid keyset name {name:?}"))
    }
}

fn key_desc(set: &str, generation: &vault::Generation) -> String {
    format!("{KEY_PREFIX}{set}:{}", vault::hex(generation))
}

/// Revoke and unlink encryption keys in the scope whose description starts with `prefix`,
/// except the one described by `keep`.
fn drop_keys(scope: &Scope, prefix: &str, keep: Option<&str>) {
    let Ok(ids) = sys::list_keyring(scope.root) else {
        return;
    };
    for id in ids {
        if let Ok((kind, desc)) = sys::describe(id)
            && kind == "user"
            && desc.starts_with(prefix)
            && Some(desc.as_str()) != keep
        {
            let _ = sys::revoke(id);
            let _ = sys::unlink(id, scope.root);
        }
    }
}

fn read_stdin_keyset() -> Res<Vec<(String, Secret)>> {
    if io::stdin().is_terminal() {
        return Err(
            "stdin is a terminal: pipe the keyset in (e.g. `pass show env | tempkeys load`)".into(),
        );
    }
    let mut raw = Vec::new();
    io::stdin()
        .read_to_end(&mut raw)
        .map_err(|e| format!("reading stdin: {e}"))?;
    let raw = Secret(raw);
    let text = std::str::from_utf8(&raw.0).map_err(|_| "input is not valid UTF-8".to_string())?;
    parse::parse_keyset(text)
}

/// Create the encryption key in `scope`'s keyring, with its timeout and permissions.
///
/// Only a possessor may change a key's timeout or permissions, and a process may
/// not possess the target keyring (it doesn't link `@u` from inside a private
/// session). So the key is created in the session keyring, which we do possess,
/// secured there, and then linked into place.
fn create_key(scope: &Scope, desc: &str, payload: &[u8], ttl: Option<u32>) -> Res<KeyId> {
    let stage = sys::SESSION_KEYRING;
    let staged = scope.root != stage;
    let ring = if staged { stage } else { scope.root };
    let id =
        sys::add_user_key(desc, payload, ring).map_err(|e| os_err("storing encryption key", e))?;
    let finish = || -> Res<()> {
        if let Some(ttl) = ttl {
            sys::set_timeout(id, ttl).map_err(|e| os_err("setting key timeout", e))?;
        }
        sys::set_perm(id, scope.perm).map_err(|e| os_err("restricting key", e))?;
        if staged {
            sys::link(id, scope.root).map_err(|e| os_err("linking key", e))?;
            sys::unlink(id, stage).map_err(|e| os_err("unstaging key", e))?;
        }
        Ok(())
    };
    if let Err(e) = finish() {
        let _ = sys::revoke(id);
        let _ = sys::unlink(id, ring);
        let _ = sys::unlink(id, scope.root);
        return Err(e);
    }
    Ok(id)
}

/// Encrypt one secret into the bytes of its file.
fn seal_file(
    key: &[u8],
    generation: &vault::Generation,
    expiry: u64,
    set: &str,
    name: &str,
    value: &Secret,
) -> Res<Vec<u8>> {
    let nonce: [u8; 24] = sys::random(24)
        .map_err(|e| os_err("random nonce", e))?
        .0
        .clone()
        .try_into()
        .unwrap();
    vault::encrypt(key, generation, expiry, set, name, &value.0, &nonce)
}

/// Make `files` (key name, file bytes) the whole contents of keyset `set`.
/// They go into a temporary directory that is swapped in, so readers never see
/// a half-written keyset.
fn install_dir(scope: &Scope, set: &str, files: &[(String, Vec<u8>)]) -> Res<()> {
    mkdir_private(&scope.dir)?;
    let tmp = scope.dir.join(format!(".{set}.new-{}", std::process::id()));
    let _ = fs::remove_dir_all(&tmp);
    let install = || -> Res<()> {
        mkdir_private(&tmp)?;
        for (name, bytes) in files {
            let path = tmp.join(format!("{name}{EXT}"));
            fs::OpenOptions::new()
                .write(true)
                .create_new(true)
                .mode(0o600)
                .open(&path)
                .and_then(|mut f| f.write_all(bytes))
                .map_err(|e| format!("writing {}: {e}", path.display()))?;
        }
        let dest = scope.dir.join(set);
        let old = scope.dir.join(format!(".{set}.old-{}", std::process::id()));
        let _ = fs::remove_dir_all(&old);
        if dest.exists() {
            fs::rename(&dest, &old).map_err(|e| format!("replacing keyset: {e}"))?;
        }
        fs::rename(&tmp, &dest).map_err(|e| format!("installing keyset: {e}"))?;
        let _ = fs::remove_dir_all(&old);
        Ok(())
    };
    let result = install();
    if result.is_err() {
        let _ = fs::remove_dir_all(&tmp);
    }
    result
}

/// The header (key generation and expiry) shared by an existing keyset's files.
fn existing_header(scope: &Scope, set: &str) -> Res<Option<vault::Header>> {
    let dir = scope.dir.join(set);
    key_names(&dir)
        .ok()
        .and_then(|names| names.into_iter().next())
        .map(|first| {
            fs::read(dir.join(format!("{first}{EXT}"))).map_err(|e| format!("reading keyset: {e}"))
        })
        .transpose()?
        .map(|f| vault::parse_header(&f))
        .transpose()
}

fn locked(set: &str) -> String {
    format!("keyset {set:?} is locked: its encryption key expired or was cleared")
}

/// Add or replace `entries` in an existing keyset, keeping its other keys, its
/// encryption key and its expiry. Returns the number of keys the keyset now has.
fn merge_keyset(
    scope: &Scope,
    set: &str,
    header: &vault::Header,
    entries: &[(String, Secret)],
) -> Res<usize> {
    let enc_key = find_key(scope, set, &header.generation)?.ok_or_else(|| locked(set))?;
    let dir = scope.dir.join(set);
    let mut files = Vec::new();
    // Untouched keys are carried over byte for byte: same key, same associated data.
    for name in key_names(&dir).map_err(|e| format!("reading keyset: {e}"))? {
        if !entries.iter().any(|(n, _)| *n == name) {
            let bytes = fs::read(dir.join(format!("{name}{EXT}")))
                .map_err(|e| format!("reading {name}: {e}"))?;
            files.push((name, bytes));
        }
    }
    for (name, value) in entries {
        files.push((
            name.clone(),
            seal_file(
                &enc_key.0,
                &header.generation,
                header.expiry,
                set,
                name,
                value,
            )?,
        ));
    }
    install_dir(scope, set, &files)?;
    Ok(files.len())
}

/// Replace `set` in `scope` with `entries`, encrypted under a fresh key.
fn store_keyset(
    scope: &Scope,
    set: &str,
    ttl: Option<u32>,
    entries: &[(String, Secret)],
) -> Res<()> {
    check_set(set)?;
    let key = sys::random(vault::KEY_LEN).map_err(|e| os_err("random key", e))?;
    let generation: vault::Generation = sys::random(vault::GEN_LEN)
        .map_err(|e| os_err("random generation", e))?
        .0
        .clone()
        .try_into()
        .unwrap();
    let expiry = ttl.map_or(NEVER, |t| now() + u64::from(t));

    // The kernel key goes in first: files are unreadable without it, never the reverse.
    let desc = key_desc(set, &generation);
    create_key(scope, &desc, &key.0, ttl)?;

    let built = || -> Res<()> {
        let mut files = Vec::with_capacity(entries.len());
        for (name, value) in entries {
            files.push((
                name.clone(),
                seal_file(&key.0, &generation, expiry, set, name, value)?,
            ));
        }
        install_dir(scope, set, &files)
    };
    if let Err(e) = built() {
        drop_keys(scope, &desc, None);
        return Err(e);
    }
    // Older generations of this keyset can no longer decrypt anything.
    drop_keys(scope, &format!("{KEY_PREFIX}{set}:"), Some(&desc));
    Ok(())
}

/// Read one value from stdin, prompting without echo on a terminal.
fn read_value(key: &str, raw: bool) -> Res<Secret> {
    let mut buf = Secret(Vec::new());
    if io::stdin().is_terminal() {
        eprint!("Value for {key}: ");
        // SAFETY: termios is plain data; fd 0 is stdin. Echo is restored below.
        let saved = unsafe {
            let mut t: libc::termios = std::mem::zeroed();
            (libc::tcgetattr(0, &mut t) == 0).then(|| {
                let saved = t;
                t.c_lflag &= !libc::ECHO;
                libc::tcsetattr(0, libc::TCSANOW, &t);
                saved
            })
        };
        let mut line = String::new();
        let read = io::stdin().read_line(&mut line);
        if let Some(saved) = saved {
            // SAFETY: restoring the attributes captured above.
            unsafe { libc::tcsetattr(0, libc::TCSANOW, &saved) };
        }
        eprintln!();
        read.map_err(|e| format!("reading value: {e}"))?;
        buf = Secret(std::mem::take(&mut line).into_bytes());
    } else {
        io::stdin()
            .read_to_end(&mut buf.0)
            .map_err(|e| format!("reading stdin: {e}"))?;
    }
    if !raw && buf.0.last() == Some(&b'\n') {
        buf.0.pop();
        if buf.0.last() == Some(&b'\r') {
            buf.0.pop();
        }
    }
    if buf.0.is_empty() {
        return Err("empty values are not supported".into());
    }
    Ok(buf)
}

fn set_key(scope: &Scope, set: &str, ttl: Option<u32>, key: &str, raw: bool) -> Res<()> {
    check_set(set)?;
    if !parse::valid_name(key) {
        return Err(format!(
            "invalid key name {key:?} (use letters, digits, underscore)"
        ));
    }
    let dir = scope.dir.join(set);
    let existing = existing_header(scope, set)?;
    let value = read_value(key, raw)?;

    let Some(header) = existing else {
        store_keyset(scope, set, ttl, &[(key.to_string(), value)])?;
        eprintln!("created keyset {set:?} with {key}, {}", fmt_expiry(ttl));
        return Ok(());
    };
    if ttl.is_some() {
        return Err(format!(
            "keyset {set:?} already exists; --ttl applies only to a new keyset (use `load` to change expiry)"
        ));
    }
    let enc_key = find_key(scope, set, &header.generation)?.ok_or_else(|| locked(set))?;
    let file = seal_file(
        &enc_key.0,
        &header.generation,
        header.expiry,
        set,
        key,
        &value,
    )?;

    // Write beside the target and rename over it, so readers see the old or new file, never a partial one.
    let tmp = dir.join(format!(".{key}.tmp-{}", std::process::id()));
    let _ = fs::remove_file(&tmp);
    let write = fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(&tmp)
        .and_then(|mut f| f.write_all(&file))
        .and_then(|()| fs::rename(&tmp, dir.join(format!("{key}{EXT}"))));
    if let Err(e) = write {
        let _ = fs::remove_file(&tmp);
        return Err(format!("writing {key}: {e}"));
    }
    eprintln!("set {key} in {set:?}");
    Ok(())
}

fn load(scope: &Scope, set: &str, ttl: Option<u32>, merge: bool) -> Res<()> {
    check_set(set)?;
    let entries = read_stdin_keyset()?;
    if merge && let Some(header) = existing_header(scope, set)? {
        if ttl.is_some() {
            return Err(format!(
                "keyset {set:?} already exists; --ttl applies only to a new keyset (load without --merge to change expiry)"
            ));
        }
        let total = merge_keyset(scope, set, &header, &entries)?;
        eprintln!("merged {} keys into {set:?} ({total} total)", entries.len());
        return Ok(());
    }
    store_keyset(scope, set, ttl, &entries)?;
    eprintln!(
        "loaded {} keys into {set:?}, {}",
        entries.len(),
        fmt_expiry(ttl)
    );
    Ok(())
}

/// Names of the secret files in a keyset directory, sorted.
fn key_names(dir: &Path) -> io::Result<Vec<String>> {
    let mut names = Vec::new();
    for entry in fs::read_dir(dir)? {
        if let Some(name) = entry?
            .file_name()
            .to_str()
            .and_then(|n| n.strip_suffix(EXT))
        {
            names.push(name.to_string());
        }
    }
    names.sort();
    Ok(names)
}

/// The encryption key for a file's generation, or None if it is gone.
fn find_key(scope: &Scope, set: &str, generation: &vault::Generation) -> Res<Option<Secret>> {
    match sys::search(scope.root, "user", &key_desc(set, generation))
        .map_err(|e| os_err("searching keyring", e))?
    {
        Some(id) => Ok(Some(
            sys::read(id).map_err(|e| os_err("reading encryption key", e))?,
        )),
        None => Ok(None),
    }
}

fn read_secret(scope: &Scope, set: &str, name: &str) -> Res<Secret> {
    check_set(set)?;
    if !parse::valid_name(name) {
        return Err(format!("invalid key name {name:?}"));
    }
    let dir = scope.dir.join(set);
    if !dir.is_dir() {
        return Err(format!(
            "no keyset {set:?} (never loaded, expired, or cleared)"
        ));
    }
    let file = match fs::read(dir.join(format!("{name}{EXT}"))) {
        Ok(f) => f,
        Err(e) if e.kind() == io::ErrorKind::NotFound => {
            return Err(format!("no key {name:?} in keyset {set:?}"));
        }
        Err(e) => return Err(format!("reading secret file: {e}")),
    };
    let header = vault::parse_header(&file)?;
    if header.expiry <= now() {
        return Err(format!("keyset {set:?} has expired"));
    }
    let key = find_key(scope, set, &header.generation)?.ok_or_else(|| {
        format!("keyset {set:?} is locked: its encryption key expired or was cleared")
    })?;
    vault::decrypt(&key.0, &file, set, name)
}

fn git_credential_noop(operation: &str) -> Res<()> {
    match operation {
        "store" | "erase" => Ok(()),
        _ => Err(format!(
            "unsupported Git credential operation {operation:?}"
        )),
    }
}

const MAX_CREDENTIAL_REQUEST: u64 = 64 * 1024;

fn credential_request_matches(request: &str, host: &str) -> bool {
    let mut protocol = None;
    let mut requested_host = None;
    for line in request.lines().take_while(|line| !line.is_empty()) {
        if let Some((name, value)) = line.split_once('=') {
            match name {
                "protocol" => protocol = Some(value),
                "host" => requested_host = Some(value),
                _ => {}
            }
        }
    }
    protocol == Some("https") && requested_host == Some(host)
}

fn git_credential(
    scopes: &[Scope],
    set: &str,
    key: &str,
    host: &str,
    username: &str,
    operation: &str,
) -> Res<()> {
    if operation == "store" || operation == "erase" {
        return Ok(());
    }
    if operation != "get" {
        return Err(format!(
            "unsupported Git credential operation {operation:?}"
        ));
    }
    if username.is_empty()
        || username.contains(['\n', '\r', '='])
        || host.is_empty()
        || host.contains(['\n', '\r'])
    {
        return Err("invalid credential username or host".into());
    }
    let mut request = String::new();
    io::stdin()
        .take(MAX_CREDENTIAL_REQUEST + 1)
        .read_to_string(&mut request)
        .map_err(|e| format!("reading Git credential request: {e}"))?;
    if request.len() as u64 > MAX_CREDENTIAL_REQUEST {
        return Err("Git credential request is too large".into());
    }
    if !credential_request_matches(&request, host) {
        return Ok(());
    }
    let scope = pick(scopes, set)?;
    let value = read_secret(&scope, set, key)?;
    if value.0.is_empty() || value.0.contains(&b'\n') || value.0.contains(&b'\r') {
        return Err(format!("key {key:?} cannot be used as a Git credential"));
    }
    let mut out = io::stdout().lock();
    write!(out, "username={username}\npassword=").map_err(|e| e.to_string())?;
    out.write_all(&value.0).map_err(|e| e.to_string())?;
    out.write_all(b"\n\n").map_err(|e| e.to_string())?;
    Ok(())
}

fn get(scope: &Scope, set: &str, key: &str) -> Res<()> {
    let value = read_secret(scope, set, key)?;
    let mut out = io::stdout().lock();
    out.write_all(&value.0).map_err(|e| e.to_string())?;
    if out.is_terminal() {
        out.write_all(b"\n").map_err(|e| e.to_string())?;
    }
    Ok(())
}

fn set_names(scope: &Scope) -> Vec<String> {
    let mut sets: Vec<String> = fs::read_dir(&scope.dir)
        .into_iter()
        .flatten()
        .flatten()
        .filter(|e| e.path().is_dir())
        .filter_map(|e| e.file_name().into_string().ok())
        .filter(|n| !n.starts_with('.'))
        .collect();
    sets.sort();
    sets
}

fn list(scopes: &[Scope], set: Option<&str>) -> Res<()> {
    if let Some(name) = set {
        let scope = pick(scopes, name)?;
        for key in key_names(&scope.dir.join(name)).map_err(|_| format!("no keyset {name:?}"))? {
            println!("{key}");
        }
        return Ok(());
    }
    for scope in scopes {
        for name in set_names(scope) {
            let dir = scope.dir.join(&name);
            let names = key_names(&dir).unwrap_or_default();
            let state = names
                .first()
                .and_then(|k| fs::read(dir.join(format!("{k}{EXT}"))).ok())
                .and_then(|f| vault::parse_header(&f).ok())
                .map(|h| match find_key(scope, &name, &h.generation) {
                    Ok(Some(_)) if h.expiry == NEVER => "no expiry".to_string(),
                    Ok(Some(_)) => {
                        format!("expires in {}", fmt_left(h.expiry.saturating_sub(now())))
                    }
                    _ => "locked".to_string(),
                })
                .unwrap_or_default();
            // With more than one scope in play, say which each keyset is in.
            let prefix = if scopes.len() > 1 {
                format!("{}\t", scope.label)
            } else {
                String::new()
            };
            println!("{prefix}{name}\t{} keys\t{state}", names.len());
        }
    }
    Ok(())
}

/// `VAR=KEY` (or `VAR`, meaning `VAR=VAR`) into (variable, key).
fn parse_mapping(spec: &str) -> Res<(String, String)> {
    let (var, key) = spec.split_once('=').unwrap_or((spec, spec));
    for (what, name) in [("variable", var), ("key", key)] {
        if !parse::valid_name(name) {
            return Err(format!("bad -e {spec:?}: invalid {what} name {name:?}"));
        }
    }
    Ok((var.to_string(), key.to_string()))
}

fn run(scopes: &[Scope], set: &str, env: &[String], quiet: bool, command: &[String]) -> Res<()> {
    let scope = &pick(scopes, set)?;
    let mut mappings = if env.is_empty() {
        let names = key_names(&scope.dir.join(set)).map_err(|_| format!("no keyset {set:?}"))?;
        names.into_iter().map(|n| (n.clone(), n)).collect()
    } else {
        env.iter()
            .map(|spec| parse_mapping(spec))
            .collect::<Res<Vec<_>>>()?
    };
    mappings.sort();
    if let Some(w) = mappings.windows(2).find(|w| w[0].0 == w[1].0) {
        return Err(format!("variable {} is mapped more than once", w[0].0));
    }

    // Decrypt everything first: a missing key fails before anything is launched.
    let mut cmd = Command::new(&command[0]);
    cmd.args(&command[1..]);
    for (var, key) in &mappings {
        let value = read_secret(scope, set, key)?;
        if value.0.contains(&0) {
            return Err(format!(
                "key {key} contains a NUL byte and can't be an environment variable (use `get`)"
            ));
        }
        cmd.env(var, OsStr::from_bytes(&value.0));
    }
    if !quiet {
        let list: Vec<String> = mappings
            .iter()
            .map(|(var, key)| {
                if var == key {
                    var.clone()
                } else {
                    format!("{var}={key}")
                }
            })
            .collect();
        // Inside a session a keyset can come from either scope, so say which.
        let from = if scopes.len() > 1 {
            format!(" (from {} keyset {set:?})", scope.label)
        } else {
            String::new()
        };
        eprintln!("tempkeys: populating {}{from}", list.join(" "));
    }
    let err = cmd.exec();
    Err(format!("exec {}: {err}", command[0]))
}

fn clear(scope: &Scope, set: &str, all: bool) -> Res<()> {
    if all {
        let sets = set_names(scope);
        for name in &sets {
            let _ = fs::remove_dir_all(scope.dir.join(name));
        }
        drop_keys(scope, KEY_PREFIX, None);
        eprintln!("cleared {} keysets", sets.len());
    } else {
        check_set(set)?;
        let dir = scope.dir.join(set);
        if !dir.is_dir() {
            return Err(format!("no keyset {set:?}"));
        }
        fs::remove_dir_all(&dir).map_err(|e| format!("removing keyset: {e}"))?;
        drop_keys(scope, &format!("{KEY_PREFIX}{set}:"), None);
        eprintln!("cleared {set:?}");
    }
    Ok(())
}

/// Every regular file below `dir`, however deep.
fn walk_files(dir: &Path, out: &mut Vec<PathBuf>) {
    for entry in fs::read_dir(dir).into_iter().flatten().flatten() {
        let path = entry.path();
        if path.is_dir() {
            walk_files(&path, out);
        } else {
            out.push(path);
        }
    }
}

fn session_is_dead(serial: KeyId) -> bool {
    // Another session's ring is not viewable (EACCES) while it lives, and the
    // kernel forgets it (ENOKEY) once nothing references it.
    matches!(
        sys::describe(serial).err().and_then(|e| e.raw_os_error()),
        Some(libc::ENOKEY) | Some(libc::EKEYREVOKED) | Some(libc::EKEYEXPIRED)
    )
}

/// Best-effort housekeeping: delete files that can never be decrypted again.
/// `scopes` are the ones we can also check for keysets whose key is gone.
fn prune(scopes: &[Scope]) {
    let Ok(base) = base_dir() else { return };
    let mut files = Vec::new();
    walk_files(&base, &mut files);
    for path in files {
        let Ok(bytes) = fs::read(&path) else { continue };
        if vault::parse_header(&bytes).is_ok_and(|h| h.expiry <= now()) {
            let _ = fs::remove_file(&path);
        }
    }
    for entry in fs::read_dir(&base).into_iter().flatten().flatten() {
        let name = entry.file_name();
        let dead = name
            .to_str()
            .and_then(|n| n.strip_prefix(SESSION_DIR_PREFIX))
            .and_then(|n| n.parse::<KeyId>().ok())
            .is_some_and(session_is_dead);
        if dead {
            let _ = fs::remove_dir_all(entry.path());
        }
    }
    for scope in scopes {
        for set in set_names(scope) {
            let dir = scope.dir.join(&set);
            for name in key_names(&dir).unwrap_or_default() {
                let path = dir.join(format!("{name}{EXT}"));
                let locked = fs::read(&path)
                    .ok()
                    .and_then(|f| vault::parse_header(&f).ok())
                    .is_some_and(|h| matches!(find_key(scope, &set, &h.generation), Ok(None)));
                if locked {
                    let _ = fs::remove_file(&path);
                }
            }
            let _ = fs::remove_dir(&dir); // only succeeds when empty
        }
    }
}

fn session(set: &str, ttl: Option<u32>, command: &[String]) -> Res<()> {
    let piped = !io::stdin().is_terminal();
    if piped && command.is_empty() {
        return Err("stdin is piped into the keyset, so a COMMAND is required".into());
    }
    // Parse before joining so bad input fails without side effects.
    let entries = if piped {
        Some(read_stdin_keyset()?)
    } else {
        None
    };

    let ring =
        sys::join_fresh_session_keyring().map_err(|e| os_err("joining session keyring", e))?;
    // Drop the default owner/group/other grants before any key goes in.
    sys::set_perm(ring, sys::PERM_POSSESSOR_ALL)
        .map_err(|e| os_err("restricting session keyring", e))?;
    let marker =
        sys::add_user_key(SESSION_MARKER, b"1", ring).map_err(|e| os_err("marking session", e))?;
    sys::set_perm(marker, sys::PERM_POSSESSOR_READ).map_err(|e| os_err("marking session", e))?;

    let scope = Scope::session()?;
    prune(std::slice::from_ref(&scope));
    if let Some(entries) = &entries {
        store_keyset(&scope, set, ttl, entries)?;
        eprintln!(
            "loaded {} keys into session keyset {set:?}, {}",
            entries.len(),
            fmt_expiry(ttl)
        );
    }
    // Members may add and remove keys but never change permissions.
    sys::set_perm(ring, sys::PERM_POSSESSOR_NO_SETATTR)
        .map_err(|e| os_err("restricting session keyring", e))?;

    let shell = std::env::var("SHELL").unwrap_or_else(|_| "/bin/sh".into());
    let argv: Vec<&str> = if command.is_empty() {
        vec![shell.as_str()]
    } else {
        command.iter().map(String::as_str).collect()
    };
    let err = Command::new(argv[0]).args(&argv[1..]).exec();
    Err(format!("exec {}: {err}", argv[0]))
}

fn main() -> ExitCode {
    let cli = Cli::parse();
    let target = match (cli.session, cli.user) {
        (true, _) => Target::Session,
        (_, true) => Target::User,
        _ => Target::Auto,
    };
    let result = match &cli.command {
        Cmd::Session { set, ttl, command } => session(&set.set, ttl.ttl, command),
        Cmd::Load { set, ttl, merge } => Scope::for_write(target).and_then(|s| {
            prune(std::slice::from_ref(&s));
            load(&s, &set.set, ttl.ttl, *merge)
        }),
        Cmd::Set { set, ttl, raw, key } => Scope::for_write(target).and_then(|s| {
            prune(std::slice::from_ref(&s));
            set_key(&s, &set.set, ttl.ttl, key, *raw)
        }),
        Cmd::GitCredential { operation, .. } if operation != "get" => {
            git_credential_noop(operation)
        }
        Cmd::Clear { set, all } => Scope::for_write(target).and_then(|s| {
            prune(std::slice::from_ref(&s));
            clear(&s, &set.set, *all)
        }),
        read => Scope::for_read(target).and_then(|scopes| {
            prune(&scopes);
            match read {
                Cmd::Get { set, key } => get(&pick(&scopes, &set.set)?, &set.set, key),
                Cmd::GitCredential {
                    set,
                    key,
                    host,
                    username,
                    operation,
                } => git_credential(&scopes, &set.set, key, host, username, operation),
                Cmd::List { set } => list(&scopes, set.as_deref()),
                Cmd::Run {
                    set,
                    env,
                    quiet,
                    command,
                } => run(&scopes, &set.set, env, *quiet, command),
                _ => unreachable!(),
            }
        }),
    };
    match result {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("tempkeys: {e}");
            ExitCode::FAILURE
        }
    }
}

#[cfg(test)]
mod credential_tests {
    use super::*;

    #[test]
    fn only_matches_https_for_the_configured_host() {
        assert!(credential_request_matches(
            "protocol=https\nhost=github.com\n\n",
            "github.com"
        ));
        assert!(!credential_request_matches(
            "protocol=http\nhost=github.com\n\n",
            "github.com"
        ));
        assert!(!credential_request_matches(
            "protocol=https\nhost=other.example\n\n",
            "github.com"
        ));
        assert!(!credential_request_matches(
            "protocol=https\nhost=github.com.evil.example\n\n",
            "github.com"
        ));
    }

    #[test]
    fn store_and_erase_do_not_require_a_keyset() {
        assert!(git_credential_noop("store").is_ok());
        assert!(git_credential_noop("erase").is_ok());
        assert!(git_credential_noop("unknown").is_err());
    }
}
