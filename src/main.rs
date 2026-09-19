mod parse;
mod sys;
mod vault;

use std::ffi::OsStr;
use std::fs;
use std::io::{self, IsTerminal, Read, Write};
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::{DirBuilderExt, OpenOptionsExt};
use std::os::unix::process::CommandExt;
use std::path::{Path, PathBuf};
use std::process::{Command, ExitCode};
use std::time::{SystemTime, UNIX_EPOCH};

use clap::{Args, Parser, Subcommand};

use sys::{KeyId, Secret};

const KEY_PREFIX: &str = "ziiring:key:";
const SESSION_MARKER: &str = "ziiring:session";
const EXT: &str = ".enc";

/// Keep a temporary keyset as encrypted files, with the key in the kernel keyring.
///
/// Each secret is its own XChaCha20-Poly1305 file. Only a random 256-bit key is
/// held by the kernel, with a timeout: when it expires (or on reboot, or `clear`)
/// the files can no longer be decrypted and are deleted.
///
/// By default the key lives in your user keyring (@u), so every process running
/// as your UID can use the keyset. With --session it lives in a private session
/// keyring created by `ziiring session`, usable only by that process family.
/// Root can always read either. Files go in $ZIIRING_DIR, else
/// $XDG_RUNTIME_DIR/ziiring, else ~/.cache/ziiring.
#[derive(Parser)]
#[command(version)]
struct Cli {
    /// Use the session keyset (inside `ziiring session`) instead of the user keyring
    #[arg(long, global = true)]
    session: bool,

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
    /// Lifetime, e.g. 90s, 15m, 8h, 2d
    #[arg(long, default_value = "1h", value_parser = parse_ttl)]
    ttl: u32,
}

#[derive(Subcommand)]
enum Cmd {
    /// Replace a keyset with the full set of keys read from stdin.
    ///
    /// Accepts dotenv lines (KEY=VALUE) or a JSON object of strings. The load is
    /// all-or-nothing: bad input leaves the current keyset untouched. Every load
    /// uses a new encryption key.
    Load {
        #[command(flatten)]
        set: SetArg,
        #[command(flatten)]
        ttl: TtlArg,
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
    /// Run a command with the keyset injected as environment variables.
    ///
    /// Environment variables are visible to same-UID readers of /proc/PID/environ
    /// and are inherited by grandchildren, so this trades protection for
    /// convenience.
    Run {
        #[command(flatten)]
        set: SetArg,
        #[arg(trailing_var_arg = true, required = true, num_args = 1.., allow_hyphen_values = true)]
        command: Vec<String>,
    },
    /// Delete a keyset (or all of them) and its encryption key right now
    Clear {
        #[command(flatten)]
        set: SetArg,
        /// Remove every ziiring keyset in the selected scope
        #[arg(long, conflicts_with = "set")]
        all: bool,
    },
    /// Start a command inside a fresh, private session keyring.
    ///
    /// Joins a new anonymous session keyring and execs COMMAND (default: $SHELL),
    /// which inherits it. If stdin is piped, the keyset is read from it and loaded
    /// with its key in the session keyring (nothing touches @u), and COMMAND is
    /// then required because stdin is used up. Inside, use
    /// `ziiring --session get|list|load|run|clear`.
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

/// Where a keyset's encryption key lives, and where its files live.
struct Scope {
    root: KeyId,
    perm: u32,
    dir: PathBuf,
}

impl Scope {
    fn user() -> Res<Scope> {
        // Owner-only: any process of this UID, no one else.
        Ok(Scope { root: sys::USER_KEYRING, perm: sys::PERM_OWNER_ALL, dir: base_dir()?.join("user") })
    }

    /// Only valid inside a session created by `ziiring session`; refusing anywhere
    /// else avoids dropping keys into a login's shared session keyring.
    fn session() -> Res<Scope> {
        let marker = sys::search(sys::SESSION_KEYRING, "user", SESSION_MARKER)
            .map_err(|e| os_err("searching session keyring", e))?;
        if marker.is_none() {
            return Err("not inside a ziiring session (start one with `ziiring session`)".into());
        }
        let serial = sys::serial(sys::SESSION_KEYRING).map_err(|e| os_err("resolving session keyring", e))?;
        Ok(Scope {
            root: sys::SESSION_KEYRING,
            perm: sys::PERM_POSSESSOR_READ,
            dir: base_dir()?.join(format!("{SESSION_DIR_PREFIX}{serial}")),
        })
    }
}

const SESSION_DIR_PREFIX: &str = "session-";

fn base_dir() -> Res<PathBuf> {
    let env = |k: &str| std::env::var_os(k).filter(|v| !v.is_empty());
    let dir = if let Some(d) = env("ZIIRING_DIR") {
        PathBuf::from(d)
    } else if let Some(d) = env("XDG_RUNTIME_DIR") {
        PathBuf::from(d).join("ziiring")
    } else if let Some(h) = env("HOME") {
        PathBuf::from(h).join(".cache/ziiring")
    } else {
        return Err("cannot locate a directory: set ZIIRING_DIR".into());
    };
    Ok(dir)
}

fn mkdir_private(path: &Path) -> Res<()> {
    fs::DirBuilder::new()
        .recursive(true)
        .mode(0o700)
        .create(path)
        .map_err(|e| format!("creating {}: {e}", path.display()))
}

fn now() -> u64 {
    SystemTime::now().duration_since(UNIX_EPOCH).map_or(0, |d| d.as_secs())
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
        Some(libc::EDQUOT) => " (key quota exceeded; see /proc/key-users and /proc/sys/kernel/keys/)",
        Some(libc::EKEYEXPIRED) => " (key expired)",
        _ => "",
    };
    format!("{what}: {e}{hint}")
}

fn check_set(name: &str) -> Res<()> {
    if !name.is_empty() && !name.starts_with('.') && name.chars().all(|c| c.is_ascii_alphanumeric() || "-_.".contains(c)) {
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
    let Ok(ids) = sys::list_keyring(scope.root) else { return };
    for id in ids {
        if let Ok((kind, desc)) = sys::describe(id) {
            if kind == "user" && desc.starts_with(prefix) && Some(desc.as_str()) != keep {
                let _ = sys::revoke(id);
                let _ = sys::unlink(id, scope.root);
            }
        }
    }
}

fn read_stdin_keyset() -> Res<Vec<(String, Secret)>> {
    if io::stdin().is_terminal() {
        return Err("stdin is a terminal: pipe the keyset in (e.g. `pass show env | ziiring load`)".into());
    }
    let mut raw = Vec::new();
    io::stdin().read_to_end(&mut raw).map_err(|e| format!("reading stdin: {e}"))?;
    let raw = Secret(raw);
    let text = std::str::from_utf8(&raw.0).map_err(|_| "input is not valid UTF-8".to_string())?;
    parse::parse_keyset(text)
}

/// Replace `set` in `scope` with `entries`, encrypted under a fresh key.
fn store_keyset(scope: &Scope, set: &str, ttl: u32, entries: &[(String, Secret)]) -> Res<()> {
    check_set(set)?;
    let key = sys::random(vault::KEY_LEN).map_err(|e| os_err("random key", e))?;
    let generation: vault::Generation = sys::random(vault::GEN_LEN)
        .map_err(|e| os_err("random generation", e))?
        .0
        .clone()
        .try_into()
        .unwrap();
    let expiry = now() + u64::from(ttl);

    // The kernel key goes in first: files are unreadable without it, never the reverse.
    let desc = key_desc(set, &generation);
    let key_id = sys::add_user_key(&desc, &key.0, scope.root).map_err(|e| os_err("storing encryption key", e))?;
    // Timeout and permissions need setattr, so tighten permissions last.
    let seal = || -> Res<()> {
        sys::set_timeout(key_id, ttl).map_err(|e| os_err("setting key timeout", e))?;
        sys::set_perm(key_id, scope.perm).map_err(|e| os_err("restricting key", e))
    };
    if let Err(e) = seal() {
        drop_keys(scope, &desc, None);
        return Err(e);
    }

    mkdir_private(&scope.dir)?;
    let tmp = scope.dir.join(format!(".{set}.new-{}", std::process::id()));
    let _ = fs::remove_dir_all(&tmp);
    let write_all = || -> Res<()> {
        mkdir_private(&tmp)?;
        for (name, value) in entries {
            let nonce: [u8; 24] = sys::random(24).map_err(|e| os_err("random nonce", e))?.0.clone().try_into().unwrap();
            let file = vault::encrypt(&key.0, &generation, expiry, set, name, &value.0, &nonce)?;
            let path = tmp.join(format!("{name}{EXT}"));
            fs::OpenOptions::new()
                .write(true)
                .create_new(true)
                .mode(0o600)
                .open(&path)
                .and_then(|mut f| f.write_all(&file))
                .map_err(|e| format!("writing {}: {e}", path.display()))?;
        }
        // Swap the whole directory in; readers never see a half-written keyset.
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
    if let Err(e) = write_all() {
        let _ = fs::remove_dir_all(&tmp);
        drop_keys(scope, &desc, None);
        return Err(e);
    }
    // Older generations of this keyset can no longer decrypt anything.
    drop_keys(scope, &format!("{KEY_PREFIX}{set}:"), Some(&desc));
    Ok(())
}

fn load(scope: &Scope, set: &str, ttl: u32) -> Res<()> {
    let entries = read_stdin_keyset()?;
    store_keyset(scope, set, ttl, &entries)?;
    eprintln!("loaded {} keys into {set:?}, expires in {}", entries.len(), fmt_ttl(u64::from(ttl)));
    Ok(())
}

/// Names of the secret files in a keyset directory, sorted.
fn key_names(dir: &Path) -> io::Result<Vec<String>> {
    let mut names = Vec::new();
    for entry in fs::read_dir(dir)? {
        if let Some(name) = entry?.file_name().to_str().and_then(|n| n.strip_suffix(EXT)) {
            names.push(name.to_string());
        }
    }
    names.sort();
    Ok(names)
}

/// The encryption key for a file's generation, or None if it is gone.
fn find_key(scope: &Scope, set: &str, generation: &vault::Generation) -> Res<Option<Secret>> {
    match sys::search(scope.root, "user", &key_desc(set, generation)).map_err(|e| os_err("searching keyring", e))? {
        Some(id) => Ok(Some(sys::read(id).map_err(|e| os_err("reading encryption key", e))?)),
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
        return Err(format!("no keyset {set:?} (never loaded, expired, or cleared)"));
    }
    let file = match fs::read(dir.join(format!("{name}{EXT}"))) {
        Ok(f) => f,
        Err(e) if e.kind() == io::ErrorKind::NotFound => return Err(format!("no key {name:?} in keyset {set:?}")),
        Err(e) => return Err(format!("reading secret file: {e}")),
    };
    let header = vault::parse_header(&file)?;
    if header.expiry <= now() {
        return Err(format!("keyset {set:?} has expired"));
    }
    let key = find_key(scope, set, &header.generation)?
        .ok_or_else(|| format!("keyset {set:?} is locked: its encryption key expired or was cleared"))?;
    vault::decrypt(&key.0, &file, set, name)
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

fn list(scope: &Scope, set: Option<&str>) -> Res<()> {
    match set {
        Some(name) => {
            check_set(name)?;
            let names = key_names(&scope.dir.join(name)).map_err(|_| format!("no keyset {name:?}"))?;
            for key in names {
                println!("{key}");
            }
        }
        None => {
            for name in set_names(scope) {
                let dir = scope.dir.join(&name);
                let names = key_names(&dir).unwrap_or_default();
                let state = names
                    .first()
                    .and_then(|k| fs::read(dir.join(format!("{k}{EXT}"))).ok())
                    .and_then(|f| vault::parse_header(&f).ok())
                    .map(|h| match find_key(scope, &name, &h.generation) {
                        Ok(Some(_)) => format!("expires in {}", fmt_left(h.expiry.saturating_sub(now()))),
                        _ => "locked".to_string(),
                    })
                    .unwrap_or_default();
                println!("{name}\t{} keys\t{state}", names.len());
            }
        }
    }
    Ok(())
}

fn run(scope: &Scope, set: &str, command: &[String]) -> Res<()> {
    check_set(set)?;
    let names = key_names(&scope.dir.join(set)).map_err(|_| format!("no keyset {set:?}"))?;
    let mut cmd = Command::new(&command[0]);
    cmd.args(&command[1..]);
    for name in names {
        let value = read_secret(scope, set, &name)?;
        cmd.env(&name, OsStr::from_bytes(&value.0));
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
fn prune(scope: Option<&Scope>) {
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
    // In our own scope we can also tell when a keyset's key is gone.
    if let Some(scope) = scope {
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

fn session(set: &str, ttl: u32, command: &[String]) -> Res<()> {
    let piped = !io::stdin().is_terminal();
    if piped && command.is_empty() {
        return Err("stdin is piped into the keyset, so a COMMAND is required".into());
    }
    // Parse before joining so bad input fails without side effects.
    let entries = if piped { Some(read_stdin_keyset()?) } else { None };

    let ring = sys::join_fresh_session_keyring().map_err(|e| os_err("joining session keyring", e))?;
    // Drop the default owner/group/other grants before any key goes in.
    sys::set_perm(ring, sys::PERM_POSSESSOR_ALL).map_err(|e| os_err("restricting session keyring", e))?;
    let marker = sys::add_user_key(SESSION_MARKER, b"1", ring).map_err(|e| os_err("marking session", e))?;
    sys::set_perm(marker, sys::PERM_POSSESSOR_READ).map_err(|e| os_err("marking session", e))?;

    let scope = Scope::session()?;
    prune(Some(&scope));
    if let Some(entries) = &entries {
        store_keyset(&scope, set, ttl, entries)?;
        eprintln!("loaded {} keys into session keyset {set:?}, expires in {}", entries.len(), fmt_ttl(u64::from(ttl)));
    }
    // Members may add and remove keys but never change permissions.
    sys::set_perm(ring, sys::PERM_POSSESSOR_NO_SETATTR).map_err(|e| os_err("restricting session keyring", e))?;

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
    let result = match &cli.command {
        Cmd::Session { set, ttl, command } => session(&set.set, ttl.ttl, command),
        cmd => {
            let scope = if cli.session { Scope::session() } else { Scope::user() };
            scope.and_then(|s| {
                prune(Some(&s));
                match cmd {
                    Cmd::Load { set, ttl } => load(&s, &set.set, ttl.ttl),
                    Cmd::Get { set, key } => get(&s, &set.set, key),
                    Cmd::List { set } => list(&s, set.as_deref()),
                    Cmd::Run { set, command } => run(&s, &set.set, command),
                    Cmd::Clear { set, all } => clear(&s, &set.set, *all),
                    Cmd::Session { .. } => unreachable!(),
                }
            })
        }
    };
    match result {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("ziiring: {e}");
            ExitCode::FAILURE
        }
    }
}
