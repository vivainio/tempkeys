//! Thin wrappers over the Linux key retention syscalls (add_key(2), keyctl(2)).
//! See keyrings(7) and https://docs.kernel.org/security/keys/core.html.

use std::ffi::CString;
use std::io;

pub type KeyId = i32;

/// `@u`, the calling UID's user keyring.
pub const USER_KEYRING: KeyId = -4;

/// `@s`, the calling process's session keyring.
pub const SESSION_KEYRING: KeyId = -3;

/// Possessor holds view, read and search only. Used for session keys.
pub const PERM_POSSESSOR_READ: u32 = 0x0b00_0000;

/// Possessor holds everything but setattr: enough to add and remove keysets,
/// not enough to widen anyone's access.
pub const PERM_POSSESSOR_NO_SETATTR: u32 = 0x1f00_0000;

/// Possessor holds all six rights; used briefly while the launcher populates its ring.
pub const PERM_POSSESSOR_ALL: u32 = 0x3f00_0000;

/// Owner holds all six rights (view, read, write, search, link, setattr);
/// possessor, group and other hold none.
pub const PERM_OWNER_ALL: u32 = 0x003f_0000;

const KEYCTL_GET_KEYRING_ID: libc::c_long = 0;
const KEYCTL_JOIN_SESSION_KEYRING: libc::c_long = 1;
const KEYCTL_REVOKE: libc::c_long = 3;
const KEYCTL_SETPERM: libc::c_long = 5;
const KEYCTL_DESCRIBE: libc::c_long = 6;
const KEYCTL_LINK: libc::c_long = 8;
const KEYCTL_UNLINK: libc::c_long = 9;
const KEYCTL_SEARCH: libc::c_long = 10;
const KEYCTL_READ: libc::c_long = 11;
const KEYCTL_SET_TIMEOUT: libc::c_long = 15;

/// Payload bytes that are overwritten when dropped. Best effort: copies made
/// elsewhere (e.g. by `Command`) are outside our control.
pub struct Secret(pub Vec<u8>);

impl Drop for Secret {
    fn drop(&mut self) {
        for b in self.0.iter_mut() {
            // SAFETY: `b` is a valid, aligned, exclusive reference.
            unsafe { std::ptr::write_volatile(b, 0) };
        }
    }
}

fn check(ret: libc::c_long) -> io::Result<libc::c_long> {
    if ret < 0 {
        Err(io::Error::last_os_error())
    } else {
        Ok(ret)
    }
}

fn cstr(s: &str) -> io::Result<CString> {
    CString::new(s).map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "embedded NUL"))
}

fn add(kind: &str, desc: &str, payload: &[u8], ring: KeyId) -> io::Result<KeyId> {
    let kind = cstr(kind)?;
    let desc = cstr(desc)?;
    let ptr = if payload.is_empty() {
        std::ptr::null()
    } else {
        payload.as_ptr()
    };
    // SAFETY: pointers are valid for the given lengths for the call's duration.
    let id = check(unsafe {
        libc::syscall(
            libc::SYS_add_key,
            kind.as_ptr(),
            desc.as_ptr(),
            ptr,
            payload.len(),
            ring,
        )
    })?;
    Ok(id as KeyId)
}

/// Add (or update) a `user`-type key.
pub fn add_user_key(desc: &str, payload: &[u8], ring: KeyId) -> io::Result<KeyId> {
    add("user", desc, payload, ring)
}

pub fn set_perm(id: KeyId, perm: u32) -> io::Result<()> {
    // SAFETY: plain integer arguments.
    check(unsafe { libc::syscall(libc::SYS_keyctl, KEYCTL_SETPERM, id, perm as libc::c_ulong) })?;
    Ok(())
}

/// Make the key or keyring expire after `secs` seconds.
pub fn set_timeout(id: KeyId, secs: u32) -> io::Result<()> {
    // SAFETY: plain integer arguments.
    check(unsafe {
        libc::syscall(
            libc::SYS_keyctl,
            KEYCTL_SET_TIMEOUT,
            id,
            secs as libc::c_ulong,
        )
    })?;
    Ok(())
}

pub fn revoke(id: KeyId) -> io::Result<()> {
    // SAFETY: plain integer arguments.
    check(unsafe { libc::syscall(libc::SYS_keyctl, KEYCTL_REVOKE, id) })?;
    Ok(())
}

pub fn link(id: KeyId, ring: KeyId) -> io::Result<()> {
    // SAFETY: plain integer arguments.
    check(unsafe { libc::syscall(libc::SYS_keyctl, KEYCTL_LINK, id, ring) })?;
    Ok(())
}

pub fn unlink(id: KeyId, ring: KeyId) -> io::Result<()> {
    // SAFETY: plain integer arguments.
    check(unsafe { libc::syscall(libc::SYS_keyctl, KEYCTL_UNLINK, id, ring) })?;
    Ok(())
}

/// Search `ring` (recursively) for a key of `kind` with exactly this description.
/// Missing, expired and revoked keys all yield `None`.
pub fn search(ring: KeyId, kind: &str, desc: &str) -> io::Result<Option<KeyId>> {
    let kind = cstr(kind)?;
    let desc = cstr(desc)?;
    // SAFETY: both pointers are NUL-terminated and outlive the call.
    let ret = unsafe {
        libc::syscall(
            libc::SYS_keyctl,
            KEYCTL_SEARCH,
            ring,
            kind.as_ptr(),
            desc.as_ptr(),
            0,
        )
    };
    if ret >= 0 {
        return Ok(Some(ret as KeyId));
    }
    let err = io::Error::last_os_error();
    match err.raw_os_error() {
        Some(libc::ENOKEY) | Some(libc::EKEYEXPIRED) | Some(libc::EKEYREVOKED) => Ok(None),
        _ => Err(err),
    }
}

/// Read a key's payload (or a keyring's packed list of key IDs).
pub fn read(id: KeyId) -> io::Result<Secret> {
    let mut buf = Secret(vec![0u8; 256]);
    loop {
        // SAFETY: `buf` is valid for `len` writable bytes.
        let need = check(unsafe {
            libc::syscall(
                libc::SYS_keyctl,
                KEYCTL_READ,
                id,
                buf.0.as_mut_ptr(),
                buf.0.len(),
            )
        })? as usize;
        if need <= buf.0.len() {
            buf.0.truncate(need);
            return Ok(buf);
        }
        buf = Secret(vec![0u8; need]);
    }
}

/// IDs of everything linked into `ring`.
pub fn list_keyring(ring: KeyId) -> io::Result<Vec<KeyId>> {
    let raw = read(ring)?;
    Ok(raw
        .0
        .chunks_exact(4)
        .map(|c| KeyId::from_ne_bytes(c.try_into().unwrap()))
        .collect())
}

/// Returns `(type, description)`; the kernel formats this as `type;uid;gid;perm;desc`.
pub fn describe(id: KeyId) -> io::Result<(String, String)> {
    let mut buf = vec![0u8; 256];
    loop {
        // SAFETY: `buf` is valid for `len` writable bytes.
        let need = check(unsafe {
            libc::syscall(
                libc::SYS_keyctl,
                KEYCTL_DESCRIBE,
                id,
                buf.as_mut_ptr(),
                buf.len(),
            )
        })? as usize;
        if need <= buf.len() {
            buf.truncate(need);
            break;
        }
        buf = vec![0u8; need];
    }
    while buf.last() == Some(&0) {
        buf.pop();
    }
    let text = String::from_utf8_lossy(&buf);
    let mut parts = text.splitn(5, ';');
    let kind = parts.next().unwrap_or_default().to_string();
    let desc = parts.nth(3).unwrap_or_default().to_string();
    Ok((kind, desc))
}

/// Create a fresh anonymous session keyring and make the calling process its
/// member. Children inherit it across fork and execve.
pub fn join_fresh_session_keyring() -> io::Result<KeyId> {
    // SAFETY: a NULL name requests a new anonymous keyring.
    let id = check(unsafe {
        libc::syscall(
            libc::SYS_keyctl,
            KEYCTL_JOIN_SESSION_KEYRING,
            std::ptr::null::<libc::c_char>(),
        )
    })?;
    Ok(id as KeyId)
}

/// Resolve a special keyring ID such as `SESSION_KEYRING` to its real serial number.
pub fn serial(special: KeyId) -> io::Result<KeyId> {
    // SAFETY: plain integer arguments; create = 0 never creates a keyring.
    let id = check(unsafe { libc::syscall(libc::SYS_keyctl, KEYCTL_GET_KEYRING_ID, special, 0) })?;
    Ok(id as KeyId)
}

/// `len` bytes from the kernel's CSPRNG.
pub fn random(len: usize) -> io::Result<Secret> {
    let mut buf = Secret(vec![0u8; len]);
    let mut filled = 0;
    while filled < len {
        // SAFETY: the pointer and length describe the unfilled tail of `buf`.
        let n = unsafe { libc::getrandom(buf.0[filled..].as_mut_ptr().cast(), len - filled, 0) };
        if n < 0 {
            let e = io::Error::last_os_error();
            if e.kind() == io::ErrorKind::Interrupted {
                continue;
            }
            return Err(e);
        }
        filled += n as usize;
    }
    Ok(buf)
}
