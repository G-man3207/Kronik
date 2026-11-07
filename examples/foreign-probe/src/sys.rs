//! The actor's three SysV IPC calls; never removes an object it did not create.
use super::Item;
use std::io;

pub struct SharedMemory {
    pub key: i32,
    id: i32,
}
impl SharedMemory {
    pub fn new(token: &str) -> io::Result<Self> {
        let key = token.bytes().fold(2166136261u32, |h, b| {
            (h ^ u32::from(b)).wrapping_mul(16777619)
        }) & 0x7fff_ffff;
        if key == 0 {
            return Err(io::Error::other("IPC_PRIVATE is not an exclusive key"));
        }
        // SAFETY: shmget has only integer arguments; IPC_EXCL protects foreign objects.
        let id =
            unsafe { libc::shmget(key as i32, 4096, libc::IPC_CREAT | libc::IPC_EXCL | 0o600) };
        if id < 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(Self {
            key: key as i32,
            id,
        })
    }
}
impl Drop for SharedMemory {
    fn drop(&mut self) {
        // SAFETY: id was returned exclusively to this object; IPC_RMID ignores the buffer.
        unsafe {
            libc::shmctl(self.id, libc::IPC_RMID, std::ptr::null_mut());
        }
    }
}

pub fn lookup(key: &str) -> Item {
    let key = match key.parse::<i32>() {
        Ok(key) if key > 0 => key,
        _ => return Item::failed(key, io::Error::other("positive SysV key required"), &[]),
    };
    // SAFETY: lookup only, with no IPC_CREAT and no pointer argument.
    let id = unsafe { libc::shmget(key, 1, 0) };
    if id < 0 {
        Item::failed(
            &key.to_string(),
            io::Error::last_os_error(),
            &[libc::ENOENT, libc::EACCES, libc::EPERM],
        )
    } else {
        Item::seen(&key.to_string(), format!("SysV shared memory id {id}"))
    }
}
