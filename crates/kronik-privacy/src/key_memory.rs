//! Dedicated locked mappings; Linux excludes their pages from core dumps.
//! macOS instead disables standard core dumps process-wide before loading keys.
// The OS mapping API and references into its uniquely owned pages require unsafe.
#![allow(unsafe_code)]

use std::ffi::c_void;
use std::sync::Arc;

use rustix::mm::{self, MapFlags, ProtFlags};
use zeroize::{Zeroize, Zeroizing};

use crate::PrivacyError;

/// Clones share the mapping; no key bytes move when this handle moves.
#[derive(Clone)]
pub(crate) struct ProtectedKey(Arc<Mapping>);

impl ProtectedKey {
    pub(crate) fn from_slice(bytes: &[u8; 32]) -> Result<Self, PrivacyError> {
        Self::initialize(|out| out.copy_from_slice(bytes))
    }

    pub(crate) fn derive(context: &str, seed: &[u8; 32]) -> Result<Self, PrivacyError> {
        Self::initialize(|out| {
            let mut hasher = Zeroizing::new(blake3::Hasher::new_derive_key(context));
            hasher.update(seed);
            let mut output = Zeroizing::new(hasher.finalize_xof());
            output.fill(out);
        })
    }

    fn initialize(fill: impl FnOnce(&mut [u8; 32])) -> Result<Self, PrivacyError> {
        let mut mapping = Mapping::allocate(protect)?;
        fill(mapping.bytes_mut());
        Ok(Self(Arc::new(mapping)))
    }

    pub(crate) fn bytes(&self) -> &[u8; 32] {
        // SAFETY: Mapping owns at least 32 initialized bytes until the final Arc drops.
        unsafe { &*self.0.ptr.cast::<[u8; 32]>() }
    }
}

struct Mapping {
    ptr: *mut c_void,
    len: usize,
}

// SAFETY: ownership of a mapping is unique; after publication through Arc its
// bytes are immutable. Drop runs only after every shared reference is gone.
unsafe impl Send for Mapping {}
unsafe impl Sync for Mapping {}

impl Mapping {
    fn allocate(
        protect: fn(*mut c_void, usize) -> Result<(), PrivacyError>,
    ) -> Result<Self, PrivacyError> {
        let len = rustix::param::page_size();
        if len < 32 {
            return Err(PrivacyError::KeyProtection);
        }
        // SAFETY: a fresh anonymous mapping has no aliases and owns whole pages,
        // so mlock/madvise cannot change protections on unrelated allocator data.
        let ptr = unsafe {
            mm::mmap_anonymous(
                std::ptr::null_mut(),
                len,
                ProtFlags::READ | ProtFlags::WRITE,
                MapFlags::PRIVATE,
            )
        }
        .map_err(|_| PrivacyError::KeyProtection)?;
        if ptr.is_null() {
            // SAFETY: even a valid zero-address mapping cannot back Rust references.
            unsafe {
                let _ = mm::munmap(ptr, len);
            }
            return Err(PrivacyError::KeyProtection);
        }
        let mapping = Self { ptr, len };
        protect(ptr, len)?;
        Ok(mapping)
    }

    fn bytes_mut(&mut self) -> &mut [u8; 32] {
        // SAFETY: the mapping is writable and exclusively borrowed before publication.
        unsafe { &mut *self.ptr.cast::<[u8; 32]>() }
    }
}

fn protect(ptr: *mut c_void, len: usize) -> Result<(), PrivacyError> {
    // SAFETY: only Mapping::allocate calls this with its complete, live mapping.
    unsafe { mm::mlock(ptr, len) }.map_err(|_| PrivacyError::KeyProtection)?;
    #[cfg(target_os = "linux")]
    {
        // SAFETY: this is the entire dedicated, page-aligned mapping.
        unsafe { mm::madvise(ptr, len, mm::Advice::LinuxDontDump) }
            .map_err(|_| PrivacyError::KeyProtection)?;
        Ok(())
    }
    #[cfg(target_os = "macos")]
    {
        // macOS has no per-mapping MADV_DONTDUMP equivalent.
        rustix::process::setrlimit(
            rustix::process::Resource::Core,
            rustix::process::Rlimit {
                current: Some(0),
                maximum: Some(0),
            },
        )
        .map_err(|_| PrivacyError::KeyProtection)
    }
    #[cfg(not(any(target_os = "linux", target_os = "macos")))]
    {
        Err(PrivacyError::KeyProtection)
    }
}

impl Drop for Mapping {
    fn drop(&mut self) {
        // SAFETY: the last owner has exclusive access to every byte, and no
        // references survive unmapping. munmap also releases any mlock.
        unsafe {
            std::slice::from_raw_parts_mut(self.ptr.cast::<u8>(), self.len).zeroize();
            let _ = mm::munmap(self.ptr, self.len);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn clones_share_stable_storage_and_derivation_is_unchanged() {
        let key = ProtectedKey::from_slice(&[7; 32]).unwrap();
        let clone = key.clone();
        assert!(std::ptr::eq(key.bytes(), clone.bytes()));
        drop(key);
        assert_eq!(clone.bytes(), &[7; 32]);
        for context in [
            "kronik secrets v1",
            "kronik secret version v1",
            "kronik keystore v1",
            "kronik keystore backup v1",
            "kronik pseudonym v1",
            "kronik keyed hash v1",
        ] {
            let derived = ProtectedKey::derive(context, clone.bytes()).unwrap();
            assert_eq!(derived.bytes(), &blake3::derive_key(context, &[7; 32]));
        }
    }

    #[test]
    fn protection_failure_is_reported_before_key_initialization() {
        let result = Mapping::allocate(|_, _| Err(PrivacyError::KeyProtection));
        assert!(matches!(result, Err(PrivacyError::KeyProtection)));
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn loading_a_key_disables_standard_process_core_dumps() {
        let _key = ProtectedKey::from_slice(&[9; 32]).unwrap();
        let limit = rustix::process::getrlimit(rustix::process::Resource::Core);
        assert_eq!(limit.current, Some(0));
        assert_eq!(limit.maximum, Some(0));
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn dedicated_mapping_is_locked_and_excluded_from_dumps() {
        let key = ProtectedKey::from_slice(&[9; 32]).unwrap();
        let address = key.bytes().as_ptr() as usize;
        assert_eq!(address % rustix::param::page_size(), 0);
        let smaps = std::fs::read_to_string("/proc/self/smaps").unwrap();
        let mut in_mapping = false;
        let mut flags = None;
        for line in smaps.lines() {
            if let Some(range) = line.split_whitespace().next()
                && let Some((start, end)) = range.split_once('-')
                && let (Ok(start), Ok(end)) = (
                    usize::from_str_radix(start, 16),
                    usize::from_str_radix(end, 16),
                )
            {
                in_mapping = start <= address && address < end;
            }
            if in_mapping && let Some(value) = line.strip_prefix("VmFlags:") {
                flags = Some(value.split_whitespace().collect::<Vec<_>>());
                break;
            }
        }
        let flags = flags.unwrap();
        assert!(flags.contains(&"lo"));
        assert!(flags.contains(&"dd"));
    }
}
