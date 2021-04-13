use std::error::Error;
use std::fs::File;
use std::io::prelude::*;
use std::mem::size_of;
use std::os::unix::io::{AsRawFd, FromRawFd, RawFd};

use libc;
use libc::{c_int, c_uint, c_ulonglong};

use crate::NixPath;
use crate::errno::Errno;

// re-export the libc::AT_FDCWD const for convenience so that consumers don't need to bring libc
// in-scope for the one const.
pub const AT_FDCWD: i32 = libc::AT_FDCWD;

libc_bitflags! {
    pub struct InitFlags: c_uint {
        FAN_CLASS_PRE_CONTENT;
        FAN_CLASS_CONTENT;
        FAN_CLASS_NOTIF;
        FAN_CLOEXEC;
        FAN_NONBLOCK;
        FAN_UNLIMITED_QUEUE;
        FAN_UNLIMITED_MARKS;
    }
}

libc_bitflags! {
    pub struct EventFlags: c_uint {
        O_RDONLY as c_uint;
        O_WRONLY as c_uint;
        O_RDWR as c_uint;
        O_LARGEFILE as c_uint;
        O_CLOEXEC as c_uint;
    }
}

libc_bitflags! {
    pub struct MarkFlags: c_uint {
        FAN_MARK_ADD;
        FAN_MARK_REMOVE;
        FAN_MARK_FLUSH;
        FAN_MARK_DONT_FOLLOW;
        FAN_MARK_ONLYDIR;
        FAN_MARK_IGNORED_MASK;
        FAN_MARK_IGNORED_SURV_MODIFY;
        FAN_MARK_INODE;
        FAN_MARK_MOUNT;
        // NOTE: Using FAN_MARK_FILESYSTEM requires Linux Kernel >= 4.20.0
        FAN_MARK_FILESYSTEM;
    }
}

libc_bitflags! {
    pub struct MaskFlags: c_ulonglong {
        FAN_ACCESS;
        FAN_MODIFY;
        FAN_CLOSE_WRITE;
        FAN_CLOSE_NOWRITE;
        FAN_OPEN;
        FAN_Q_OVERFLOW;
        FAN_OPEN_PERM;
        FAN_ACCESS_PERM;
        FAN_ONDIR;
        FAN_EVENT_ON_CHILD;
        FAN_CLOSE;
    }
}

#[derive(Debug)]
pub struct FanotifyEvent {
    pub mask: MaskFlags,
    pub file: Option<File>,
    pub pid: i32,
}

impl FanotifyEvent {
    pub fn overflowed(&self) -> bool {
        self.file.is_none() || self.mask.contains(MaskFlags::FAN_Q_OVERFLOW)
    }
}

#[derive(Debug, Clone, Copy)]
#[repr(u32)]
pub enum FanotifyPermissionResponse {
    FAN_ALLOW = libc::FAN_ALLOW,
    FAN_DENY = libc::FAN_DENY,
}

#[derive(Debug, Clone, Copy)]
pub struct FanotifyResponse {
    pub fd: RawFd,
    pub response: FanotifyPermissionResponse,
}

#[derive(Debug)]
pub struct Fanotify {
    fd: File,
}

impl Fanotify {
    pub fn init(flags: InitFlags, event_flags: EventFlags) -> crate::Result<Fanotify> {
        let res = Errno::result(unsafe { libc::fanotify_init(flags.bits(), event_flags.bits()) });
        res.map(|fd| Fanotify {
            fd: unsafe { File::from_raw_fd(fd) },
        })
    }

    pub fn mark<P: ?Sized + NixPath>(
        &self,
        flags: MarkFlags,
        mask: MaskFlags,
        dirfd: c_int,
        path: &P,
    ) -> crate::Result<()> {
        let res = path.with_nix_path(|cstr| unsafe {
            libc::fanotify_mark(
                self.fd.as_raw_fd(),
                flags.bits(),
                mask.bits(),
                dirfd,
                cstr.as_ptr(),
            )
        })?;
        Errno::result(res).map(|_| ())
    }

    pub fn read_events(&mut self) -> Result<Vec<FanotifyEvent>, Box<dyn Error>> {
        let header_size = size_of::<libc::fanotify_event_metadata>();
        let mut buffer = [0u8; 4096];
        let mut events = Vec::new();
        let mut offset = 0;

        let nread = self.fd.read(&mut buffer)?;

        while (nread - offset) >= header_size {
            let event = unsafe {
                // NOTE: Clippy complains that we are casting to "a more-strictly-aligned pointer".
                // Since we use this casted ptr only as an input to ptr::read_unaligned(ptr as
                // *const T) this is fine and a false positive to suppress.
                //
                // See https://github.com/rust-lang/rust-clippy/issues/2881
                    #[allow(clippy::cast_ptr_alignment)]
                (buffer.as_ptr().add(offset) as *const libc::fanotify_event_metadata)
                    .read_unaligned()
            };

            events.push(FanotifyEvent {
                file: match event.fd {
                    fd if fd != libc::FAN_NOFD => Some(unsafe { File::from_raw_fd(fd) }),
                    _ => None,
                },
                mask: MaskFlags::from_bits_truncate(event.mask),
                pid: event.pid,
            });

            offset += event.event_len as usize;
        }

        Ok(events)
    }

    pub fn respond(&mut self, response: FanotifyResponse) -> Result<(), Box<dyn Error>> {
        // Append the FD in native byte order to response_bytes
        let mut response_bytes = response.fd.to_ne_bytes().to_vec();
        // Append the response in native byte order as well
        let mut resp_code_bytes = (response.response as u32).to_ne_bytes().to_vec();
        response_bytes.append(&mut resp_code_bytes);
        // Write the full response to the fanotify fd
        Ok(self.fd.write_all(&response_bytes)?)
    }

    pub fn as_raw_fd(&self) -> RawFd {
        self.fd.as_raw_fd()
    }
}
