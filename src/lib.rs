#![cfg(target_os = "linux")]
use std::ffi::CString;
use std::fs::File;
use std::io;
use std::os::unix::ffi::OsStrExt;
use std::os::unix::io::{AsRawFd, FromRawFd, RawFd};
use std::path::Path;

const SYS_OPENAT2: i64 = 437;
const RESOLVE_NO_MAGICLINKS: u64 = 0x02;
const RESOLVE_BENEATH: u64 = 0x08;

#[repr(C)]
#[derive(Debug, Default)]
pub struct OpenHow {
    oflag: u64,
    mode: u64,
    resolve: u64,
}

const SIZEOF_OPEN_HOW: usize = std::mem::size_of::<OpenHow>();

/// This is a test wrapper around openat2 syscall.
pub fn openat2(dir: &File, path: &Path) -> io::Result<File> {
    let open_how = OpenHow {
        oflag: 0,
        mode: 0,
        resolve: RESOLVE_BENEATH | RESOLVE_NO_MAGICLINKS,
    };
    let path_cstr = CString::new(path.as_os_str().as_bytes())?;
    let rc = unsafe {
        libc::syscall(
            SYS_OPENAT2,
            dir.as_raw_fd(),
            path_cstr.as_ptr(),
            &open_how,
            SIZEOF_OPEN_HOW,
        )
    };
    if rc == -1 {
        return Err(io::Error::last_os_error());
    }
    Ok(unsafe { File::from_raw_fd(rc as RawFd) })
}

#[cfg(test)]
mod test {
    use super::*;
    use std::env::current_dir;
    use std::fs::{self, OpenOptions};

    #[test]
    fn smoke() {
        let cwd_path = current_dir().expect("could get cwd");
        let cwd = OpenOptions::new()
            .read(true)
            .open(&cwd_path)
            .expect("could open cwd as File");

        // create some dir
        fs::create_dir(cwd_path.join("hmm")).expect("could create 'hmm' subdir");

        // check openat2
        openat2(cwd, "hmm").expect("openat2 should succeed");
    }
}
