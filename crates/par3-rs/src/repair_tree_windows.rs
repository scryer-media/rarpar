//! Private directory creation and file and directory identity checks through
//! Windows handles.
//!
//! This is the sole unsafe-code boundary in the crate. All callers use owned
//! directory capabilities and safe wrappers; no pointer escapes this module.

#![deny(unsafe_op_in_unsafe_fn)]

use cap_std::fs::Dir;
use std::ffi::{OsStr, c_void};
use std::io;
use std::os::windows::ffi::OsStrExt;
use std::os::windows::io::{AsRawHandle, FromRawHandle};
use std::ptr::null_mut;

#[repr(C)]
struct UnicodeString {
    length: u16,
    capacity: u16,
    buffer: *mut u16,
}
#[repr(C)]
struct ObjectAttributes {
    length: u32,
    root: *mut c_void,
    name: *mut UnicodeString,
    attributes: u32,
    security: *mut c_void,
    qos: *mut c_void,
}
#[repr(C)]
struct IoStatusBlock {
    status: usize,
    information: usize,
}

#[link(name = "ntdll")]
unsafe extern "system" {
    fn NtCreateFile(
        handle: *mut *mut c_void,
        access: u32,
        attributes: *mut ObjectAttributes,
        status: *mut IoStatusBlock,
        allocation: *mut i64,
        file_attributes: u32,
        share: u32,
        disposition: u32,
        options: u32,
        ea: *mut c_void,
        ea_len: u32,
    ) -> i32;
    fn RtlNtStatusToDosError(status: i32) -> u32;
}
#[link(name = "advapi32")]
unsafe extern "system" {
    fn ConvertStringSecurityDescriptorToSecurityDescriptorW(
        string: *const u16,
        revision: u32,
        descriptor: *mut *mut c_void,
        length: *mut u32,
    ) -> i32;
}
#[link(name = "kernel32")]
unsafe extern "system" {
    fn LocalFree(memory: *mut c_void) -> *mut c_void;
}

struct SecurityDescriptor(*mut c_void);
impl Drop for SecurityDescriptor {
    fn drop(&mut self) {
        // SAFETY: the descriptor was allocated by the conversion API, and
        // this owner releases it exactly once after NtCreateFile returns.
        unsafe {
            LocalFree(self.0);
        }
    }
}

pub(super) fn create_private_dir(parent: &Dir, name: &OsStr) -> io::Result<Dir> {
    let mut wide: Vec<u16> = name.encode_wide().collect();
    let length = wide
        .len()
        .checked_mul(2)
        .and_then(|n| u16::try_from(n).ok())
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "staging name too long"))?;
    if wide
        .iter()
        .any(|&c| c == 0 || c == b'/' as u16 || c == b'\\' as u16)
    {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "staging name is not one component",
        ));
    }
    let mut name = UnicodeString {
        length,
        capacity: length,
        buffer: wide.as_mut_ptr(),
    };
    // Protected DACL: only the object owner receives access. OI/CI carry
    // that rule to staging files and children; permissive parent ACLs do not.
    let sddl: Vec<u16> = "D:P(A;OICI;FA;;;OW)\0".encode_utf16().collect();
    let mut descriptor = null_mut();
    // SAFETY: the input is NUL terminated and both output pointers are valid.
    if unsafe {
        ConvertStringSecurityDescriptorToSecurityDescriptorW(
            sddl.as_ptr(),
            1,
            &mut descriptor,
            null_mut(),
        )
    } == 0
    {
        return Err(io::Error::last_os_error());
    }
    let descriptor = SecurityDescriptor(descriptor);
    let mut attributes = ObjectAttributes {
        length: size_of::<ObjectAttributes>() as u32,
        root: parent.as_raw_handle(),
        name: &mut name,
        attributes: 0,
        security: descriptor.0,
        qos: null_mut(),
    };
    let mut status = IoStatusBlock {
        status: 0,
        information: 0,
    };
    let mut handle = null_mut();
    // FILE_CREATE is exclusive. Match cap-std's readable directory handles:
    // FILE_GENERIC_READ excludes DELETE, and sharing permits reads/writes but
    // not deletion. This allows identity reopens while preventing renames of
    // a live capability, as Dir::from_std_file requires on Windows.
    // SAFETY: every buffer/descriptor lives through this synchronous call;
    // the borrowed root stays open and the output handle is adopted below.
    let result = unsafe {
        NtCreateFile(
            &mut handle,
            0x0012_0089,
            &mut attributes,
            &mut status,
            null_mut(),
            0x80,
            3,
            2,
            0x21,
            null_mut(),
            0,
        )
    };
    if result < 0 {
        // SAFETY: the conversion accepts any NTSTATUS value.
        return Err(io::Error::from_raw_os_error(
            unsafe { RtlNtStatusToDosError(result) } as i32,
        ));
    }
    // SAFETY: successful FILE_CREATE returned a new owned kernel handle.
    Ok(Dir::from_std_file(unsafe {
        std::fs::File::from_raw_handle(handle)
    }))
}

#[repr(C)]
#[derive(Default, PartialEq, Eq)]
struct FileIdInfo {
    volume: u64,
    id: [u8; 16],
}

/// FILE_BASIC_INFO; only the change time is read.
#[repr(C)]
#[derive(Default)]
struct FileBasicInfo {
    _times: [i64; 3],
    change: i64,
    _attributes: u32,
}

/// BY_HANDLE_FILE_INFORMATION; only the volume and file index are read.
#[repr(C)]
#[derive(Default)]
struct ByHandleFileInformation {
    _attributes: u32,
    _times: [u32; 6],
    volume: u32,
    _size: [u32; 2],
    _links: u32,
    index_high: u32,
    index_low: u32,
}

#[link(name = "kernel32")]
unsafe extern "system" {
    fn GetFileInformationByHandleEx(
        handle: *mut c_void,
        class: i32,
        information: *mut c_void,
        size: u32,
    ) -> i32;
    fn GetFileInformationByHandle(
        handle: *mut c_void,
        information: *mut ByHandleFileInformation,
    ) -> i32;
    fn GetVolumeInformationByHandleW(
        handle: *mut c_void,
        name: *mut u16,
        name_len: u32,
        serial: *mut u32,
        max_component: *mut u32,
        flags: *mut u32,
        fs_name: *mut u16,
        fs_name_len: u32,
    ) -> i32;
}

/// Whether the volume `file` lives on deletes and renames over open files at
/// once (FILE_SUPPORTS_POSIX_UNLINK_RENAME). Without it (FAT, exFAT, SMB,
/// NTFS before Windows 10 1809) a handle held open leaves a deleted file
/// pending deletion, refusing opens, and refuses a rename over the file.
pub(crate) fn posix_unlink_rename(file: &std::fs::File) -> bool {
    const FILE_SUPPORTS_POSIX_UNLINK_RENAME: u32 = 0x400;
    let mut flags = 0;
    // SAFETY: null buffers with zero lengths are permitted for every output
    // but `flags`, a live u32; the borrowed handle stays open for the call.
    let ok = unsafe {
        GetVolumeInformationByHandleW(
            file.as_raw_handle(),
            null_mut(),
            0,
            null_mut(),
            null_mut(),
            &mut flags,
            null_mut(),
            0,
        )
    };
    ok != 0 && flags & FILE_SUPPORTS_POSIX_UNLINK_RENAME != 0
}

/// Query one fixed-size information class of a live handle.
///
/// # Safety
///
/// `T` must have the documented layout of information class `class`.
unsafe fn query<T: Default>(handle: &impl AsRawHandle, class: i32) -> io::Result<T> {
    let mut information = T::default();
    // SAFETY: the caller guarantees `T` is the class's layout; the buffer is
    // writable and correctly sized, and the borrowed handle stays live
    // throughout the synchronous query.
    if unsafe {
        GetFileInformationByHandleEx(
            handle.as_raw_handle(),
            class,
            (&raw mut information).cast(),
            size_of::<T>() as u32,
        )
    } == 0
    {
        return Err(io::Error::last_os_error());
    }
    Ok(information)
}

pub(super) fn same_directory(first: &Dir, second: &Dir) -> io::Result<bool> {
    // SAFETY: FileIdInfo has the documented FILE_ID_INFO layout, class 18.
    let identity = |directory: &Dir| unsafe { query::<FileIdInfo>(directory, 18) };
    Ok(identity(first)? == identity(second)?)
}

/// The file an open handle reads, and the last time it changed.
pub(crate) struct FileStamp {
    /// Volume serial number.
    pub(crate) volume: u64,
    /// File id within the volume. ReFS uses all 128 bits; NTFS the low 64.
    pub(crate) id: [u8; 16],
    /// FILE_BASIC_INFO's ChangeTime, which every data or metadata write
    /// moves. A writer holding FILE_WRITE_ATTRIBUTES can set it back through
    /// SetFileInformationByHandle, hiding a same-length rewrite; Unix ctime
    /// cannot be set back this way.
    pub(crate) change: i64,
}

/// The volume and 128-bit id of the file `file` reads, or `None` where the
/// filesystem reports none. Filesystems without FILE_ID_INFO, such as some
/// network shares, fall back to the 64-bit index every handle reports.
pub(crate) fn file_id(file: &std::fs::File) -> io::Result<Option<(u64, [u8; 16])>> {
    // SAFETY: FileIdInfo has the documented FILE_ID_INFO layout, class 18.
    let (volume, id) = match unsafe { query::<FileIdInfo>(file, 18) } {
        Ok(information) => (information.volume, information.id),
        Err(_) => {
            let mut information = ByHandleFileInformation::default();
            // SAFETY: the struct has the documented BY_HANDLE_FILE_INFORMATION
            // layout and the borrowed handle stays live for the call.
            if unsafe { GetFileInformationByHandle(file.as_raw_handle(), &mut information) } == 0 {
                return Err(io::Error::last_os_error());
            }
            let index =
                (u64::from(information.index_high) << 32) | u64::from(information.index_low);
            let mut id = [0; 16];
            id[..8].copy_from_slice(&index.to_le_bytes());
            (u64::from(information.volume), id)
        }
    };
    Ok((id != [0; 16]).then_some((volume, id)))
}

/// [`file_id`] and the change time of the file `file` reads, or `None` where
/// the filesystem reports either as zero.
pub(crate) fn file_stamp(file: &std::fs::File) -> io::Result<Option<FileStamp>> {
    let Some((volume, id)) = file_id(file)? else {
        return Ok(None);
    };
    // SAFETY: FileBasicInfo has the documented FILE_BASIC_INFO layout, class 0.
    let change = unsafe { query::<FileBasicInfo>(file, 0) }?.change;
    Ok((change != 0).then_some(FileStamp { volume, id, change }))
}

#[cfg(test)]
pub(super) fn dacl_string(directory: &Dir) -> io::Result<String> {
    #[link(name = "advapi32")]
    unsafe extern "system" {
        fn GetSecurityInfo(
            handle: *mut c_void,
            object_type: u32,
            information: u32,
            owner: *mut *mut c_void,
            group: *mut *mut c_void,
            dacl: *mut *mut c_void,
            sacl: *mut *mut c_void,
            descriptor: *mut *mut c_void,
        ) -> u32;
        fn ConvertSecurityDescriptorToStringSecurityDescriptorW(
            descriptor: *const c_void,
            revision: u32,
            information: u32,
            string: *mut *mut u16,
            length: *mut u32,
        ) -> i32;
    }
    let mut descriptor = null_mut();
    // SAFETY: the directory is live and the requested descriptor output is valid.
    let error = unsafe {
        GetSecurityInfo(
            directory.as_raw_handle(),
            1,
            4,
            null_mut(),
            null_mut(),
            null_mut(),
            null_mut(),
            &mut descriptor,
        )
    };
    if error != 0 {
        return Err(io::Error::from_raw_os_error(error as i32));
    }
    let descriptor = SecurityDescriptor(descriptor);
    let mut string = null_mut();
    let mut len = 0;
    // SAFETY: GetSecurityInfo supplied a valid descriptor and outputs live here.
    if unsafe {
        ConvertSecurityDescriptorToStringSecurityDescriptorW(
            descriptor.0,
            1,
            4,
            &mut string,
            &mut len,
        )
    } == 0
    {
        return Err(io::Error::last_os_error());
    }
    let allocation = SecurityDescriptor(string.cast());
    // SAFETY: the conversion returns len UTF-16 code units, including its NUL.
    let text = unsafe { std::slice::from_raw_parts(string, len as usize) };
    let result = String::from_utf16_lossy(text.strip_suffix(&[0]).unwrap_or(text));
    drop(allocation);
    Ok(result)
}
