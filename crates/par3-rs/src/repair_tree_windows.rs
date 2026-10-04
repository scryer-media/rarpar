//! Private directory creation and identity checks through Windows handles.
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
    // FILE_CREATE is exclusive. FILE_DIRECTORY_FILE and synchronous I/O
    // return an owned directory handle without reopening an ambient path.
    // SAFETY: every buffer/descriptor lives through this synchronous call;
    // the borrowed root stays open and the output handle is adopted below.
    let result = unsafe {
        NtCreateFile(
            &mut handle,
            0x001f_01ff,
            &mut attributes,
            &mut status,
            null_mut(),
            0x80,
            7,
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

pub(super) fn same_directory(first: &Dir, second: &Dir) -> io::Result<bool> {
    #[link(name = "kernel32")]
    unsafe extern "system" {
        fn GetFileInformationByHandleEx(
            handle: *mut c_void,
            class: i32,
            information: *mut FileIdInfo,
            size: u32,
        ) -> i32;
    }
    let identity = |directory: &Dir| -> io::Result<FileIdInfo> {
        let mut information = FileIdInfo::default();
        // SAFETY: FileIdInfo has the documented FILE_ID_INFO layout, the
        // buffer is writable and correctly sized, and the borrowed handle
        // stays live throughout the synchronous query. FileIdInfo is class 18.
        if unsafe {
            GetFileInformationByHandleEx(
                directory.as_raw_handle(),
                18,
                &mut information,
                size_of::<FileIdInfo>() as u32,
            )
        } == 0
        {
            return Err(io::Error::last_os_error());
        }
        Ok(information)
    };
    Ok(identity(first)? == identity(second)?)
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
