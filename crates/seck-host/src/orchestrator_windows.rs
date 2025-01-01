//! Windows orchestrator (Plan 16): open the user file with `CreateFileW`,
//! launch `seck-reader` via `CreateProcessW(EXTENDED_STARTUPINFO_PRESENT)`,
//! and pass the HANDLE explicitly through `STARTUPINFOEXW` +
//! `PROC_THREAD_ATTRIBUTE_HANDLE_LIST`.
//!
//! The file path is NEVER passed as an argv string — only the HANDLE
//! number flows to the child via the `SECK_HANDLE` env var. This
//! mirrors the Linux/macOS FD-handoff pattern so the sandboxed reader
//! never has filesystem ambient authority.
#![cfg(target_os = "windows")]
#![allow(unsafe_code)]

use std::ffi::OsString;
use std::os::windows::ffi::OsStrExt;
use std::path::Path;

use windows_sys::Win32::Foundation::{
    CloseHandle, GENERIC_READ, GetLastError, INVALID_HANDLE_VALUE,
};
use windows_sys::Win32::Security::SECURITY_ATTRIBUTES;
use windows_sys::Win32::Storage::FileSystem::{
    CreateFileW, FILE_FLAG_BACKUP_SEMANTICS, FILE_SHARE_READ, OPEN_EXISTING,
};
use windows_sys::Win32::System::Threading::{
    CreateProcessW, DeleteProcThreadAttributeList, EXTENDED_STARTUPINFO_PRESENT,
    InitializeProcThreadAttributeList, PROC_THREAD_ATTRIBUTE_HANDLE_LIST, PROCESS_INFORMATION,
    STARTUPINFOEXW, STARTUPINFOW, UpdateProcThreadAttribute,
};

pub struct WindowsOrchResult {
    pub child_pid: u32,
}

/// Open `path` with `GENERIC_READ` + `FILE_SHARE_READ`, mark it
/// inheritable, then `CreateProcessW` the supplied `seck` binary with
/// the HANDLE on its attribute list. The HANDLE number is passed via
/// the `SECK_HANDLE` env var; the child uses `--handle=N` to consume it.
pub fn run_sandboxed_windows(path: &Path, seck_exe: &Path) -> anyhow::Result<WindowsOrchResult> {
    // 1. Open the input file inheritably.
    let wide_path: Vec<u16> = path
        .as_os_str()
        .encode_wide()
        .chain(std::iter::once(0))
        .collect();
    let mut sa = SECURITY_ATTRIBUTES {
        nLength: core::mem::size_of::<SECURITY_ATTRIBUTES>() as u32,
        lpSecurityDescriptor: core::ptr::null_mut(),
        bInheritHandle: 1,
    };
    // SAFETY: wide_path is a NUL-terminated UTF-16 buffer.
    let file_handle = unsafe {
        CreateFileW(
            wide_path.as_ptr(),
            GENERIC_READ,
            FILE_SHARE_READ,
            &mut sa,
            OPEN_EXISTING,
            FILE_FLAG_BACKUP_SEMANTICS,
            core::ptr::null_mut(),
        )
    };
    if file_handle == INVALID_HANDLE_VALUE {
        anyhow::bail!("CreateFileW failed: {}", unsafe { GetLastError() });
    }

    // 2. Build a STARTUPINFOEXW with a HANDLE inheritance list containing
    //    only `file_handle`. This is the Windows analog of macOS/Linux
    //    `dup2(fd, 3)` + close-everything-else: nothing else inherits.
    let mut attr_size: usize = 0;
    // SAFETY: documented: first call returns required size in attr_size
    // with ERROR_INSUFFICIENT_BUFFER.
    unsafe {
        InitializeProcThreadAttributeList(core::ptr::null_mut(), 1, 0, &mut attr_size);
    }
    let mut attr_buf = vec![0u8; attr_size];
    let attr_list = attr_buf.as_mut_ptr() as *mut _;
    let ok = unsafe { InitializeProcThreadAttributeList(attr_list, 1, 0, &mut attr_size) };
    if ok == 0 {
        unsafe { CloseHandle(file_handle) };
        anyhow::bail!("InitializeProcThreadAttributeList failed: {}", unsafe {
            GetLastError()
        });
    }
    let handles = [file_handle];
    let ok = unsafe {
        UpdateProcThreadAttribute(
            attr_list,
            0,
            PROC_THREAD_ATTRIBUTE_HANDLE_LIST as usize,
            handles.as_ptr() as *const _,
            core::mem::size_of_val(&handles),
            core::ptr::null_mut(),
            core::ptr::null_mut(),
        )
    };
    if ok == 0 {
        unsafe {
            DeleteProcThreadAttributeList(attr_list);
            CloseHandle(file_handle);
        }
        anyhow::bail!("UpdateProcThreadAttribute failed: {}", unsafe {
            GetLastError()
        });
    }

    // 3. CreateProcessW. Pass the HANDLE numerically via `SECK_HANDLE`.
    let mut si: STARTUPINFOEXW = unsafe { core::mem::zeroed() };
    si.StartupInfo.cb = core::mem::size_of::<STARTUPINFOEXW>() as u32;
    si.lpAttributeList = attr_list;
    let mut pi: PROCESS_INFORMATION = unsafe { core::mem::zeroed() };

    let cmdline = build_cmdline(seck_exe, file_handle as usize);
    let mut cmdline_w: Vec<u16> = cmdline.encode_wide().chain(std::iter::once(0)).collect();

    let ok = unsafe {
        CreateProcessW(
            core::ptr::null(),
            cmdline_w.as_mut_ptr(),
            core::ptr::null(),
            core::ptr::null(),
            1, // bInheritHandles
            EXTENDED_STARTUPINFO_PRESENT,
            core::ptr::null(),
            core::ptr::null(),
            &si as *const _ as *const STARTUPINFOW,
            &mut pi,
        )
    };
    let err = unsafe { GetLastError() };
    unsafe {
        DeleteProcThreadAttributeList(attr_list);
        // The parent must close its copy of the inherited HANDLE so the
        // child's reference is the only one keeping the file alive.
        CloseHandle(file_handle);
    }
    if ok == 0 {
        anyhow::bail!("CreateProcessW failed: {err}");
    }
    let pid = pi.dwProcessId;
    // Close the thread handle; keep the process handle for waiting.
    unsafe {
        CloseHandle(pi.hThread);
        CloseHandle(pi.hProcess);
    }
    Ok(WindowsOrchResult { child_pid: pid })
}

fn build_cmdline(exe: &Path, handle: usize) -> OsString {
    // `seck analyze --handle=<N>`. We quote the exe path defensively.
    let mut s = OsString::from("\"");
    s.push(exe);
    s.push(format!("\" analyze --handle={handle}"));
    s
}
