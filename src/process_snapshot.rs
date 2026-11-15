//! Processes that were already running when the sensor started.
//!
//! ETW reports only processes created while the sensor runs, so activity of
//! older processes (services, the shell, anything started before the
//! sensor) would carry no process name. At start the sensor seeds its
//! process cache from this snapshot.

/// A process running at sensor start.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RunningProcess {
    pub pid: u32,
    pub ppid: u32,
    /// NT path (`\Device\HarddiskVolumeN\...`, as ETW reports image paths),
    /// or just the executable name when the full path cannot be read.
    pub image_path: String,
    /// Creation time (FILETIME), the value ETW reports as `CreateTime`.
    pub create_time: Option<u64>,
}

/// Snapshot of the running processes (empty where unsupported).
#[cfg(target_os = "windows")]
pub fn running_processes() -> Vec<RunningProcess> {
    windows_impl::running_processes()
}

#[cfg(not(target_os = "windows"))]
pub fn running_processes() -> Vec<RunningProcess> {
    Vec::new()
}

#[cfg(target_os = "windows")]
mod windows_impl {
    use super::RunningProcess;
    use windows::core::PWSTR;
    use windows::Win32::Foundation::{CloseHandle, FILETIME};
    use windows::Win32::System::Diagnostics::ToolHelp::{
        CreateToolhelp32Snapshot, Process32FirstW, Process32NextW, PROCESSENTRY32W,
        TH32CS_SNAPPROCESS,
    };
    use windows::Win32::System::Threading::{
        GetProcessTimes, OpenProcess, QueryFullProcessImageNameW, PROCESS_NAME_NATIVE,
        PROCESS_QUERY_LIMITED_INFORMATION,
    };

    pub fn running_processes() -> Vec<RunningProcess> {
        let mut out = Vec::new();
        let Ok(snapshot) = (unsafe { CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0) }) else {
            tracing::warn!("Could not take a process snapshot");
            return out;
        };
        let mut entry = PROCESSENTRY32W {
            dwSize: std::mem::size_of::<PROCESSENTRY32W>() as u32,
            ..Default::default()
        };
        let mut more = unsafe { Process32FirstW(snapshot, &mut entry) }.is_ok();
        while more {
            let pid = entry.th32ProcessID;
            // PID 0 is the idle process, not a real one.
            if pid != 0 {
                let exe = wide_to_string(&entry.szExeFile);
                let (image, create_time) = query(pid);
                out.push(RunningProcess {
                    pid,
                    ppid: entry.th32ParentProcessID,
                    image_path: image.unwrap_or(exe),
                    create_time,
                });
            }
            more = unsafe { Process32NextW(snapshot, &mut entry) }.is_ok();
        }
        unsafe {
            let _ = CloseHandle(snapshot);
        }
        out
    }

    /// Full image path (native form) and creation time. Limited query
    /// access works for most processes, protected ones included.
    fn query(pid: u32) -> (Option<String>, Option<u64>) {
        let Ok(handle) = (unsafe { OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, false, pid) })
        else {
            return (None, None);
        };
        let mut buf = [0u16; 1024];
        let mut len = buf.len() as u32;
        let image = unsafe {
            QueryFullProcessImageNameW(
                handle,
                PROCESS_NAME_NATIVE,
                PWSTR(buf.as_mut_ptr()),
                &mut len,
            )
        }
        .ok()
        .map(|_| String::from_utf16_lossy(&buf[..len as usize]))
        .filter(|s| !s.is_empty());

        let mut created = FILETIME::default();
        let (mut exited, mut kernel, mut user) = (
            FILETIME::default(),
            FILETIME::default(),
            FILETIME::default(),
        );
        let create_time =
            unsafe { GetProcessTimes(handle, &mut created, &mut exited, &mut kernel, &mut user) }
                .ok()
                .map(|_| {
                    (u64::from(created.dwHighDateTime) << 32) | u64::from(created.dwLowDateTime)
                })
                .filter(|t| *t != 0);
        unsafe {
            let _ = CloseHandle(handle);
        }
        (image, create_time)
    }

    fn wide_to_string(wide: &[u16]) -> String {
        let end = wide.iter().position(|&c| c == 0).unwrap_or(wide.len());
        String::from_utf16_lossy(&wide[..end])
    }
}

#[cfg(test)]
mod tests {
    #[cfg(not(target_os = "windows"))]
    #[test]
    fn empty_where_unsupported() {
        assert!(super::running_processes().is_empty());
    }
}
