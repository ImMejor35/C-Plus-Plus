use std::mem;
use winapi::um::winnt::{PROCESS_VM_READ, PROCESS_QUERY_INFORMATION, MEMORY_BASIC_INFORMATION};
use winapi::um::processthreadsapi::OpenProcess;
use winapi::um::memoryapi::{ReadProcessMemory, VirtualQueryEx};
use winapi::um::handleapi::CloseHandle;
use winapi::um::tlhelp32::{CreateToolhelp32Snapshot, Process32FirstW, Process32NextW, PROCESSENTRY32W, TH32CS_SNAPPROCESS};
use winapi::shared::minwindef::{DWORD, LPVOID};
use std::ptr::null_mut;
use thiserror::Error;

#[derive(Error, Debug)]
pub enum MemoryError {
    #[error("Failed to find Roblox process")]
    ProcessNotFound,
    #[error("Failed to open process")]
    ProcessOpenError,
    #[error("Memory read error")]
    MemoryReadError,
    #[error("Pattern not found")]
    PatternNotFound,
}

fn find_roblox_pid() -> Result<DWORD, MemoryError> {
    unsafe {
        let snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
        if snapshot == winapi::um::handleapi::INVALID_HANDLE_VALUE {
            return Err(MemoryError::ProcessNotFound);
        }

        let mut entry: PROCESSENTRY32W = mem::zeroed();
        entry.dwSize = mem::size_of::<PROCESSENTRY32W>() as DWORD;

        if Process32FirstW(snapshot, &mut entry as *mut _) != 0 {
            loop {
                let process_name = String::from_utf16_lossy(&entry.szExeFile)
                    .trim_matches('\0')
                    .to_string();
                
                if process_name == "RobloxPlayerBeta.exe" {
                    CloseHandle(snapshot);
                    return Ok(entry.th32ProcessID);
                }

                if Process32NextW(snapshot, &mut entry as *mut _) == 0 {
                    break;
                }
            }
        }

        CloseHandle(snapshot);
        Err(MemoryError::ProcessNotFound)
    }
}

fn scan_memory_for_hypv(process_handle: *mut winapi::ctypes::c_void) -> Result<Vec<usize>, MemoryError> {
    let mut results = Vec::new();
    let mut mem_info: MEMORY_BASIC_INFORMATION = unsafe { mem::zeroed() };
    let mut address: LPVOID = null_mut();

    unsafe {
        while VirtualQueryEx(
            process_handle,
            address,
            &mut mem_info,
            mem::size_of::<MEMORY_BASIC_INFORMATION>(),
        ) != 0 {
            // Check if memory is committed and readable
            if mem_info.State & winapi::um::winnt::MEM_COMMIT != 0 
                && (mem_info.Protect & winapi::um::winnt::PAGE_READONLY != 0 
                    || mem_info.Protect & winapi::um::winnt::PAGE_READWRITE != 0
                    || mem_info.Protect & winapi::um::winnt::PAGE_EXECUTE_READ != 0
                    || mem_info.Protect & winapi::um::winnt::PAGE_EXECUTE_READWRITE != 0)
            {
                let mut buffer = vec![0u8; mem_info.RegionSize];
                if ReadProcessMemory(
                    process_handle,
                    mem_info.BaseAddress,
                    buffer.as_mut_ptr() as _,
                    mem_info.RegionSize,
                    null_mut(),
                ) != 0 {
                    if let Some(pos) = search_pattern(&buffer, b"HYPV") {
                        let base_addr = mem_info.BaseAddress as usize + pos;
                        results.push(base_addr);
                        
                        let mut version_buffer = vec![0u8; 32];
                        if ReadProcessMemory(
                            process_handle,
                            base_addr as *mut winapi::ctypes::c_void,
                            version_buffer.as_mut_ptr() as _,
                            32,
                            null_mut(),
                        ) != 0 {
                            let s = String::from_utf8_lossy(&version_buffer);
                            let cleaned = s.trim_matches('\0')
                                .trim()
                                .replace(['\r', '\n'], "");
                            if !cleaned.is_empty() {
                                println!("Found at 0x{:X}: {}", base_addr, cleaned);
                            }
                        }
                    }
                }
            }
            address = ((mem_info.BaseAddress as usize) + mem_info.RegionSize) as LPVOID;
        }
    }

    if results.is_empty() {
        Err(MemoryError::PatternNotFound)
    } else {
        Ok(results)
    }
}

fn search_pattern(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    haystack.windows(needle.len())
        .position(|window| window == needle)
}

fn main() -> Result<(), MemoryError> {
    println!("Searching for RobloxPlayerBeta.exe...");
    
    let pid = find_roblox_pid()?;
    println!("Found Roblox process with PID: {}", pid);

    let process_handle = unsafe {
        OpenProcess(PROCESS_VM_READ | PROCESS_QUERY_INFORMATION, 0, pid)
    };

    if process_handle.is_null() {
        return Err(MemoryError::ProcessOpenError);
    }

    println!("Scanning memory for HYPV pattern...");
    match scan_memory_for_hypv(process_handle) {
        Ok(addresses) => {
            if addresses.is_empty() {
                println!("No HYPV patterns found.");
            }
        }
        Err(e) => {
            println!("Error: {}", e);
        }
    }

    unsafe {
        CloseHandle(process_handle);
    }

    Ok(())
}
