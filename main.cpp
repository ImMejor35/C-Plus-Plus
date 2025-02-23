#include <windows.h>
#include <tlhelp32.h>
#include <iostream>
#include <vector>
#include <string>
#include <algorithm>
#include <cstdint>

DWORD find_roblox_pid() {
    HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snapshot == INVALID_HANDLE_VALUE) {
        return 0;
    }

    PROCESSENTRY32W entry;
    entry.dwSize = sizeof(PROCESSENTRY32W);

    if (Process32FirstW(snapshot, &entry)) {
        do {
            std::wstring process_name(entry.szExeFile);
            if (process_name == L"RobloxPlayerBeta.exe") {
                CloseHandle(snapshot);
                return entry.th32ProcessID;
            }
        } while (Process32NextW(snapshot, &entry));
    }

    CloseHandle(snapshot);
    return 0;
}

std::vector<uintptr_t> scan_memory_for_hypv(HANDLE process_handle) {
    std::vector<uintptr_t> results;
    MEMORY_BASIC_INFORMATION mem_info;
    LPVOID address = 0;

    while (VirtualQueryEx(process_handle, address, &mem_info, sizeof(mem_info)) != 0) {
        if (mem_info.State & MEM_COMMIT &&
            (mem_info.Protect & PAGE_READONLY ||
                mem_info.Protect & PAGE_READWRITE ||
                mem_info.Protect & PAGE_EXECUTE_READ ||
                mem_info.Protect & PAGE_EXECUTE_READWRITE)) {
            std::vector<uint8_t> buffer(mem_info.RegionSize);
            SIZE_T bytes_read;
            if (ReadProcessMemory(process_handle, mem_info.BaseAddress, buffer.data(), mem_info.RegionSize, &bytes_read) &&
                bytes_read == mem_info.RegionSize) {
                std::vector<uint8_t> needle = { 'H', 'Y', 'P', 'V' };
                auto it = std::search(buffer.begin(), buffer.end(), needle.begin(), needle.end());
                if (it != buffer.end()) {
                    size_t pos = std::distance(buffer.begin(), it);
                    uintptr_t base_addr = reinterpret_cast<uintptr_t>(mem_info.BaseAddress) + pos;
                    results.push_back(base_addr);

                    std::vector<uint8_t> version_buffer(32);
                    if (ReadProcessMemory(process_handle, reinterpret_cast<LPVOID>(base_addr), version_buffer.data(), 32, &bytes_read) &&
                        bytes_read == 32) {
                        std::string s(version_buffer.begin(), version_buffer.end());
                        size_t null_pos = s.find('\0');
                        if (null_pos != std::string::npos) {
                            s = s.substr(0, null_pos);
                        }
                        s.erase(std::remove(s.begin(), s.end(), '\r'), s.end());
                        s.erase(std::remove(s.begin(), s.end(), '\n'), s.end());
                        if (!s.empty()) {
                            std::cout << "Found at 0x" << std::hex << base_addr << ": " << s << std::endl;
                        }
                    }
                }
            }
        }
        address = reinterpret_cast<LPVOID>(reinterpret_cast<uintptr_t>(mem_info.BaseAddress) + mem_info.RegionSize);
    }
    return results;
}

int main() {
    std::cout << "Searching for RobloxPlayerBeta.exe..." << std::endl;
    DWORD pid = find_roblox_pid();
    if (pid == 0) {
        std::cerr << "Failed to find Roblox process" << std::endl;
        return 1;
    }
    std::cout << "Found Roblox process with PID: " << pid << std::endl;

    HANDLE process_handle = OpenProcess(PROCESS_VM_READ | PROCESS_QUERY_INFORMATION, FALSE, pid);
    if (process_handle == NULL) {
        std::cerr << "Failed to open process" << std::endl;
        return 1;
    }

    std::cout << "Scanning memory for HYPV pattern..." << std::endl;
    std::vector<uintptr_t> addresses = scan_memory_for_hypv(process_handle);
    if (addresses.empty()) {
        std::cout << "No HYPV patterns found." << std::endl;
    }

    CloseHandle(process_handle);
    return 0;
}
